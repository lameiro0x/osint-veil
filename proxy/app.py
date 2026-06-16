"""API local del Privacy Proxy (FastAPI).

Regla de oro: nada llega a Claude sin pasar antes por el sanitizador.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import logging
from contextlib import asynccontextmanager

from .config import Settings, get_case_config, get_settings, validate_settings
from .claude_client import ClaudeClient
from .egress import EgressNotLocked
from .gateway import ToolGateway, builtin_tools
from .logging_setup import setup_logging
from .orchestrator import Budget, Orchestrator
from .report import build_report, review_queue
from .sanitizer import Sanitizer
from .storage import CaseStore

_log = logging.getLogger("osint_veil.app")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    setup_logging()
    errors, warnings = validate_settings(require_api_key=False)
    for w in warnings:
        _log.warning(w)
    for e in errors:
        # No se aborta el arranque (las rutas autenticadas ya devuelven 503 con
        # la clave por defecto), pero se avisa fuerte en el log.
        _log.error("CONFIG: %s", e)
    yield


app = FastAPI(title="osint-veil", version="0.1.0", lifespan=_lifespan)


# ── Autenticación local ──────────────────────────────────────────────
def require_local_key(authorization: str | None = Header(default=None)) -> None:
    settings = get_settings()
    # No arrancar con la clave por defecto: expondría mappings/rehydrate/osint.
    if settings.proxy_local_api_key in ("", "change-me"):
        raise HTTPException(
            status_code=503,
            detail="PROXY_LOCAL_API_KEY no configurada (sigue siendo el valor por "
                   "defecto). Cámbiala en .env antes de usar el proxy.",
        )
    expected = f"Bearer {settings.proxy_local_api_key}"
    if not authorization or authorization != expected:
        raise HTTPException(status_code=401, detail="Missing or invalid local API key")


def _resolve_case_id(case_id: str | None) -> str:
    return case_id or get_settings().default_case_id


# ── Modelos de petición ──────────────────────────────────────────────
class SanitizeRequest(BaseModel):
    case_id: str | None = None
    text: str


class RehydrateRequest(BaseModel):
    case_id: str | None = None
    text: str
    force: bool = False


class ChatMessage(BaseModel):
    role: str
    content: Any


class ChatRequest(BaseModel):
    model: str | None = None
    messages: list[ChatMessage]
    temperature: float | None = None
    max_tokens: int = 2000
    case_id: str | None = None
    dry_run: bool = False


class OsintRequest(BaseModel):
    case_id: str | None = None
    target: str
    scope: list[str] = []
    max_iterations: int = 12


# ── Endpoints ─────────────────────────────────────────────────────────
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/privacy/sanitize", dependencies=[Depends(require_local_key)])
def sanitize_endpoint(req: SanitizeRequest) -> dict[str, Any]:
    case_id = _resolve_case_id(req.case_id)
    case = get_case_config(case_id)
    store = CaseStore(case_id)
    result = Sanitizer(store, case).sanitize(req.text)
    store.write_audit(type_counts=result.type_counts, provider=case.provider,
                      mode=case.mode, dry_run=True)
    return {
        "sanitized_text": result.sanitized_text,
        "findings": result.findings,
        "annotations": result.annotations,
    }


@app.post("/privacy/rehydrate", dependencies=[Depends(require_local_key)])
def rehydrate_endpoint(req: RehydrateRequest) -> dict[str, Any]:
    case_id = _resolve_case_id(req.case_id)
    case = get_case_config(case_id)
    if not (case.rehydrate_output or req.force):
        raise HTTPException(
            status_code=403,
            detail="Rehydrate deshabilitado para este caso. Usa force=true o "
                   "rehydrate_output=true en la config del caso.",
        )
    store = CaseStore(case_id)
    return {"rehydrated_text": store.rehydrate(req.text)}


@app.get("/privacy/mappings/{case_id}", dependencies=[Depends(require_local_key)])
def mappings_endpoint(case_id: str) -> dict[str, Any]:
    store = CaseStore(case_id)
    return {"case_id": case_id, "mappings": store.mappings}


@app.get("/privacy/audit-log/{case_id}", dependencies=[Depends(require_local_key)])
def audit_endpoint(case_id: str) -> dict[str, Any]:
    store = CaseStore(case_id)
    return {"case_id": case_id, "audit_log": store.read_audit()}


@app.get("/privacy/review-queue/{case_id}", dependencies=[Depends(require_local_key)])
def review_queue_endpoint(case_id: str) -> dict[str, Any]:
    store = CaseStore(case_id)
    return {"case_id": case_id, "review_queue": review_queue(store)}


@app.post("/osint/run", dependencies=[Depends(require_local_key)])
def osint_run(req: OsintRequest) -> dict[str, Any]:
    """Lanza un OSINT autónomo y seguro (loop client-side). Síncrono."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY no configurada.")
    case_id = _resolve_case_id(req.case_id)
    case = get_case_config(case_id)
    store = CaseStore(case_id)
    gateway = ToolGateway(scope_domains=[req.target] + req.scope, tools=builtin_tools())
    orch = Orchestrator(
        client=ClaudeClient(settings), gateway=gateway, store=store, case=case,
        target=req.target, budget=Budget(max_iterations=req.max_iterations),
        model=case.model,
    )
    try:
        result = orch.run()
    except EgressNotLocked as e:
        raise HTTPException(status_code=409, detail=str(e))
    store.write_audit(type_counts=result.type_counts, provider=case.provider,
                      mode=case.mode, dry_run=False, note=f"osint stop={result.stop_reason}")
    # El análisis se devuelve TOKENIZADO. Rehidratar es decisión local del caso.
    analysis = result.final_text
    if case.rehydrate_output and case.mode == "reporting":
        analysis = store.rehydrate(analysis)
    return {
        "case_id": case_id,
        "stop_reason": result.stop_reason,
        "iterations": result.iterations,
        "total_tokens": result.total_tokens,
        "censored": result.type_counts,
        "tool_calls": result.tool_calls,
        "analysis": analysis,
    }


@app.get("/osint/report/{case_id}", dependencies=[Depends(require_local_key)])
def osint_report(case_id: str, rehydrate: bool = False, force: bool = False) -> dict[str, Any]:
    """Devuelve el informe en Markdown. rehydrate=true requiere permiso del caso."""
    case = get_case_config(case_id)
    store = CaseStore(case_id)
    if rehydrate and not (case.rehydrate_output or force):
        raise HTTPException(
            status_code=403,
            detail="Rehydrate deshabilitado para este caso. Usa force=true o "
                   "rehydrate_output=true. (El informe rehidratado es solo para uso local.)",
        )
    md = build_report(store, case, analysis="", rehydrate=rehydrate)
    return {"case_id": case_id, "rehydrated": rehydrate, "report_markdown": md}


@app.post("/v1/chat/completions", dependencies=[Depends(require_local_key)])
def chat_completions(req: ChatRequest) -> dict[str, Any]:
    settings: Settings = get_settings()
    case_id = _resolve_case_id(req.case_id)
    case = get_case_config(case_id)
    store = CaseStore(case_id)
    sanitizer = Sanitizer(store, case)

    # 1-7. Sanitizar cada mensaje ANTES de cualquier llamada externa.
    safe_messages: list[dict] = []
    total_counts: dict[str, int] = {}
    annotations: dict[str, str] = {}
    for msg in req.messages:
        content = msg.content
        if isinstance(content, str):
            res = sanitizer.sanitize(content)
            safe_content: Any = res.sanitized_text
        elif isinstance(content, list):
            parts = []
            res_text = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    r = sanitizer.sanitize(part.get("text", ""))
                    parts.append({"type": "text", "text": r.sanitized_text})
                    res_text.append(r)
                else:
                    parts.append(part)
            safe_content = parts
            res = _merge(res_text)
        else:
            res = sanitizer.sanitize(str(content))
            safe_content = res.sanitized_text
        for k, v in res.type_counts.items():
            total_counts[k] = total_counts.get(k, 0) + v
        annotations.update(res.annotations)
        safe_messages.append({"role": msg.role, "content": safe_content})

    # Glosario de tokens (pistas de relevancia) como DATOS NO CONFIABLES en el
    # canal de usuario — nunca en el canal de sistema (invariante 3). Las pistas
    # derivan de datos y no deben tratarse como instrucciones de operador.
    glossary = Sanitizer.render_annotations(annotations)
    if glossary:
        safe_messages.append({"role": "user", "content": glossary})

    # dry-run: no se llama a Claude, solo se reporta qué se censuraría.
    if req.dry_run:
        store.write_audit(type_counts=total_counts, provider=case.provider,
                          mode=case.mode, dry_run=True)
        return {
            "id": f"dryrun-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion.dryrun",
            "created": int(time.time()),
            "model": req.model or case.model,
            "sanitized_messages": safe_messages,
            "censored": total_counts,
            "annotations": annotations,
        }

    if not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY no configurada.")

    # 8. Llamar a Claude SOLO con texto anonimizado.
    client = ClaudeClient(settings)
    answer = client.chat(
        messages=safe_messages,
        model=req.model or case.model,
        max_tokens=req.max_tokens,
        temperature=req.temperature,
    )

    # 9-10. Respuesta. Rehidratar solo si el caso lo permite (reporting).
    out_text = answer["text"]
    if case.rehydrate_output and case.mode == "reporting":
        out_text = store.rehydrate(out_text)

    store.write_audit(type_counts=total_counts, provider=case.provider,
                      mode=case.mode, dry_run=False)

    return {
        "id": answer["id"],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": answer["model"],
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": out_text},
                "finish_reason": _finish(answer["stop_reason"]),
            }
        ],
        "usage": answer["usage"],
    }


def _merge(results: list) -> Any:
    """Combina varios SanitizeResult en uno (solo necesitamos type_counts)."""
    from .sanitizer import SanitizeResult

    merged = SanitizeResult(sanitized_text="")
    for r in results:
        for k, v in r.type_counts.items():
            merged.type_counts[k] = merged.type_counts.get(k, 0) + v
        merged.findings.extend(r.findings)
        merged.annotations.update(r.annotations)
    return merged


def _finish(stop_reason: str | None) -> str:
    return {"end_turn": "stop", "max_tokens": "length"}.get(stop_reason or "", "stop")
