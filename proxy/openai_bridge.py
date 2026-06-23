"""Puente OpenAI ↔ Anthropic con privacidad para clientes agénticos (OpenOSINT).

Traduce peticiones OpenAI `/chat/completions` con *function calling* a la Messages
API de Anthropic y de vuelta. Dos garantías:

- ENTRANTE (cliente → Claude): se sanitiza CADA contenido (system/user/assistant),
  incluidos los argumentos de tool_calls y, sobre todo, los RESULTADOS de las
  herramientas (`role: tool`) — ahí están los hallazgos OSINT sensibles. A Claude
  solo le llegan tokens.
- SALIENTE (Claude → cliente): se REHIDRATAN los argumentos de los tool_calls
  (valor a valor, sin romper el JSON) para que el cliente ejecute las herramientas
  contra los objetivos REALES. Un token (DOMAIN_001) no sirve para ejecutar nada.

Las funciones son puras: reciben callables `sanitize`/`rehydrate`, así se prueban
sin SDK ni red.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def _walk(obj: Any, fn: Callable[[str], str]) -> Any:
    """Aplica `fn` a cada string dentro de dicts/listas anidados."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    return obj


def _as_text(content: Any) -> str:
    """Normaliza el `content` de un mensaje OpenAI a texto plano."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            p.get("text", "") for p in content
            if isinstance(p, dict) and "text" in p
        )
    return str(content)


def _args_to_obj(arguments: Any) -> Any:
    """Los `arguments` OpenAI pueden ser string JSON o dict; devuelve objeto."""
    if isinstance(arguments, str):
        try:
            return json.loads(arguments or "{}")
        except (json.JSONDecodeError, TypeError):
            return {}
    return arguments or {}


def oai_tools_to_anthropic(tools: list[dict] | None) -> list[dict]:
    """[{type:function, function:{name,description,parameters}}] → tools Anthropic."""
    out: list[dict] = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function", t)
        name = fn.get("name")
        if not name:
            continue
        out.append({
            "name": name,
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return out


def oai_tool_choice_to_anthropic(choice: Any) -> dict | None:
    """Mapea tool_choice OpenAI → Anthropic. 'auto'/'none'/None → None (auto)."""
    if choice in (None, "auto", "none"):
        return None
    if choice == "required":
        return {"type": "any"}
    if isinstance(choice, dict):
        fn = choice.get("function", {})
        if fn.get("name"):
            return {"type": "tool", "name": fn["name"]}
    return None


def oai_messages_to_anthropic(
    messages: list[dict], sanitize: Callable[[str], str]
) -> tuple[str | None, list[dict]]:
    """Mensajes OpenAI → (system, convo) Anthropic, sanitizando todo el contenido.

    Agrupa los `role: tool` consecutivos en un único turno de usuario con bloques
    `tool_result` (como exige Anthropic tras un turno con `tool_use`).
    """
    system_parts: list[str] = []
    convo: list[dict] = []
    pending: list[dict] = []  # tool_result pendientes de volcar en un turno user
    _anon = 0  # contador para ids ausentes (clientes malformados)

    def flush() -> None:
        nonlocal pending
        if pending:
            convo.append({"role": "user", "content": pending})
            pending = []

    for m in messages:
        role = m.get("role")
        content = m.get("content")

        if role == "tool":
            tcid = m.get("tool_call_id")
            if not tcid:  # cliente malformado: id único para no colisionar
                _anon += 1
                tcid = f"anon_tool_{_anon}"
            pending.append({
                "type": "tool_result",
                "tool_use_id": tcid,
                "content": sanitize(_as_text(content)),
            })
            continue

        flush()

        if role == "system":
            txt = sanitize(_as_text(content))
            if txt:
                system_parts.append(txt)
        elif role == "assistant":
            blocks: list[dict] = []
            txt = sanitize(_as_text(content)) if content else ""
            if txt:
                blocks.append({"type": "text", "text": txt})
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {})
                inp = _walk(_args_to_obj(fn.get("arguments")), sanitize)
                blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id") or "",
                    "name": fn.get("name", ""),
                    "input": inp if isinstance(inp, dict) else {},
                })
            if not blocks:
                blocks = [{"type": "text", "text": ""}]
            convo.append({"role": "assistant", "content": blocks})
        else:  # user (o rol desconocido → tratado como user)
            convo.append({"role": "user", "content": sanitize(_as_text(content))})

    flush()
    system = "\n\n".join(p for p in system_parts if p) or None
    return system, convo


def append_glossary(convo: list[dict], glossary: str) -> None:
    """Añade el glosario de tokens al último turno user, si es seguro hacerlo.

    No se añade tras un turno `assistant` con tool_use (rompería la adyacencia
    tool_use→tool_result que exige Anthropic).
    """
    if not glossary or not convo or convo[-1]["role"] != "user":
        return
    c = convo[-1]["content"]
    if isinstance(c, list):
        c.append({"type": "text", "text": glossary})
    else:
        convo[-1]["content"] = (c + "\n\n" + glossary) if c else glossary


def anthropic_to_oai_message(
    content_blocks: list[dict], rehydrate: Callable[[str], str],
    *, rehydrate_text: bool = False,
) -> tuple[dict, str]:
    """Bloques de respuesta Anthropic → (message OpenAI, finish_reason).

    Rehidrata SIEMPRE los argumentos de los tool_calls (valor a valor) para que el
    cliente ejecute contra objetivos reales. El texto del asistente solo se rehidrata
    si `rehydrate_text` (según la política del caso).
    """
    text_parts: list[str] = []
    tool_calls: list[dict] = []
    for b in content_blocks:
        btype = b.get("type")
        if btype == "text":
            text_parts.append(b.get("text", ""))
        elif btype == "tool_use":
            real_input = _walk(b.get("input", {}), rehydrate)
            tool_calls.append({
                "id": b.get("id", ""),
                "type": "function",
                "function": {
                    "name": b.get("name", ""),
                    "arguments": json.dumps(real_input, ensure_ascii=False),
                },
            })

    text = "".join(text_parts)
    if rehydrate_text and text:
        text = rehydrate(text)

    msg: dict = {"role": "assistant", "content": text or None}
    if tool_calls:
        msg["tool_calls"] = tool_calls
        return msg, "tool_calls"
    return msg, "stop"
