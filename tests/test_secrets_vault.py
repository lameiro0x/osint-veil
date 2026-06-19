"""Tests del vault de secretos (opt-in, cifrado, nunca a Claude)."""

import uuid
from dataclasses import replace

import pytest
from cryptography.fernet import Fernet

from proxy import config
from proxy.config import get_case_config
from proxy.gateway import ToolGateway, ToolSpec
from proxy.orchestrator import Orchestrator
from proxy.report import build_report
from proxy.sanitizer import Sanitizer
from proxy.storage import CaseStore

GHP = "ghp_" + "a" * 30  # secreto FALSO ensamblado (no es un token real)


@pytest.fixture
def enc(monkeypatch):
    monkeypatch.setenv("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def _store():
    return CaseStore(f"sv-{uuid.uuid4().hex[:8]}")


def test_secreto_se_guarda_cifrado_y_no_va_a_claude(enc):
    case = replace(get_case_config("cliente_a_2026"), store_secrets=True)
    store = _store()
    res = Sanitizer(store, case).sanitize(f"token {GHP} aqui")

    # NO va a Claude:
    assert GHP not in res.sanitized_text
    assert "SECRET_REMOVED" in res.sanitized_text
    # SÍ en el vault de secretos, valor completo (uso local):
    assert any(s["value"] == GHP for s in store.read_secrets())
    # NO en mappings (no se tokeniza):
    assert GHP not in " ".join(store.mappings.values())
    # La vista redactada (API) NO expone el valor completo:
    assert all(GHP not in str(r) for r in store.secrets_redacted())


def test_sin_encryption_no_guarda_en_claro(monkeypatch):
    monkeypatch.delenv("PROXY_ENCRYPTION_KEY", raising=False)
    config.get_settings.cache_clear()
    try:
        case = replace(get_case_config("cliente_a_2026"), store_secrets=True)
        store = _store()
        Sanitizer(store, case).sanitize(f"x {GHP}")
        assert store.read_secrets() == []  # no se escribe secreto en claro
    finally:
        config.get_settings.cache_clear()


def test_default_no_guarda_secretos(enc):
    case = get_case_config("cliente_a_2026")  # store_secrets=False por defecto
    assert case.store_secrets is False
    store = _store()
    Sanitizer(store, case).sanitize(f"x {GHP}")
    assert store.read_secrets() == []


def test_informe_revela_secretos_solo_en_local(enc):
    case = replace(get_case_config("cliente_a_2026"), store_secrets=True)
    store = _store()
    Sanitizer(store, case).sanitize(f"x {GHP}")
    # Por defecto (uso API): solo vista previa, nunca el valor completo.
    md_api = build_report(store, case, rehydrate=True, reveal_secrets=False)
    assert GHP not in md_api
    # En local (CLI/archivo): valor completo.
    md_local = build_report(store, case, rehydrate=True, reveal_secrets=True)
    assert GHP in md_local


def test_orquestador_guarda_secreto_y_findings_limpios(enc):
    case = replace(get_case_config("cliente_a_2026"), store_secrets=True)
    store = _store()
    tool = ToolSpec(
        name="recon", description="x",
        input_schema={"type": "object", "properties": {"host": {"type": "string"}},
                      "required": ["host"]},
        handler=lambda inp: f"hallado {GHP} en el host", target_arg="host")
    gw = ToolGateway(scope_domains=["cliente.com"], tools=[tool])

    class FC:
        n = 0

        def run_turn(self, **k):
            FC.n += 1
            if FC.n == 1:
                return {"content": [{"type": "tool_use", "id": "t", "name": "recon",
                                     "input": {"host": "vpn.cliente.com"}}],
                        "stop_reason": "tool_use", "usage": {}}
            return {"content": [{"type": "text", "text": "fin"}],
                    "stop_reason": "end_turn", "usage": {}}

    Orchestrator(client=FC(), gateway=gw, store=store, case=case, target="cliente.com").run()
    # Secreto guardado en local:
    assert any(s["value"] == GHP for s in store.read_secrets())
    # Y NUNCA en los findings (que sí van resumidos hacia Claude):
    assert all(GHP not in f["text"] for f in store.read_findings())
