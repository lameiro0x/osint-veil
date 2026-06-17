"""Tests del blindaje (Ola 1): egress preflight, logging seguro, validación,
detección de cuentas de servicio / nombres / app-vs-tenant GUID."""

import logging
import uuid

import pytest

from proxy import egress
from proxy.config import Settings, validate_settings
from proxy.logging_setup import SecretRedactingFilter
from proxy.sanitizer import Sanitizer
from proxy.storage import CaseStore


# ── egress preflight ──────────────────────────────────────────────────
def test_preflight_enforce_sin_lock_falla():
    with pytest.raises(egress.EgressNotLocked):
        egress.preflight(mode="enforce", locked=False)


def test_preflight_enforce_con_lock_ok():
    assert egress.preflight(mode="enforce", locked=True) is None


def test_preflight_warn_devuelve_aviso():
    assert "AVISO" in (egress.preflight(mode="warn", locked=False) or "")


def test_preflight_off_ok():
    assert egress.preflight(mode="off", locked=False) is None


# ── validación de settings ────────────────────────────────────────────
def test_validate_clave_por_defecto_es_error():
    s = Settings(proxy_local_api_key="change-me")
    errors, _ = validate_settings(s)
    assert any("PROXY_LOCAL_API_KEY" in e for e in errors)


def test_validate_sin_encryption_es_aviso():
    s = Settings(proxy_local_api_key="k-larga", encryption_key="")
    errors, warnings = validate_settings(s)
    assert not errors
    assert any("ENCRYPTION" in w.upper() for w in warnings)


# ── logging seguro ────────────────────────────────────────────────────
def test_filtro_redacta_secretos_en_logs():
    rec = logging.LogRecord("x", logging.INFO, __file__, 1,
                            "fuga ghp_abcdefabcdefabcdefabcdefabcdef123456 aqui", (), None)
    SecretRedactingFilter().filter(rec)
    assert "ghp_" not in rec.getMessage()
    assert "SECRET_REMOVED" in rec.getMessage()


# ── detección nueva ───────────────────────────────────────────────────
def _san(names=None):
    from dataclasses import replace

    from proxy.config import get_case_config
    case = replace(get_case_config("cliente_a_2026"), sensitive_names=names or [])
    store = CaseStore(f"hard-{uuid.uuid4().hex[:8]}")
    return Sanitizer(store, case), store


def test_cuenta_de_servicio():
    s, _ = _san()
    out = s.sanitize("la cuenta svc_backup y CORP\\administrador acceden")
    assert "SERVICE_ACCOUNT_001" in out.sanitized_text
    assert "svc_backup" not in out.sanitized_text


def test_nombre_persona_por_config():
    s, _ = _san(names=["Juan Pérez"])
    out = s.sanitize("el responsable es Juan Pérez del equipo")
    assert "PERSON_001" in out.sanitized_text
    assert "Juan Pérez" not in out.sanitized_text


def test_guid_app_vs_tenant_por_contexto():
    s, _ = _san()
    guid = "11111111-2222-3333-4444-555555555555"
    other = "66666666-7777-8888-9999-000000000000"
    out = s.sanitize(f"client_id={guid} y el tenant {other}")
    assert "APP_ID_001" in out.sanitized_text
    assert "TENANT_ID_001" in out.sanitized_text
