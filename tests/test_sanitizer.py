"""Tests del motor de sanitización (los 10 mínimos del spec + extras)."""

import uuid

from proxy.config import get_case_config
from proxy.sanitizer import Sanitizer
from proxy.storage import CaseStore


def _sanitizer(mode_case_id="cliente_a_2026"):
    case = get_case_config(mode_case_id)
    store = CaseStore(f"{mode_case_id}-{uuid.uuid4().hex[:8]}")  # caso aislado
    return Sanitizer(store, case), store


def test_emails_se_tokenizan():
    s, _ = _sanitizer()
    out = s.sanitize("contacto juan.perez@cliente.com aquí")
    assert "EMAIL_001" in out.sanitized_text
    assert "juan.perez@cliente.com" not in out.sanitized_text


def test_dominios_sensibles_se_tokenizan():
    s, _ = _sanitizer()
    out = s.sanitize("el host vpn.cliente.com responde")
    assert "SUBDOMAIN_001" in out.sanitized_text
    assert "cliente.com" not in out.sanitized_text


def test_ips_internas_se_tokenizan():
    s, _ = _sanitizer()
    out = s.sanitize("servidor en 192.168.1.50 y 10.0.0.8")
    assert "INTERNAL_IP_001" in out.sanitized_text
    assert "INTERNAL_IP_002" in out.sanitized_text
    assert "192.168.1.50" not in out.sanitized_text


def test_ip_publica_en_strict():
    s, _ = _sanitizer()
    out = s.sanitize("la ip publica es 8.8.8.8")
    assert "PUBLIC_IP_001" in out.sanitized_text


def test_github_tokens_se_eliminan():
    s, _ = _sanitizer()
    out = s.sanitize("token ghp_abcdefabcdefabcdefabcdefabcdef123456 fin")
    assert "SECRET_REMOVED" in out.sanitized_text
    assert "ghp_" not in out.sanitized_text


def test_jwt_se_elimina():
    s, _ = _sanitizer()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36"
    out = s.sanitize(f"auth {jwt} end")
    assert "JWT_REMOVED" in out.sanitized_text
    assert "eyJ" not in out.sanitized_text


def test_bearer_se_elimina():
    s, _ = _sanitizer()
    out = s.sanitize("Authorization: Bearer abc.def.ghi-secret-value")
    assert "SECRET_REMOVED" in out.sanitized_text
    assert "abc.def.ghi-secret-value" not in out.sanitized_text


def test_no_se_guardan_secretos_en_mappings():
    s, store = _sanitizer()
    s.sanitize(
        "ghp_abcdefabcdefabcdefabcdefabcdef123456 password=Sup3rSecret "
        "AKIAIOSFODNN7EXAMPLE"
    )
    blob = " ".join(store.mappings.values())
    assert "ghp_" not in blob
    assert "Sup3rSecret" not in blob
    assert "AKIA" not in blob


def test_mismo_email_mismo_token():
    s, _ = _sanitizer()
    out = s.sanitize("a juan.perez@cliente.com b juan.perez@cliente.com")
    assert out.sanitized_text.count("EMAIL_001") == 2
    assert "EMAIL_002" not in out.sanitized_text


def test_casos_distintos_mappings_separados():
    case = get_case_config("cliente_a_2026")
    store_a = CaseStore(f"caseA-{uuid.uuid4().hex[:8]}")
    store_b = CaseStore(f"caseB-{uuid.uuid4().hex[:8]}")
    Sanitizer(store_a, case).sanitize("ana@cliente.com")
    Sanitizer(store_b, case).sanitize("luis@cliente.com")
    assert store_a.mappings != store_b.mappings
    assert "ana@cliente.com" in store_a.mappings.values()
    assert "ana@cliente.com" not in store_b.mappings.values()


def test_repo_se_tokeniza():
    s, _ = _sanitizer()
    out = s.sanitize("repo https://github.com/cliente/proyecto interno")
    assert "REPO_001" in out.sanitized_text
    assert "github.com/cliente/proyecto" not in out.sanitized_text


def test_clave_privada_pem_se_elimina():
    s, _ = _sanitizer()
    pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n"
           "-----END RSA PRIVATE KEY-----")
    out = s.sanitize(f"clave: {pem}")
    assert "SECRET_REMOVED" in out.sanitized_text
    assert "BEGIN RSA PRIVATE KEY" not in out.sanitized_text


def test_rehidratacion():
    s, store = _sanitizer()
    out = s.sanitize("juan.perez@cliente.com en vpn.cliente.com")
    rehydrated = store.rehydrate(out.sanitized_text)
    assert "juan.perez@cliente.com" in rehydrated
    assert "vpn.cliente.com" in rehydrated
