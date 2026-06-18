"""Tests de la cobertura ampliada de secretos e identificadores."""

import uuid

from proxy.config import get_case_config
from proxy.sanitizer import Sanitizer, _luhn_ok
from proxy.secrets import scrub_secrets
from proxy.storage import CaseStore


def _san():
    case = get_case_config("cliente_a_2026")
    return Sanitizer(CaseStore(f"det-{uuid.uuid4().hex[:8]}"), case)


# ── secretos de proveedores ───────────────────────────────────────────
# Los valores son FALSOS y se ensamblan por concatenación a propósito: así el
# escáner de secretos de GitHub no los detecta como tokens reales en el código.
def test_secretos_proveedores_se_eliminan():
    samples = {
        "slack": "xoxb" + "-0123456789-abcdefghijkl",
        "google": "AI" + "za" + "B" * 35,
        "stripe": "sk_" + "live_0123456789abcdef",
        "sendgrid": "SG" + ".0123456789abcdef.0123456789abcdefABCD",
        "gitlab": "glpat" + "-0123456789abcdefghij",
        "npm": "npm_" + "a" * 36,
        "azure": "AccountKey=" + "0123456789abcdef0123456789abcdef==",
        "apikey": "api_key=" + "ABCDEFGH12345678",
    }
    for name, secret in samples.items():
        cleaned, counts = scrub_secrets(f"valor {secret} fin")
        assert secret not in cleaned, f"{name} no eliminado"
        assert counts, f"{name} no detectado"


def test_password_corta_aun_se_elimina():
    cleaned, _ = scrub_secrets("password=abc")
    assert "abc" not in cleaned
    assert "SECRET_REMOVED" in cleaned


def test_apikey_valor_corto_no_falso_positivo():
    # api_key con valor < 8 chars: no se considera secreto (evita FP).
    cleaned, _ = scrub_secrets("api_key=short")
    assert "short" in cleaned


# ── identificadores nuevos ────────────────────────────────────────────
def test_luhn():
    assert _luhn_ok("4242424242424242")
    assert not _luhn_ok("4242424242424243")


def test_tarjeta_credito_valida_se_tokeniza():
    s = _san()
    out = s.sanitize("pago con 4242 4242 4242 4242 hoy")
    assert "CREDIT_CARD_001" in out.sanitized_text
    assert "4242 4242 4242 4242" not in out.sanitized_text


def test_numero_largo_no_valido_no_se_toca():
    s = _san()
    out = s.sanitize("id 1234567890123456 interno")  # falla Luhn
    assert "CREDIT_CARD" not in out.sanitized_text
    assert "1234567890123456" in out.sanitized_text


def test_mac_y_crypto():
    s = _san()
    out = s.sanitize("mac 00:1A:2B:3C:4D:5E eth 0x52908400098527886E0F7030069857D2E4169EE7")
    assert "MAC_001" in out.sanitized_text
    assert "CRYPTO_ADDR_001" in out.sanitized_text


def test_secret_shaped_cubre_twilio_y_authtoken():
    from proxy.secrets import looks_like_secret
    twilio = "SK" + "0123456789abcdef0123456789abcdef"  # falso, ensamblado
    assert looks_like_secret(twilio)
    assert looks_like_secret("auth_token=loquesea")
    assert not looks_like_secret("dominio.com normal")


def test_cc_no_traga_separador_final():
    s = _san()
    out = s.sanitize("4111 1111 1111 1111 fin")
    assert "CREDIT_CARD_001 fin" in out.sanitized_text  # espacio preservado


def test_nuevos_secretos_no_entran_al_vault():
    s = _san()
    slack = "xoxb" + "-0123456789-abcdefghijkl"
    s.sanitize(f"token {slack} y " + "AI" + "za" + "B" * 35)
    blob = " ".join(s.store.mappings.values())
    assert "xoxb-" not in blob
    assert "AIza" not in blob
