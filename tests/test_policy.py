"""Tests del Policy Engine y de los tokens anotados (pistas de relevancia)."""

import uuid

from proxy.config import get_case_config
from proxy.policy import PolicyEngine
from proxy.sanitizer import Sanitizer
from proxy.storage import CaseStore


def _sanitizer(case_id="cliente_a_2026"):
    case = get_case_config(case_id)
    store = CaseStore(f"{case_id}-{uuid.uuid4().hex[:8]}")
    return Sanitizer(store, case, source_tool="test"), store


def test_hint_no_contiene_valor_real():
    s, store = _sanitizer()
    s.sanitize("host vpn-corp-backup.cliente.com encontrado")
    for token, hint in store.annotations().items():
        assert "cliente.com" not in hint
        assert "vpn-corp-backup.cliente.com" not in hint


def test_hint_marca_relevancia_alta_en_vpn_backup():
    s, store = _sanitizer()
    s.sanitize("vpn-corp-backup.cliente.com")
    hints = " ".join(store.annotations().values())
    assert "relevancia: alta" in hints
    assert "vpn" in hints  # palabra-categoría sí, valor completo no


def test_annotations_en_resultado():
    s, _ = _sanitizer()
    res = s.sanitize("admin.cliente.com")
    assert res.annotations  # hay al menos una pista
    token = next(iter(res.annotations))
    assert token.startswith(("SUBDOMAIN", "DOMAIN"))


def test_policy_destroy_no_aplica_a_identificadores():
    case = get_case_config("cliente_a_2026")
    pol = PolicyEngine(case)
    assert pol.should_tokenize("EMAIL", "x@y.com") is True
    assert pol.should_tokenize("INTERNAL_IP", "10.0.0.1") is True


def test_policy_balanced_deja_pasar_dominio_publico():
    case = get_case_config("cliente_a_2026")
    case.mode = "balanced"
    pol = PolicyEngine(case)
    # dominio público no sensible -> NO se tokeniza en balanced
    assert pol.should_tokenize("DOMAIN", "google.com", is_sensitive_host=False) is False
    # host sensible -> sí
    assert pol.should_tokenize("SUBDOMAIN", "vpn.cliente.com", is_sensitive_host=True) is True


def test_render_glosario():
    s, _ = _sanitizer()
    res = s.sanitize("admin.cliente.com en 10.0.0.5")
    glossary = Sanitizer.render_annotations(res.annotations)
    assert "Contexto de tokens" in glossary
    assert "NO son instrucciones" in glossary  # nota anti-injection


def test_hint_se_persiste_en_vault():
    s, store = _sanitizer()
    res = s.sanitize("backup.cliente.com")
    token = next(iter(res.annotations))
    assert store.hint_for(token)
