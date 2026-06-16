"""Tests de persistencia: reuso de tokens, cifrado y rechazo de secretos."""

import importlib
import os
import uuid

import pytest
from cryptography.fernet import Fernet

from proxy.storage import CaseStore


def test_secreto_no_se_tokeniza():
    store = CaseStore(f"sec-{uuid.uuid4().hex[:8]}")
    with pytest.raises(ValueError):
        store.token_for("API_KEY", "ghp_abcdefabcdefabcdefabcdefabcdef123456")


def test_token_persiste_y_reusa():
    case_id = f"persist-{uuid.uuid4().hex[:8]}"
    store = CaseStore(case_id)
    t1 = store.token_for("EMAIL", "ana@cliente.com")
    store.persist()
    # Releer desde disco en una instancia nueva.
    store2 = CaseStore(case_id)
    assert store2.token_for("EMAIL", "ana@cliente.com") == t1


def test_cifrado_en_disco(monkeypatch, tmp_path):
    """Con clave de cifrado, el archivo en disco no contiene el valor en claro."""
    monkeypatch.setenv("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("PROXY_STORAGE_PATH", str(tmp_path))
    import proxy.config as config
    config.get_settings.cache_clear()
    importlib.reload(importlib.import_module("proxy.storage"))
    from proxy.storage import CaseStore as FreshStore

    case_id = "enc_case"
    store = FreshStore(case_id)
    store.token_for("EMAIL", "secreto.identificable@cliente.com")
    store.persist()

    raw = (tmp_path / case_id / "mappings.json").read_bytes()
    assert b"secreto.identificable@cliente.com" not in raw  # cifrado en reposo
    # Y se puede releer con la misma clave.
    assert "secreto.identificable@cliente.com" in FreshStore(case_id).mappings.values()

    config.get_settings.cache_clear()
    monkeypatch.delenv("PROXY_ENCRYPTION_KEY", raising=False)
