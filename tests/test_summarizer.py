"""Tests del summarizer local opcional (Ollama). Sin Ollama real (httpx mockeado)."""

import proxy.summarizer as summ
from proxy.config import Settings


class _Resp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def _settings(**kw):
    base = dict(summarizer="ollama", summarizer_min_chars=10,
                summarizer_model="llama3.2", summarizer_host="http://127.0.0.1:11434")
    base.update(kw)
    return Settings(**base)


def test_desactivado_por_defecto():
    s = Settings()  # summarizer="off"
    assert summ.summarize("x" * 5000, s) is None


def test_no_resume_si_es_corto():
    assert summ.summarize("corto", _settings()) is None


def test_resume_cuando_activo(monkeypatch):
    monkeypatch.setattr(summ.httpx, "post",
                        lambda *a, **k: _Resp({"response": "Resumen: SUBDOMAIN_001 cluster vpn"}))
    out = summ.summarize("SUBDOMAIN_001 ... " * 50, _settings())
    assert out == "Resumen: SUBDOMAIN_001 cluster vpn"


def test_fail_safe_si_ollama_cae(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(summ.httpx, "post", boom)
    summ._warned = False
    assert summ.summarize("SUBDOMAIN_001 " * 50, _settings()) is None  # no rompe


def test_resumen_se_limpia_de_secretos(monkeypatch):
    leak = "ghp_" + "a" * 30
    monkeypatch.setattr(summ.httpx, "post",
                        lambda *a, **k: _Resp({"response": f"token {leak} encontrado"}))
    out = summ.summarize("SUBDOMAIN_001 " * 50, _settings())
    assert leak not in out
    assert "SECRET_REMOVED" in out
