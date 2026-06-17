"""Tests de los wrappers de binarios externos (registro condicional + seguridad)."""

import proxy.tools_external as te


def test_valid_target():
    assert te._valid_target("cliente.com")
    assert te._valid_target("vpn.corp.cliente.com")
    assert not te._valid_target("cliente.com; rm -rf /")
    assert not te._valid_target("a b c")
    assert not te._valid_target("")
    assert not te._valid_target("localhost")  # sin punto -> no es dominio


def test_solo_binarios_instalados(monkeypatch):
    # Solo 'subfinder' instalado.
    monkeypatch.setattr(te.shutil, "which",
                        lambda b: "/usr/bin/subfinder" if b == "subfinder" else None)
    names = te.available(allow_active=False)
    assert "subfinder" in names
    assert "nmap_fast" not in names


def test_activas_detras_de_flag(monkeypatch):
    monkeypatch.setattr(te.shutil, "which", lambda b: f"/usr/bin/{b}")  # todo instalado
    assert "nmap_fast" not in te.available(allow_active=False)
    assert "nmap_fast" in te.available(allow_active=True)
    assert "subfinder" in te.available(allow_active=False)  # pasiva siempre


def test_handler_rechaza_objetivo_malicioso(monkeypatch):
    calls = []
    monkeypatch.setattr(te.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(te.subprocess, "run",
                        lambda *a, **k: calls.append(a) or _fake_proc())
    tool = next(t for t in te.external_tools(allow_active=False) if t.name == "subfinder")
    out = tool.handler({"domain": "cliente.com; whoami"})
    assert "inválido" in out
    assert calls == []  # nunca se ejecutó el binario


def test_handler_ejecuta_con_objetivo_valido(monkeypatch):
    captured = {}
    monkeypatch.setattr(te.shutil, "which", lambda b: f"/usr/bin/{b}")

    def fake_run(cmd, **k):
        captured["cmd"] = cmd
        return _fake_proc(stdout="sub.cliente.com")
    monkeypatch.setattr(te.subprocess, "run", fake_run)

    tool = next(t for t in te.external_tools(allow_active=False) if t.name == "subfinder")
    out = tool.handler({"domain": "cliente.com"})
    assert "sub.cliente.com" in out
    assert captured["cmd"] == ["subfinder", "-silent", "-d", "cliente.com"]  # args como lista


class _FakeProc:
    def __init__(self, stdout="", stderr=""):
        self.stdout, self.stderr, self.returncode = stdout, stderr, 0


def _fake_proc(stdout="", stderr=""):
    return _FakeProc(stdout, stderr)
