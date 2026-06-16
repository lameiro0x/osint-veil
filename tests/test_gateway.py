"""Tests del Tool Gateway y del egress control (software)."""

import uuid

import pytest

from proxy.egress import EgressViolation, assert_tool_target_allowed
from proxy.gateway import ScopeError, ToolGateway, ToolNotAllowed, ToolSpec


def _spec(calls):
    return ToolSpec(
        name="recon",
        description="fake",
        input_schema={"type": "object", "properties": {"host": {"type": "string"}},
                      "required": ["host"]},
        handler=lambda inp: calls.append(inp) or "ok",
        target_arg="host",
    )


def test_egress_bloquea_anthropic():
    with pytest.raises(EgressViolation):
        assert_tool_target_allowed("https://api.anthropic.com/v1/messages")
    with pytest.raises(EgressViolation):
        assert_tool_target_allowed("claude.ai")
    # objetivo normal -> permitido
    assert_tool_target_allowed("https://cliente.com/robots.txt")


def test_gateway_rechaza_tool_no_permitida():
    gw = ToolGateway(scope_domains=["cliente.com"], tools=[])
    with pytest.raises(ToolNotAllowed):
        gw.execute("inexistente", {"host": "cliente.com"})


def test_gateway_scope_guard():
    calls = []
    gw = ToolGateway(scope_domains=["cliente.com"], tools=[_spec(calls)])
    # fuera de scope -> ScopeError y NO se ejecuta el handler
    with pytest.raises(ScopeError):
        gw.execute("recon", {"host": "evil.com"})
    assert calls == []
    # dentro de scope -> ejecuta
    assert gw.execute("recon", {"host": "vpn.cliente.com"}) == "ok"
    assert calls and calls[0]["host"] == "vpn.cliente.com"


def test_safe_get_revalida_cada_redirect(monkeypatch):
    import proxy.egress as eg

    class FakeResp:
        def __init__(self, redirect, location=None):
            self.is_redirect = redirect
            self.headers = {"location": location} if location else {}
            self.next_request = type("R", (), {"url": location})() if location else None
            self.status_code = 302 if redirect else 200

    state = {"n": 0}

    def fake_get(url, timeout, follow_redirects):
        state["n"] += 1
        if state["n"] == 1:
            return FakeResp(True, "https://api.anthropic.com/evil")  # redirect malicioso
        return FakeResp(False)

    monkeypatch.setattr(eg.httpx, "get", fake_get)
    with pytest.raises(eg.EgressViolation):
        eg.safe_get("https://cliente.com")


def test_gateway_bloquea_objetivo_anthropic():
    gw = ToolGateway(scope_domains=["anthropic.com"], tools=[_spec([])])
    with pytest.raises(EgressViolation):
        gw.execute("recon", {"host": "api.anthropic.com"})
