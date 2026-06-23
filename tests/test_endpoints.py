"""Tests de los endpoints FastAPI (sin llamar a Claude de verdad)."""

from fastapi.testclient import TestClient

from proxy.app import app

client = TestClient(app)
AUTH = {"Authorization": "Bearer test-key"}


def test_health_sin_auth():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert isinstance(body["encryption_enabled"], bool)
    # No debe filtrar valores de claves, solo flags booleanos.
    assert "test-key" not in str(body)


def test_sanitize_requiere_auth():
    r = client.post("/privacy/sanitize", json={"case_id": "c1", "text": "x"})
    assert r.status_code == 401


def test_sanitize_funciona():
    payload = {
        "case_id": "endpoint_case",
        "text": "El email juan.perez@cliente.com aparece en vpn.cliente.com "
                "con token ghp_abcdefabcdefabcdefabcdefabcdef123456",
    }
    r = client.post("/privacy/sanitize", json=payload, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "EMAIL_001" in body["sanitized_text"]
    assert "SUBDOMAIN_001" in body["sanitized_text"]
    assert "SECRET_REMOVED" in body["sanitized_text"]
    assert "juan.perez@cliente.com" not in body["sanitized_text"]
    assert "ghp_" not in body["sanitized_text"]
    assert any(f["type"] == "EMAIL" for f in body["findings"])


def test_chat_dry_run_no_llama_a_claude():
    payload = {
        "case_id": "dry_case",
        "dry_run": True,
        "messages": [
            {"role": "system", "content": "Eres un analista de seguridad"},
            {"role": "user", "content": "Analiza admin@cliente.com en 10.0.0.5"},
        ],
    }
    r = client.post("/v1/chat/completions", json=payload, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion.dryrun"
    joined = str(body["sanitized_messages"])
    assert "admin@cliente.com" not in joined
    assert "10.0.0.5" not in joined
    assert body["censored"]


def test_chat_tools_dry_run_sanitiza_tool_results():
    payload = {
        "case_id": "dry_case",
        "dry_run": True,
        "tools": [{"type": "function", "function": {
            "name": "whois", "parameters": {"type": "object",
            "properties": {"domain": {"type": "string"}}}}}],
        "messages": [
            {"role": "user", "content": "investiga cliente.com"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "whois", "arguments": "{\"domain\": \"cliente.com\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "admin@cliente.com en 10.0.0.5"},
        ],
    }
    r = client.post("/v1/chat/completions", json=payload, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion.dryrun"
    joined = str(body["sanitized_messages"])
    assert "admin@cliente.com" not in joined  # el tool_result se anonimiza
    assert "10.0.0.5" not in joined
    assert body["tools"][0]["name"] == "whois"  # tools traducidas a Anthropic


def test_chat_tools_rehidrata_argumentos(monkeypatch):
    import re

    import proxy.app as appmod

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def run_turn(self, *, system, messages, tools, model=None, max_tokens=4000):
            # El proxy debe haber tokenizado el dominio antes de llegar aquí.
            assert "cliente.com" not in str(messages)
            m = re.search(r"[A-Z_]+_\d+", str(messages))  # el token del dominio
            assert m, f"no se tokenizó el dominio: {messages}"
            return {
                "content": [
                    {"type": "text", "text": "Enumero subdominios"},
                    {"type": "tool_use", "id": "tu1", "name": "subfinder",
                     "input": {"domain": m.group(0)}},
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }

    monkeypatch.setattr(appmod, "ClaudeClient", FakeClient)
    monkeypatch.setattr(appmod.get_settings(), "anthropic_api_key", "sk-test", raising=False)

    payload = {
        "case_id": "tools_case",
        "tools": [{"type": "function", "function": {
            "name": "subfinder",
            "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}}}}],
        "messages": [{"role": "user", "content": "investiga cliente.com"}],
    }
    r = client.post("/v1/chat/completions", json=payload, headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["choices"][0]["finish_reason"] == "tool_calls"
    args = body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    # El argumento sale REHIDRATADO: el cliente ejecuta contra el objetivo real.
    assert "cliente.com" in args
    assert "DOMAIN_" not in args


def test_chat_stream_rechazado():
    r = client.post("/v1/chat/completions", headers=AUTH,
                    json={"stream": True, "messages": [{"role": "user", "content": "hola"}]})
    assert r.status_code == 400


def test_mappings_y_audit():
    case = "mapcase"
    client.post("/privacy/sanitize",
                json={"case_id": case, "text": "ana@cliente.com"}, headers=AUTH)
    rm = client.get(f"/privacy/mappings/{case}", headers=AUTH)
    assert rm.status_code == 200
    assert "ana@cliente.com" in rm.json()["mappings"].values()

    ra = client.get(f"/privacy/audit-log/{case}", headers=AUTH)
    assert ra.status_code == 200
    log = ra.json()["audit_log"]
    assert log and "EMAIL" in log[-1]["censored"]
    # El audit log no debe contener el valor real.
    assert "ana@cliente.com" not in str(log)


def test_clave_por_defecto_bloquea(monkeypatch):
    from proxy import app as appmod
    from proxy.config import Settings
    monkeypatch.setattr(appmod, "get_settings",
                        lambda: Settings(proxy_local_api_key="change-me"))
    r = client.post("/privacy/sanitize",
                    json={"case_id": "x", "text": "y"},
                    headers={"Authorization": "Bearer change-me"})
    assert r.status_code == 503


def test_osint_report_rehydrate_bloqueado():
    case = "rehyrep"
    client.post("/privacy/sanitize",
                json={"case_id": case, "text": "vpn.cliente.com"}, headers=AUTH)
    r = client.get(f"/osint/report/{case}?rehydrate=true", headers=AUTH)
    assert r.status_code == 403
    r2 = client.get(f"/osint/report/{case}?rehydrate=true&force=true", headers=AUTH)
    assert r2.status_code == 200


def test_osint_job_start_sin_api_key_da_500():
    r = client.post("/osint/jobs",
                    json={"case_id": "jc", "target": "cliente.com"}, headers=AUTH)
    assert r.status_code == 500


def test_osint_job_desconocido_404():
    r = client.get("/osint/jobs/job-noexiste", headers=AUTH)
    assert r.status_code == 404


def test_review_queue_endpoint():
    case = "rqcase"
    client.post("/privacy/sanitize",
                json={"case_id": case, "text": "vpn.cliente.com"}, headers=AUTH)
    r = client.get(f"/privacy/review-queue/{case}", headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json()["review_queue"], list)


def test_osint_run_sin_api_key_da_500():
    r = client.post("/osint/run",
                    json={"case_id": "osc", "target": "cliente.com"}, headers=AUTH)
    # Sin ANTHROPIC_API_KEY en el entorno de test -> 500 controlado.
    assert r.status_code == 500


def test_osint_report_endpoint():
    case = "orcase"
    client.post("/privacy/sanitize",
                json={"case_id": case, "text": "admin.cliente.com"}, headers=AUTH)
    r = client.get(f"/osint/report/{case}", headers=AUTH)
    assert r.status_code == 200
    assert "Informe OSINT" in r.json()["report_markdown"]


def test_rehydrate_bloqueado_por_defecto():
    case = "rehy_case"
    client.post("/privacy/sanitize",
                json={"case_id": case, "text": "ana@cliente.com"}, headers=AUTH)
    r = client.post("/privacy/rehydrate",
                    json={"case_id": case, "text": "ana es EMAIL_001"}, headers=AUTH)
    assert r.status_code == 403
    # Con force=true sí rehidrata.
    r2 = client.post("/privacy/rehydrate",
                     json={"case_id": case, "text": "ana es EMAIL_001", "force": True},
                     headers=AUTH)
    assert r2.status_code == 200
    assert "ana@cliente.com" in r2.json()["rehydrated_text"]
