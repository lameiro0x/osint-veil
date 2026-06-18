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
