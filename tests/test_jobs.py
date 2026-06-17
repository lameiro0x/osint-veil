"""Tests del JobManager (OSINT en background + eventos de progreso)."""

import time

import proxy.jobs as jobs


class FakeClaude:
    """Sustituye a ClaudeClient: termina en el primer turno, sin tools."""

    def __init__(self, settings):
        pass

    def run_turn(self, *, system, messages, tools, model=None, max_tokens=4000):
        return {"content": [{"type": "text", "text": "Informe final."}],
                "stop_reason": "end_turn", "usage": {"input_tokens": 3, "output_tokens": 3}}


def _wait(job, timeout=5.0):
    start = time.time()
    while job.status == "running" and time.time() - start < timeout:
        time.sleep(0.05)
    return job


def test_job_corre_y_emite_progreso(monkeypatch):
    monkeypatch.setattr(jobs, "ClaudeClient", FakeClaude)
    mgr = jobs.JobManager()
    job = mgr.start(case_id="jobcase", target="cliente.com", scope=[],
                    max_iterations=3, allow_active=False)
    _wait(job)

    assert job.status == "done"
    assert job.result and job.result["stop_reason"] == "completed"
    kinds = [e["event"] for e in job.events]
    assert "start" in kinds
    assert "done" in kinds


def test_job_fallo_se_captura(monkeypatch):
    class Boom:
        def __init__(self, settings):
            raise RuntimeError("explota")
    monkeypatch.setattr(jobs, "ClaudeClient", Boom)
    mgr = jobs.JobManager()
    job = mgr.start(case_id="jobcase2", target="cliente.com", scope=[],
                    max_iterations=2, allow_active=False)
    _wait(job)
    assert job.status == "failed"
    assert job.error
