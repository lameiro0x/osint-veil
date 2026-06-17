"""Gestor de trabajos en background para OSINT (no bloquear la API).

POST inicia el trabajo y devuelve un job_id; el cliente sigue el progreso por
SSE o polling. En memoria (un proceso). Para multi-worker, sustituir por una
cola/persistencia — ver TODO en README.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from .claude_client import ClaudeClient
from .config import get_case_config, get_settings
from .gateway import ToolGateway, builtin_tools
from .orchestrator import Budget, Orchestrator
from .tools_external import external_tools


@dataclass
class Job:
    id: str
    case_id: str
    target: str
    status: str = "running"           # running | done | failed
    events: list[dict] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)


_MAX_JOBS = 100  # retención en memoria; se evictan los más antiguos


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def snapshot(self, job_id: str) -> dict | None:
        """Copia coherente (bajo lock) del estado del job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return {"id": job.id, "status": job.status, "events": list(job.events),
                    "result": job.result, "error": job.error}

    def start(self, *, case_id: str, target: str, scope: list[str],
              max_iterations: int, allow_active: bool) -> Job:
        job = Job(id=f"job-{uuid.uuid4().hex[:12]}", case_id=case_id, target=target)
        with self._lock:
            self._jobs[job.id] = job
            # Evicta los más antiguos si superamos el tope.
            if len(self._jobs) > _MAX_JOBS:
                for old in sorted(self._jobs.values(), key=lambda j: j.created_at)[:-_MAX_JOBS]:
                    self._jobs.pop(old.id, None)
        t = threading.Thread(target=self._run, args=(job, scope, max_iterations, allow_active),
                             daemon=True)
        t.start()
        return job

    def _run(self, job: Job, scope, max_iterations, allow_active) -> None:
        from .storage import CaseStore  # import tardío: evita ciclos en el arranque
        try:
            settings = get_settings()
            case = get_case_config(job.case_id)
            store = CaseStore(job.case_id)
            tools = builtin_tools() + external_tools(allow_active=allow_active)
            gateway = ToolGateway(scope_domains=[job.target, *scope], tools=tools)

            def progress(ev: dict) -> None:
                with self._lock:
                    job.events.append({"ts": time.time(), **ev})

            orch = Orchestrator(
                client=ClaudeClient(settings), gateway=gateway, store=store, case=case,
                target=job.target, budget=Budget(max_iterations=max_iterations),
                model=case.model, progress=progress,
            )
            result = orch.run()
            store.write_audit(type_counts=result.type_counts, provider=case.provider,
                              mode=case.mode, dry_run=False,
                              note=f"job stop={result.stop_reason}")
            analysis = result.final_text
            if case.rehydrate_output and case.mode == "reporting":
                analysis = store.rehydrate(analysis)
            job.result = {
                "stop_reason": result.stop_reason,
                "iterations": result.iterations,
                "total_tokens": result.total_tokens,
                "censored": result.type_counts,
                "tool_calls": result.tool_calls,
                "analysis": analysis,
            }
            job.status = "done"
        except Exception as e:  # noqa: BLE001 — reportar el fallo en el job, no romper el server
            job.error = str(e)
            job.status = "failed"


# Instancia única para la app.
manager = JobManager()
