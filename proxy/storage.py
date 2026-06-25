"""Vault local: mappings, metadatos, hallazgos, secretos y audit log por case_id.

Reglas duras:
- Los mappings (token -> valor real identificativo) se separan por case_id.
- Si hay PROXY_ENCRYPTION_KEY, el almacenamiento se cifra con Fernet.
- Las pistas de relevancia (hints) pasan por el scanner de secretos antes de
  guardarse/devolverse: una pista jamás puede filtrar un secreto.
- Los SECRETOS solo se guardan si el caso lo activa (store_secrets) Y hay clave
  de cifrado. Se guardan en un archivo SEPARADO, cifrado, y NUNCA se envían a
  Claude (el flujo hacia la IA siempre ve SECRET_REMOVED).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings
from .secrets import looks_like_secret, scrub_secrets

_log = logging.getLogger("osint_veil.storage")


def _redact(value: str) -> str:
    """Vista previa segura de un secreto (no revela el valor completo)."""
    v = value.strip()
    if len(v) <= 6:
        return "***"
    return f"{v[:3]}…{v[-2:]} ({len(v)} chars)"


def _safe_case_id(case_id: str) -> str:
    """Evita path traversal en el case_id."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", case_id).strip("._")
    return cleaned or "default_case"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseStore:
    """Vault de un caso. Token reuse determinista + metadatos + audit log."""

    def __init__(self, case_id: str):
        settings = get_settings()
        self.case_id = case_id
        self._dir = settings.storage_path / _safe_case_id(case_id)
        self._mappings_path = self._dir / "mappings.json"
        self._audit_path = self._dir / "audit-log.json"
        self._findings_path = self._dir / "findings.json"
        self._secrets_path = self._dir / "secrets.json"
        self._analysis_path = self._dir / "analysis.json"

        self._fernet: Fernet | None = None
        if settings.encryption_key:
            self._fernet = Fernet(settings.encryption_key.encode())

        self.mappings: dict[str, str] = {}          # token -> valor real
        self.reverse: dict[str, str] = {}           # valor real -> token
        self.meta: dict[str, dict] = {}             # token -> {type, hint, ...}
        self.counters: dict[str, int] = {}
        self._load()

    # ── (de)serialización en disco ───────────────────────────────────
    def _read_blob(self, path: Path) -> bytes | None:
        if not path.is_file():
            return None
        data = path.read_bytes()
        if self._fernet:
            try:
                return self._fernet.decrypt(data)
            except InvalidToken as exc:
                raise RuntimeError(
                    f"No se pudo descifrar {path}. ¿PROXY_ENCRYPTION_KEY correcta?"
                ) from exc
        return data

    def _write_blob(self, path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if self._fernet:
            payload = self._fernet.encrypt(payload)
        path.write_bytes(payload)

    def _load(self) -> None:
        blob = self._read_blob(self._mappings_path)
        if not blob:
            return
        data = json.loads(blob.decode("utf-8"))
        self.mappings = dict(data.get("mappings", {}))
        self.meta = dict(data.get("meta", {}))
        self.reverse = {v: k for k, v in self.mappings.items()}
        for token in self.mappings:
            type_name, _, num = token.rpartition("_")
            if num.isdigit():
                self.counters[type_name] = max(self.counters.get(type_name, 0), int(num))

    def _save_mappings(self) -> None:
        payload = json.dumps(
            {"case_id": self.case_id, "mappings": self.mappings, "meta": self.meta},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        self._write_blob(self._mappings_path, payload)

    # ── API pública ──────────────────────────────────────────────────
    def token_for(self, type_name: str, original: str, *,
                  hint: str | None = None, source_tool: str | None = None) -> str:
        """Devuelve un token estable para `original` dentro de este caso.

        Mismo valor -> mismo token. Rechaza valores con forma de secreto
        (los secretos se eliminan, no se tokenizan). La pista (hint) se limpia
        de cualquier secreto antes de almacenarse.
        """
        if looks_like_secret(original):
            raise ValueError("Los secretos no se tokenizan ni se almacenan.")

        if original in self.reverse:
            token = self.reverse[original]
            # Completar la pista si antes no había una.
            if hint and not self.meta.get(token, {}).get("hint"):
                self.meta.setdefault(token, {})["hint"] = self._safe_hint(hint)
            return token

        n = self.counters.get(type_name, 0) + 1
        self.counters[type_name] = n
        token = f"{type_name}_{n:03d}"
        self.mappings[token] = original
        self.reverse[original] = token
        self.meta[token] = {
            "type": type_name,
            "hint": self._safe_hint(hint) if hint else None,
            "source_tool": source_tool,
            "first_seen": _now(),
        }
        return token

    @staticmethod
    def _safe_hint(hint: str) -> str:
        """La pista no puede contener secretos. Salvaguarda extra."""
        cleaned, _ = scrub_secrets(hint)
        return cleaned

    def hint_for(self, token: str) -> str | None:
        return (self.meta.get(token) or {}).get("hint")

    def annotations(self) -> dict[str, str]:
        """token -> pista (solo los que tienen pista)."""
        return {t: m["hint"] for t, m in self.meta.items() if m.get("hint")}

    def persist(self) -> None:
        self._save_mappings()

    def rehydrate(self, text: str) -> str:
        """Sustituye tokens conocidos por sus valores reales (solo en local)."""
        for token in sorted(self.mappings, key=len, reverse=True):
            text = text.replace(token, self.mappings[token])
        return text

    def write_audit(self, *, type_counts: dict[str, int], provider: str, mode: str,
                    dry_run: bool, note: str | None = None) -> None:
        """Registra QUÉ tipos se censuraron y cuántas veces. Sin datos reales."""
        entry = {
            "timestamp": _now(),
            "case_id": self.case_id,
            "provider": provider,
            "mode": mode,
            "dry_run": dry_run,
            "censored": type_counts,
            "occurrences": sum(type_counts.values()),
        }
        if note:
            entry["note"] = note
        existing: list = []
        blob = self._read_blob(self._audit_path)
        if blob:
            try:
                existing = json.loads(blob.decode("utf-8"))
            except json.JSONDecodeError:
                existing = []
        existing.append(entry)
        self._write_blob(
            self._audit_path,
            json.dumps(existing, ensure_ascii=False, indent=2).encode("utf-8"),
        )

    def add_finding(self, tool: str, text: str) -> None:
        """Guarda un hallazgo REAL (cifrado) en el vault para el informe local.

        El texto debe venir YA libre de secretos (los secretos no se guardan).
        Salvaguarda: se vuelve a pasar por el scrubber por si acaso.
        """
        clean, _ = scrub_secrets(text)
        findings = self.read_findings()
        findings.append({"timestamp": _now(), "tool": tool, "text": clean})
        self._write_blob(
            self._findings_path,
            json.dumps(findings, ensure_ascii=False, indent=2).encode("utf-8"),
        )

    def read_findings(self) -> list[dict]:
        blob = self._read_blob(self._findings_path)
        if not blob:
            return []
        try:
            return json.loads(blob.decode("utf-8"))
        except json.JSONDecodeError:
            return []

    def save_analysis(self, text: str) -> None:
        """Persiste el análisis final de Claude (en TOKENS) para regenerar el informe.

        El texto está tokenizado (Claude solo conoce tokens). Se cifra como el resto.
        """
        self._write_blob(
            self._analysis_path,
            json.dumps({"timestamp": _now(), "analysis": text or ""},
                       ensure_ascii=False, indent=2).encode("utf-8"),
        )

    def read_analysis(self) -> str:
        blob = self._read_blob(self._analysis_path)
        if not blob:
            return ""
        try:
            return json.loads(blob.decode("utf-8")).get("analysis", "")
        except json.JSONDecodeError:
            return ""

    # ── Vault de SECRETOS (opt-in, cifrado obligatorio, jamás a Claude) ──
    @property
    def encryption_enabled(self) -> bool:
        return self._fernet is not None

    def add_secret(self, type_name: str, value: str, *, source_tool: str | None = None,
                   location: str | None = None) -> bool:
        """Guarda un secreto REAL en local, cifrado. Devuelve True si se guardó.

        SEGURIDAD: se NIEGA a guardar si no hay cifrado (no escribe secretos en
        claro). Este archivo NUNCA se envía a Claude ni se expone con valor
        completo por la API (solo vista previa redactada).
        """
        if self._fernet is None:
            _log.warning("store_secrets activo pero sin PROXY_ENCRYPTION_KEY: "
                         "el secreto NO se guarda (no se escriben secretos en claro).")
            return False
        secrets = self.read_secrets()
        secrets.append({
            "type": type_name,
            "value": value,
            "preview": _redact(value),
            "source_tool": source_tool,
            "location": location,
            "first_seen": _now(),
        })
        self._write_blob(
            self._secrets_path,
            json.dumps(secrets, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        return True

    def read_secrets(self) -> list[dict]:
        """Secretos COMPLETOS (uso LOCAL: CLI/informe). No exponer por red."""
        blob = self._read_blob(self._secrets_path)
        if not blob:
            return []
        try:
            return json.loads(blob.decode("utf-8"))
        except json.JSONDecodeError:
            return []

    def secrets_redacted(self) -> list[dict]:
        """Metadatos + vista previa (sin valor completo). Seguro para la API."""
        return [{"type": s.get("type"), "preview": s.get("preview"),
                 "source_tool": s.get("source_tool"), "location": s.get("location"),
                 "first_seen": s.get("first_seen")}
                for s in self.read_secrets()]

    def read_audit(self) -> list[dict]:
        blob = self._read_blob(self._audit_path)
        if not blob:
            return []
        try:
            return json.loads(blob.decode("utf-8"))
        except json.JSONDecodeError:
            return []
