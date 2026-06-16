"""Logging seguro: nada de secretos ni cuerpos con datos reales en los logs.

Vectores de fuga que cierra:
- El SDK de Anthropic / httpx pueden loguear URLs y, en debug, cuerpos.
- uvicorn loguea cada petición (path + querystring).
- Un `logger.info(f"...{valor}")` despistado podría imprimir datos reales.

Solución:
- Se baja el nivel de los loggers ruidosos a WARNING.
- Se DESACTIVAN los access logs de uvicorn por defecto (los reactiva PROXY_ACCESS_LOG=1).
- Se instala un filtro que pasa CADA mensaje de log por el scrubber de secretos,
  así aunque algo se loguee por error, el secreto no queda en disco/terminal.
"""

from __future__ import annotations

import logging
import os

from .secrets import scrub_secrets

_NOISY = ("httpx", "httpcore", "anthropic", "urllib3",
          "uvicorn", "uvicorn.error", "uvicorn.access")


class SecretRedactingFilter(logging.Filter):
    """Pasa cada registro por el scrubber de secretos antes de emitirlo."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — formateo defectuoso: no arriesgar
            return True
        cleaned, counts = scrub_secrets(msg)
        if counts:
            record.msg = cleaned
            record.args = ()
        return True


def setup_logging(level: str | None = None) -> None:
    """Configura logging seguro a nivel de proceso. Idempotente."""
    lvl = (level or os.getenv("PROXY_LOG_LEVEL", "INFO")).upper()
    root = logging.getLogger()
    root.setLevel(lvl)

    redactor = SecretRedactingFilter()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    for h in root.handlers:
        h.addFilter(redactor)

    # Loggers ruidosos: solo avisos/errores, y también redactados.
    for name in _NOISY:
        lg = logging.getLogger(name)
        lg.setLevel(logging.WARNING)
        lg.addFilter(redactor)

    # Access log de uvicorn desactivado salvo opt-in explícito.
    if os.getenv("PROXY_ACCESS_LOG", "0") != "1":
        logging.getLogger("uvicorn.access").disabled = True
