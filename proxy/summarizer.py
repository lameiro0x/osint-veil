"""Summarizer local OPCIONAL (Ollama). Condensa salidas grandes antes de Claude.

Diseño y privacidad:
- Es OPT-IN (`PROXY_SUMMARIZER=ollama`). Por defecto está apagado y NO se necesita
  instalar nada: si no se activa, el pipeline funciona igual.
- Opera SOLO sobre texto YA sanitizado (tokenizado, sin secretos). Así, aunque el
  host de Ollama estuviera mal configurado a un servidor remoto, solo viajarían
  tokens, nunca datos reales. Defensa extra: se re-escanea por secretos.
- Fail-safe: si Ollama no está disponible, devuelve None y el pipeline sigue con
  el texto completo (nunca rompe el OSINT).

No añade dependencias nuevas: habla con la API HTTP local de Ollama vía httpx.
"""

from __future__ import annotations

import logging

import httpx

from .config import Settings
from .secrets import scrub_secrets

_log = logging.getLogger("osint_veil.summarizer")
_warned = False

_PROMPT = """Eres un asistente que CONDENSA salidas de herramientas OSINT ya \
anonimizadas. Las entradas contienen tokens como SUBDOMAIN_007 o INTERNAL_IP_002 \
con pistas de relevancia.

Reglas:
- Resume en español, conciso y accionable, preservando los TOKENS tal cual \
(SUBDOMAIN_007, etc.) — no los inventes ni los cambies.
- Conserva las relaciones y agrupaciones relevantes (p.ej. clusters de hosts).
- No añadas información que no esté en la entrada. No saques conclusiones nuevas.
- Devuelve solo el resumen, sin preámbulos.

Salida de herramienta a condensar:
---
{text}
---
Resumen:"""


def is_enabled(settings: Settings) -> bool:
    return settings.summarizer == "ollama"


def summarize(text: str, settings: Settings) -> str | None:
    """Devuelve un resumen condensado, o None si no aplica/no está disponible.

    Solo resume si está habilitado y el texto supera el umbral. Nunca lanza:
    ante cualquier fallo (Ollama caído, timeout) devuelve None.
    """
    global _warned
    if not is_enabled(settings):
        return None
    if len(text) < settings.summarizer_min_chars:
        return None

    # Defensa extra: el texto ya viene sanitizado, pero re-escaneamos secretos.
    safe_input, _ = scrub_secrets(text)
    payload = {
        "model": settings.summarizer_model,
        "prompt": _PROMPT.format(text=safe_input),
        "stream": False,
        "options": {"temperature": 0.1},
    }
    try:
        resp = httpx.post(f"{settings.summarizer_host.rstrip('/')}/api/generate",
                          json=payload, timeout=120.0)
        resp.raise_for_status()
        out = (resp.json().get("response") or "").strip()
    except Exception as e:  # noqa: BLE001 — nunca romper el pipeline por el resumidor
        if not _warned:
            _log.warning("Summarizer (Ollama) no disponible (%s): se usa el texto "
                         "completo. Desactiva con PROXY_SUMMARIZER=off.", e)
            _warned = True
        return None

    if not out:
        return None
    # Salvaguarda final: el resumen tampoco puede contener secretos.
    cleaned, _ = scrub_secrets(out)
    return cleaned
