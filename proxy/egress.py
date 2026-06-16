"""Egress control a nivel de software (capa 1 de 2).

INVARIANTE 2 (ver docs/DESIGN.md): el ÚNICO proceso que puede hablar con
Anthropic es el proxy. Las herramientas salen a internet (eso es el OSINT) pero
NO pueden alcanzar Anthropic.

Esta capa de software refuerza la invariante a nivel de proceso: cualquier
llamada de red que haga una herramienta debe pasar por `safe_get`, que rechaza
destinos de Anthropic. Es una salvaguarda, NO la garantía final.

La garantía FINAL es a nivel de red (firewall/netns): ver `deploy/egress_lockdown.sh`.
El software no puede impedir que un binario externo abra su propio socket; por eso
el bloqueo de red es obligatorio en producción.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

# Dominios del proveedor de IA que las HERRAMIENTAS nunca deben tocar.
BLOCKED_SUFFIXES = (
    "anthropic.com",
    "api.anthropic.com",
    "claude.ai",
)


class EgressViolation(RuntimeError):
    """Una herramienta intentó alcanzar al proveedor de IA. Bloqueado."""


class EgressNotLocked(RuntimeError):
    """Modo enforce activo pero el lockdown de red no está confirmado."""


def preflight(*, mode: str, locked: bool) -> str | None:
    """Comprobación previa al OSINT autónomo.

    El software no puede verificar la política de red por sí mismo; lo que sí
    puede es NEGARSE a lanzar el loop autónomo (que ejecuta herramientas) salvo
    que el despliegue confirme que el lockdown de red está aplicado
    (PROXY_EGRESS_LOCKED=1, lo pone deploy/egress_lockdown.sh / Docker).

    - enforce + no locked -> EgressNotLocked (no arranca).
    - warn    + no locked -> devuelve aviso (string).
    - off / locked        -> None (ok).
    """
    if locked or mode == "off":
        return None
    if mode == "enforce":
        raise EgressNotLocked(
            "PROXY_EGRESS=enforce y el lockdown de red NO está confirmado "
            "(PROXY_EGRESS_LOCKED!=1). Aplica deploy/egress_lockdown.sh y marca la "
            "variable antes de lanzar OSINT autónomo."
        )
    return ("AVISO: egress no forzado (PROXY_EGRESS=warn). Una herramienta podría "
            "abrir su propio socket hacia Anthropic. Usa 'enforce' + lockdown en producción.")


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def assert_tool_target_allowed(target: str) -> None:
    """Lanza EgressViolation si una herramienta apunta al proveedor de IA."""
    host = _host_of(target)
    if any(host == s or host.endswith("." + s) for s in BLOCKED_SUFFIXES):
        raise EgressViolation(
            f"Bloqueado: una herramienta intentó alcanzar {host} (proveedor IA). "
            "Solo el proxy puede hablar con Anthropic."
        )


def safe_get(url: str, *, timeout: float = 10.0, max_redirects: int = 5) -> httpx.Response:
    """GET para herramientas. Rechaza destinos del proveedor de IA.

    NO usa follow_redirects automático: un host en scope podría devolver un 302
    hacia api.anthropic.com y httpx lo seguiría sin revalidar. Seguimos las
    redirecciones manualmente, comprobando CADA salto contra la lista de bloqueo.
    """
    assert_tool_target_allowed(url)
    current = url
    for _ in range(max_redirects + 1):
        resp = httpx.get(current, timeout=timeout, follow_redirects=False)
        if resp.is_redirect and "location" in resp.headers:
            current = str(resp.next_request.url) if resp.next_request else resp.headers["location"]
            assert_tool_target_allowed(current)  # revalida cada salto
            continue
        return resp
    return resp
