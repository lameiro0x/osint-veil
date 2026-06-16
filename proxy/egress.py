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
