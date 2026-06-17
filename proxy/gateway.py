"""Tool Gateway: allowlist de herramientas + validación de args + scope guard.

Solo se ejecutan herramientas registradas y aprobadas. Cada llamada se valida
contra el ALCANCE autorizado (scope): si una herramienta apunta a un objetivo
fuera del scope, se bloquea (esto evita scope creep, que es un problema legal).

Las herramientas corren EN LOCAL (invariante 1). Su salida de red pasa por
`egress.safe_get`, que impide alcanzar al proveedor de IA (invariante 2).
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

from .egress import assert_tool_target_allowed, safe_get


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], str]
    target_arg: str | None = None  # arg que contiene el objetivo (para scope)


class ScopeError(RuntimeError):
    pass


class ToolNotAllowed(RuntimeError):
    pass


def _host_of(value: str) -> str:
    if "://" in value:
        from urllib.parse import urlparse
        return (urlparse(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0].lower()


class ToolGateway:
    """Registro y ejecución controlada de herramientas."""

    def __init__(self, scope_domains: list[str], tools: list[ToolSpec] | None = None):
        self.scope_domains = [d.lower().lstrip("*.") for d in scope_domains]
        self._tools: dict[str, ToolSpec] = {}
        for t in tools or []:
            self.register(t)

    def register(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def tool_names(self) -> list[str]:
        return list(self._tools)

    def anthropic_tools(self) -> list[dict]:
        """Esquemas de herramientas en formato Anthropic (para el tool_use)."""
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in self._tools.values()
        ]

    def in_scope(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.scope_domains)

    def validate(self, name: str, tool_input: dict) -> None:
        """Valida allowlist + scope. Lanza si no procede."""
        if name not in self._tools:
            raise ToolNotAllowed(f"Herramienta no permitida: {name}")
        spec = self._tools[name]
        if spec.target_arg:
            target = str(tool_input.get(spec.target_arg, ""))
            if not target:
                raise ScopeError(f"Falta el objetivo '{spec.target_arg}' en {name}")
            host = _host_of(target)
            assert_tool_target_allowed(target)  # nunca al proveedor de IA
            if self.scope_domains and not self.in_scope(host):
                raise ScopeError(
                    f"Fuera de alcance: {host} no está en el scope autorizado "
                    f"{self.scope_domains}"
                )

    def execute(self, name: str, tool_input: dict) -> str:
        """Valida y ejecuta. Devuelve la salida CRUDA (irá al vault)."""
        self.validate(name, tool_input)
        return self._tools[name].handler(tool_input)


# ── Herramientas integradas (dependencia mínima, reales) ─────────────────
def _dns_resolve(inp: dict) -> str:
    host = str(inp["host"])
    assert_tool_target_allowed(host)
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return f"DNS {host}:\n" + "\n".join(ips) if ips else f"DNS {host}: sin registros"
    except OSError as e:
        return f"DNS {host}: error ({e})"


# Cabeceras que pueden portar credenciales/sesión: no se exponen a Claude.
_HEADER_DENYLIST = {
    "set-cookie", "cookie", "authorization", "proxy-authorization",
    "www-authenticate", "x-api-key", "x-amz-security-token", "x-auth-token",
    "x-csrf-token", "x-xsrf-token",
}


def _http_headers(inp: dict) -> str:
    url = str(inp["url"])
    try:
        r = safe_get(url)
        lines = [f"{k}: {v}" for k, v in r.headers.items()
                 if k.lower() not in _HEADER_DENYLIST]
        return f"HTTP {url} -> {r.status_code}\n" + "\n".join(lines)
    except Exception as e:  # noqa: BLE001 — devolver error como dato, no romper loop
        return f"HTTP {url}: error ({e})"


def builtin_tools() -> list[ToolSpec]:
    """Herramientas OSINT pasivas, sin binarios externos. Amplía aquí."""
    return [
        ToolSpec(
            name="dns_resolve",
            description="Resuelve un host a sus direcciones IP (DNS).",
            input_schema={
                "type": "object",
                "properties": {"host": {"type": "string", "description": "Host a resolver"}},
                "required": ["host"],
            },
            handler=_dns_resolve,
            target_arg="host",
        ),
        ToolSpec(
            name="http_headers",
            description="Obtiene las cabeceras HTTP de una URL del objetivo.",
            input_schema={
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL del objetivo"}},
                "required": ["url"],
            },
            handler=_http_headers,
            target_arg="url",
        ),
    ]
