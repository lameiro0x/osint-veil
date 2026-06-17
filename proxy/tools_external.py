"""Wrappers de herramientas OSINT externas (binarios), opcionales.

Cada wrapper se registra SOLO si su binario está instalado (`shutil.which`).
- Pasivas (subfinder, amass -passive, whois): disponibles si están instaladas.
- Activas/intrusivas (nmap, amass -active): solo con allow_active=True.

Seguridad:
- NUNCA shell=True. Los argumentos van como lista; el objetivo se valida con un
  regex estricto (host/dominio) antes de ejecutar — sin metacaracteres de shell.
- Timeout y tope de tamaño de salida (evita floods al pipeline).
- El scope (que el objetivo esté autorizado) lo refuerza además el ToolGateway.
- La salida es DATO: cualquier error se devuelve como texto, no rompe el loop.

Recuerda: el egress de los subprocesos (que no hablen con Anthropic) es cosa del
lockdown de RED (deploy/egress_lockdown.sh), no del software.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .gateway import ToolSpec

# Host/dominio válido: letras, dígitos, guiones y puntos. Sin espacios ni metachars.
_VALID_TARGET = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")

_TIMEOUT = 120
_MAX_BYTES = 20_000


def _valid_target(value: str) -> bool:
    return bool(_VALID_TARGET.match(value.strip()))


def _run(cmd: list[str], *, timeout: int = _TIMEOUT) -> str:
    """Ejecuta un binario SIN shell, con timeout, y trunca la salida."""
    try:
        proc = subprocess.run(  # noqa: S603 — args como lista, sin shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        return f"[{cmd[0]}] no instalado"
    except subprocess.TimeoutExpired:
        return f"[{cmd[0]}] timeout tras {timeout}s"
    except Exception as e:  # noqa: BLE001
        return f"[{cmd[0]}] error: {e}"
    out = (proc.stdout or "") + (("\n[stderr] " + proc.stderr) if proc.stderr else "")
    if len(out) > _MAX_BYTES:
        out = out[:_MAX_BYTES] + f"\n[...truncado a {_MAX_BYTES} bytes...]"
    return out.strip() or f"[{cmd[0]}] sin salida"


def _domain_handler(binary: str, build):
    def handler(inp: dict) -> str:
        target = str(inp.get("domain") or inp.get("host") or "").strip()
        if not _valid_target(target):
            return f"[{binary}] objetivo inválido (esperado dominio/host): {target!r}"
        return _run(build(target))
    return handler


def _spec(name: str, desc: str, arg: str, binary: str, build) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=desc,
        input_schema={
            "type": "object",
            "properties": {arg: {"type": "string", "description": "Dominio/host objetivo"}},
            "required": [arg],
        },
        handler=_domain_handler(binary, build),
        target_arg=arg,
    )


# (nombre, binario, descripción, arg, builder, activa?)
_CANDIDATES = [
    ("subfinder", "subfinder", "Enumera subdominios (pasivo) con subfinder.",
     "domain", lambda t: ["subfinder", "-silent", "-d", t], False),
    ("amass_passive", "amass", "Enumera subdominios en modo PASIVO con amass.",
     "domain", lambda t: ["amass", "enum", "-passive", "-d", t], False),
    ("whois", "whois", "Consulta WHOIS de un dominio.",
     "domain", lambda t: ["whois", t], False),
    ("nmap_fast", "nmap", "Escaneo de puertos rápido (ACTIVO/intrusivo) con nmap.",
     "host", lambda t: ["nmap", "-T4", "-F", "-Pn", t], True),
    ("amass_active", "amass", "Enumeración ACTIVA de subdominios con amass.",
     "domain", lambda t: ["amass", "enum", "-active", "-d", t], True),
]


def external_tools(*, allow_active: bool = False) -> list[ToolSpec]:
    """Devuelve los wrappers cuyos binarios estén instalados.

    Las activas solo se incluyen si allow_active=True.
    """
    tools: list[ToolSpec] = []
    for name, binary, desc, arg, build, active in _CANDIDATES:
        if active and not allow_active:
            continue
        if shutil.which(binary) is None:
            continue
        tools.append(_spec(name, desc, arg, binary, build))
    return tools


def available(*, allow_active: bool = False) -> list[str]:
    return [t.name for t in external_tools(allow_active=allow_active)]
