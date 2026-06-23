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

import os
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


def _tool_user_prefix() -> list[str]:
    """Si PROXY_TOOLS_USER está fijado, ejecuta la herramienta como ESE usuario.

    Así el lockdown de red por-usuario (iptables --uid-owner) corta de verdad la
    salida de las herramientas hacia el proveedor de IA, aunque el binario intente
    abrir su propio socket. Requiere sudoers: el usuario del proxy puede correr
    como PROXY_TOOLS_USER sin contraseña (lo configura el Dockerfile/despliegue).
    """
    user = os.getenv("PROXY_TOOLS_USER", "").strip()
    if user and shutil.which("sudo"):
        return ["sudo", "-n", "-u", user]
    return []


def _run(cmd: list[str], *, timeout: int = _TIMEOUT) -> str:
    """Ejecuta un binario SIN shell, con timeout, y trunca la salida."""
    name = cmd[0] if cmd else "?"  # binario real (antes de anteponer sudo)
    cmd = _tool_user_prefix() + cmd
    try:
        proc = subprocess.run(  # noqa: S603 — args como lista, sin shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        return f"[{name}] no instalado"
    except subprocess.TimeoutExpired:
        return f"[{name}] timeout tras {timeout}s"
    except Exception as e:  # noqa: BLE001
        return f"[{name}] error: {e}"
    out = (proc.stdout or "") + (("\n[stderr] " + proc.stderr) if proc.stderr else "")
    if len(out) > _MAX_BYTES:
        out = out[:_MAX_BYTES] + f"\n[...truncado a {_MAX_BYTES} bytes...]"
    return out.strip() or f"[{name}] sin salida"


def _domain_handler(binary: str, build):
    def handler(inp: dict) -> str:
        target = str(inp.get("domain") or inp.get("host") or "").strip()
        if not _valid_target(target):
            return f"[{binary}] objetivo inválido (esperado dominio/host): {target!r}"
        return _run(build(binary, target))
    return handler


def _resolve(binary) -> str | None:
    """Primer alias del binario que esté instalado (p.ej. theHarvester/theharvester)."""
    aliases = (binary,) if isinstance(binary, str) else tuple(binary)
    for b in aliases:
        if shutil.which(b):
            return b
    return None


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
#
# PASIVAS: consultan fuentes terceras / DNS; no tocan al objetivo de forma
# intrusiva. ACTIVAS (activa=True): conectan/escanean el objetivo; solo se
# exponen al agente con allow_active=True (--allow-active).
# El builder recibe (binary_resuelto, target): así cmd[0] siempre es el binario
# que realmente está instalado (p.ej. theHarvester vs theharvester).
_CANDIDATES = [
    # ── Pasivas (recon/OSINT) ─────────────────────────────────────────
    ("subfinder", "subfinder", "Enumera subdominios (pasivo) con subfinder.",
     "domain", lambda b, t: [b, "-silent", "-d", t], False),
    ("amass_passive", "amass", "Enumera subdominios en modo PASIVO con amass.",
     "domain", lambda b, t: [b, "enum", "-passive", "-d", t], False),
    ("assetfinder", "assetfinder", "Descubre subdominios (pasivo) con assetfinder.",
     "domain", lambda b, t: [b, "--subs-only", t], False),
    ("whois", "whois", "Consulta WHOIS de un dominio.",
     "domain", lambda b, t: [b, t], False),
    ("dns_records", "dig", "Registros DNS del dominio (A/AAAA/MX/NS/TXT) con dig.",
     "domain", lambda b, t: [b, "+noall", "+answer", t, "ANY"], False),
    ("dnsrecon", "dnsrecon", "Enumeración DNS estándar (pasiva) con dnsrecon.",
     "domain", lambda b, t: [b, "-d", t], False),
    ("theharvester", ("theHarvester", "theharvester"),
     "OSINT de subdominios/hosts vía crt.sh con theHarvester.",
     "domain", lambda b, t: [b, "-d", t, "-b", "crtsh"], False),
    # ── Activas (intrusivas: solo con allow_active) ───────────────────
    ("nmap_fast", "nmap", "Escaneo de puertos rápido (ACTIVO/intrusivo) con nmap.",
     "host", lambda b, t: [b, "-T4", "-F", "-Pn", t], True),
    ("amass_active", "amass", "Enumeración ACTIVA de subdominios con amass.",
     "domain", lambda b, t: [b, "enum", "-active", "-d", t], True),
    ("whatweb", "whatweb", "Fingerprint de tecnologías web (ACTIVO) con whatweb.",
     "host", lambda b, t: [b, "--no-errors", t], True),
    ("wafw00f", "wafw00f", "Detecta WAF (ACTIVO) con wafw00f.",
     "host", lambda b, t: [b, t], True),
    ("nuclei", "nuclei", "Escaneo de vulnerabilidades por plantillas (ACTIVO) con nuclei.",
     "host", lambda b, t: [b, "-silent", "-u", t], True),
]


def external_tools(*, allow_active: bool = False) -> list[ToolSpec]:
    """Devuelve los wrappers cuyos binarios estén instalados.

    Las activas solo se incluyen si allow_active=True.
    """
    tools: list[ToolSpec] = []
    for name, binary, desc, arg, build, active in _CANDIDATES:
        if active and not allow_active:
            continue
        resolved = _resolve(binary)
        if resolved is None:
            continue
        tools.append(_spec(name, desc, arg, resolved, build))
    return tools


def available(*, allow_active: bool = False) -> list[str]:
    return [t.name for t in external_tools(allow_active=allow_active)]
