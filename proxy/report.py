"""Generación del informe final (en LOCAL) y cola de revisión no bloqueante.

El informe se rehidrata desde el vault SOLO en local — nunca sale hacia Claude.
La cola de revisión es una vista de hallazgos de alta relevancia para que el
operador los mire si quiere; NO bloquea el avance del orquestador.
"""

from __future__ import annotations

from .config import CaseConfig
from .storage import CaseStore


def review_queue(store: CaseStore) -> list[dict]:
    """Hallazgos de alta relevancia, para revisión humana opcional (no bloqueante)."""
    items = []
    for token, meta in store.meta.items():
        hint = meta.get("hint") or ""
        if "relevancia: alta" in hint:
            items.append({"token": token, "type": meta.get("type"),
                          "hint": hint, "source_tool": meta.get("source_tool")})
    return items


def build_report(store: CaseStore, case: CaseConfig, *, analysis: str = "",
                 rehydrate: bool = True, reveal_secrets: bool = False) -> str:
    """Construye un informe en Markdown. Rehidrata tokens en local si se pide.

    `reveal_secrets` solo debe activarse en uso LOCAL (CLI / archivo). El valor
    completo de los secretos JAMÁS debe cruzar la red: la API genera el informe
    con reveal_secrets=False (solo vista previa).
    """
    audit = store.read_audit()
    total_censored: dict[str, int] = {}
    for e in audit:
        for k, v in e.get("censored", {}).items():
            total_censored[k] = total_censored.get(k, 0) + v

    lines: list[str] = []
    lines.append(f"# Informe OSINT — caso `{case.case_id}`\n")
    lines.append(f"- Modo de privacidad: **{case.mode}**")
    lines.append(f"- Tokens en el vault: **{len(store.mappings)}**")
    lines.append(f"- Hallazgos crudos guardados: **{len(store.read_findings())}**")
    lines.append("")

    lines.append("## Análisis de Claude\n")
    text = store.rehydrate(analysis) if (rehydrate and analysis) else analysis
    lines.append(text or "_(sin análisis)_")
    lines.append("")

    # Inventario de activos descubiertos, agrupado por tipo y legible. Es lo que
    # el operador quiere ver de un vistazo (subdominios, IPs, URLs, emails…).
    by_type: dict[str, list[str]] = {}
    for token in store.mappings:
        ttype = store.meta.get(token, {}).get("type", "OTRO")
        value = store.mappings[token] if rehydrate else token
        by_type.setdefault(ttype, []).append(value)
    if by_type:
        lines.append("## Activos descubiertos\n")
        for ttype in sorted(by_type):
            valores = sorted(set(by_type[ttype]))
            lines.append(f"### {ttype} ({len(valores)})")
            for v in valores:
                lines.append(f"- `{v}`")
            lines.append("")

    secrets = store.read_secrets()
    if secrets:
        lines.append("## Secretos encontrados (LOCAL — nunca enviados a Claude)\n")
        for s in secrets:
            shown = s.get("value") if reveal_secrets else s.get("preview")
            origen = f" — origen: {s['source_tool']}" if s.get("source_tool") else ""
            lines.append(f"- **{s.get('type')}**: `{shown}`{origen}")
        lines.append("")

    high = review_queue(store)
    if high:
        lines.append("## Hallazgos de alta relevancia\n")
        for item in high:
            label = store.mappings.get(item["token"], item["token"]) if rehydrate \
                else item["token"]
            lines.append(f"- **{label}** — {item['hint']}")
        lines.append("")

    if total_censored:
        lines.append("## Privacidad — qué se censuró (sin valores reales)\n")
        for k, v in sorted(total_censored.items()):
            lines.append(f"- `{k}`: {v}")
        lines.append("")

    nota = "rehidratado en local" if rehydrate else "anonimizado (tokens)"
    lines.append(f"---\n_Informe {nota}. Generado por Privacy Gateway._")
    return "\n".join(lines)
