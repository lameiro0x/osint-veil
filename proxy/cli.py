"""CLI del Privacy Gateway (osint-veil), con interfaz rich.

Comandos:
    osint-veil audit   --case C --target dominio.com [--allow-active]
    osint-veil report  --case C [--anon]
    osint-veil review  --case C
    osint-veil tools   [--allow-active]
"""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from .claude_client import ClaudeClient
from .config import get_case_config, get_settings, validate_settings
from .egress import EgressNotLocked
from .gateway import ToolGateway, builtin_tools
from .logging_setup import setup_logging
from .orchestrator import Budget, Orchestrator
from .report import build_report, review_queue
from .storage import CaseStore
from .tools_external import external_tools

console = Console()
err = Console(stderr=True)

# Paleta
C_OK, C_BAD, C_DIM, C_ACCENT = "green", "red", "dim", "cyan"


def _counts_table(counts: dict[str, int], title: str) -> Table:
    t = Table(title=title, title_style="bold", show_edge=True, expand=False)
    t.add_column("Tipo", style=C_ACCENT, overflow="fold")
    t.add_column("Censurado", justify="right")
    for k, v in sorted(counts.items()):
        t.add_row(k, str(v))
    if not counts:
        t.add_row("—", "0")
    return t


def _cmd_audit(args) -> int:
    settings = get_settings()
    errors, warnings = validate_settings(settings, require_api_key=True)
    for w in warnings:
        err.print(f"[yellow]⚠[/]  {w}")
    if errors:
        for e in errors:
            err.print(f"[red]✖[/]  {e}")
        return 2

    case = get_case_config(args.case)
    store = CaseStore(args.case)
    tools = builtin_tools() + external_tools(allow_active=args.allow_active)
    gateway = ToolGateway(scope_domains=[args.target] + (args.scope or []), tools=tools)
    budget = Budget(max_iterations=args.max_iter)

    console.print(Panel.fit(
        f"[bold]Objetivo:[/] {args.target}\n"
        f"[bold]Caso:[/] {args.case}    [bold]Modo:[/] {case.mode}\n"
        f"[bold]Herramientas:[/] {', '.join(gateway.tool_names())}\n"
        f"[bold]Límites:[/] {budget.max_iterations} iter · "
        f"{budget.max_total_tokens} tokens · {budget.max_seconds:.0f}s"
        + ("    [red](herramientas activas habilitadas)[/]" if args.allow_active else ""),
        title="🛡  osint-veil — OSINT seguro", border_style=C_ACCENT,
    ))

    def progress(ev: dict) -> None:
        kind = ev.get("event")
        if kind == "iteration":
            console.print(f"[{C_DIM}]›[/] iteración [bold]{ev['n']}[/]/{ev['max']}")
        elif kind == "tool":
            mark = f"[{C_OK}]✓[/]" if ev.get("ok") else f"[{C_BAD}]✗[/]"
            console.print(f"   {mark} [{C_ACCENT}]{ev.get('tool')}[/]")

    orch = Orchestrator(client=ClaudeClient(settings), gateway=gateway, store=store,
                        case=case, target=args.target, budget=budget, model=case.model,
                        progress=progress)
    try:
        with console.status("[bold green]Claude trabajando…", spinner="dots"):
            result = orch.run()
    except EgressNotLocked as e:
        err.print(f"[red]✖[/]  {e}")
        return 3

    store.write_audit(type_counts=result.type_counts, provider=case.provider,
                      mode=case.mode, dry_run=False, note=f"audit stop={result.stop_reason}")

    if result.stop_reason == "api_error":
        err.print(Panel.fit(f"[red]Error de la API de Claude:[/]\n{result.error}",
                            title="✖ OSINT abortado", border_style=C_BAD))
        return 4

    n_secrets = len(store.read_secrets())
    color = C_OK if result.stop_reason == "completed" else "yellow"
    console.print(Panel.fit(
        f"[bold]Estado:[/] [{color}]{result.stop_reason}[/]\n"
        f"[bold]Iteraciones:[/] {result.iterations}    "
        f"[bold]Tokens:[/] {result.total_tokens}    "
        f"[bold]Herramientas usadas:[/] {len(result.tool_calls)}"
        + (f"\n[bold red]Secretos guardados (local):[/] {n_secrets} "
           f"(ver: osint-veil secrets --case {args.case})" if n_secrets else ""),
        title="Resumen", border_style=color,
    ))
    console.print(_counts_table(result.type_counts, "Privacidad — qué se censuró"))

    report = build_report(store, case, analysis=result.final_text, rehydrate=True,
                          reveal_secrets=True)  # informe LOCAL en archivo
    out = args.report or f"informe_{args.case}.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)

    # Inventario de activos descubiertos (valores reales, LOCAL) — lo que el
    # operador quiere ver de un vistazo.
    _print_assets(store)

    if result.final_text:
        analysis = store.rehydrate(result.final_text)
        try:
            console.print(Panel(Markdown(analysis),
                                title="Análisis (rehidratado · LOCAL)", border_style=C_DIM))
        except Exception:  # noqa: BLE001 — markdown malformado: fallback a texto plano
            console.print(Panel(analysis,
                                title="Análisis (rehidratado · LOCAL)", border_style=C_DIM))
    else:
        console.print("[yellow]No hubo análisis final (revisa la API key / presupuesto).[/]")

    console.print(f"\n[{C_OK}]✔[/] Informe completo y legible (rehidratado, LOCAL) → "
                  f"[bold]{out}[/]")
    console.print(f"[{C_DIM}]  Ábrelo con:  cat {out}   ·   o regenéralo: "
                  f"osint-veil report --case {args.case}[/]")
    return 0


def _print_assets(store: CaseStore) -> None:
    """Tabla de activos descubiertos agrupados por tipo (valores reales, LOCAL)."""
    by_type: dict[str, list[str]] = {}
    for token, real in store.mappings.items():
        ttype = store.meta.get(token, {}).get("type", "OTRO")
        by_type.setdefault(ttype, []).append(real)
    if not by_type:
        return
    t = Table(title="Activos descubiertos (valores reales · LOCAL)", title_style="bold",
              show_lines=False)
    t.add_column("Tipo", style=C_ACCENT, overflow="fold")
    t.add_column("Nº", justify="right")
    t.add_column("Valores", overflow="fold")
    for ttype in sorted(by_type):
        vals = sorted(set(by_type[ttype]))
        shown = ", ".join(vals[:8]) + (f"  (+{len(vals) - 8} más)" if len(vals) > 8 else "")
        t.add_row(ttype, str(len(vals)), shown)
    console.print(t)


def _cmd_report(args) -> int:
    case = get_case_config(args.case)
    store = CaseStore(args.case)
    report = build_report(store, case, analysis="", rehydrate=not args.anon,
                          reveal_secrets=not args.anon)  # informe LOCAL en archivo
    out = args.report or f"informe_{args.case}.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    console.print(f"[{C_OK}]✔[/] Informe escrito en [bold]{out}[/] "
                  f"({'anonimizado' if args.anon else 'rehidratado, LOCAL'})")
    return 0


def _cmd_review(args) -> int:
    store = CaseStore(args.case)
    items = review_queue(store)
    if not items:
        console.print("[dim]Cola de revisión vacía.[/]")
        return 0
    t = Table(title=f"Cola de revisión — {len(items)} de alta relevancia",
              title_style="bold", show_lines=False)
    t.add_column("Token", style=C_ACCENT, overflow="fold")
    t.add_column("Valor real (LOCAL)", style="bold", overflow="fold")
    t.add_column("Pista", style=C_DIM, overflow="fold")
    for it in items:
        real = store.mappings.get(it["token"], it["token"])
        t.add_row(it["token"], real, it["hint"])
    console.print(t)
    return 0


def _cmd_secrets(args) -> int:
    store = CaseStore(args.case)
    secrets = store.read_secrets()
    if not secrets:
        console.print("[dim]Sin secretos guardados para este caso "
                      "(¿store_secrets activo + PROXY_ENCRYPTION_KEY?).[/]")
        return 0
    t = Table(title=f"Secretos hallados — {len(secrets)} (LOCAL, nunca enviados a Claude)",
              title_style="bold red")
    t.add_column("Tipo", style=C_ACCENT, overflow="fold")
    t.add_column("Valor" if args.reveal else "Vista previa", style="bold", overflow="fold")
    t.add_column("Origen", style=C_DIM, overflow="fold")
    for s in secrets:
        shown = s.get("value") if args.reveal else s.get("preview")
        t.add_row(s.get("type", "?"), shown or "", s.get("source_tool") or "—")
    console.print(t)
    if not args.reveal:
        console.print("[dim]Usa --reveal para ver los valores completos (en local).[/]")
    return 0


def _cmd_tools(args) -> int:
    builtin = builtin_tools()
    ext = external_tools(allow_active=args.allow_active)
    t = Table(title="Herramientas disponibles", title_style="bold")
    t.add_column("Herramienta", style=C_ACCENT, overflow="fold")
    t.add_column("Tipo")
    t.add_column("Descripción", overflow="fold")
    for spec in builtin:
        t.add_row(spec.name, "integrada", spec.description)
    for spec in ext:
        t.add_row(spec.name, "[yellow]externa[/]", spec.description)
    console.print(t)
    if not args.allow_active:
        console.print("[dim]Sugerencia: usa --allow-active para incluir nmap/amass-active "
                      "(intrusivas).[/]")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    p = argparse.ArgumentParser(prog="osint-veil",
                                description="Privacy Gateway para OSINT con IA")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="Lanza un OSINT autónomo y seguro")
    a.add_argument("--case", required=True)
    a.add_argument("--target", required=True)
    a.add_argument("--scope", nargs="*", help="Dominios extra dentro de alcance")
    a.add_argument("--max-iter", type=int, default=20)
    a.add_argument("--allow-active", action="store_true",
                   help="Habilita herramientas activas/intrusivas (nmap, amass -active)")
    a.add_argument("--report")
    a.set_defaults(func=_cmd_audit)

    r = sub.add_parser("report", help="Regenera el informe local")
    r.add_argument("--case", required=True)
    r.add_argument("--report")
    r.add_argument("--anon", action="store_true", help="No rehidratar (mantener tokens)")
    r.set_defaults(func=_cmd_report)

    rv = sub.add_parser("review", help="Muestra la cola de revisión (alta relevancia)")
    rv.add_argument("--case", required=True)
    rv.set_defaults(func=_cmd_review)

    sc = sub.add_parser("secrets", help="Muestra los secretos guardados (LOCAL, opt-in)")
    sc.add_argument("--case", required=True)
    sc.add_argument("--reveal", action="store_true", help="Muestra los valores completos")
    sc.set_defaults(func=_cmd_secrets)

    tl = sub.add_parser("tools", help="Lista las herramientas OSINT disponibles")
    tl.add_argument("--allow-active", action="store_true")
    tl.set_defaults(func=_cmd_tools)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
