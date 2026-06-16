"""CLI del Privacy Gateway.

Ejemplos:
    # Lanzar un OSINT autónomo y seguro:
    python -m proxy.cli audit --case cliente_a_2026 --target cliente.com

    # Regenerar el informe local de un caso:
    python -m proxy.cli report --case cliente_a_2026

    # Ver la cola de revisión (alta relevancia):
    python -m proxy.cli review --case cliente_a_2026
"""

from __future__ import annotations

import argparse
import sys

from .claude_client import ClaudeClient
from .config import get_case_config, get_settings, validate_settings
from .egress import EgressNotLocked
from .gateway import ToolGateway, builtin_tools
from .logging_setup import setup_logging
from .orchestrator import Budget, Orchestrator
from .report import build_report, review_queue
from .storage import CaseStore


def _cmd_audit(args) -> int:
    settings = get_settings()
    errors, warnings = validate_settings(settings, require_api_key=True)
    for w in warnings:
        print(f"⚠  {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"✖  {e}", file=sys.stderr)
        return 2

    case = get_case_config(args.case)
    store = CaseStore(args.case)
    gateway = ToolGateway(scope_domains=[args.target] + (args.scope or []),
                          tools=builtin_tools())
    client = ClaudeClient(settings)
    budget = Budget(max_iterations=args.max_iter)

    print(f"▶ OSINT de {args.target} | caso {args.case} | modo {case.mode}")
    print(f"  herramientas: {[t['name'] for t in gateway.anthropic_tools()]}")
    print(f"  límites: {budget.max_iterations} iteraciones, "
          f"{budget.max_total_tokens} tokens, {budget.max_seconds:.0f}s\n")

    orch = Orchestrator(client=client, gateway=gateway, store=store, case=case,
                        target=args.target, budget=budget, model=case.model)
    try:
        result = orch.run()
    except EgressNotLocked as e:
        print(f"✖  {e}", file=sys.stderr)
        return 3

    print(f"\n■ Fin: {result.stop_reason} | {result.iterations} iteraciones | "
          f"{result.total_tokens} tokens")
    print(f"  llamadas a herramientas: {len(result.tool_calls)}")
    print(f"  censurado: {result.type_counts}")

    store.write_audit(type_counts=result.type_counts, provider=case.provider,
                      mode=case.mode, dry_run=False, note=f"audit stop={result.stop_reason}")

    report = build_report(store, case, analysis=result.final_text, rehydrate=True)
    out = args.report or f"informe_{args.case}.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n✔ Informe (rehidratado, LOCAL) escrito en: {out}")
    return 0


def _cmd_report(args) -> int:
    case = get_case_config(args.case)
    store = CaseStore(args.case)
    report = build_report(store, case, analysis="", rehydrate=not args.anon)
    out = args.report or f"informe_{args.case}.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"✔ Informe escrito en: {out}")
    return 0


def _cmd_review(args) -> int:
    store = CaseStore(args.case)
    items = review_queue(store)
    if not items:
        print("Cola de revisión vacía.")
        return 0
    print(f"Cola de revisión ({len(items)} de alta relevancia):")
    for it in items:
        real = store.mappings.get(it["token"], it["token"])
        print(f"  - {it['token']} = {real}  [{it['hint']}]")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    p = argparse.ArgumentParser(prog="proxy.cli", description="Privacy Gateway para OSINT con IA")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="Lanza un OSINT autónomo y seguro")
    a.add_argument("--case", required=True)
    a.add_argument("--target", required=True)
    a.add_argument("--scope", nargs="*", help="Dominios extra dentro de alcance")
    a.add_argument("--max-iter", type=int, default=12)
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

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
