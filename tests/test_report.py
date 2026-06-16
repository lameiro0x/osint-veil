"""Tests de informe, cola de revisión y CLI."""

import uuid

from proxy.cli import main
from proxy.config import get_case_config
from proxy.report import build_report, review_queue
from proxy.sanitizer import Sanitizer
from proxy.storage import CaseStore


def _populated_store():
    case = get_case_config("cliente_a_2026")
    store = CaseStore(f"rep-{uuid.uuid4().hex[:8]}")
    Sanitizer(store, case, source_tool="recon").sanitize(
        "host vpn-corp-backup.cliente.com en 10.0.0.9 y mail.cliente.com"
    )
    return store, case


def test_report_rehidratado_local():
    store, case = _populated_store()
    md = build_report(store, case, analysis="SUBDOMAIN_001 es prioritario", rehydrate=True)
    assert "vpn-corp-backup.cliente.com" in md
    assert "Privacidad — qué se censuró" in md or "Hallazgos de alta relevancia" in md


def test_report_anonimo_no_rehidrata():
    store, case = _populated_store()
    md = build_report(store, case, analysis="SUBDOMAIN_001 es prioritario", rehydrate=False)
    assert "SUBDOMAIN_001" in md
    assert "vpn-corp-backup.cliente.com" not in md


def test_review_queue_alta_relevancia():
    store, _ = _populated_store()
    items = review_queue(store)
    hints = " ".join(i["hint"] for i in items)
    assert items
    assert "relevancia: alta" in hints


def test_cli_review(capsys):
    case = get_case_config("cliente_a_2026")
    case_id = f"clirev-{uuid.uuid4().hex[:8]}"
    store = CaseStore(case_id)
    Sanitizer(store, case, source_tool="recon").sanitize("vpn.cliente.com")
    rc = main(["review", "--case", case_id])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vpn.cliente.com" in out  # rehidratado en local en la CLI
