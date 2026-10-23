from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from interlink.ledger import Ledger, RequestCollision


def test_idempotency_lifecycle(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "l.sqlite3")
    assert ledger.begin("r1", "launch", {"a": 1}, None).state == "new"
    assert ledger.begin("r1", "launch", {"a": 1}, None).state == "in_flight"
    assert [u["request_id"] for u in ledger.unresolved()] == ["r1"]
    ledger.finish("r1", {"ok": True})
    replay = ledger.begin("r1", "launch", {"a": 1}, None)
    assert replay.state == "finished" and replay.result == {"ok": True}
    assert ledger.unresolved() == []


def test_collision_is_refused_and_receipted(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "l.sqlite3")
    ledger.begin("r1", "launch", {"a": 1}, "i1")
    with pytest.raises(RequestCollision):
        ledger.begin("r1", "launch", {"a": 2}, "i1")
    assert ledger.receipts("i1")[-1]["kind"] == "request_collision"


def test_receipt_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "l.sqlite3"
    ledger = Ledger(path)
    for n in range(5):
        ledger.receipt("i1", "event", {"n": n})
    assert ledger.verify_chain() == {
        "valid": True,
        "receipts": 5,
        "head": ledger.receipts()[-1]["hash"],
    }
    with sqlite3.connect(path) as db:
        db.execute("UPDATE receipts SET body=? WHERE sequence=3", ('{"n":99}',))
    result = Ledger(path).verify_chain()
    assert result["valid"] is False and result["broken_at"] == 3


def test_ledger_survives_reopen(tmp_path: Path) -> None:
    path = tmp_path / "l.sqlite3"
    Ledger(path).receipt(None, "boot", {})
    assert Ledger(path).receipts()[0]["kind"] == "boot"
