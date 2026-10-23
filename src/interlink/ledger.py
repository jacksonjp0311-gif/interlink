"""Idempotent operation ledger with a hash-chained, append-only receipt log.

Ported from PEGASUS Interlink. The rules are deliberately strict:

* A ``request_id`` names one operation forever. Retrying the *same* request returns the
  recorded result instead of doing the work twice.
* Reusing a ``request_id`` for a *different* request is a collision and is refused.
* An operation that started but never recorded a result is reported as
  ``unknown_outcome`` - Interlink never guesses that "it probably didn't happen".
* Every state change appends a receipt whose hash covers the previous receipt, so the
  evidence bundle can prove the log was not edited after the fact (tamper-evident,
  not tamper-proof: anyone with write access could rebuild the whole chain).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interlink.security import canonical, sha256_text, sha256_value

GENESIS = "0" * 64


class RequestCollision(ValueError):
    """The request_id was already used for a different request body."""


@dataclass(frozen=True)
class Recorded:
    """What ``begin`` found for a request id."""

    state: str  # "new" | "finished" | "in_flight"
    result: dict[str, Any] | None = None


class Ledger:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS operations(
                request_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                operation TEXT NOT NULL,
                instance_id TEXT,
                state TEXT NOT NULL,
                result TEXT,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                at REAL NOT NULL,
                instance_id TEXT,
                kind TEXT NOT NULL,
                body TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS receipts_instance ON receipts(instance_id, sequence);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- idempotency -------------------------------------------------------------------

    def begin(
        self, request_id: str, operation: str, body: dict[str, Any], instance_id: str | None
    ) -> Recorded:
        digest = sha256_value({"operation": operation, "body": body})
        with self._lock:
            row = self._db.execute(
                "SELECT digest, state, result FROM operations WHERE request_id=?", (request_id,)
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO operations VALUES(?,?,?,?,?,?,?)",
                    (request_id, digest, operation, instance_id, "issued", None, time.time()),
                )
                return Recorded("new")
        if row[0] != digest:
            self.receipt(
                instance_id,
                "request_collision",
                {"request_id": request_id, "operation": operation},
            )
            raise RequestCollision(
                f"request_id {request_id} was already used for a different request"
            )
        if row[1] == "finished":
            return Recorded("finished", json.loads(row[2]))
        return Recorded("in_flight")

    def finish(self, request_id: str, result: dict[str, Any]) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE operations SET state='finished', result=? "
                "WHERE request_id=? AND state='issued'",
                (canonical(result), request_id),
            )

    def unresolved(self, instance_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT request_id, operation, instance_id, created FROM operations WHERE state='issued'"
        args: tuple[Any, ...] = ()
        if instance_id:
            query += " AND instance_id=?"
            args = (instance_id,)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return [
            {"request_id": r[0], "operation": r[1], "instance_id": r[2], "created": r[3]}
            for r in rows
        ]

    # -- receipts ------------------------------------------------------------------------

    def receipt(self, instance_id: str | None, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            last = self._db.execute(
                "SELECT hash FROM receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            prev = last[0] if last else GENESIS
            at = round(time.time(), 6)
            text = canonical(body)
            digest = sha256_text(canonical([prev, at, instance_id, kind, text]))
            cursor = self._db.execute(
                "INSERT INTO receipts(at, instance_id, kind, body, prev_hash, hash) "
                "VALUES(?,?,?,?,?,?)",
                (at, instance_id, kind, text, prev, digest),
            )
            return {"sequence": cursor.lastrowid, "kind": kind, "hash": digest}

    def receipts(self, instance_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:

        query = "SELECT sequence, at, instance_id, kind, body, prev_hash, hash FROM receipts"
        args: tuple[Any, ...] = ()
        if instance_id:
            query += " WHERE instance_id=?"
            args = (instance_id,)
        query += " ORDER BY sequence LIMIT ?"
        with self._lock:
            rows = self._db.execute(query, (*args, limit)).fetchall()
        return [
            {
                "sequence": r[0],
                "at": r[1],
                "instance_id": r[2],
                "kind": r[3],
                "body": json.loads(r[4]),
                "prev_hash": r[5],
                "hash": r[6],
            }
            for r in rows
        ]

    def verify_chain(self) -> dict[str, Any]:
        """Recompute every receipt hash. Returns the first break, if any."""
        with self._lock:
            rows = self._db.execute(
                "SELECT sequence, at, instance_id, kind, body, prev_hash, hash "
                "FROM receipts ORDER BY sequence"
            ).fetchall()
        prev = GENESIS
        for sequence, at, instance_id, kind, body, prev_hash, digest in rows:
            expected = sha256_text(canonical([prev, at, instance_id, kind, body]))
            if prev_hash != prev or digest != expected:
                return {"valid": False, "receipts": len(rows), "broken_at": sequence}
            prev = digest
        return {"valid": True, "receipts": len(rows), "head": prev}
