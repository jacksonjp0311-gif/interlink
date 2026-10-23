#!/usr/bin/env python3
"""Verify this evidence package offline.

    pip install -e .           # from the repo root (needs interlink + cryptography)
    python evidence/live-2026-10-23/verify.py

Checks, in order:
  1. MANIFEST.sha256.sig is a valid Ed25519 signature (domain-separated) over
     MANIFEST.sha256 by the key in evidence-signing-key.pub;
  2. every file listed in MANIFEST.sha256 matches its SHA-256, and no file is unlisted;
  3. each signed peer result verifies against the host's public key (invite code);
  4. each peer audit log's hash chain recomputes;
  5. each receipt ledger's hash chain recomputes.
Exit code 0 only if everything passes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = Path(__file__).resolve().parent
DOMAIN = b"interlink-evidence-package/1\n"
UNSIGNED = {"MANIFEST.sha256", "MANIFEST.sha256.sig"}
failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


def main() -> int:
    manifest = (HERE / "MANIFEST.sha256").read_bytes()
    pub = bytes.fromhex((HERE / "evidence-signing-key.pub").read_text().split()[0])
    sig = bytes.fromhex((HERE / "MANIFEST.sha256.sig").read_text().strip())
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, DOMAIN + manifest)
        check(True, "manifest signature (Ed25519)")
    except Exception:
        check(False, "manifest signature (Ed25519)")

    listed: dict[str, str] = {}
    for line in manifest.decode().splitlines():
        digest, name = line.split(None, 1)
        listed[name.strip()] = digest
    for name, digest in listed.items():
        path = HERE / name
        ok = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest
        check(ok, f"sha256 {name}")
    present = {
        p.relative_to(HERE).as_posix()
        for p in HERE.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    extra = sorted(present - set(listed) - UNSIGNED)
    check(not extra, "no unlisted files" + (f": {extra}" if extra else ""))

    from interlink.ledger import Ledger
    from interlink.peer.crypto import decode_invite
    from interlink.peer.protocol import verify_result
    from interlink.peer.store import AuditLog

    for env_path in sorted(HERE.rglob("peer-result-envelope.json")):
        d = json.loads(env_path.read_text(encoding="utf-8"))
        try:
            rep = verify_result(
                d["envelope"],
                host_public=decode_invite(d["host_invite"]),
                host_fp=d["host_fingerprint"],
                own_fp=d["requester_fingerprint"],
            )
            check(bool(rep), f"signed peer result {env_path.relative_to(HERE).as_posix()}")
        except Exception as exc:
            check(False, f"signed peer result {env_path.relative_to(HERE).as_posix()}: {exc}")

    for audit in sorted(HERE.rglob("*audit.jsonl")):
        rep = AuditLog(audit).verify()
        check(
            bool(rep.get("valid")),
            f"audit chain {audit.relative_to(HERE).as_posix()} ({rep.get('entries')} entries)",
        )

    for db in sorted(HERE.rglob("*.sqlite3")):
        with tempfile.TemporaryDirectory() as tmp:  # work on a copy: opening sets WAL mode
            copy = Path(tmp) / db.name
            shutil.copyfile(db, copy)
            led = Ledger(copy)
            rep = led.verify_chain()
            close = getattr(led, "close", None)
            if close:
                close()
        check(
            bool(rep.get("valid")),
            f"receipt ledger {db.relative_to(HERE).as_posix()} ({rep.get('receipts')} receipts)",
        )

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{len(failures)} CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
