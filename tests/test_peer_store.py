"""Contact book, policy defaults, nonce cache, hash-chained audit log, rate limiter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from interlink.peer.crypto import Identity
from interlink.peer.store import (
    AuditLog,
    HashChain,
    NonceCache,
    PeerBook,
    PeerError,
    Policy,
    RateLimiter,
    check_separation,
    verify_chain,
)


def test_default_policy_allows_nothing() -> None:
    policy = Policy()
    assert policy.harnesses == [] and policy.approval == "prompt"
    with pytest.raises(ValueError):
        Policy(unknown=True)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Policy(max_timeout_s=99_999)


def test_book_add_refuses_own_key_duplicates_and_bad_names(tmp_path: Path) -> None:
    me, friend = Identity.generate(), Identity.generate()
    book = PeerBook(tmp_path / "home")
    with pytest.raises(PeerError, match="your own"):
        book.add("me", me.public_raw, own_fingerprint=me.fingerprint)
    book.add("friend", friend.public_raw)
    with pytest.raises(PeerError, match="already exists"):
        book.add("friend", Identity.generate().public_raw)
    with pytest.raises(PeerError, match="already in your book"):
        book.add("again", friend.public_raw)
    with pytest.raises(ValueError):
        book.add("../evil", Identity.generate().public_raw)
    with pytest.raises(PeerError):
        book.add("short", b"123")
    assert [p.name for p in PeerBook(tmp_path / "home").all()] == ["friend"]


def test_revoke_remove_and_cross_process_refresh(tmp_path: Path) -> None:
    friend = Identity.generate()
    serving = PeerBook(tmp_path / "home")
    serving.add("friend", friend.public_raw)
    assert serving.by_fingerprint(friend.fingerprint) is not None
    PeerBook(tmp_path / "home").revoke("friend")  # e.g. `interlink peer revoke` elsewhere
    record = serving.by_fingerprint(friend.fingerprint)
    assert record is not None and record.revoked
    PeerBook(tmp_path / "home").remove("friend")
    assert serving.by_fingerprint(friend.fingerprint) is None
    with pytest.raises(PeerError):
        serving.remove("friend")


def test_keys_must_live_outside_state(tmp_path: Path) -> None:
    check_separation(tmp_path / "home", tmp_path / "state")
    with pytest.raises(PeerError, match="overlap"):
        check_separation(tmp_path / "state" / "keys", tmp_path / "state")
    with pytest.raises(PeerError, match="overlap"):
        check_separation(tmp_path / "x", tmp_path / "x" / "peer")


def test_nonce_cache_blocks_replay_across_restarts(tmp_path: Path) -> None:
    import time

    cache = NonceCache(tmp_path / "nonces.sqlite")
    assert cache.claim("alice", "n1", time.time() + 60)
    assert not cache.claim("alice", "n1", time.time() + 60)
    assert cache.claim("bob", "n1", time.time() + 60)  # namespaced per peer
    cache.close()
    reopened = NonceCache(tmp_path / "nonces.sqlite")
    assert not reopened.claim("alice", "n1", time.time() + 60)
    reopened.close()


def test_audit_log_is_tamper_evident_and_resumes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", i=i)
    assert log.verify() == {"valid": True, "entries": 5, "head": log.entries()[-1]["hash"]}
    AuditLog(path).append("after_restart")
    assert AuditLog(path).verify()["valid"] and len(AuditLog(path).entries()) == 6

    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["i"] = 99
    lines[2] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert AuditLog(path).verify() == {"valid": False, "entries": 6, "broken_at": 2}

    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")  # deleting a line also shows
    assert not AuditLog(path).verify()["valid"]


def test_hash_chain_detects_edits_and_reordering() -> None:
    chain = HashChain()
    for name in ("a", "b", "c"):
        chain.append(name)
    assert verify_chain(chain.entries)["valid"]
    swapped = [chain.entries[1], chain.entries[0], chain.entries[2]]
    assert not verify_chain(swapped)["valid"]
    edited = [dict(e) for e in chain.entries]
    edited[1]["event"] = "z"
    assert verify_chain(edited) == {"valid": False, "entries": 3, "broken_at": 1}


def test_rate_limiter_sliding_window() -> None:
    limiter = RateLimiter()
    assert all(limiter.allow("k", 3, 60) for _ in range(3))
    assert not limiter.allow("k", 3, 60)
    assert limiter.allow("other", 3, 60)
    assert limiter.allow("fast", 1, 0.01)
    import time

    time.sleep(0.05)
    assert limiter.allow("fast", 1, 0.01)
