"""Where peer state lives, and the small durable structures it needs.

Two separate roots, on purpose:

* **peer home** (``$INTERLINK_PEER_HOME`` or ``<config dir>/interlink/peer``) holds the
  private key and the contact book. It must NOT be inside the state root.
* **state** (``<state root>/peer``) holds the nonce cache, audit log, tasks and results.
  Anything a harness or an inbound task can influence lives here, never next to keys.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from interlink.config import default_state_root, user_config_path
from interlink.peer.crypto import CryptoError, b64d, b64e, fingerprint, public_key
from interlink.security import atomic_write_json, canonical, read_json, sha256_text, within

PEERS_FILE = "peers.json"
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
GENESIS = "0" * 64


class PeerError(ValueError):
    """A peer-book, policy or setup problem the user can fix."""

    pass


def peer_home() -> Path:
    """Where keys and the peer book live: ``$INTERLINK_PEER_HOME`` or next to the config."""
    if env := os.environ.get("INTERLINK_PEER_HOME"):
        return Path(env).expanduser().resolve()
    return user_config_path().parent / "peer"


def peer_state(state_root: Path | None = None) -> Path:
    """Where peer tasks, results, nonces and the audit log live."""
    return (state_root or default_state_root()) / "peer"


def check_separation(home: Path, state: Path) -> None:
    """Keys must never sit inside (or contain) the directory tasks and ledgers write to."""
    home, state = home.resolve(), state.resolve()
    if within(home, state) or within(state, home):
        raise PeerError(
            f"peer home {home} and peer state {state} overlap; keep keys outside the state root"
        )


class Policy(BaseModel):
    """What one peer may do on this machine. Defaults allow nothing to run."""

    model_config = ConfigDict(extra="forbid")

    harnesses: list[str] = Field(default_factory=list)
    approval: Literal["prompt", "auto"] = "prompt"
    max_concurrent: int = Field(1, ge=1, le=16)
    max_tasks_per_hour: int = Field(10, ge=1, le=1000)
    max_requests_per_minute: int = Field(120, ge=10, le=6000)
    max_timeout_s: float = Field(300, gt=0, le=3600)
    max_prompt_chars: int = Field(20_000, ge=1, le=200_000)
    max_files: int = Field(20, ge=0, le=200)
    max_file_bytes: int = Field(256 * 1024, ge=1, le=1024 * 1024)
    max_result_bytes: int = Field(1024 * 1024, ge=4096, le=8 * 1024 * 1024)


class PeerRecord(BaseModel):
    """One paired friend: pinned key, optional URL and CA, and policy."""

    model_config = ConfigDict(extra="forbid")

    name: str
    public_key: str  # base64url, 32 raw bytes
    fingerprint: str
    added_at: float = Field(default_factory=time.time)
    revoked_at: float | None = None
    url: str | None = None  # where to reach them, for sending
    tls_ca: str | None = None  # CA / self-signed cert to trust for their https url
    policy: Policy = Field(default_factory=Policy)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not NAME.match(value):
            raise ValueError("peer names are 1-32 chars of a-z, 0-9, '-' or '_'")
        return value

    @property
    def public_raw(self) -> bytes:
        """The pinned raw public key."""
        return b64d(self.public_key)

    @property
    def revoked(self) -> bool:
        """True once ``peer revoke`` has been run."""
        return self.revoked_at is not None


class PeerBook:
    """The contact book. Small JSON file, atomically rewritten, re-read on change."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.path = home / PEERS_FILE
        self._lock = threading.Lock()
        self._stamp: tuple[int, int, int] | None = None
        self._peers: dict[str, PeerRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            self._peers, self._stamp = {}, None
            return
        data = read_json(self.path)
        self._peers = {p["name"]: PeerRecord.model_validate(p) for p in data.get("peers", [])}
        self._stamp = self._file_stamp()

    def _file_stamp(self) -> tuple[int, int, int] | None:
        # atomic rewrites replace the inode, so a same-tick edit is still noticed
        try:
            info = self.path.stat()
        except FileNotFoundError:
            return None
        return (info.st_mtime_ns, info.st_ino, info.st_size)

    def refresh(self) -> None:
        """Pick up edits made by another process (e.g. `interlink peer revoke`)."""
        with self._lock:
            if self._file_stamp() != self._stamp:
                self._load()

    def _save(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        payload = {"schema": "interlink-peers/1", "peers": [p.model_dump() for p in self.all()]}
        atomic_write_json(self.path, payload)
        if os.name != "nt":
            self.path.chmod(0o600)
        self._stamp = self._file_stamp()

    def all(self) -> list[PeerRecord]:
        """Every peer, sorted by name."""
        return sorted(self._peers.values(), key=lambda p: p.name)

    def get(self, name: str) -> PeerRecord:
        """One peer by name."""
        self.refresh()
        if name not in self._peers:
            raise PeerError(f"no peer named {name!r}")
        return self._peers[name]

    def by_fingerprint(self, fp: str) -> PeerRecord | None:
        """The peer with this fingerprint, re-reading the file if it changed."""
        self.refresh()
        for peer in self._peers.values():
            if peer.fingerprint == fp:
                return peer
        return None

    def add(
        self,
        name: str,
        public_raw: bytes,
        *,
        url: str | None = None,
        tls_ca: str | None = None,
        policy: Policy | None = None,
        own_fingerprint: str | None = None,
    ) -> PeerRecord:
        """Pair with a new peer. Names and keys must be unique."""
        try:
            public_key(public_raw)
        except CryptoError as exc:
            raise PeerError(str(exc)) from exc
        fp = fingerprint(public_raw)
        if fp == own_fingerprint:
            raise PeerError("that invite code is your own")
        with self._lock:
            if name in self._peers:
                raise PeerError(f"a peer named {name!r} already exists")
            for other in self._peers.values():
                if other.fingerprint == fp:
                    raise PeerError(f"that key is already in your book as {other.name!r}")
            record = PeerRecord(
                name=name,
                public_key=b64e(public_raw),
                fingerprint=fp,
                url=url,
                tls_ca=tls_ca,
                policy=policy or Policy(),
            )
            self._peers[name] = record
            self._save()
            return record

    def update(self, name: str, **changes: Any) -> PeerRecord:
        """Change a peer's URL, CA or policy (merged and re-validated)."""
        with self._lock:
            if name not in self._peers:
                raise PeerError(f"no peer named {name!r}")
            current = self._peers[name].model_dump()
            policy = {**current["policy"], **changes.pop("policy", {})}
            record = PeerRecord.model_validate({**current, **changes, "policy": policy})
            self._peers[name] = record
            self._save()
            return record

    def revoke(self, name: str) -> PeerRecord:
        """Block a peer while keeping the record."""
        return self.update(name, revoked_at=time.time())

    def remove(self, name: str) -> None:
        """Forget a peer entirely."""
        with self._lock:
            if self._peers.pop(name, None) is None:
                raise PeerError(f"no peer named {name!r}")
            self._save()


class NonceCache:
    """Seen request nonces, persisted until they expire, so a restart can't reopen replay."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, peer TEXT, expires REAL)"
        )
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def claim(self, peer: str, nonce: str, expires: float) -> bool:
        """True the first time a nonce is seen; False on every replay."""
        now = time.time()
        with self._lock:
            if now - self._last_prune > 30:
                self._db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
                self._last_prune = now
            try:
                self._db.execute(
                    "INSERT INTO nonces(nonce, peer, expires) VALUES (?, ?, ?)",
                    (f"{peer}:{nonce}", peer, expires),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def close(self) -> None:
        """Close the database."""
        self._db.close()


def chain_hash(prev: str, entry: dict[str, Any]) -> str:
    """Hash of one chain entry linked to the previous head."""
    return sha256_text(canonical([prev, entry]))


def verify_chain(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute a hash chain of ``{..., "prev": ..., "hash": ...}`` entries."""
    prev = GENESIS
    for index, item in enumerate(entries):
        body = {k: v for k, v in item.items() if k not in ("prev", "hash")}
        if item.get("prev") != prev or item.get("hash") != chain_hash(prev, body):
            return {"valid": False, "entries": len(entries), "broken_at": index}
        prev = item["hash"]
    return {"valid": True, "entries": len(entries), "head": prev}


class HashChain:
    """An in-memory hash chain (used per task and embedded in the signed result)."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    @property
    def head(self) -> str:
        """Hash of the latest entry (``GENESIS`` when empty)."""
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, event: str, **data: Any) -> dict[str, Any]:
        """Add an event and return the new entry."""
        body = {"seq": len(self.entries) + 1, "at": round(time.time(), 3), "event": event, **data}
        entry = {**body, "prev": self.head, "hash": chain_hash(self.head, body)}
        self.entries.append(entry)
        return entry


class AuditLog:
    """Append-only, hash-chained JSONL. ``verify()`` recomputes the whole chain."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._head, self._seq = GENESIS, 0
        if path.is_file():
            with path.open("rb") as handle:
                last = None
                for last in handle:  # noqa: B007 - we want the final line
                    pass
            if last:
                entry = json.loads(last)
                self._head, self._seq = entry["hash"], entry["seq"]

    def append(self, event: str, **data: Any) -> dict[str, Any]:
        """Append an event durably and return the entry."""
        with self._lock:
            body = {"seq": self._seq + 1, "at": round(time.time(), 3), "event": event, **data}
            entry = {**body, "prev": self._head, "hash": chain_hash(self._head, body)}
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._head, self._seq = entry["hash"], entry["seq"]
            return entry

    def entries(self) -> list[dict[str, Any]]:
        """All entries on disk."""
        if not self.path.is_file():
            return []
        with self.path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def verify(self) -> dict[str, Any]:
        """Recompute the chain; reports where it breaks."""
        return verify_chain(self.entries())


class RateLimiter:
    """Sliding-window counter per key."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_s: float) -> bool:
        """Record a hit and report whether it fits ``limit`` per ``window_s``."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > window_s:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True
