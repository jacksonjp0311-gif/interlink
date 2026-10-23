"""Shared fixtures for the peer (v0.2) tests: two people, one host, real signatures."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from conftest import make_config
from interlink.peer.client import PeerClient
from interlink.peer.crypto import Identity, b64e
from interlink.peer.host import PeerHost, PeerServer, serve
from interlink.peer.protocol import AUTH_HEADER, SIG_HEADER, sign_request
from interlink.peer.store import PeerBook, PeerRecord, Policy
from interlink.security import canonical

PY = sys.executable
HARNESSES = {
    "mock": {"adapter": "mock"},
    "writer": {
        "adapter": "command",
        "argv": [PY, "-c", "import sys; open('out.txt','w').write(sys.stdin.read().upper())"],
    },
    "envdump": {
        "adapter": "command",
        "argv": [PY, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
        "pass_env": ["INTERLINK_LEAK_TOKEN", "INTERLINK_LEAK_PLAIN"],
        "secrets": ["INTERLINK_LEAK_TOKEN"],
        "env": {"INTERLINK_INJECTED": "from-config"},
    },
    "sleeper": {"adapter": "command", "argv": [PY, "-c", "import time; time.sleep(60)"]},
}


@dataclass
class Pair:
    alice: Identity
    bob: Identity
    host: PeerHost  # bob's host
    bob_book: PeerBook
    alice_book: PeerBook
    tmp: Path

    @property
    def alice_record(self) -> PeerRecord:
        return self.bob_book.get("alice")

    def raw(
        self,
        path: str,
        payload: Any,
        *,
        identity: Identity | None = None,
        to: str | None = None,
        body: bytes | None = None,
        claims: dict[str, Any] | None = None,
        remote: str = "127.0.0.1",
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        """Send one request through bob's host without sockets; returns (status, json, headers)."""
        identity = identity or self.alice
        data = json.dumps(payload, sort_keys=True).encode() if body is None else body
        headers, signed = sign_request(identity, to or self.bob.fingerprint, "POST", path, data)
        if claims is not None:  # re-sign with overridden claims
            signed = {**signed, **claims}
            raw = canonical(signed).encode()
            headers = {AUTH_HEADER: b64e(raw), SIG_HEADER: b64e(identity.sign("request", raw))}
        status, out, response_headers = self.host.handle("POST", path, headers, data, remote)
        return status, json.loads(out), response_headers

    def submit(self, **task: Any) -> tuple[int, dict[str, Any]]:
        task.setdefault("task_id", _uuid())
        task.setdefault("harness", "mock")
        task.setdefault("prompt", "say hi")
        status, body, _ = self.raw("/v1/tasks", task)
        return status, body

    def wait(self, task_id: str, timeout: float = 30) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _status, body, _ = self.raw("/v1/tasks/status", {"task_id": task_id})
            if body.get("ok") and body["data"]["result_ready"]:
                return self.raw("/v1/tasks/result", {"task_id": task_id})[1]["data"]
            time.sleep(0.1)
        raise AssertionError(f"task {task_id} did not finish")


def _uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def make_pair(tmp: Path, policy: dict[str, Any] | None = None, **host_kwargs: Any) -> Pair:
    alice, bob = Identity.generate(), Identity.generate()
    bob_book = PeerBook(tmp / "bob-home")
    bob_book.add(
        "alice",
        alice.public_raw,
        policy=Policy(**{"harnesses": ["mock", "writer"], "approval": "auto", **(policy or {})}),
    )
    alice_book = PeerBook(tmp / "alice-home")
    host = PeerHost(bob, bob_book, make_config(HARNESSES), tmp / "bob-state", **host_kwargs)
    return Pair(alice, bob, host, bob_book, alice_book, tmp)


@dataclass
class Live:
    pair: Pair
    server: PeerServer
    url: str

    def client(self, identity: Identity | None = None, **record: Any) -> PeerClient:
        identity = identity or self.pair.alice
        book = self.pair.alice_book
        name = record.pop("name", "bob")
        try:
            peer = book.get(name)
        except Exception:
            peer = book.add(
                name, record.pop("public_raw", self.pair.bob.public_raw), url=self.url, **record
            )
        return PeerClient(identity, peer, self.pair.tmp / "alice-state", timeout_s=10)


def start(pair: Pair, **serve_kwargs: Any) -> Iterator[Live]:
    server = serve(pair.host, "127.0.0.1", 0, **serve_kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = "https" if serve_kwargs.get("tls_cert") else "http"
    host = "localhost" if scheme == "https" else "127.0.0.1"
    try:
        yield Live(pair, server, f"{scheme}://{host}:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
