"""The requesting side: send a task to a friend's Interlink and verify what comes back."""

from __future__ import annotations

import http.client
import json
import ssl
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from interlink.peer.crypto import Identity
from interlink.peer.host import is_loopback
from interlink.peer.protocol import (
    SIG_HEADER,
    ProtocolError,
    check_response,
    sign_request,
    verify_result,
)
from interlink.peer.store import AuditLog, PeerError, PeerRecord
from interlink.security import atomic_write_json, read_json

MAX_RESPONSE = 32 * 1024 * 1024


class PeerCallError(Exception):
    """The host refused the call (signed refusal) or the reply could not be trusted."""

    def __init__(self, code: str, message: str, status: int = 0, verified: bool = True) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status, self.verified = code, message, status, verified


class PeerClient:
    """Talks to one paired host. Every reply must be signed by the pinned host key."""

    def __init__(
        self, identity: Identity, peer: PeerRecord, state_dir: Path, *, timeout_s: float = 30
    ) -> None:
        if not peer.url:
            raise PeerError(
                f"peer {peer.name!r} has no URL; set one with `interlink peer add --url`"
            )
        if peer.revoked:
            raise PeerError(f"peer {peer.name!r} is revoked")
        parts = urlsplit(peer.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise PeerError(f"bad peer URL {peer.url!r}")
        if parts.scheme == "http" and not is_loopback(parts.hostname):
            raise PeerError("refusing plain http to a non-loopback host; the peer must use https")
        self.identity, self.peer, self.state_dir, self.timeout_s = (
            identity,
            peer,
            state_dir,
            timeout_s,
        )
        self._parts = parts
        self.audit = AuditLog(state_dir / "client-audit.jsonl")
        (state_dir / "sent").mkdir(parents=True, exist_ok=True)
        (state_dir / "received").mkdir(parents=True, exist_ok=True)

    def _connection(self) -> http.client.HTTPConnection:
        host, port = self._parts.hostname or "", self._parts.port
        if self._parts.scheme == "https":
            context = ssl.create_default_context(cafile=self.peer.tls_ca or None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            return http.client.HTTPSConnection(
                host, port or 443, timeout=self.timeout_s, context=context
            )
        return http.client.HTTPConnection(host, port or 80, timeout=self.timeout_s)

    def call(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """One signed round trip. Returns ``data`` or raises :class:`PeerCallError`."""
        body = json.dumps(payload, sort_keys=True).encode()
        headers, claims = sign_request(self.identity, self.peer.fingerprint, "POST", path, body)
        connection = self._connection()
        try:
            connection.request(
                "POST", path, body=body, headers={**headers, "Content-Type": "application/json"}
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            status, signature = response.status, response.getheader(SIG_HEADER)
        except (OSError, http.client.HTTPException) as exc:
            raise PeerCallError("unreachable", f"{type(exc).__name__}: {exc}") from exc
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE:
            raise PeerCallError("response_too_large", "host reply exceeded the client limit")
        try:
            check_response(
                self.peer.public_raw,
                self.peer.fingerprint,
                self.identity.fingerprint,
                claims["nonce"],
                status,
                raw,
                signature,
            )
        except ProtocolError as exc:
            hint = _unverified_code(raw)
            raise PeerCallError(
                exc.code, f"{exc} (host said: {hint})", status, verified=False
            ) from exc
        reply = json.loads(raw)
        if not reply.get("ok"):
            error = reply.get("error") or {}
            raise PeerCallError(str(error.get("code")), str(error.get("message")), status)
        return reply["data"]

    def hello(self) -> dict[str, Any]:
        """Check the host is up; returns what this peer may run there."""
        return self.call("/v1/hello", {})

    def submit(
        self,
        harness: str,
        prompt: str,
        files: dict[str, str] | None = None,
        *,
        timeout_s: float | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        """Send a task. The exact task is saved first so its result can be verified."""
        task = {
            "task_id": task_id or str(uuid.uuid4()),
            "harness": harness,
            "prompt": prompt,
            "files": dict(files or {}),
            "timeout_s": timeout_s,
        }
        # remember exactly what we asked for: the signed result must bind to it
        atomic_write_json(self._sent_path(task["task_id"]), task)
        status = self.call("/v1/tasks", task)
        self.audit.append(
            "task_sent", peer=self.peer.fingerprint, task=task["task_id"], harness=harness
        )
        return status

    def status(self, task_id: str) -> dict[str, Any]:
        """The task's current state."""
        return self.call("/v1/tasks/status", {"task_id": task_id})

    def cancel(self, task_id: str) -> dict[str, Any]:
        """Cancel a pending or running task."""
        return self.call("/v1/tasks/cancel", {"task_id": task_id})

    def result(self, task_id: str) -> dict[str, Any]:
        """Fetch and verify the signed result. Returns ``{"verification", "statement"}``."""
        envelope = self.call("/v1/tasks/result", {"task_id": task_id})
        sent = self._sent_path(task_id)
        task = read_json(sent) if sent.is_file() else None
        report = verify_result(
            envelope,
            host_public=self.peer.public_raw,
            host_fp=self.peer.fingerprint,
            own_fp=self.identity.fingerprint,
            task=task,
        )
        report["bound_to_sent_task"] = task is not None
        atomic_write_json(self.state_dir / "received" / f"{task_id}.json", envelope)
        self.audit.append(
            "result_verified",
            peer=self.peer.fingerprint,
            task=task_id,
            state=report["state"],
            chain_head=report["chain_head"],
        )
        return {"verification": report, "statement": envelope["statement"]}

    def wait(self, task_id: str, timeout_s: float = 600, poll_s: float = 1.0) -> dict[str, Any]:
        """Poll until the task finishes, then return the verified result."""
        deadline = time.monotonic() + timeout_s
        while True:
            status = self.status(task_id)
            if status.get("result_ready"):
                return self.result(task_id)
            if time.monotonic() > deadline:
                raise PeerCallError("wait_timeout", f"task still {status.get('state')}")
            time.sleep(poll_s)

    def _sent_path(self, task_id: str) -> Path:
        uuid.UUID(task_id)  # never build paths from unvalidated ids
        return self.state_dir / "sent" / f"{self.peer.fingerprint}__{task_id}.json"


def _unverified_code(raw: bytes) -> str:
    try:
        return str(json.loads(raw).get("error", {}).get("code", "?"))[:64]
    except (ValueError, AttributeError):
        return "?"
