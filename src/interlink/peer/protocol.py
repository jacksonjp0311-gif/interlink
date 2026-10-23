"""``interlink-peer/1``: signed requests, signed responses, signed results.

Request
    Headers ``X-Interlink-Auth`` (base64url canonical JSON claims) and
    ``X-Interlink-Signature`` (Ed25519 over the claims, domain-separated). Claims bind the
    sender and recipient fingerprints, method, path, body hash, a random nonce and a short
    validity window, so a captured request cannot be replayed, redirected to another host
    or have its body swapped.

Response
    ``X-Interlink-Signature`` over ``{from, to, nonce, status, body_sha256}``: the host
    proves it answered *this* request, so the client is authenticated to the host and the
    host to the client (mutual authentication on top of TLS).

Result
    ``{"statement": {...}, "signature": "..."}``. The statement carries the task's own
    hash chain and the full evidence bundle; the requester verifies all of it offline.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from interlink.peer import PROTOCOL
from interlink.peer.crypto import CryptoError, Identity, b64d, b64e, verify
from interlink.peer.store import verify_chain
from interlink.security import canonical, sha256_text

AUTH_HEADER = "X-Interlink-Auth"
SIG_HEADER = "X-Interlink-Signature"
MAX_AUTH_HEADER = 2048
CLOCK_SKEW_S = 120
MAX_VALIDITY_S = 300
RESULT_SCHEMA = "interlink-peer-result/1"


class ProtocolError(ValueError):
    """A request or reply that must be rejected. ``code`` is stable and machine-readable."""

    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code, self.status = code, status


def body_digest(body: bytes) -> str:
    """SHA-256 hex of a request or response body."""
    return hashlib.sha256(body).hexdigest()


def sign_request(
    identity: Identity, to_fp: str, method: str, path: str, body: bytes, validity_s: float = 60
) -> tuple[dict[str, str], dict[str, Any]]:
    """Return the auth headers for one request, plus the claims (the client keeps the nonce)."""
    now = int(time.time() * 1000)
    claims = {
        "v": PROTOCOL,
        "from": identity.fingerprint,
        "to": to_fp,
        "method": method.upper(),
        "path": path,
        "nonce": secrets.token_hex(16),
        "iat": now,
        "exp": now + int(validity_s * 1000),
        "body_sha256": body_digest(body),
    }
    raw = canonical(claims).encode()
    headers = {AUTH_HEADER: b64e(raw), SIG_HEADER: b64e(identity.sign("request", raw))}
    return headers, claims


def read_claims(header: str | None) -> tuple[dict[str, Any], bytes]:
    """Parse (but do not yet trust) the claims header."""
    if not header or len(header) > MAX_AUTH_HEADER:
        raise ProtocolError("unauthenticated", "missing or oversized auth header")
    try:
        raw = b64d(header, max_len=MAX_AUTH_HEADER)
        claims = json.loads(raw)
    except (CryptoError, ValueError) as exc:
        raise ProtocolError("unauthenticated", "malformed auth header") from exc
    if not isinstance(claims, dict) or claims.get("v") != PROTOCOL:
        raise ProtocolError("unauthenticated", "unsupported protocol version")
    for key, kind in (
        ("from", str),
        ("to", str),
        ("method", str),
        ("path", str),
        ("nonce", str),
        ("iat", int),
        ("exp", int),
        ("body_sha256", str),
    ):
        if not isinstance(claims.get(key), kind):
            raise ProtocolError("unauthenticated", f"auth claim {key!r} missing or mistyped")
    if not (16 <= len(claims["nonce"]) <= 64):
        raise ProtocolError("unauthenticated", "bad nonce")
    return claims, raw


def check_request(
    claims: dict[str, Any],
    raw: bytes,
    signature_header: str | None,
    public_raw: bytes,
    *,
    own_fp: str,
    method: str,
    path: str,
    body: bytes,
    now: float | None = None,
) -> None:
    """Everything except the nonce check (the caller owns the nonce cache)."""
    try:
        signature = b64d(signature_header or "", max_len=256)
    except CryptoError as exc:
        raise ProtocolError("unauthenticated", "malformed signature") from exc
    if not verify(public_raw, "request", raw, signature):
        raise ProtocolError("bad_signature", "request signature does not verify")
    if claims["to"] != own_fp:
        raise ProtocolError("wrong_recipient", "request was addressed to a different host")
    if claims["method"] != method.upper() or claims["path"] != path:
        raise ProtocolError("bad_binding", "signed method/path do not match the request")
    now_ms = (now if now is not None else time.time()) * 1000
    if claims["iat"] > now_ms + CLOCK_SKEW_S * 1000:
        raise ProtocolError("clock_skew", "request is from the future; check your clock")
    if claims["exp"] < now_ms:
        raise ProtocolError("expired", "request has expired")
    if claims["exp"] - claims["iat"] > MAX_VALIDITY_S * 1000 or claims["exp"] <= claims["iat"]:
        raise ProtocolError("bad_validity", "request validity window is too long")
    if claims["body_sha256"] != body_digest(body):
        raise ProtocolError("bad_binding", "body does not match the signed digest")


def response_message(
    host_fp: str, requester_fp: str, nonce: str, status: int, body: bytes
) -> bytes:
    """The bytes a host signs for one response."""
    return canonical(
        {
            "v": PROTOCOL,
            "from": host_fp,
            "to": requester_fp,
            "nonce": nonce,
            "status": status,
            "body_sha256": body_digest(body),
        }
    ).encode()


def sign_response(
    identity: Identity, requester_fp: str, nonce: str, status: int, body: bytes
) -> str:
    """Signature header value for a response to ``claims``."""
    return b64e(
        identity.sign(
            "response", response_message(identity.fingerprint, requester_fp, nonce, status, body)
        )
    )


def check_response(
    host_public: bytes,
    host_fp: str,
    own_fp: str,
    nonce: str,
    status: int,
    body: bytes,
    signature_header: str | None,
) -> None:
    """Verify a host's response signature against its pinned key."""
    try:
        signature = b64d(signature_header or "", max_len=256)
    except CryptoError as exc:
        raise ProtocolError("bad_response_signature", "malformed response signature") from exc
    message = response_message(host_fp, own_fp, nonce, status, body)
    if not verify(host_public, "response", message, signature):
        raise ProtocolError("bad_response_signature", "response is not signed by the expected host")


def request_digest(task: dict[str, Any]) -> str:
    """What the result statement binds to: the canonical submitted task."""
    return sha256_text(canonical(task))


def sign_result(identity: Identity, statement: dict[str, Any]) -> dict[str, Any]:
    """Wrap a result statement with the host's signature."""
    raw = canonical(statement).encode()
    return {"statement": statement, "signature": b64e(identity.sign("result", raw))}


def verify_result(
    envelope: dict[str, Any],
    *,
    host_public: bytes,
    host_fp: str,
    own_fp: str,
    task: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check a signed result end to end. Returns a report; raises ProtocolError on failure."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("statement"), dict):
        raise ProtocolError("bad_result", "result envelope is malformed", 502)
    statement = envelope["statement"]
    try:
        signature = b64d(str(envelope.get("signature", "")), max_len=256)
    except CryptoError as exc:
        raise ProtocolError("bad_result_signature", "malformed result signature", 502) from exc
    if not verify(host_public, "result", canonical(statement).encode(), signature):
        raise ProtocolError("bad_result_signature", "result is not signed by the host", 502)
    if statement.get("schema") != RESULT_SCHEMA:
        raise ProtocolError("bad_result", "unknown result schema", 502)
    if statement.get("host") != host_fp or statement.get("requester") != own_fp:
        raise ProtocolError("bad_result", "result is bound to a different host or requester", 502)
    if task is not None:
        if statement.get("task_id") != task.get("task_id"):
            raise ProtocolError("bad_result", "result is for a different task", 502)
        if statement.get("request_sha256") != request_digest(task):
            raise ProtocolError("bad_result", "result does not match the task that was sent", 502)
    chain = verify_chain(statement.get("chain") or [])
    if not chain["valid"] or chain.get("head") != statement.get("chain_head"):
        raise ProtocolError("bad_result", "task hash chain is broken", 502)
    evidence = statement.get("evidence") or {}
    if evidence.get("bundle") is not None and evidence.get("sha256") != sha256_text(
        canonical(evidence["bundle"])
    ):
        raise ProtocolError("bad_result", "evidence bundle does not match its digest", 502)
    for item in statement.get("files") or []:
        if item.get("text") is not None and sha256_text(item["text"]) != item.get("sha256"):
            raise ProtocolError(
                "bad_result", f"file {item.get('path')!r} does not match its digest", 502
            )
    return {
        "verified": True,
        "task_id": statement.get("task_id"),
        "state": statement.get("state"),
        "chain_entries": chain["entries"],
        "chain_head": chain["head"],
        "evidence_sha256": evidence.get("sha256"),
    }
