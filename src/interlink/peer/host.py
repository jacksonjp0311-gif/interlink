"""The sharing side: accept signed tasks from known peers and run them in the sandbox.

Nothing here runs unless someone calls :func:`serve` (``interlink share``). Every inbound
task goes through, in order: size limit -> signature -> known peer -> recipient/binding/
expiry -> not revoked -> nonce (replay) -> rate limit -> schema -> per-peer policy
(harness allow-list, quotas, timeout ceiling) -> approval -> the normal Interlink
sandbox with **no** inherited secrets, ``pass_env`` or real HOME.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import re
import ssl
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from interlink import __version__
from interlink.config import Config, ServerSettings
from interlink.engine import Engine, InterlinkError
from interlink.peer.crypto import Identity
from interlink.peer.protocol import (
    AUTH_HEADER,
    RESULT_SCHEMA,
    SIG_HEADER,
    ProtocolError,
    check_request,
    read_claims,
    request_digest,
    sign_response,
    sign_result,
)
from interlink.peer.store import (
    AuditLog,
    HashChain,
    NonceCache,
    PeerBook,
    PeerError,
    PeerRecord,
    RateLimiter,
)
from interlink.security import atomic_write_json, canonical, read_json, sha256_text

MAX_BODY = 8 * 1024 * 1024  # hard ceiling before authentication, whatever the policy says
MAX_FINAL_TEXT = 16_000
ACTIVE = {"pending_approval", "queued", "running"}
TERMINAL = {"complete", "failed", "cancelled", "timed_out", "error", "denied", "expired"}
SAFE_REL = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/ -]{0,255}$")
ROUTES = ("/v1/hello", "/v1/tasks", "/v1/tasks/status", "/v1/tasks/result", "/v1/tasks/cancel")


class TaskRequest(BaseModel):
    """The only shape an inbound task may have. Unknown fields are refused."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    harness: str = Field(min_length=1, max_length=64)
    prompt: str = Field(min_length=1, max_length=200_000)
    files: dict[str, str] = Field(default_factory=dict)
    timeout_s: float | None = Field(None, gt=0, le=86_400)


class TaskRef(BaseModel):
    """A request body that names one task."""

    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(min_length=36, max_length=36)


def safe_relative_path(path: str) -> bool:
    """Seed paths: relative, forward slashes, no `..`, no drive letters, no control chars."""
    if not SAFE_REL.match(path) or path.startswith("/") or "//" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def sanitize_config(config: Config, max_concurrent: int) -> Config:
    """The engine peers get: same harnesses, but no secrets, no pass_env, no real HOME."""
    harnesses = {}
    for name, adapter in config.harnesses.items():
        options = adapter.options.model_dump()
        options.update(pass_env=[], secrets=[], env={}, isolate_home=True)
        harnesses[name] = type(adapter)(name, options)
    server = ServerSettings(
        max_instances=max(4, max_concurrent * 2),
        max_concurrent_runs=max_concurrent,
        max_run_timeout_s=3600,
        keep_workspaces=False,
        auto_detect=False,
    )
    return Config(server=server, harnesses=harnesses, source=config.source, notes=[])


@dataclass
class Task:
    """One inbound task and everything the host knows about it."""

    task_id: str
    peer_fp: str
    peer_name: str
    request: dict[str, Any]
    request_sha256: str
    timeout_s: float
    state: str = "pending_approval"
    created: float = field(default_factory=time.time)
    finished: float | None = None
    chain: HashChain = field(default_factory=HashChain)
    instance_id: str | None = None
    run_id: str | None = None
    result: dict[str, Any] | None = None
    reason: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)

    @property
    def key(self) -> str:
        """Storage key: requester fingerprint plus task id."""
        return f"{self.peer_fp}__{self.task_id}"

    def status(self) -> dict[str, Any]:
        """What the requester may see while the task is in flight."""
        return {
            "task_id": self.task_id,
            "state": self.state,
            "harness": self.request["harness"],
            "created": self.created,
            "finished": self.finished,
            "reason": self.reason,
            "result_ready": self.result is not None,
        }

    def record(self) -> dict[str, Any]:
        """The persisted record (prompt as preview and hash only)."""
        return {
            **self.status(),
            "peer": self.peer_name,
            "peer_fingerprint": self.peer_fp,
            "prompt_sha256": sha256_text(self.request["prompt"]),
            "prompt_preview": self.request["prompt"][:200],
            "files": sorted(self.request.get("files", {})),
            "timeout_s": self.timeout_s,
        }


class PeerHost:
    """Transport-independent request handling, so tests can drive it without sockets."""

    def __init__(
        self,
        identity: Identity,
        book: PeerBook,
        config: Config,
        state_dir: Path,
        *,
        max_concurrent: int = 2,
        approval_timeout_s: float = 600,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.identity, self.book, self.state_dir = identity, book, state_dir
        self.engine = Engine(sanitize_config(config, max_concurrent), state_dir / "engine")
        self.nonces = NonceCache(state_dir / "nonces.sqlite")
        self.audit = AuditLog(state_dir / "audit.jsonl")
        self.limiter = RateLimiter()
        self.approval_timeout_s = approval_timeout_s
        self.on_event = on_event or (lambda kind, info: None)
        self.tasks: dict[str, Task] = {}
        self._lock = threading.RLock()
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._stopping = threading.Event()
        (state_dir / "tasks").mkdir(parents=True, exist_ok=True)
        (state_dir / "decisions").mkdir(parents=True, exist_ok=True)
        (state_dir / "results").mkdir(parents=True, exist_ok=True)
        self._watcher = threading.Thread(target=self._watch, name="peer-approvals", daemon=True)
        self._watcher.start()
        self.audit.append("host_started", fingerprint=identity.fingerprint, version=__version__)

    # -- request entry point -------------------------------------------------------
    def handle(
        self, method: str, path: str, headers: dict[str, str], body: bytes, remote: str = "?"
    ) -> tuple[int, bytes, dict[str, str]]:
        """Authenticate and serve one request. Returns status, body and headers."""
        requester, nonce = "", ""
        try:
            if method != "POST" or path not in ROUTES:
                raise ProtocolError("not_found", "no such endpoint", 404)
            if len(body) > MAX_BODY:
                raise ProtocolError("payload_too_large", "request body is too large", 413)
            claims, raw = read_claims(_header(headers, AUTH_HEADER))
            requester, nonce = claims["from"], claims["nonce"]
            peer = self.book.by_fingerprint(requester)
            if peer is None:
                raise ProtocolError("unknown_peer", "this host does not know your key", 401)
            check_request(
                claims,
                raw,
                _header(headers, SIG_HEADER),
                peer.public_raw,
                own_fp=self.identity.fingerprint,
                method=method,
                path=path,
                body=body,
            )
            if peer.revoked:
                raise ProtocolError("revoked", "your access to this host was revoked", 403)
            if not self.nonces.claim(requester, nonce, claims["exp"] / 1000 + 300):
                raise ProtocolError("replay", "this request was already used", 401)
            if not self.limiter.allow(f"req:{requester}", peer.policy.max_requests_per_minute, 60):
                raise ProtocolError("rate_limited", "too many requests; slow down", 429)
            status, data = self._route(peer, path, body)
            payload = {"ok": True, "data": data}
        except ProtocolError as exc:
            status, payload = (
                exc.status,
                {"ok": False, "error": {"code": exc.code, "message": str(exc)}},
            )
            if exc.status in (401, 403):
                key = f"fail:{remote}"
                if not self.limiter.allow(key, 30, 60):
                    status = 429
                    payload["error"] = {"code": "rate_limited", "message": "too many failures"}
            self.audit.append(
                "request_rejected",
                peer=requester or None,
                path=path[:64],
                code=payload["error"]["code"],
                remote=remote,
            )
        except Exception as exc:  # pragma: no cover - defensive: never leak a traceback
            status = 500
            payload = {"ok": False, "error": {"code": "internal", "message": type(exc).__name__}}
            self.audit.append("internal_error", peer=requester or None, error=type(exc).__name__)
        out = json.dumps(payload, sort_keys=True).encode()
        headers_out = {"Content-Type": "application/json"}
        if requester:
            headers_out[SIG_HEADER] = sign_response(self.identity, requester, nonce, status, out)
        return status, out, headers_out

    def _route(self, peer: PeerRecord, path: str, body: bytes) -> tuple[int, dict[str, Any]]:
        data = _json_body(body)
        if path == "/v1/hello":
            harnesses = [h for h in peer.policy.harnesses if h in self.engine.config.harnesses]
            return 200, {
                "host": self.identity.fingerprint,
                "you": peer.fingerprint,
                "version": __version__,
                "harnesses": harnesses,
                "approval": peer.policy.approval,
                "limits": peer.policy.model_dump(exclude={"harnesses", "approval"}),
            }
        if path == "/v1/tasks":
            return self._submit(peer, body, data)
        ref = _validate(TaskRef, data)
        task = self.tasks.get(f"{peer.fingerprint}__{ref.task_id}")
        if task is None:  # other peers' tasks are indistinguishable from missing ones
            raise ProtocolError("unknown_task", "no such task", 404)
        if path == "/v1/tasks/status":
            return 200, task.status()
        if path == "/v1/tasks/result":
            if task.result is None:
                raise ProtocolError("not_finished", f"task is {task.state}", 409)
            return 200, task.result
        return 200, self.cancel(task)

    # -- tasks -----------------------------------------------------------------------
    def _submit(self, peer: PeerRecord, body: bytes, data: Any) -> tuple[int, dict[str, Any]]:
        policy = peer.policy
        budget = policy.max_prompt_chars * 4 + policy.max_files * (policy.max_file_bytes * 2 + 512)
        if len(body) > budget + 4096:
            raise ProtocolError("payload_too_large", "task exceeds your size allowance", 413)
        request = _validate(TaskRequest, data)
        if len(request.prompt) > policy.max_prompt_chars:
            raise ProtocolError("prompt_too_long", "prompt exceeds your allowance", 413)
        if len(request.files) > policy.max_files:
            raise ProtocolError("too_many_files", "too many files for your allowance", 413)
        for rel, text in request.files.items():
            if not safe_relative_path(rel):
                raise ProtocolError("path_refused", f"file path {rel[:80]!r} is not allowed", 400)
            if len(text.encode("utf-8")) > policy.max_file_bytes:
                raise ProtocolError("file_too_large", f"{rel[:80]!r} exceeds your allowance", 413)
        if (
            request.harness not in policy.harnesses
            or request.harness not in self.engine.config.harnesses
        ):
            raise ProtocolError(
                "harness_not_allowed", f"you may not run harness {request.harness!r} here", 403
            )
        timeout = request.timeout_s if request.timeout_s is not None else policy.max_timeout_s
        if timeout > policy.max_timeout_s:
            raise ProtocolError(
                "timeout_exceeds_policy",
                f"timeout_s may be at most {policy.max_timeout_s:g} for you",
                400,
            )
        task_dict = request.model_dump()
        digest = request_digest(data)  # exactly what the requester signed and remembers
        key = f"{peer.fingerprint}__{request.task_id}"
        with self._lock:
            existing = self.tasks.get(key)
            if existing is not None:
                if existing.request_sha256 != digest:
                    raise ProtocolError(
                        "task_collision", "task_id reused with different content", 409
                    )
                return 200, existing.status()
            active = sum(
                1
                for t in self.tasks.values()
                if t.peer_fp == peer.fingerprint and t.state in ACTIVE
            )
            if active >= policy.max_concurrent:
                raise ProtocolError("concurrency_limit", "you already have tasks in flight", 429)
            if not self.limiter.allow(f"task:{peer.fingerprint}", policy.max_tasks_per_hour, 3600):
                raise ProtocolError("quota_exceeded", "hourly task quota reached", 429)
            task = Task(
                task_id=request.task_id,
                peer_fp=peer.fingerprint,
                peer_name=peer.name,
                request=task_dict,
                request_sha256=digest,
                timeout_s=timeout,
            )
            task.chain.append(
                "received",
                requester=peer.fingerprint,
                request_sha256=digest,
                harness=request.harness,
                files=len(request.files),
            )
            self.tasks[key] = task
        self.audit.append(
            "task_received",
            peer=peer.fingerprint,
            name=peer.name,
            task=task.task_id,
            harness=request.harness,
            request_sha256=digest,
        )
        if policy.approval == "auto":
            self._approve(task, "auto-approved by policy")
        else:
            self._persist(task)
            self.on_event("pending", task.record())
        return 202, task.status()

    def pending(self) -> list[dict[str, Any]]:
        """Tasks waiting for approval."""
        with self._lock:
            return [t.record() for t in self.tasks.values() if t.state == "pending_approval"]

    def decide(self, task_id: str, approve: bool, note: str = "") -> dict[str, Any]:
        """Approve or deny a pending task."""
        with self._lock:
            matches = [t for t in self.tasks.values() if t.task_id == task_id]
            if not matches:
                raise PeerError(f"no task {task_id}")
            task = matches[0]
            if task.state != "pending_approval":
                raise PeerError(f"task {task_id} is {task.state}, not pending")
            if approve:
                self._approve(task, note or "approved by operator")
            else:
                self._finish(task, "denied", note or "denied by operator")
        return task.status()

    def _approve(self, task: Task, how: str) -> None:
        task.state = "queued"
        task.chain.append("approved", how=how)
        self.audit.append("task_approved", peer=task.peer_fp, task=task.task_id, how=how)
        self._persist(task)
        threading.Thread(
            target=self._execute, args=(task,), name=f"peer-{task.task_id[:8]}", daemon=True
        ).start()

    def cancel(self, task: Task) -> dict[str, Any]:
        """Cancel a task: drop it if pending, kill it if running."""
        with self._lock:
            if task.state in TERMINAL:
                return task.status()
            task.cancel.set()
            if task.state in ("pending_approval", "queued"):
                self._finish(task, "cancelled", "cancelled by requester")
                return task.status()
            if task.instance_id and task.run_id:
                with contextlib.suppress(InterlinkError):
                    self.engine.cancel(task.instance_id, task.run_id)
        return task.status()

    def _execute(self, task: Task) -> None:
        with self._slots:
            if task.cancel.is_set() or self._stopping.is_set():
                if task.state not in TERMINAL:
                    self._finish(task, "cancelled", "cancelled before start")
                return
            try:
                self._run(task)
            except Exception as exc:
                self._finish(task, "error", f"{type(exc).__name__}: {str(exc)[:200]}")

    def _run(self, task: Task) -> None:
        request = task.request
        launched = self.engine.launch(
            request["harness"], files=request["files"] or None, label=f"peer:{task.peer_name}"
        )
        task.instance_id = launched["instance_id"]
        task.state = "running"
        task.chain.append("started", instance_id=task.instance_id)
        self._persist(task)
        started = self.engine.prompt(task.instance_id, request["prompt"], timeout_s=task.timeout_s)
        task.run_id = started["run_id"]
        if task.cancel.is_set():
            self.engine.cancel(task.instance_id, task.run_id)
        cursor, window = 0, {}
        while True:
            window = self.engine.observe(
                task.instance_id, task.run_id, after=cursor, limit=256, wait_s=1
            )
            cursor = window["next_cursor"]
            if window["done"] and not window["more"]:
                break
        policy = self.book.by_fingerprint(task.peer_fp)
        budget = policy.policy.max_result_bytes if policy else 1024 * 1024
        files, deleted = self._collect_files(task.instance_id, budget)
        exported = self.engine.evidence(task.instance_id)
        bundle = read_json(Path(exported["path"]))
        self.engine.stop(task.instance_id, discard=True)
        task.chain.append(
            "finished",
            state=window["state"],
            exit_code=window.get("exit_code"),
            evidence_sha256=sha256_text(canonical(bundle)),
            files=len(files),
        )
        self._finish(
            task,
            window["state"],
            None,
            exit_code=window.get("exit_code"),
            final_text=(window.get("final_text") or "")[:MAX_FINAL_TEXT],
            files=files,
            deleted=deleted,
            bundle=bundle,
        )

    def _collect_files(
        self, instance_id: str, budget: int
    ) -> tuple[list[dict[str, Any]], list[str]]:
        listing = self.engine.files(instance_id)
        out, spent = [], 0
        for item in listing["files"]:
            if item["status"] not in ("added", "modified"):
                continue
            entry = {k: item[k] for k in ("path", "status", "size", "sha256")}
            entry["text"] = None
            if spent + item["size"] <= budget:
                read = self.engine.files(
                    instance_id, item["path"], max_bytes=min(budget - spent, 4 * 1024 * 1024) or 1
                )
                if not read.get("truncated") and isinstance(read.get("text"), str):
                    entry["text"] = read["text"]
                    spent += item["size"]
            entry["omitted"] = entry["text"] is None
            out.append(entry)
        deleted = [d if isinstance(d, str) else d.get("path") for d in listing.get("deleted", [])]
        return out, deleted

    def _finish(self, task: Task, state: str, reason: str | None, **result: Any) -> None:
        with self._lock:
            if task.state in TERMINAL:
                return
            if state in ("denied", "expired", "cancelled", "error") and (
                not task.chain.entries or task.chain.entries[-1]["event"] != "finished"
            ):
                task.chain.append(state, reason=reason)
            task.state, task.reason, task.finished = state, reason, time.time()
            bundle = result.get("bundle")
            statement = {
                "schema": RESULT_SCHEMA,
                "task_id": task.task_id,
                "host": self.identity.fingerprint,
                "requester": task.peer_fp,
                "request_sha256": task.request_sha256,
                "harness": task.request["harness"],
                "state": state,
                "reason": reason,
                "exit_code": result.get("exit_code"),
                "final_text": result.get("final_text"),
                "files": result.get("files", []),
                "deleted": result.get("deleted", []),
                "evidence": {
                    "sha256": sha256_text(canonical(bundle)) if bundle is not None else None,
                    "bundle": bundle,
                },
                "chain": task.chain.entries,
                "chain_head": task.chain.head,
                "created_at": task.created,
                "finished_at": task.finished,
                "host_version": __version__,
                "isolation": "fresh workspace, private HOME/TMP, env allow-list, no host secrets",
            }
            task.result = sign_result(self.identity, statement)
            atomic_write_json(self.state_dir / "results" / f"{task.key}.json", task.result)
            self._persist(task)
        self.audit.append(
            "task_finished",
            peer=task.peer_fp,
            task=task.task_id,
            state=state,
            chain_head=task.chain.head,
            reason=reason,
        )
        self.on_event("finished", task.record())

    def _persist(self, task: Task) -> None:
        atomic_write_json(self.state_dir / "tasks" / f"{task.key}.json", task.record())

    def _watch(self) -> None:
        """Apply decisions written by `interlink peer approve/deny`, expire stale requests."""
        decisions = self.state_dir / "decisions"
        while not self._stopping.wait(0.25):
            for path in decisions.glob("*.json"):
                try:
                    decision = read_json(path)
                    path.unlink()
                    self.decide(
                        str(decision["task_id"]),
                        decision.get("decision") == "approve",
                        "approved via CLI"
                        if decision.get("decision") == "approve"
                        else "denied via CLI",
                    )
                except (PeerError, KeyError, ValueError, OSError):
                    continue
            now = time.time()
            with self._lock:
                stale = [
                    t
                    for t in self.tasks.values()
                    if t.state == "pending_approval" and now - t.created > self.approval_timeout_s
                ]
            for task in stale:
                self._finish(task, "expired", "nobody approved it in time")

    def shutdown(self) -> None:
        """Stop the watcher, cancel running tasks and close the engine."""
        self._stopping.set()
        with self._lock:
            live = [t for t in self.tasks.values() if t.state in ACTIVE]
        for task in live:
            self.cancel(task)
        self.engine.shutdown()
        self.audit.append("host_stopped")
        self.nonces.close()


def write_decision(state_dir: Path, task_id: str, approve: bool) -> Path:
    """Used by `interlink peer approve|deny` from another terminal."""
    uuid.UUID(task_id)
    path = state_dir / "decisions" / f"{task_id}.json"
    atomic_write_json(path, {"task_id": task_id, "decision": "approve" if approve else "deny"})
    return path


def list_pending(state_dir: Path) -> list[dict[str, Any]]:
    """Pending tasks read from disk, for `interlink peer pending` in another terminal."""
    out = []
    for path in sorted((state_dir / "tasks").glob("*.json")):
        try:
            record = read_json(path)
        except (OSError, ValueError):
            continue
        if record.get("state") == "pending_approval":
            out.append(record)
    return out


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _json_body(body: bytes) -> Any:
    try:
        return json.loads(body or b"{}")
    except ValueError as exc:
        raise ProtocolError("bad_request", "body is not JSON", 400) from exc


def _validate(model: type[BaseModel], data: Any) -> Any:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first.get("loc", ()))
        raise ProtocolError("bad_request", f"{where}: {first.get('msg')}", 400) from exc


# -- HTTP(S) transport ---------------------------------------------------------------
def is_loopback(host: str) -> bool:
    """True for localhost and loopback addresses."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Handler(BaseHTTPRequestHandler):
    server_version = "Interlink"
    sys_version = ""
    timeout = 15  # slow clients are dropped (slowloris)
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        host: PeerHost = self.server.peer_host  # type: ignore[attr-defined]
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            return self._raw(411, {"code": "length_required", "message": "Content-Length required"})
        if int(length) > MAX_BODY:
            host.audit.append(
                "request_rejected", code="payload_too_large", remote=self.client_address[0]
            )
            return self._raw(
                413, {"code": "payload_too_large", "message": "request body is too large"}
            )
        body = self.rfile.read(int(length))
        status, out, headers = host.handle(
            "POST", self.path, dict(self.headers.items()), body, self.client_address[0]
        )
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _raw(self, status: int, error: dict[str, str]) -> None:
        out = json.dumps({"ok": False, "error": error}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(out)
        self.close_connection = True

    def do_GET(self) -> None:
        self._raw(405, {"code": "method_not_allowed", "message": "use POST"})

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET

    def log_message(self, format: str, *args: Any) -> None:
        return  # the audit log is the record; don't echo request lines


class PeerServer(ThreadingHTTPServer):
    """Threaded HTTP server bound to one ``PeerHost``."""

    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address: tuple[str, int], host: PeerHost) -> None:
        super().__init__(address, _Handler)
        self.peer_host = host


def serve(
    host: PeerHost,
    bind: str = "127.0.0.1",
    port: int = 7464,
    *,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> PeerServer:
    """Bind the HTTP(S) listener. Non-loopback addresses require TLS - no exceptions."""
    if not is_loopback(bind) and not (tls_cert and tls_key):
        raise PeerError(
            f"refusing to listen on {bind} without TLS; pass --tls-cert/--tls-key "
            "(see `interlink peer cert`) or bind to 127.0.0.1"
        )
    server = PeerServer((bind, port), host)
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    host.audit.append("listening", bind=bind, port=server.server_address[1], tls=bool(tls_cert))
    return server
