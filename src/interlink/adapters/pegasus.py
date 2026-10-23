"""PEGASUS desktop host adapter (experimental).

This is the harness Interlink was originally built for. PEGASUS is a long-lived
desktop app, so this is a *host* adapter: ``start`` launches a PEGASUS build with an
Interlink boot envelope, then every prompt is a ``pegasus-interlink/1`` request over
an authenticated local channel, and progress is read back with ``observe``.

What it does on launch (mirrors the original PEGASUS Interlink service):

1. Hashes the disposable PEGASUS source tree (``source_root``) with the host's exact
   exclusion rules and writes ``profile/interlink/source-manifest.json``.
2. Writes the owner marker and a ``boot.json`` with a fresh generation UUID and a
   256-bit token, inside this instance's workspace.
3. Links ``<source_root>/data`` and ``<source_root>/runtime/hermes-home`` into the
   sandbox profile, so the app's state lands in the throwaway workspace.
4. Starts the executable with ``PEGASUS_INTERLINK_BOOT`` and the redirected
   ``PEGASUS_DATA_DIR`` / ``HERMES_HOME`` / ``HOME`` / ``WEBVIEW2_USER_DATA_FOLDER``.
5. Polls ``inspect`` until the host answers, then acquires the controller lease.

Never point ``source_root`` at your everyday PEGASUS install: use a disposable copy.
Interlink refuses ``~/PEGASUS`` outright.

Status: the protocol is exercised end to end against a faithful fake host in the test
suite (tests/fakes/fake_pegasus_host.py). It has **not** yet been run against a live
PEGASUS build from this repository - treat it as experimental.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from interlink.adapters._pegasus_wire import (
    BOOT_SCHEMA,
    OWNER_SCHEMA,
    PROTOCOL,
    SOURCE_SCHEMA,
    TERMINAL_TASK_STATES,
    Ambiguous,
    ChannelRefused,
    NamedPipeChannel,
    UnixSocketChannel,
    source_digest,
    source_inventory,
)
from interlink.adapters.base import (
    AdapterOptions,
    HarnessAdapter,
    InstanceView,
    RunContext,
    RunOutcome,
)
from interlink.process import ManagedProcess
from interlink.sandbox import refuse_protected
from interlink.security import IS_WINDOWS, SecurityError, atomic_write_json, sha256_file


class PegasusModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    path: str
    endpoint: str
    context: int = 65536


class PegasusOptions(AdapterOptions):
    executable: str = Field(description="A PEGASUS build that contains the Interlink host.")
    source_root: str = Field(description="A DISPOSABLE PEGASUS source tree for that build.")
    argv: list[str] = Field(default_factory=list, description="Extra arguments for the app.")
    project_subdir: str = "fixtures"
    hermes_root: str | None = Field(None, description="Optional Hermes runtime to link in.")
    build_sha256: str | None = Field(None, description="Defaults to sha256 of the executable.")
    inference: bool = Field(False, description="Allow prompts to reach a model at all.")
    model: PegasusModel | None = None
    reasoning_profile: str = Field("fast", pattern="^(fast|deep)$")
    startup_timeout_s: float = Field(90, gt=0, le=600)
    poll_interval_s: float = Field(0.25, gt=0, le=5)
    isolation_links: bool = True
    timeout_s: float = Field(900, gt=0, le=86_400)


class PegasusAdapter(HarnessAdapter):
    kind: ClassVar[str] = "host"
    summary: ClassVar[str] = (
        "PEGASUS desktop host over its authenticated local pipe (experimental)."
    )
    Options: ClassVar[type[AdapterOptions]] = PegasusOptions
    options: PegasusOptions

    # -- launch --------------------------------------------------------------------------

    def start(self, instance: InstanceView) -> dict[str, Any]:
        o = self.options
        source = Path(o.source_root).expanduser().resolve()
        executable = Path(o.executable).expanduser().resolve()
        if not source.is_dir():
            raise SecurityError("source_root must be an existing directory")
        if not executable.is_file():
            raise SecurityError("executable not found")
        personal = Path.home() / "PEGASUS"
        if source == personal.resolve() or personal.resolve() in source.parents:
            raise SecurityError("refusing a personal PEGASUS installation; use a disposable copy")
        refuse_protected(source, purpose="used as a PEGASUS source root")
        project = (source / o.project_subdir).resolve()
        project.mkdir(parents=True, exist_ok=True)

        ws = instance.workspace
        profile = ws.root / "profile"
        for sub in (
            "data",
            "hermes-home",
            "webview",
            "home",
            "memory",
            "temp",
            "interlink/requests",
        ):
            (profile / sub).mkdir(parents=True, exist_ok=True)

        if o.isolation_links:
            _link(source / "data", profile / "data")
            _link(source / "runtime" / "hermes-home", profile / "hermes-home")
            if o.hermes_root:
                _link(source / "runtime" / "hermes", Path(o.hermes_root).expanduser().resolve())

        files = source_inventory(source)
        if not files:
            raise SecurityError("source_root contains no source files")
        source_sha = source_digest(files)
        manifest = profile / "interlink" / "source-manifest.json"
        atomic_write_json(
            manifest,
            {
                "schema": SOURCE_SCHEMA,
                "source_sha256": source_sha,
                "files": [{"path": p, "sha256": h} for p, h in files],
            },
        )
        atomic_write_json(
            profile / "interlink" / "owner.json",
            {"schema": OWNER_SCHEMA, "instance_id": instance.id, "repair_root": str(source)},
        )
        generation = str(uuid.uuid4())
        token = secrets.token_hex(32)
        boot = {
            "schema": BOOT_SCHEMA,
            "instance_id": instance.id,
            "generation": generation,
            "token": token,
            "profile_dir": str(profile),
            "repair_root": str(source),
            "project_root": str(project),
            "source_sha256": source_sha,
            "build_sha256": o.build_sha256 or sha256_file(executable),
            "source_manifest_path": str(manifest),
            "inference_enabled": bool(o.inference),
            "model": o.model.model_dump() if o.model else None,
        }
        boot_path = ws.root / "boot.json"
        atomic_write_json(boot_path, boot)
        with contextlib.suppress(OSError):
            os.chmod(boot_path, 0o600)

        env = dict(instance.env)
        env.update(
            PEGASUS_INTERLINK_BOOT=str(boot_path),
            PEGASUS_ROOT=str(source),
            PEGASUS_DATA_DIR=str(profile / "data"),
            HERMES_HOME=str(profile / "hermes-home"),
            HERMES_CONFIG_DIR=str(profile / "hermes-home"),
            WEBVIEW2_USER_DATA_FOLDER=str(profile / "webview"),
            TEMP=str(profile / "temp"),
            TMP=str(profile / "temp"),
        )
        socket_path = None
        if not IS_WINDOWS:
            socket_path = os.path.join(tempfile.gettempdir(), f"pgil-{instance.id[:12]}.sock")
            env["PEGASUS_INTERLINK_SOCKET"] = socket_path

        log = ws.root / "host.log"
        process = ManagedProcess(
            [str(executable), *o.argv],
            cwd=source,
            env=env,
            stdout_sink=lambda _line: None,
            stderr_sink=lambda _line: None,
            stdout_log=log,
            stderr_log=log,
        )
        if IS_WINDOWS:  # pragma: no cover
            channel: Any = NamedPipeChannel(
                f"\\\\.\\pipe\\pegasus-interlink-{instance.id}-{generation}",
                expected_pid=lambda: process.pid if process.alive else None,
            )
        else:
            channel = UnixSocketChannel(socket_path or "", peer_check=lambda: process.alive)
        host = {
            "process": process,
            "channel": channel,
            "generation": generation,
            "token": token,
            "controller_id": str(uuid.uuid4()),
            "lease_id": None,
            "lease_expires_ms": 0,
            "socket_path": socket_path,
        }
        instance.state["host"] = host
        self._await_ready(instance)
        self._acquire(instance)
        return {
            "pid": process.pid,
            "identity": process.identity,
            "generation": generation,
            "source_sha256": source_sha,
            "build_sha256": boot["build_sha256"],
            "inference_enabled": boot["inference_enabled"],
            "boundary": "separate profile + authenticated host; same OS account, not an OS sandbox",
        }

    def _await_ready(self, instance: InstanceView) -> None:
        host = instance.state["host"]
        deadline = time.monotonic() + self.options.startup_timeout_s
        last = "no reply yet"
        while time.monotonic() < deadline:
            if not host["process"].alive:
                raise RuntimeError(f"PEGASUS exited during startup (code {host['process'].poll()})")
            try:
                reply = self.request(instance, "inspect", {}, timeout=5)
                if reply["status"] == "complete":
                    return
                last = (reply.get("error") or {}).get("code", reply["status"])
            except (ChannelRefused, Ambiguous) as exc:
                last = str(exc)
            time.sleep(0.2)
        host["process"].kill_tree()
        raise TimeoutError(f"PEGASUS host did not become ready: {last}")

    def _acquire(self, instance: InstanceView) -> None:
        host = instance.state["host"]
        reply = self.request(instance, "acquire", {"ttl_ms": 60_000}, timeout=10)
        if reply["status"] != "complete":
            raise RuntimeError(f"lease refused: {reply.get('error')}")
        host["lease_id"] = reply["data"]["lease_id"]
        host["lease_expires_ms"] = reply["data"]["expires_ms"]

    def _renew_if_needed(self, instance: InstanceView) -> None:
        host = instance.state["host"]
        if host["lease_expires_ms"] - time.time() * 1000 > 20_000:
            return
        reply = self.request(instance, "renew", {"ttl_ms": 60_000}, timeout=10)
        if reply["status"] == "complete":
            host["lease_expires_ms"] = reply["data"]["expires_ms"]

    # -- protocol ------------------------------------------------------------------------

    def request(
        self,
        instance: InstanceView,
        operation: str,
        args: dict[str, Any],
        *,
        request_id: str | None = None,
        timeout: float = 10,
    ) -> dict[str, Any]:
        host = instance.state["host"]
        envelope = {
            "schema": PROTOCOL,
            "instance_id": instance.id,
            "generation": host["generation"],
            "token": host["token"],
            "controller_id": host["controller_id"],
            "lease_id": host["lease_id"],
            "request_id": request_id or str(uuid.uuid4()),
            "deadline_ms": int(time.time() * 1000 + min(timeout, 59) * 1000),
            "operation": operation,
            "args": args,
        }
        return host["channel"].request(envelope)

    # -- turns ---------------------------------------------------------------------------

    def run(self, ctx: RunContext) -> RunOutcome:
        instance = ctx.instance
        if "host" not in instance.state:
            return RunOutcome("error", detail={"code": "host_not_running"})
        self._renew_if_needed(instance)
        session = instance.session.get("session_id")
        if not session:
            reply = self.request(
                instance, "session", {"action": "create", "title": f"Interlink {instance.id[:8]}"}
            )
            if reply["status"] != "complete":
                return _refused(ctx, reply)
            session = instance.session["session_id"] = reply["data"]["session_id"]
            ctx.emit("status", event="session_created", session_id=session)
        try:
            reply = self.request(
                instance,
                "prompt",
                {
                    "session_id": session,
                    "prompt": ctx.prompt,
                    "reasoning_profile": self.options.reasoning_profile,
                },
                request_id=ctx.run_id,
                timeout=30,
            )
        except Ambiguous as exc:
            ctx.emit("error", code="unknown_outcome", message=str(exc))
            return RunOutcome("error", detail={"code": "unknown_outcome", "replayed": False})
        if reply["status"] != "complete":
            return _refused(ctx, reply)
        ctx.emit("status", event="submission_scheduled", run_id=ctx.run_id)
        return self._follow(ctx, session)

    def _follow(self, ctx: RunContext, session: str) -> RunOutcome:
        cursor = 0
        cancel_sent = False
        reason = None
        settle_deadline = None
        while True:
            with contextlib.suppress(ChannelRefused, Ambiguous):
                self._renew_if_needed(ctx.instance)
            if not cancel_sent and (ctx.cancelled.is_set() or time.monotonic() >= ctx.deadline):
                reason = "cancelled" if ctx.cancelled.is_set() else "timed_out"
                with contextlib.suppress(ChannelRefused, Ambiguous):
                    self.request(
                        ctx.instance,
                        "control",
                        {"session_id": session, "run_id": ctx.run_id, "action": "cancel"},
                    )
                ctx.emit("interlink", event="cancel_requested", reason=reason)
                cancel_sent = True
                settle_deadline = time.monotonic() + 15
            if settle_deadline and time.monotonic() >= settle_deadline:
                return RunOutcome(reason or "error", detail={"settled": False})
            try:
                reply = self.request(
                    ctx.instance,
                    "observe",
                    {
                        "session_id": session,
                        "run_id": ctx.run_id,
                        "after_cursor": cursor,
                        "limit": 64,
                    },
                )
            except (ChannelRefused, Ambiguous) as exc:
                if not ctx.instance.state["host"]["process"].alive:
                    ctx.emit("error", code="host_exited", message=str(exc))
                    return RunOutcome("error", detail={"code": "host_exited"})
                time.sleep(self.options.poll_interval_s)
                continue
            if reply["status"] != "complete":
                code = (reply.get("error") or {}).get("code", "")
                if code == "run_unavailable":  # accepted but not yet visible: keep waiting
                    time.sleep(self.options.poll_interval_s)
                    continue
                return _refused(ctx, reply)
            data = reply["data"]
            for event in data.get("events") or []:
                _translate(ctx, event)
            cursor = data.get("next_cursor", cursor)
            state = (data.get("snapshot") or {}).get("state")
            if state in TERMINAL_TASK_STATES and not data.get("events"):
                answer = _last_assistant(data.get("messages") or [])
                ctx.emit("result", text=answer, native_state=state)
                if reason:
                    return RunOutcome(reason, detail={"native_state": state})
                mapped = {"complete": "complete", "stopped": "cancelled"}.get(state, "failed")
                return RunOutcome(mapped, detail={"native_state": state})
            time.sleep(self.options.poll_interval_s)

    # -- stop ----------------------------------------------------------------------------

    def stop(self, instance: InstanceView) -> dict[str, Any]:
        host = instance.state.pop("host", None)
        if not host:
            return {"host": "not_running"}
        process: ManagedProcess = host["process"]
        detail: dict[str, Any] = {}
        instance.state["host"] = host
        try:
            with contextlib.suppress(ChannelRefused, Ambiguous):
                self._renew_if_needed(instance)
            reply = self.request(instance, "shutdown", {}, timeout=10)
            detail["shutdown"] = reply.get("status")
        except (ChannelRefused, Ambiguous) as exc:
            detail["shutdown"] = f"unreachable: {exc}"
        finally:
            instance.state.pop("host", None)
        deadline = time.monotonic() + 10
        while process.alive and time.monotonic() < deadline:
            time.sleep(0.1)
        if process.alive:
            process.kill_tree()
            detail["forced"] = True
        if host.get("socket_path"):
            with contextlib.suppress(OSError):
                os.unlink(host["socket_path"])
        detail["exit_code"] = process.poll()
        return detail

    def doctor(self) -> dict[str, Any]:
        o = self.options
        checks = [
            self.check("executable", Path(o.executable).expanduser().is_file(), o.executable),
            self.check("source_root", Path(o.source_root).expanduser().is_dir(), o.source_root),
        ]
        if IS_WINDOWS:  # pragma: no cover
            try:
                import win32pipe  # noqa: F401

                checks.append(self.check("pywin32", True))
            except ImportError:
                checks.append(self.check("pywin32", False, "pip install pywin32"))
        else:
            checks.append(self.check("channel", True, "POSIX uses the Unix-socket test channel"))
        return {"ok": all(c["ok"] for c in checks), "checks": checks}


def _link(link: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(link):
        if os.path.realpath(link) == os.path.realpath(target):
            return
        if link.is_symlink() or (IS_WINDOWS and _is_junction(link)):
            link.unlink() if link.is_symlink() else os.rmdir(link)
        else:
            raise SecurityError(f"{link} already exists as real data; use a fresh source copy")
    link.parent.mkdir(parents=True, exist_ok=True)
    if IS_WINDOWS:  # pragma: no cover
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def _is_junction(path: Path) -> bool:  # pragma: no cover
    return bool(getattr(os.lstat(path), "st_file_attributes", 0) & 0x400)


def _refused(ctx: RunContext, reply: dict[str, Any]) -> RunOutcome:
    error = reply.get("error") or {}
    ctx.emit("error", code=error.get("code"), message=error.get("message"), status=reply["status"])
    return RunOutcome("failed", detail={"code": error.get("code"), "host_status": reply["status"]})


def _translate(ctx: RunContext, event: dict[str, Any]) -> None:
    chunk = event.get("chunk") or {}
    kind = chunk.get("kind")
    text = chunk.get("text")
    native = {"native_seq": event.get("seq")}
    if kind == "text":
        ctx.emit("text", text=text or "", partial=True, **native)
    elif kind in ("question", "approval"):
        ctx.emit("question", kind=kind, payload=text, **native)
    elif kind == "public_event":
        ctx.emit("status", event="public_event", payload=text, **native)
    elif kind == "error":
        ctx.emit("error", message=text, **native)
    else:
        ctx.emit("raw", native_kind=kind, payload=text, **native)


def _last_assistant(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "assistant" and isinstance(message.get("content"), str):
            return message["content"]
    return ""
