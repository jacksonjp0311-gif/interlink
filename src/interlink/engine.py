"""The Interlink engine: owns instances, runs, limits, receipts and evidence.

The MCP server and the CLI are thin shells around this class, so everything here
can be (and is) tested without MCP in the loop.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from interlink import __version__
from interlink.adapters.base import HarnessAdapter, InstanceView, RunContext, RunOutcome
from interlink.config import Config
from interlink.events import TERMINAL_STATES, RunLog
from interlink.ledger import Ledger, RequestCollision
from interlink.process import ManagedProcess, pid_alive, reap_recorded
from interlink.sandbox import Workspace, diff_snapshots, refuse_protected
from interlink.security import (
    Redactor,
    SecurityError,
    atomic_write_json,
    build_environment,
    canonical,
    confine,
    is_link,
    platform_label,
    read_json,
    sha256_file,
    sha256_text,
)

MAX_PROMPT_CHARS = 200_000
MAX_SEED_FILES = 200
MAX_LISTING = 500
EVIDENCE_MIN, EVIDENCE_DEFAULT, EVIDENCE_MAX = 1024, 262_144, 4 * 1024 * 1024
FILE_READ_DEFAULT, FILE_READ_MAX = 65_536, 1_048_576
LIVE_STATES = {"starting", "ready", "running"}


class InterlinkError(Exception):
    """A refusal or hold with a stable machine-readable code."""

    def __init__(self, code: str, message: str, status: str = "refused", **data: Any) -> None:
        super().__init__(message)
        self.code, self.message, self.status, self.data = code, message, status, data


@dataclass
class Run:
    """One prompt delivered to an instance."""

    id: str
    log: RunLog
    prompt_sha256: str
    timeout_s: float
    started: float = field(default_factory=time.time)
    finished: float | None = None
    cancelled: threading.Event = field(default_factory=threading.Event)
    processes: list[ManagedProcess] = field(default_factory=list)
    thread: threading.Thread | None = None

    def record(self) -> dict[str, Any]:
        """The run as stored in ``instance.json``."""
        return {
            "id": self.id,
            "state": self.log.state,
            "exit_code": self.log.exit_code,
            "started": self.started,
            "finished": self.finished,
            "timeout_s": self.timeout_s,
            "prompt_sha256": self.prompt_sha256,
            "processes": [{"pid": p.pid, "identity": p.identity} for p in self.processes],
            "detail": self.log.detail,
        }


@dataclass
class Instance:
    """A launched harness and its private workspace."""

    view: InstanceView
    adapter: HarnessAdapter
    label: str
    created: float
    redactor: Redactor
    seed: dict[str, Any]
    state: str = "starting"
    runs: dict[str, Run] = field(default_factory=dict)
    active_run: str | None = None
    host: dict[str, Any] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)

    @property
    def id(self) -> str:
        """The instance id."""
        return self.view.id

    @property
    def workspace(self) -> Workspace:
        """The instance's workspace on disk."""
        return self.view.workspace


class Engine:
    """Launches, drives and cleans up harness instances. Thread-safe."""

    def __init__(self, config: Config, state_root: Path | None = None) -> None:
        self.config = config
        self.root = (state_root or config.state_root).expanduser().resolve()
        refuse_protected(self.root, purpose="the Interlink state root")
        (self.root / "instances").mkdir(parents=True, exist_ok=True)
        (self.root / "exports").mkdir(exist_ok=True)
        self.ledger = Ledger(self.root / "ledger.sqlite3")
        self.server_id = str(uuid.uuid4())
        self.instances: dict[str, Instance] = {}
        self._lock = threading.RLock()
        self._running = 0
        self._closed = False
        self.recovered = self._recover_orphans()
        self.ledger.receipt(
            None, "server_started", {"server_id": self.server_id, "pid": os.getpid()}
        )

    # == helpers ==========================================================================

    def _idempotent(
        self,
        request_id: str | None,
        operation: str,
        body: dict[str, Any],
        instance_id: str | None,
        work: Any,
    ) -> dict[str, Any]:
        if request_id is None:
            return work()
        try:
            request_id = str(uuid.UUID(request_id))
        except ValueError as exc:
            raise InterlinkError("invalid_request_id", "request_id must be a UUID") from exc
        try:
            recorded = self.ledger.begin(request_id, operation, body, instance_id)
        except RequestCollision as exc:
            raise InterlinkError("request_collision", str(exc)) from exc
        if recorded.state == "finished":
            result = dict(recorded.result or {})
            if "__error__" in result:
                error = result["__error__"]
                raise InterlinkError(
                    error["code"], error["message"], error["status"], replayed=True
                )
            return {**result, "replayed": True}
        if recorded.state == "in_flight":
            raise InterlinkError(
                "unknown_outcome",
                "An earlier attempt with this request_id never recorded a result. Inspect the "
                "instance before deciding; Interlink will not replay it.",
                "held",
            )
        try:
            result = work()
        except InterlinkError as exc:
            self.ledger.finish(
                request_id,
                {"__error__": {"code": exc.code, "message": exc.message, "status": exc.status}},
            )
            raise
        self.ledger.finish(request_id, result)
        return result

    def _live(self, instance_id: str) -> Instance:
        with self._lock:
            instance = self.instances.get(instance_id)
        if instance is None:
            if (self.root / "instances" / instance_id / "instance.json").is_file():
                raise InterlinkError(
                    "not_owned",
                    "That instance belongs to another (or an earlier) Interlink server. "
                    "You can inspect it and export evidence, but not drive it.",
                )
            raise InterlinkError("unknown_instance", f"no instance {instance_id}")
        return instance

    def _persist(self, instance: Instance) -> None:
        atomic_write_json(instance.workspace.root / "instance.json", self._record(instance))

    def _record(self, instance: Instance) -> dict[str, Any]:
        return {
            "schema": "interlink-instance/1",
            "id": instance.id,
            "harness": instance.view.harness,
            "adapter": instance.adapter.options.adapter,
            "kind": instance.adapter.kind,
            "label": instance.label,
            "created": instance.created,
            "state": instance.state,
            "server_id": self.server_id,
            "server_pid": os.getpid(),
            "env_keys": sorted(instance.view.env),
            "secret_keys": sorted(
                k for k in instance.adapter.options.secrets if k in instance.view.env
            ),
            "session": instance.view.session,
            "seed": instance.seed,
            "host": instance.host,
            "runs": [run.record() for run in instance.runs.values()],
        }

    def _disk_record(self, instance_id: str) -> dict[str, Any]:
        try:
            uuid.UUID(instance_id)
        except ValueError as exc:
            raise InterlinkError("invalid_instance_id", "instance_id must be a UUID") from exc
        with self._lock:
            live = self.instances.get(instance_id)
        if live is not None:
            with live.lock:
                return self._record(live)
        path = self.root / "instances" / instance_id / "instance.json"
        if not path.is_file():
            raise InterlinkError("unknown_instance", f"no instance {instance_id}")
        return read_json(path)

    def _recover_orphans(self) -> list[dict[str, Any]]:
        """Mark instances whose server died; reap their processes only if provably ours."""
        recovered = []
        for path in sorted((self.root / "instances").glob("*/instance.json")):
            try:
                record = read_json(path)
            except (OSError, ValueError, SecurityError):
                continue
            if record.get("state") not in LIVE_STATES or pid_alive(
                int(record.get("server_pid", 0))
            ):
                continue
            reaped = []
            for run in record.get("runs", []):
                if run.get("state") not in TERMINAL_STATES:
                    run["state"] = "interrupted"
                for proc in run.get("processes", []):
                    outcome = reap_recorded(int(proc["pid"]), proc.get("identity"))
                    reaped.append({"pid": proc["pid"], "outcome": outcome})
            host = record.get("host") or {}
            if host.get("pid"):
                outcome = reap_recorded(int(host["pid"]), host.get("identity"))
                reaped.append({"pid": host["pid"], "outcome": outcome, "role": "host"})
            record["state"] = "orphaned"
            atomic_write_json(path, record)
            self.ledger.receipt(record["id"], "orphan_recovered", {"reaped": reaped})
            recovered.append({"instance_id": record["id"], "reaped": reaped})
        return recovered

    # == tools ============================================================================

    def harnesses(self, check: bool = True) -> dict[str, Any]:
        """Configured harnesses, with readiness checks when ``check`` is true."""
        items = []
        for adapter in self.config.harnesses.values():
            item = adapter.describe()
            if check:
                try:
                    item["doctor"] = adapter.doctor()
                except Exception as exc:  # doctor must never take the server down
                    item["doctor"] = {
                        "ok": False,
                        "checks": [{"name": "doctor", "ok": False, "detail": str(exc)}],
                    }
            items.append(item)
        return {"harnesses": items, "notes": self.config.notes}

    def launch(
        self,
        harness: str,
        *,
        project: str | None = None,
        files: dict[str, str] | None = None,
        label: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Create an instance: fresh workspace, optional project copy and seed files."""
        body = {"harness": harness, "project": project, "files": files, "label": label}
        return self._idempotent(
            request_id, "launch", body, None, partial(self._launch, harness, project, files, label)
        )

    def _launch(
        self, harness: str, project: str | None, files: dict[str, str] | None, label: str | None
    ) -> dict[str, Any]:
        if self._closed:
            raise InterlinkError("shutting_down", "server is shutting down", "held")
        adapter = self.config.harnesses.get(harness)
        if adapter is None:
            raise InterlinkError(
                "unknown_harness",
                f"no harness {harness!r}; available: {', '.join(sorted(self.config.harnesses))}",
            )
        if files and len(files) > MAX_SEED_FILES:
            raise InterlinkError("too_many_files", f"at most {MAX_SEED_FILES} seed files")
        with self._lock:
            live = sum(1 for i in self.instances.values() if i.state in LIVE_STATES)
            if live >= self.config.server.max_instances:
                raise InterlinkError(
                    "instance_limit",
                    f"{live} live instances (max {self.config.server.max_instances}); stop one first",
                    "held",
                )
            instance_id = str(uuid.uuid4())
            workspace = Workspace(self.root / "instances" / instance_id).create()
            placeholder = Instance(
                view=InstanceView(instance_id, harness, workspace, {}),
                adapter=adapter,
                label=(label or harness)[:120],
                created=time.time(),
                redactor=Redactor(),
                seed={},
            )
            self.instances[instance_id] = placeholder
        instance = placeholder
        try:
            seed: dict[str, Any] = {}
            if project:
                seed["project"] = workspace.seed_project(Path(project))
            if files:
                seed["files"] = workspace.seed_files(files)
            options = adapter.options
            redirects = (
                workspace.redirects()
                if options.isolate_home
                else {
                    k: v for k, v in workspace.redirects().items() if k in ("TMP", "TEMP", "TMPDIR")
                }
            )
            redirects.update(adapter.environment(workspace))
            redirects.update(
                INTERLINK_INSTANCE_ID=instance_id, INTERLINK_WORKSPACE=str(workspace.work)
            )
            env = build_environment(
                pass_env=options.pass_env,
                secrets=options.secrets,
                set_env=options.env,
                redirects=redirects,
            )
            instance.view.env = env
            instance.redactor = Redactor.for_environment(env, options.secrets)
            snapshot = workspace.snapshot()
            atomic_write_json(workspace.root / "seed-snapshot.json", snapshot)
            seed["files_total"] = len(snapshot)
            instance.seed = seed
            adapter.prepare(instance.view)
            instance.host = instance.redactor.scrub_value(adapter.start(instance.view) or {})
            instance.state = "ready"
        except SecurityError as exc:
            instance.state = "failed"
            self._persist(instance)
            raise InterlinkError("refused_by_policy", str(exc)) from exc
        except Exception as exc:
            instance.state = "failed"
            self._persist(instance)
            raise InterlinkError(
                "launch_failed",
                f"{type(exc).__name__}: {instance.redactor.scrub(str(exc))}",
                "failed",
            ) from exc
        self._persist(instance)
        self.ledger.receipt(
            instance_id,
            "launched",
            {"harness": harness, "adapter": options.adapter, "seed": seed, "env_keys": sorted(env)},
        )
        return {
            "instance_id": instance_id,
            "harness": harness,
            "state": instance.state,
            "workspace": str(workspace.work),
            "seed": seed,
            "host": instance.host,
            "isolation": "copy-of-project + redirected HOME/TMP + env allow-list (not an OS sandbox)"
            if options.isolate_home
            else "copy-of-project + env allow-list; HOME NOT isolated (isolate_home=false)",
        }

    def prompt(
        self,
        instance_id: str,
        prompt: str,
        *,
        timeout_s: float | None = None,
        wait_s: float = 0,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Start a run in the background and return its id (optionally waiting ``wait_s``)."""
        body = {
            "instance_id": instance_id,
            "prompt_sha256": sha256_text(prompt),
            "timeout_s": timeout_s,
        }
        result = self._idempotent(
            request_id,
            "prompt",
            body,
            instance_id,
            partial(self._prompt, instance_id, prompt, timeout_s),
        )
        if wait_s > 0 and not result.get("replayed"):
            with self._lock:
                live = self.instances.get(instance_id)
            if live is not None and result["run_id"] in live.runs:
                live.runs[result["run_id"]].log.wait_done(min(float(wait_s), 60.0))
            return self.observe(instance_id, result["run_id"], limit=128) | {
                "run_id": result["run_id"]
            }
        return result

    def _prompt(self, instance_id: str, prompt: str, timeout_s: float | None) -> dict[str, Any]:
        instance = self._live(instance_id)
        if not prompt.strip():
            raise InterlinkError("empty_prompt", "prompt is empty")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise InterlinkError("prompt_too_long", f"prompt exceeds {MAX_PROMPT_CHARS} characters")
        limit = self.config.server.max_run_timeout_s
        timeout = float(timeout_s or instance.adapter.options.timeout_s)
        if timeout <= 0 or timeout > limit:
            raise InterlinkError("invalid_timeout", f"timeout_s must be in (0, {limit}]")
        with instance.lock:
            if instance.active_run:
                raise InterlinkError(
                    "run_active",
                    f"run {instance.active_run} is still active; observe it or cancel it first",
                    "held",
                    run_id=instance.active_run,
                )
            if instance.state not in ("ready",):
                raise InterlinkError(
                    "instance_not_ready",
                    f"instance is {instance.state}",
                    "held",
                    state=instance.state,
                )
            with self._lock:
                if self._running >= self.config.server.max_concurrent_runs:
                    raise InterlinkError(
                        "concurrency_limit",
                        f"{self._running} runs active (max {self.config.server.max_concurrent_runs})",
                        "held",
                    )
                self._running += 1
            run_id = str(uuid.uuid4())
            run_dir = instance.workspace.run_dir(run_id)
            prompt_file = run_dir / "prompt.txt"
            prompt_file.write_bytes(prompt.encode("utf-8"))
            log = RunLog(run_dir / "events.jsonl", instance.redactor)
            run = Run(run_id, log, sha256_text(prompt), timeout)
            instance.runs[run_id] = run
            instance.active_run = run_id
            instance.state = "running"
            log.set_state("running")
            self._persist(instance)
            ctx = RunContext(
                instance=instance.view,
                run_id=run_id,
                prompt=prompt,
                prompt_file=prompt_file,
                run_dir=run_dir,
                log=log,
                deadline=time.monotonic() + timeout,
                cancelled=run.cancelled,
                spawn=partial(self._spawn, instance, run),
            )
            run.thread = threading.Thread(
                target=self._execute,
                args=(instance, run, ctx),
                daemon=True,
                name=f"run-{run_id[:8]}",
            )
            self.ledger.receipt(
                instance_id,
                "prompt_submitted",
                {"run_id": run_id, "prompt_sha256": run.prompt_sha256},
            )
            run.thread.start()
        return {"run_id": run_id, "state": "running", "timeout_s": timeout}

    def _spawn(
        self,
        instance: Instance,
        run: Run,
        argv: list[str],
        *,
        stdout_sink: Any,
        stdin_text: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> ManagedProcess:
        if run.cancelled.is_set():
            raise InterlinkError("cancelled", "run was cancelled before spawn", "cancelled")
        env = {**instance.view.env, **(extra_env or {})}
        run_dir = instance.workspace.run_dir(run.id)
        process = ManagedProcess(
            argv,
            cwd=instance.workspace.work,
            env=env,
            stdout_sink=stdout_sink,
            stderr_sink=lambda line: run.log.emit("stderr", text=line) if line.strip() else None,
            stdin_text=stdin_text,
            stdout_log=run_dir / "stdout.log",
            stderr_log=run_dir / "stderr.log",
            scrub=instance.redactor.scrub if instance.redactor else None,
        )
        run.processes.append(process)
        with instance.lock:
            self._persist(instance)
        return process

    def _execute(self, instance: Instance, run: Run, ctx: RunContext) -> None:
        try:
            outcome = instance.adapter.run(ctx)
        except InterlinkError as exc:
            outcome = RunOutcome(
                "cancelled" if exc.code == "cancelled" else "error", detail={"code": exc.code}
            )
        except Exception as exc:
            outcome = RunOutcome(
                "error",
                detail={
                    "exception": type(exc).__name__,
                    "message": instance.redactor.scrub(str(exc))[:500],
                },
            )
        finally:
            for process in run.processes:
                if process.alive:
                    process.kill_tree()
        if outcome.state not in TERMINAL_STATES:
            outcome = RunOutcome("error", outcome.exit_code, {"invalid_state": outcome.state})
        run.finished = time.time()
        run.log.exit_code = outcome.exit_code
        run.log.emit(
            "interlink",
            event="finished",
            state=outcome.state,
            exit_code=outcome.exit_code,
            duration_s=round(run.finished - run.started, 3),
        )
        with instance.lock:
            instance.active_run = None
            if instance.state == "running":
                instance.state = "ready"
            with self._lock:
                self._running -= 1
            run.log.set_state(outcome.state, **outcome.detail)
            self._persist(instance)
        self.ledger.receipt(
            instance.id,
            "run_finished",
            {
                "run_id": run.id,
                "state": outcome.state,
                "exit_code": outcome.exit_code,
                "events": run.log.counts(),
            },
        )

    def observe(
        self,
        instance_id: str,
        run_id: str | None = None,
        *,
        after: int = 0,
        limit: int = 64,
        wait_s: float = 0,
    ) -> dict[str, Any]:
        """Page through a run's events from ``after``, long-polling up to ``wait_s``."""
        limit = max(1, min(int(limit), 256))
        wait_s = max(0.0, min(float(wait_s), 60.0))
        record = self._disk_record(instance_id)
        with self._lock:
            live = self.instances.get(instance_id)
        runs = record.get("runs", [])
        if not runs:
            return {"instance_id": instance_id, "state": record["state"], "runs": 0, "events": []}
        run_id = run_id or runs[-1]["id"]
        if live is not None and run_id in live.runs:
            run = live.runs[run_id]
            window = run.log.read(after, limit, wait_s)
            if window["done"]:
                window["final_text"] = run.log.text()[:8000]
        else:
            if not any(r["id"] == run_id for r in runs):
                raise InterlinkError("unknown_run", f"no run {run_id} on this instance")
            path = self.root / "instances" / instance_id / "runs" / run_id / "events.jsonl"
            events = []
            if path.is_file():
                with open(path, encoding="utf-8") as handle:
                    events = [json.loads(line) for line in handle if line.strip()]
            run_record = next(r for r in runs if r["id"] == run_id)
            chunk = events[after : after + limit]
            window = {
                "state": run_record["state"],
                "done": run_record["state"] in TERMINAL_STATES or record["state"] == "orphaned",
                "exit_code": run_record.get("exit_code"),
                "events": chunk,
                "next_cursor": chunk[-1]["seq"] if chunk else after,
                "more": len(events) > after + len(chunk),
                "dropped": 0,
                "detail": run_record.get("detail", {}),
                "source": "disk",
            }
        return {
            "instance_id": instance_id,
            "run_id": run_id,
            "instance_state": record["state"],
            **window,
        }

    def cancel(
        self, instance_id: str, run_id: str | None = None, *, request_id: str | None = None
    ) -> dict[str, Any]:
        """Kill the running prompt's whole process tree."""
        body = {"instance_id": instance_id, "run_id": run_id}
        return self._idempotent(
            request_id, "cancel", body, instance_id, partial(self._cancel, instance_id, run_id)
        )

    def _cancel(self, instance_id: str, run_id: str | None) -> dict[str, Any]:
        instance = self._live(instance_id)
        run_id = run_id or instance.active_run
        if not run_id or run_id not in instance.runs:
            return {"run_id": run_id, "state": "nothing_to_cancel"}
        run = instance.runs[run_id]
        if run.log.done:
            return {"run_id": run_id, "state": run.log.state, "effect": "already_finished"}
        run.cancelled.set()
        settled = run.log.wait_done(15)
        self.ledger.receipt(instance_id, "cancel_requested", {"run_id": run_id, "settled": settled})
        return {
            "run_id": run_id,
            "state": run.log.state,
            "settled": settled,
            "effects_reversed": False,
            "note": "Cancel stops the harness; it does not undo changes already made in the workspace.",
        }

    def stop(
        self, instance_id: str, *, discard: bool = False, request_id: str | None = None
    ) -> dict[str, Any]:
        """Stop an instance; ``discard`` also deletes its workspace."""
        body = {"instance_id": instance_id, "discard": discard}
        return self._idempotent(
            request_id, "stop", body, instance_id, partial(self._stop, instance_id, discard)
        )

    def _stop(self, instance_id: str, discard: bool) -> dict[str, Any]:
        with self._lock:
            instance = self.instances.get(instance_id)
        if instance is None:
            record = self._disk_record(instance_id)
            if record["state"] in LIVE_STATES and pid_alive(int(record.get("server_pid", 0))):
                raise InterlinkError("not_owned", "instance is owned by another running server")
            if discard:
                Workspace(self.root / "instances" / instance_id).destroy(self.root)
            self.ledger.receipt(instance_id, "stopped", {"discarded": discard, "owner": "other"})
            return {
                "instance_id": instance_id,
                "state": "discarded" if discard else record["state"],
            }
        detail: dict[str, Any] = {}
        if instance.active_run:
            detail["cancel"] = self._cancel(instance_id, instance.active_run)
        with instance.lock:
            if instance.state in LIVE_STATES or instance.state == "failed":
                try:
                    detail["harness"] = instance.adapter.stop(instance.view)
                except Exception as exc:
                    detail["harness"] = {"error": f"{type(exc).__name__}: {exc}"}
                instance.state = "stopped"
            self._persist(instance)
        evidence_hint = None
        if discard:
            instance.workspace.destroy(self.root)
            with self._lock:
                self.instances.pop(instance_id, None)
        else:
            evidence_hint = "workspace kept; call interlink_evidence or `interlink cleanup` later"
        self.ledger.receipt(instance_id, "stopped", {"discarded": discard})
        return {
            "instance_id": instance_id,
            "state": "discarded" if discard else "stopped",
            "detail": detail,
            "note": evidence_hint,
        }

    def inspect(self, instance_id: str | None = None) -> dict[str, Any]:
        """One instance in detail, or a summary of all of them."""
        if instance_id is None:
            items = []
            for path in sorted((self.root / "instances").glob("*/instance.json")):
                try:
                    record = self._disk_record(path.parent.name)
                except (InterlinkError, OSError, ValueError):
                    continue
                items.append(
                    {
                        "instance_id": record["id"],
                        "harness": record["harness"],
                        "label": record.get("label"),
                        "state": record["state"],
                        "runs": len(record.get("runs", [])),
                        "created": record["created"],
                        "owned_by_this_server": record["id"] in self.instances,
                    }
                )
            items.sort(key=lambda item: item["created"], reverse=True)
            return {
                "server": {
                    "server_id": self.server_id,
                    "version": __version__,
                    "state_root": str(self.root),
                    "harnesses": sorted(self.config.harnesses),
                    "running": self._running,
                    "limits": self.config.server.model_dump(),
                    "recovered_orphans": len(self.recovered),
                },
                "instances": items[:200],
                "unresolved_requests": self.ledger.unresolved()[:50],
            }
        record = self._disk_record(instance_id)
        workspace = Workspace(self.root / "instances" / instance_id)
        changes = self._changes(workspace)
        return {
            **{
                k: record[k]
                for k in ("id", "harness", "adapter", "kind", "label", "created", "state")
            },
            "workspace": str(workspace.work),
            "owned_by_this_server": instance_id in self.instances,
            "session": record.get("session", {}),
            "host": record.get("host", {}),
            "env_keys": record.get("env_keys", []),
            "runs": [
                {
                    k: r.get(k)
                    for k in ("id", "state", "exit_code", "started", "finished", "timeout_s")
                }
                for r in record.get("runs", [])
            ],
            "changes": {k: v[:100] for k, v in changes.items()},
        }

    def _changes(self, workspace: Workspace) -> dict[str, list[str]]:
        seed_path = workspace.root / "seed-snapshot.json"
        before = read_json(seed_path, 64 * 1024 * 1024) if seed_path.is_file() else {}
        return diff_snapshots(before, workspace.snapshot())

    def files(
        self, instance_id: str, path: str | None = None, *, max_bytes: int = FILE_READ_DEFAULT
    ) -> dict[str, Any]:
        """List changed files against the seed snapshot, or read one confined file."""
        self._disk_record(instance_id)
        workspace = Workspace(self.root / "instances" / instance_id)
        max_bytes = max(1, min(int(max_bytes), FILE_READ_MAX))
        try:
            target = confine(path or ".", workspace.work, must_exist=True)
        except SecurityError as exc:
            raise InterlinkError("path_refused", str(exc)) from exc
        if target.is_dir():
            seed_path = workspace.root / "seed-snapshot.json"
            before = read_json(seed_path, 64 * 1024 * 1024) if seed_path.is_file() else {}
            entries = []
            for child in sorted(target.rglob("*")):
                if len(entries) >= MAX_LISTING:
                    break
                if is_link(child) or not child.is_file():
                    continue
                rel = child.relative_to(workspace.work).as_posix()
                digest = sha256_file(child, 64 * 1024 * 1024)
                status = (
                    "added"
                    if rel not in before
                    else ("modified" if before[rel].get("sha256") != digest else "unchanged")
                )
                entries.append(
                    {"path": rel, "size": child.stat().st_size, "sha256": digest, "status": status}
                )
            return {
                "instance_id": instance_id,
                "path": target.relative_to(workspace.work).as_posix() or ".",
                "files": entries,
                "truncated": len(entries) >= MAX_LISTING,
                "deleted": [p for p in before if not (workspace.work / p).exists()][:MAX_LISTING],
            }
        size = target.stat().st_size
        with open(target, "rb") as handle:
            raw = handle.read(max_bytes)
        result: dict[str, Any] = {
            "instance_id": instance_id,
            "path": target.relative_to(workspace.work).as_posix(),
            "size": size,
            "sha256": sha256_file(target, 64 * 1024 * 1024),
            "truncated": size > max_bytes,
        }
        try:
            result["text"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            result["binary"] = True
        return result

    def evidence(
        self,
        instance_id: str,
        *,
        include_transcript: bool = False,
        max_bytes: int = EVIDENCE_DEFAULT,
    ) -> dict[str, Any]:
        """Export a redacted, hash-chained evidence bundle and record its digest."""
        max_bytes = max(EVIDENCE_MIN, min(int(max_bytes), EVIDENCE_MAX))
        record = self._disk_record(instance_id)
        workspace = Workspace(self.root / "instances" / instance_id)
        after = workspace.snapshot()
        seed_path = workspace.root / "seed-snapshot.json"
        before = read_json(seed_path, 64 * 1024 * 1024) if seed_path.is_file() else {}
        diff = diff_snapshots(before, after)
        runs = []
        for run in record.get("runs", []):
            path = workspace.runs / run["id"] / "events.jsonl"
            events = []
            if path.is_file():
                with open(path, encoding="utf-8") as handle:
                    events = [json.loads(line) for line in handle if line.strip()]
            counts: dict[str, int] = {}
            for event in events:
                counts[event["type"]] = counts.get(event["type"], 0) + 1
            item = {
                "run_id": run["id"],
                "state": run["state"],
                "exit_code": run.get("exit_code"),
                "started": run.get("started"),
                "finished": run.get("finished"),
                "timeout_s": run.get("timeout_s"),
                "prompt_sha256": run.get("prompt_sha256"),
                "event_counts": counts,
                "events_sha256": sha256_file(path) if path.is_file() else None,
                "detail": run.get("detail", {}),
            }
            if include_transcript:
                item["transcript"] = events
            runs.append(item)
        bundle: dict[str, Any] = {
            "schema": "interlink-evidence/1",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "interlink": {
                "version": __version__,
                "platform": platform_label(),
                "server_id": self.server_id,
            },
            "instance": {
                k: record.get(k)
                for k in (
                    "id",
                    "harness",
                    "adapter",
                    "kind",
                    "label",
                    "created",
                    "state",
                    "env_keys",
                    "secret_keys",
                    "seed",
                    "host",
                )
            },
            "runs": runs,
            "workspace": {
                "files_total": len(after),
                "added": [{"path": p, **after[p]} for p in diff["added"]],
                "modified": [
                    {"path": p, "before": before[p]["sha256"], "after": after[p]["sha256"]}
                    for p in diff["modified"]
                ],
                "deleted": diff["deleted"],
            },
            "receipts": [
                {"sequence": r["sequence"], "at": r["at"], "kind": r["kind"], "hash": r["hash"]}
                for r in self.ledger.receipts(instance_id)
            ],
            "receipt_chain": self.ledger.verify_chain(),
            "unresolved_requests": self.ledger.unresolved(instance_id),
            "omitted": [
                "prompt text (sha256 only)",
                "raw stdout/stderr logs",
                "environment values",
            ],
            "truncated": [],
        }
        bundle = _fit(bundle, max_bytes)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = self.root / "exports" / f"{instance_id}-{stamp}-{uuid.uuid4().hex[:6]}.json"
        atomic_write_json(out, bundle)
        digest = sha256_file(out)
        self.ledger.receipt(
            instance_id, "evidence_exported", {"sha256": digest, "bytes": out.stat().st_size}
        )
        return {
            "path": str(out),
            "sha256": digest,
            "bytes": out.stat().st_size,
            "summary": {
                "runs": [
                    {"run_id": r["run_id"], "state": r["state"], "exit_code": r["exit_code"]}
                    for r in runs
                ],
                "added": len(diff["added"]),
                "modified": len(diff["modified"]),
                "deleted": len(diff["deleted"]),
                "receipt_chain_valid": bundle["receipt_chain"]["valid"],
                "truncated": bundle["truncated"],
            },
        }

    # == lifecycle ========================================================================

    def cleanup(self, *, include_orphaned: bool = True, older_than_s: float = 0) -> dict[str, Any]:
        """Delete workspaces of stopped (and optionally orphaned) instances."""
        removed = []
        now = time.time()
        for path in sorted((self.root / "instances").glob("*/instance.json")):
            instance_id = path.parent.name
            if instance_id in self.instances and self.instances[instance_id].state in LIVE_STATES:
                continue
            try:
                record = read_json(path)
            except (OSError, ValueError, SecurityError):
                continue
            states = {"stopped", "failed"} | ({"orphaned"} if include_orphaned else set())
            if (
                record.get("state") not in states
                or now - float(record.get("created", now)) < older_than_s
            ):
                continue
            Workspace(path.parent).destroy(self.root)
            self.instances.pop(instance_id, None)
            removed.append(instance_id)
        if removed:
            self.ledger.receipt(None, "cleanup", {"removed": removed})
        return {"removed": removed}

    def shutdown(self) -> None:
        """Stop every live instance this server owns. Safe to call twice."""
        if self._closed:
            return
        self._closed = True
        for instance_id, instance in list(self.instances.items()):
            if instance.state in LIVE_STATES:
                with contextlib.suppress(Exception):
                    self._stop(instance_id, discard=False)
        self.ledger.receipt(None, "server_stopped", {"server_id": self.server_id})
        self.ledger.close()


def _fit(bundle: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Shrink a bundle to the byte budget, recording exactly what was dropped."""

    def size() -> int:
        return len(canonical(bundle).encode("utf-8")) + 4096  # headroom for pretty-printing

    if size() <= max_bytes:
        return bundle
    for run in bundle["runs"]:
        if run.pop("transcript", None) is not None and "transcripts" not in bundle["truncated"]:
            bundle["truncated"].append("transcripts")
    if size() <= max_bytes:
        return bundle
    for key in ("receipts", "added", "modified", "deleted"):
        container = bundle if key == "receipts" else bundle["workspace"]
        while container[key] and size() > max_bytes:
            keep = len(container[key]) // 2
            container[key] = container[key][:keep]
            if f"{key}_partial" not in bundle["truncated"]:
                bundle["truncated"].append(f"{key}_partial")
    for run in bundle["runs"]:
        if size() > max_bytes:
            run["detail"] = {}
    return bundle
