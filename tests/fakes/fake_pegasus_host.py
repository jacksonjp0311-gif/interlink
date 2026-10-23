"""A faithful-enough fake of the PEGASUS Interlink host (``pegasus-interlink/1``).

It enforces what the real host enforces - boot schema, manifest digest, token,
generation, deadline window, controller lease for mutations, one active task,
inference gating - and simulates turns. It listens on the Unix socket named by
``PEGASUS_INTERLINK_SOCKET`` (the POSIX test seam; the real host uses a named pipe).

Prompt keywords: ``SLOW`` streams until cancelled, ``FAIL`` ends in ``failed``.
Every accepted operation (never the token) is appended to ``<profile>/fake-ops.jsonl``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

EXCLUDED_DIRS = {
    "data",
    "runtime",
    "models",
    "node_modules",
    ".venv",
    "target",
    "dist",
    ".git",
    "__pycache__",
    "bin",
    ".pytest_cache",
    "playwright-report",
    "test-results",
}
READ_ONLY = {"inspect", "observe", "reconcile", "acquire"}


def inventory(root: Path) -> list[list[str]]:
    files = []
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRS]
        for name in names:
            if name.lower() == ".git" or name.lower().endswith((".pyc", ".pyo", ".tsbuildinfo")):
                continue
            path = Path(current) / name
            files.append(
                [path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()]
            )
    return sorted(files)


class Host:
    def __init__(self, boot: dict) -> None:
        self.boot = boot
        self.lock = threading.Lock()
        self.lease: dict | None = None
        self.sessions: dict[str, dict] = {}
        self.tasks: dict[str, dict] = {}
        self.stop = threading.Event()
        self.ops = Path(boot["profile_dir"]) / "fake-ops.jsonl"

    def reply(self, req: dict, status: str, data=None, code=None, message="") -> dict:
        body = {
            "schema": "pegasus-interlink/1",
            "instance_id": self.boot["instance_id"],
            "generation": self.boot["generation"],
            "request_id": req.get("request_id"),
            "status": status,
        }
        if code:
            body["error"] = {"code": code, "message": message, "retryable": status == "held"}
        else:
            body["data"] = data if data is not None else {}
        return body

    def handle(self, req: dict) -> dict:
        now = time.time() * 1000
        if req.get("schema") != "pegasus-interlink/1":
            return self.reply(req, "refused", code="schema")
        if (
            req.get("instance_id") != self.boot["instance_id"]
            or req.get("generation") != self.boot["generation"]
        ):
            return self.reply(req, "refused", code="identity")
        if not hmac.compare_digest(str(req.get("token")), self.boot["token"]):
            return self.reply(req, "refused", code="unauthorized")
        if not (now <= req.get("deadline_ms", 0) <= now + 60_000):
            return self.reply(req, "refused", code="deadline_window")
        op, args = req.get("operation"), req.get("args") or {}
        with self.lock:
            if op not in READ_ONLY:
                lease = self.lease
                if (
                    not lease
                    or lease["id"] != req.get("lease_id")
                    or lease["controller"] != req.get("controller_id")
                    or lease["expires"] < now
                ):
                    return self.reply(req, "refused", code="lease_required")
            with open(self.ops, "a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "op": op,
                            "args": {k: v for k, v in args.items() if k != "prompt"},
                            "prompt_chars": len(args.get("prompt", "")),
                        }
                    )
                    + "\n"
                )
            return getattr(self, f"op_{op}", self.op_unknown)(req, args, now)

    def op_unknown(self, req, args, now):
        return self.reply(req, "refused", code="unknown_operation")

    def op_inspect(self, req, args, now):
        return self.reply(
            req,
            "complete",
            {"instance_id": self.boot["instance_id"], "active_tasks": self.active()},
        )

    def op_acquire(self, req, args, now):
        ttl = args.get("ttl_ms")
        if not isinstance(ttl, int) or not 1000 <= ttl <= 60_000:
            return self.reply(req, "refused", code="invalid_lease_ttl")
        if (
            self.lease
            and self.lease["expires"] > now
            and self.lease["controller"] != req["controller_id"]
        ):
            return self.reply(req, "held", code="lease_held")
        self.lease = {
            "id": str(uuid.uuid4()),
            "controller": req["controller_id"],
            "expires": now + ttl,
        }
        return self.reply(
            req,
            "complete",
            {"lease_id": self.lease["id"], "expires_ms": int(self.lease["expires"])},
        )

    def op_renew(self, req, args, now):
        self.lease["expires"] = now + int(args["ttl_ms"])
        return self.reply(
            req,
            "complete",
            {"lease_id": self.lease["id"], "expires_ms": int(self.lease["expires"])},
        )

    def op_session(self, req, args, now):
        if args.get("action") != "create" or len(args.get("title", "")) > 120:
            return self.reply(req, "refused", code="invalid_session")
        session = str(uuid.uuid4())
        self.sessions[session] = {"messages": []}
        return self.reply(req, "complete", {"session_id": session})

    def active(self) -> int:
        return sum(
            1
            for t in self.tasks.values()
            if t["state"] not in ("complete", "failed", "stopped", "interrupted")
        )

    def op_prompt(self, req, args, now):
        if not self.boot["inference_enabled"] or not self.boot.get("model"):
            return self.reply(req, "refused", code="inference_disabled")
        if args.get("session_id") not in self.sessions:
            return self.reply(req, "refused", code="unknown_session")
        if self.active():
            return self.reply(req, "held", code="task_active")
        prompt = args["prompt"]
        if not 1 <= len(prompt) <= 32_000:
            return self.reply(req, "refused", code="invalid_prompt")
        run_id = req["request_id"]
        task = {"state": "running", "events": [], "cancel": False, "session": args["session_id"]}
        self.tasks[run_id] = task
        threading.Thread(target=self.simulate, args=(run_id, prompt), daemon=True).start()
        return self.reply(
            req,
            "complete",
            {"session_id": args["session_id"], "run_id": run_id, "state": "submission_scheduled"},
        )

    def simulate(self, run_id: str, prompt: str) -> None:
        task = self.tasks[run_id]

        def chunk(kind, text):
            with self.lock:
                task["events"].append(
                    {"seq": len(task["events"]) + 1, "chunk": {"kind": kind, "text": text}}
                )

        chunk("public_event", "thinking")
        if "SLOW" in prompt:
            for _ in range(600):
                if task["cancel"]:
                    break
                chunk("text", ".")
                time.sleep(0.05)
            with self.lock:
                task["state"] = "stopped" if task["cancel"] else "complete"
            return
        answer = f"PEGASUS heard {len(prompt)} chars"
        for word in answer.split(" "):
            chunk("text", word + " ")
            time.sleep(0.01)
        with self.lock:
            self.sessions[task["session"]]["messages"] += [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": answer},
            ]
            task["state"] = "failed" if "FAIL" in prompt else "complete"

    def op_observe(self, req, args, now):
        task = self.tasks.get(args.get("run_id"))
        if task is None:
            return self.reply(req, "refused", code="run_unavailable")
        after, limit = int(args.get("after_cursor", 0)), int(args.get("limit", 64))
        events = task["events"][after : after + limit]
        return self.reply(
            req,
            "complete",
            {
                "snapshot": {
                    "state": task["state"],
                    "chatId": task["session"],
                    "events": len(task["events"]),
                },
                "events": events,
                "next_cursor": events[-1]["seq"] if events else after,
                "messages": self.sessions[task["session"]]["messages"],
            },
        )

    def op_control(self, req, args, now):
        task = self.tasks.get(args.get("run_id"))
        if task is None or args.get("action") != "cancel":
            return self.reply(req, "refused", code="invalid_control")
        task["cancel"] = True
        return self.reply(req, "complete", {"state": "cancel_requested"})

    def op_shutdown(self, req, args, now):
        if self.active():
            return self.reply(req, "held", code="tasks_active")
        self.stop.set()
        return self.reply(req, "complete", {"state": "shutting_down"})


def main() -> int:
    boot_path = Path(os.environ["PEGASUS_INTERLINK_BOOT"])
    boot = json.loads(boot_path.read_text(encoding="utf-8"))
    assert boot["schema"] == "pegasus-interlink-boot/1"
    profile = Path(boot["profile_dir"])
    manifest = json.loads(Path(boot["source_manifest_path"]).read_text(encoding="utf-8"))
    files = inventory(Path(boot["repair_root"]))
    digest = hashlib.sha256(
        json.dumps(files, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if digest != boot["source_sha256"] or manifest["source_sha256"] != digest:
        print("source digest mismatch", file=sys.stderr)
        return 3
    if Path(os.environ["PEGASUS_DATA_DIR"]).resolve() != (profile / "data").resolve():
        print("data dir not redirected", file=sys.stderr)
        return 4
    for name in os.environ:
        if name.endswith(("_API_KEY", "_TOKEN", "_SECRET")):
            print(f"secret-looking variable leaked: {name}", file=sys.stderr)
            return 5
    host = Host(boot)
    path = os.environ["PEGASUS_INTERLINK_SOCKET"]
    if os.path.exists(path):
        os.unlink(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, 0o600)
    server.listen(16)
    server.settimeout(0.2)
    while not host.stop.is_set():
        try:
            conn, _ = server.accept()
        except TimeoutError:
            continue
        with conn:
            data = b""
            while b"\n" not in data:
                part = conn.recv(65536)
                if not part:
                    break
                data += part
            try:
                req = json.loads(data.split(b"\n", 1)[0])
                reply = host.handle(req)
            except Exception as exc:  # malformed request
                reply = {"status": "refused", "error": {"code": "malformed", "message": str(exc)}}
            conn.sendall((json.dumps(reply) + "\n").encode())
    server.close()
    os.unlink(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
