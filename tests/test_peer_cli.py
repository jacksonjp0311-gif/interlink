"""`interlink peer ...` / `interlink share` end to end, as two people would use them."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from interlink.cli import main
from interlink.peer.cli import _save_files
from interlink.server import PEER_TOOL_NAMES, TOOL_NAMES

CONFIG = '[server]\nauto_detect = false\n\n[harness.mock]\nadapter = "mock"\n'


# Generous: a cold macOS/Windows CI runner can take many seconds to import cryptography
# and the MCP SDK in a fresh interpreter. Real hangs still fail, with the host's output.
STARTUP_TIMEOUT = 90.0
TASK_TIMEOUT = 60.0


class _Lines:
    """Collects a subprocess's output lines on a background thread."""

    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.lines: list[str] = []
        self.cond = threading.Condition()
        self.thread = threading.Thread(target=self._pump, args=(proc,), daemon=True)
        self.thread.start()

    def _pump(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            with self.cond:
                self.lines.append(line)
                self.cond.notify_all()
        with self.cond:
            self.lines.append("")  # EOF marker
            self.cond.notify_all()


_READERS: dict[int, _Lines] = {}


def share_output(proc: subprocess.Popen[str]) -> str:
    reader = _READERS.get(proc.pid)
    return "".join(reader.lines) if reader else ""


def wait_for_line(proc: subprocess.Popen[str], needle: str, timeout: float) -> None:
    """Block until ``proc`` prints ``needle``; fail fast (with its output) if it exits."""
    reader = _READERS.setdefault(proc.pid, _Lines(proc))
    deadline = time.monotonic() + timeout
    with reader.cond:
        while not any(needle in line for line in reader.lines):
            assert "" not in reader.lines, f"process exited early:\n{''.join(reader.lines)}"
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"no {needle!r} after {timeout:g}s:\n{''.join(reader.lines)}"
            reader.cond.wait(min(remaining, 1.0))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Person:
    def __init__(self, root: Path, name: str, monkeypatch: pytest.MonkeyPatch) -> None:
        self.env = {
            "INTERLINK_PEER_HOME": str(root / f"{name}-home"),
            "INTERLINK_STATE": str(root / f"{name}-state"),
        }
        self.monkeypatch = monkeypatch

    def __call__(self, *argv: str) -> int:
        for key, value in self.env.items():
            self.monkeypatch.setenv(key, value)
        return main(list(argv))

    def json(self, capsys: pytest.CaptureFixture[str], *argv: str) -> object:
        capsys.readouterr()
        assert self(*argv) == 0
        return json.loads(capsys.readouterr().out)


def test_pair_share_send_approve_revoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob = Person(tmp_path, "alice", monkeypatch), Person(tmp_path, "bob", monkeypatch)
    config = tmp_path / "bob.toml"
    config.write_text(CONFIG)
    a_id = alice.json(capsys, "peer", "id", "--json")
    b_id = bob.json(capsys, "peer", "id", "--json")
    assert a_id["fingerprint"] != b_id["fingerprint"]

    port = free_port()
    assert bob("peer", "add", "alice", a_id["invite"]) == 0
    assert "can't run anything" in capsys.readouterr().out
    assert bob("peer", "allow", "alice", "mock") == 0
    assert bob("peer", "add", "alice", a_id["invite"]) == 2  # duplicate
    assert bob("peer", "add", "me", b_id["invite"]) == 2  # own code
    assert bob("peer", "add", "typo", a_id["invite"][:-3] + "AAA") == 2
    policy = bob.json(capsys, "peer", "policy", "alice", "--max-timeout", "60")
    assert policy["max_timeout_s"] == 60 and policy["harnesses"] == ["mock"]
    assert bob("peer", "policy", "alice", "--max-concurrent", "0") == 2
    assert alice("peer", "add", "bob", b_id["invite"], "--url", f"http://127.0.0.1:{port}") == 0
    peers = bob.json(capsys, "peer", "list", "--json")
    assert [p["name"] for p in peers] == ["alice"]

    share = subprocess.Popen(
        [sys.executable, "-m", "interlink", "share", "--config", str(config), "--port", str(port)],
        env={**os.environ, **bob.env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_line(share, "Interlink is sharing on", timeout=STARTUP_TIMEOUT)

        ping = alice.json(capsys, "peer", "ping", "bob", "--json")
        assert ping["harnesses"] == ["mock"] and ping["host"] == b_id["fingerprint"]
        capsys.readouterr()
        assert alice("peer", "send", "bob", "mock", "say hi\nwrite r.txt ok", "--no-wait") == 0
        task_id = capsys.readouterr().err.split()[2]
        pending = bob.json(capsys, "peer", "pending", "--json")
        assert [p["task_id"] for p in pending] == [task_id]
        assert bob("peer", "approve", task_id) == 0
        deadline = time.monotonic() + TASK_TIMEOUT
        while (
            state := alice.json(capsys, "peer", "status", "bob", task_id)["state"]
        ) != "complete":
            assert state not in ("failed", "error", "denied", "expired", "cancelled"), state
            assert time.monotonic() < deadline, (
                f"task still {state!r}; host said:\n{share_output(share)}"
            )
            time.sleep(0.2)
        out = tmp_path / "out"
        capsys.readouterr()
        assert alice("peer", "result", "bob", task_id, "--out", str(out)) == 0
        assert "signature OK" in capsys.readouterr().out
        assert (out / "r.txt").read_text().strip() == "ok"

        assert bob("peer", "deny", "00000000-0000-4000-8000-000000000000") == 2
        assert bob("peer", "revoke", "alice") == 0
        capsys.readouterr()
        assert alice("peer", "send", "bob", "mock", "hi", "--no-wait") == 2
        assert "revoked" in capsys.readouterr().err
        assert bob.json(capsys, "peer", "audit", "--verify")["valid"]
        assert alice.json(capsys, "peer", "audit", "--client", "--verify")["valid"]
        assert bob("peer", "audit") == 0
        assert bob("peer", "remove", "alice") == 0
    finally:
        share.terminate()
        share.wait(10)


def test_audit_verify_fails_on_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from interlink.peer.store import AuditLog

    bob = Person(tmp_path, "bob", monkeypatch)
    log_path = tmp_path / "bob-state" / "peer" / "audit.jsonl"
    log = AuditLog(log_path)
    log.append("a")
    log.append("b")
    log_path.write_bytes(log_path.read_bytes().replace(b'"a"', b'"z"'))
    assert bob("peer", "audit", "--verify") == 1


def test_keys_inside_state_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTERLINK_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("INTERLINK_PEER_HOME", str(tmp_path / "state" / "peer" / "keys"))
    assert main(["peer", "id"]) == 2
    assert not (tmp_path / "state" / "peer" / "keys").exists()


def test_non_loopback_share_without_tls_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bob = Person(tmp_path, "bob", monkeypatch)
    config = tmp_path / "bob.toml"
    config.write_text(CONFIG)
    assert bob("share", "--config", str(config), "--bind", "0.0.0.0", "--port", "0") == 2
    assert "without TLS" in capsys.readouterr().err


def test_saving_returned_files_never_escapes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    statement = {
        "files": [
            {"path": "ok/a.txt", "text": "fine"},
            {"path": "../escape.txt", "text": "bad"},
            {"path": "/tmp/abs.txt", "text": "bad"},
            {"path": "big.bin", "text": None},
        ]
    }
    written = _save_files(statement, str(tmp_path / "out"))
    assert written == ["ok/a.txt"]
    assert not (tmp_path / "escape.txt").exists()
    assert capsys.readouterr().err.count("skipped unsafe path") == 2


def test_mcp_peer_tools_are_opt_in(tmp_path: Path) -> None:
    config = tmp_path / "interlink.toml"
    config.write_text("[server]\nauto_detect = false\n")
    env = {
        **os.environ,
        "INTERLINK_PEER_HOME": str(tmp_path / "home"),
        "INTERLINK_STATE": str(tmp_path / "state"),
    }

    async def tools(*extra: str) -> tuple[list[str], dict | None]:
        args = ["-m", "interlink", "serve", "--config", str(config), *extra]
        params = StdioServerParameters(command=sys.executable, args=args, env=env)
        async with Client(params, read_timeout_seconds=60) as client:
            names = [t.name for t in (await client.list_tools()).tools]
            peers = None
            if "interlink_peers" in names:
                peers = (await client.call_tool("interlink_peers", {})).structured_content
                missing = await client.call_tool(
                    "interlink_peer_result",
                    {"peer": "nobody", "task_id": "00000000-0000-4000-8000-000000000000"},
                )
                assert missing.structured_content["status"] == "refused"
            return names, peers

    names, _ = asyncio.run(asyncio.wait_for(tools(), 90))
    assert sorted(names) == sorted(TOOL_NAMES)
    names, peers = asyncio.run(asyncio.wait_for(tools("--peer-tools"), 90))
    assert sorted(names) == sorted(TOOL_NAMES + PEER_TOOL_NAMES)
    assert peers["data"] == {"peers": []}


def test_unverifiable_result_exits_cleanly_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from interlink.peer.client import PeerClient
    from interlink.peer.protocol import ProtocolError

    alice = Person(tmp_path, "alice", monkeypatch)
    friend = Person(tmp_path, "friend", monkeypatch)
    code = friend.json(capsys, "peer", "id", "--json")["invite"]
    assert alice("peer", "add", "bob", code, "--url", "http://127.0.0.1:9") == 0

    def forged(self: PeerClient, task_id: str) -> None:
        raise ProtocolError("bad_result", "the result is not signed by this host", 502)

    monkeypatch.setattr(PeerClient, "result", forged)
    capsys.readouterr()
    out = tmp_path / "out"
    task = "00000000-0000-4000-8000-000000000000"
    assert alice("peer", "result", "bob", task, "--out", str(out)) == 2
    assert "not signed" in capsys.readouterr().err
    assert not out.exists()
