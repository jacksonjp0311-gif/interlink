from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from interlink.process import ManagedProcess, pid_alive, process_identity, reap_recorded


def spawn(tmp_path: Path, code: str, **kw):
    out: list[str] = []
    err: list[str] = []
    proc = ManagedProcess(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=dict(os.environ),
        stdout_sink=out.append,
        stderr_sink=err.append,
        stdout_log=tmp_path / "stdout.log",
        stderr_log=tmp_path / "stderr.log",
        **kw,
    )
    return proc, out, err


def test_streams_lines_and_exit_code(tmp_path: Path) -> None:
    proc, out, err = spawn(
        tmp_path, "import sys; print('a'); print('b'); sys.stderr.write('c\\n'); sys.exit(4)"
    )
    assert proc.wait() == (4, "exited")
    assert out == ["a", "b"] and err == ["c"]
    assert (tmp_path / "stdout.log").read_text().splitlines() == ["a", "b"]


def test_stdin_is_fed(tmp_path: Path) -> None:
    proc, out, _ = spawn(
        tmp_path, "import sys; print(sys.stdin.read().upper())", stdin_text="hello"
    )
    proc.wait()
    assert out == ["HELLO"]


def test_scrub_applies_to_logs_and_sinks(tmp_path: Path) -> None:
    proc, out, _ = spawn(
        tmp_path, "print('key=hunter2hunter2')", scrub=lambda s: s.replace("hunter2hunter2", "***")
    )
    proc.wait()
    assert out == ["key=***"]
    assert "hunter2" not in (tmp_path / "stdout.log").read_text()


def test_timeout_kills(tmp_path: Path) -> None:
    proc, _, _ = spawn(tmp_path, "import time; time.sleep(60)")
    started = time.monotonic()
    code, reason = proc.wait(deadline=time.monotonic() + 0.5)
    assert reason == "timeout" and code is not None
    assert time.monotonic() - started < 10
    assert not proc.alive


def test_cancel_kills(tmp_path: Path) -> None:
    proc, _, _ = spawn(tmp_path, "import time; time.sleep(60)")
    cancelled = threading.Event()
    threading.Timer(0.3, cancelled.set).start()
    assert proc.wait(cancelled=cancelled)[1] == "cancelled"


@pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX; Windows uses Job objects")
def test_kill_tree_takes_grandchildren(tmp_path: Path) -> None:
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    proc, out, _ = spawn(tmp_path, code)
    for _ in range(100):
        if out:
            break
        time.sleep(0.05)
    grandchild = int(out[0])
    assert pid_alive(grandchild)
    proc.kill_tree(grace=1)
    for _ in range(100):
        if not pid_alive(grandchild) or _is_zombie(grandchild):
            break
        time.sleep(0.05)
    assert not pid_alive(grandchild) or _is_zombie(grandchild)


def _is_zombie(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ")[1].startswith("Z")
    except OSError:
        return True


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs /proc")
def test_reap_recorded_requires_matching_identity(tmp_path: Path) -> None:
    proc, _, _ = spawn(tmp_path, "import time; time.sleep(60)")
    try:
        assert process_identity(proc.pid) == proc.identity is not None
        assert reap_recorded(proc.pid, "linux-start:0") == "identity_unverified_not_killed"
        assert reap_recorded(proc.pid, None) == "identity_unverified_not_killed"
        assert proc.alive
        assert reap_recorded(proc.pid, proc.identity) == "killed"
        assert proc.popen.wait(timeout=5) is not None
        assert reap_recorded(proc.pid, proc.identity) == "already_gone"
    finally:
        proc.kill_tree(grace=0.5)


def test_pid_alive_rejects_nonsense() -> None:
    assert pid_alive(0) is False
    assert pid_alive(-5) is False
