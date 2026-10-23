"""Owned child processes: spawn in their own group, stream output, kill the whole tree.

Interlink only ever signals processes it started itself and still holds a handle to.
A PID read back from disk is never treated as permission to kill (PIDs get reused);
orphans are only reaped when their recorded start-time identity still matches.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Any

IS_WINDOWS = os.name == "nt"

try:  # Windows Job objects make "kill the tree" exact. Optional.
    import win32api  # type: ignore[import-not-found]
    import win32con  # type: ignore[import-not-found]
    import win32job  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - only present on Windows with pywin32
    win32job = None


LineSink = Callable[[str], None]


class ManagedProcess:
    """A child process (and its descendants) that Interlink owns end to end."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        stdout_sink: LineSink,
        stderr_sink: LineSink,
        stdin_text: str | None = None,
        stdout_log: Path | None = None,
        stderr_log: Path | None = None,
        max_line_chars: int = 65536,
        scrub: Callable[[str], str] | None = None,
    ) -> None:
        self.argv = list(argv)
        self.started_at = time.time()
        self._job = None
        kwargs: dict[str, Any] = {
            "cwd": str(cwd),
            "env": dict(env),
            "stdin": subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if IS_WINDOWS:
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True  # new session => new process group
        self.popen = subprocess.Popen(self.argv, **kwargs)
        self.pid = self.popen.pid
        self.identity = process_identity(self.pid)
        if IS_WINDOWS and win32job is not None:  # pragma: no cover - Windows only
            self._job = _attach_job(self.pid)
        self._threads = [
            threading.Thread(
                target=_pump,
                args=(self.popen.stdout, stdout_sink, stdout_log, max_line_chars, scrub),
                daemon=True,
                name=f"interlink-stdout-{self.pid}",
            ),
            threading.Thread(
                target=_pump,
                args=(self.popen.stderr, stderr_sink, stderr_log, max_line_chars, scrub),
                daemon=True,
                name=f"interlink-stderr-{self.pid}",
            ),
        ]
        for thread in self._threads:
            thread.start()
        if stdin_text is not None and self.popen.stdin is not None:
            threading.Thread(target=_feed, args=(self.popen.stdin, stdin_text), daemon=True).start()

    # -- lifecycle -----------------------------------------------------------------------

    def poll(self) -> int | None:
        return self.popen.poll()

    def wait(
        self,
        *,
        deadline: float | None = None,
        cancelled: threading.Event | None = None,
        interval: float = 0.05,
    ) -> tuple[int | None, str]:
        """Wait for exit. Returns ``(exit_code, reason)`` where reason is
        ``exited`` | ``timeout`` | ``cancelled``. On timeout/cancel the tree is killed."""
        while True:
            code = self.popen.poll()
            if code is not None:
                self.drain()
                return code, "exited"
            if cancelled is not None and cancelled.is_set():
                return self.kill_tree(), "cancelled"
            if deadline is not None and time.monotonic() >= deadline:
                return self.kill_tree(), "timeout"
            time.sleep(interval)

    def kill_tree(self, grace: float = 2.0) -> int | None:
        """Terminate the whole process group, escalate to kill, then reap."""
        if self.popen.poll() is None:
            _signal_tree(self, hard=False)
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.popen.wait(timeout=grace)
        # Even if the leader exited, descendants may survive in the group.
        _signal_tree(self, hard=True)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.popen.wait(timeout=grace)
        self.drain(timeout=grace)
        if self._job is not None:  # pragma: no cover - Windows only
            with contextlib.suppress(Exception):
                win32api.CloseHandle(self._job)
            self._job = None
        return self.popen.returncode

    def drain(self, timeout: float = 5.0) -> None:
        for thread in self._threads:
            thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self.popen.poll() is None


def _feed(stream: IO[bytes], text: str) -> None:
    with contextlib.suppress(BrokenPipeError, OSError):
        stream.write(text.encode("utf-8"))
        stream.close()


def _pump(
    stream: IO[bytes],
    sink: LineSink,
    log: Path | None,
    max_chars: int,
    scrub: Callable[[str], str] | None,
) -> None:
    handle = open(log, "a", encoding="utf-8", newline="\n") if log else None  # noqa: SIM115 - closed below
    try:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if scrub is not None:
                line = scrub(line)  # secrets never reach disk, not even the raw log
            if handle:
                handle.write(line + "\n")
                handle.flush()
            if len(line) > max_chars:
                line = line[:max_chars] + " [truncated]"
            with contextlib.suppress(Exception):
                sink(line)
    except (OSError, ValueError):
        pass
    finally:
        if handle:
            handle.close()
        with contextlib.suppress(Exception):
            stream.close()


def _signal_tree(proc: ManagedProcess, *, hard: bool) -> None:
    if IS_WINDOWS:  # pragma: no cover - exercised by Windows CI
        if proc._job is not None:
            with contextlib.suppress(Exception):
                win32job.TerminateJobObject(proc._job, 1)
            return
        if proc.popen.poll() is None or hard:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                check=False,
            )
        return
    sig = signal.SIGKILL if hard else signal.SIGTERM
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, sig)  # pgid == leader pid because of start_new_session


def _attach_job(pid: int) -> Any:  # pragma: no cover - Windows only
    job = win32job.CreateJobObject(None, "")
    info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
    handle = win32api.OpenProcess(
        win32con.PROCESS_TERMINATE | win32con.PROCESS_SET_QUOTA, False, pid
    )
    try:
        win32job.AssignProcessToJobObject(job, handle)
    finally:
        win32api.CloseHandle(handle)
    return job


def process_identity(pid: int) -> str | None:
    """A token that changes if ``pid`` is reused by a different process.

    Linux: the start time in clock ticks from /proc. Elsewhere: unknown (``None``),
    which means Interlink will refuse to reap that PID from disk records.
    """
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        text = stat_path.read_text()
    except OSError:
        return None
    # The command name is in parentheses and may contain spaces; fields follow ')'.
    fields = text[text.rfind(")") + 2 :].split()
    return f"linux-start:{fields[19]}" if len(fields) > 19 else None


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if IS_WINDOWS:  # pragma: no cover
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_recorded(pid: int, identity: str | None) -> str:
    """Kill a *recorded* process group only if its identity provably still matches."""
    if not pid_alive(pid):
        return "already_gone"
    if identity is None or process_identity(pid) != identity:
        return "identity_unverified_not_killed"
    if IS_WINDOWS:  # pragma: no cover
        return "identity_unverified_not_killed"
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)
    return "killed"


def python_executable() -> str:
    return sys.executable
