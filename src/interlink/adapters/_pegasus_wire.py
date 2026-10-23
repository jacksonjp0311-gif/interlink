"""Wire-level pieces of the PEGASUS host protocol (``pegasus-interlink/1``).

One JSON line request -> one JSON line response, one connection per request. Every
request carries the instance id, generation, a 256-bit bearer token, a controller id,
the controller lease and an absolute deadline. Responses must echo the identity and
request id back exactly or they are treated as *ambiguous* (effect unknown, never
blindly replayed).

Channels:
* Windows: the PEGASUS named pipe ``\\\\.\\pipe\\pegasus-interlink-<instance>-<generation>``.
  Before any token byte is written the pipe server's PID is checked against the
  process Interlink itself launched (requires pywin32).
* POSIX: a Unix domain socket named by ``PEGASUS_INTERLINK_SOCKET``. Upstream PEGASUS
  does not listen on this today; it exists so the protocol can be exercised in tests
  (see tests/fakes/fake_pegasus_host.py) and by future non-Windows hosts.
"""

from __future__ import annotations

import json
import os
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from interlink.security import sha256_text

PROTOCOL = "pegasus-interlink/1"
BOOT_SCHEMA = "pegasus-interlink-boot/1"
OWNER_SCHEMA = "pegasus-interlink-owner/1"
SOURCE_SCHEMA = "pegasus-interlink-source/1"
MAX_REQUEST = 131_072
MAX_RESPONSE = 1_048_576
STATUSES = {"complete", "held", "refused", "failed"}
TERMINAL_TASK_STATES = {"complete", "failed", "stopped", "interrupted"}

EXCLUDED_SOURCE_DIRS = {
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


class Ambiguous(TimeoutError):
    """The request may have reached the host; its effect is unknown. Do not replay."""


class ChannelRefused(ConnectionError):
    """Nothing was sent (peer unverifiable, channel absent, bounds)."""


def _excluded(name: str, is_dir: bool) -> bool:
    if is_dir:
        return name.lower() in EXCLUDED_SOURCE_DIRS
    lower = name.lower()
    return lower == ".git" or lower.endswith((".pyc", ".pyo", ".tsbuildinfo"))


def source_inventory(root: Path, limit: int = 20_000) -> list[tuple[str, str]]:
    """Exactly mirrors the PEGASUS host's ``source_inventory`` exclusion rules."""
    import hashlib

    files: list[tuple[str, str]] = []

    def walk(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda e: e.name):
            path = Path(entry.path)
            # Windows junctions keep the DIRECTORY attribute; POSIX symlinks to a directory
            # are classified the same way so the isolation links (data/, runtime/...) are
            # excluded by name exactly as on the real host. Any non-excluded link is refused.
            is_dir = (
                entry.is_dir(follow_symlinks=False)
                or bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x10)
                or (entry.is_symlink() and entry.is_dir(follow_symlinks=True))
            )
            if _excluded(entry.name, is_dir):
                continue
            if entry.is_symlink():
                raise ChannelRefused(f"linked source path refused: {path.relative_to(root)}")
            if is_dir:
                walk(path)
            elif entry.is_file(follow_symlinks=False):
                if len(files) >= limit or entry.stat().st_size > 33_554_432:
                    raise ChannelRefused("source_inventory_bounds")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                files.append((path.relative_to(root).as_posix(), digest))
            else:
                raise ChannelRefused("non_regular_source_refused")

    walk(root)
    files.sort()
    return files


def source_digest(files: list[tuple[str, str]]) -> str:
    """sha256 of ``serde_json::to_string`` of the sorted (path, sha256) pairs."""
    return sha256_text(
        json.dumps(
            [list(pair) for pair in sorted(files)], separators=(",", ":"), ensure_ascii=False
        )
    )


def check_reply(envelope: dict[str, Any], reply: Any) -> dict[str, Any]:
    if not isinstance(reply, dict):
        raise Ambiguous("Host reply is not an object")
    for key in ("schema", "instance_id", "generation", "request_id"):
        if reply.get(key) != envelope[key]:
            raise Ambiguous("Host identity or request binding mismatch")
    if reply.get("status") not in STATUSES:
        raise Ambiguous("Unknown host outcome")
    return reply


def _encode(envelope: dict[str, Any]) -> bytes:
    payload = (json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    if len(payload) > MAX_REQUEST:
        raise ChannelRefused("Request byte limit exceeded")
    if time.time() * 1000 >= envelope["deadline_ms"]:
        raise ChannelRefused("Deadline expired before connect")
    return payload


def _decode(envelope: dict[str, Any], response: bytes) -> dict[str, Any]:
    if response.count(b"\n") != 1 or response.split(b"\n", 1)[1]:
        raise Ambiguous("Malformed host framing")
    try:
        value = json.loads(response[:-1])
    except json.JSONDecodeError as exc:
        raise Ambiguous("Host reply is not JSON") from exc
    return check_reply(envelope, value)


class UnixSocketChannel:
    def __init__(self, path: str, peer_check: Callable[[], bool] | None = None) -> None:
        self.path = path
        self.peer_check = peer_check

    def request(self, envelope: dict[str, Any]) -> dict[str, Any]:
        payload = _encode(envelope)
        if self.peer_check is not None and not self.peer_check():
            raise ChannelRefused("Owned host process is not running; no request was sent")
        deadline = envelope["deadline_ms"] / 1000
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            try:
                sock.connect(self.path)
            except OSError as exc:
                raise ChannelRefused("Owned host channel is unavailable") from exc
            try:
                sock.sendall(payload)
                response = bytearray()
                while b"\n" not in response:
                    sock.settimeout(max(0.05, deadline - time.time()))
                    chunk = sock.recv(16384)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE:
                        raise Ambiguous("Host reply exceeded bounds")
            except TimeoutError as exc:
                raise Ambiguous("Host request timed out; effect unknown") from exc
            except OSError as exc:
                raise Ambiguous("Disconnected after issue; effect unknown") from exc
            return _decode(envelope, bytes(response))
        finally:
            sock.close()


class NamedPipeChannel:  # pragma: no cover - Windows only, requires pywin32
    def __init__(self, name: str, expected_pid: Callable[[], int | None]) -> None:
        if not name.startswith("\\\\.\\pipe\\pegasus-interlink-"):
            raise ChannelRefused("Unrecognized local pipe")
        self.name = name
        self.expected_pid = expected_pid

    def request(self, envelope: dict[str, Any]) -> dict[str, Any]:
        import pywintypes
        import win32con
        import win32event
        import win32file
        import win32pipe

        payload = _encode(envelope)
        deadline = envelope["deadline_ms"] / 1000

        def remaining() -> int:
            return max(1, min(1000, int((deadline - time.time()) * 1000)))

        try:
            win32pipe.WaitNamedPipe(self.name, remaining())
            handle = win32file.CreateFile(
                self.name,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_OVERLAPPED,
                None,
            )
        except pywintypes.error as exc:
            raise ChannelRefused("Owned native pipe is unavailable") from exc
        issued = False

        def wait(overlap: Any) -> int:
            while time.time() < deadline:
                if (
                    win32event.WaitForSingleObject(overlap.hEvent, remaining())
                    == win32event.WAIT_OBJECT_0
                ):
                    return win32file.GetOverlappedResult(handle, overlap, False)
            win32file.CancelIoEx(handle, overlap)
            raise Ambiguous("Native request timed out; effect unknown")

        try:
            expected = self.expected_pid()
            if expected is None or win32pipe.GetNamedPipeServerProcessId(handle) != expected:
                raise ChannelRefused("Pipe server is not the owned process; no request was sent")
            overlap = pywintypes.OVERLAPPED()
            overlap.hEvent = win32event.CreateEvent(None, True, False, None)
            issued = True
            code, _ = win32file.WriteFile(handle, payload, overlap)
            if code == 997:
                wait(overlap)
            response = bytearray()
            while b"\n" not in response:
                overlap = pywintypes.OVERLAPPED()
                overlap.hEvent = win32event.CreateEvent(None, True, False, None)
                code, data = win32file.ReadFile(handle, 16384, overlap)
                count = (
                    wait(overlap)
                    if code == 997
                    else win32file.GetOverlappedResult(handle, overlap, False)
                )
                response.extend(bytes(data[:count]))
                if len(response) > MAX_RESPONSE:
                    raise Ambiguous("Host reply exceeded bounds")
            return _decode(envelope, bytes(response))
        except (Ambiguous, ChannelRefused):
            raise
        except Exception as exc:
            if issued:
                raise Ambiguous("Disconnected after issue; effect unknown") from exc
            raise
        finally:
            win32file.CloseHandle(handle)
