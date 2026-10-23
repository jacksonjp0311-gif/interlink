from __future__ import annotations

import os
import stat
import sys
import textwrap
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from interlink.config import Config, parse
from interlink.engine import Engine

FAKES = Path(__file__).parent / "fakes"
FIXTURES = Path(__file__).parent / "fixtures"
IS_WINDOWS = os.name == "nt"


def make_config(harness: dict[str, Any] | None = None, **server: Any) -> Config:
    return parse(
        {"server": {"auto_detect": False, **server}, "harness": harness or {}},
    )


def make_executable(directory: Path, name: str, python_source: str) -> Path:
    """Create a real executable (shebang script on POSIX, .cmd wrapper on Windows)."""
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / f"{name}.py"
    script.write_text(textwrap.dedent(python_source), encoding="utf-8")
    if IS_WINDOWS:
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper
    launcher = directory / name
    launcher.write_text(f"#!{sys.executable}\n" + script.read_text(encoding="utf-8"))
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return launcher


def replay_executable(directory: Path, name: str, fixture: str, exit_code: int = 0) -> Path:
    """An executable that records its argv/env into $HOME and replays a JSONL fixture."""
    return make_executable(
        directory,
        name,
        f"""
        import json, os, sys
        from pathlib import Path
        home = Path(os.environ["HOME"])
        (home / "argv.json").write_text(json.dumps(sys.argv[1:]))
        (home / "env.json").write_text(json.dumps(sorted(os.environ)))
        stdin = "" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read()
        (home / "stdin.txt").write_text(stdin)
        sys.stdout.write(Path({str(FIXTURES / fixture)!r}).read_text(encoding="utf-8"))
        sys.exit({exit_code})
        """,
    )


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def engine_factory(state_root: Path) -> Iterator[Callable[..., Engine]]:
    engines: list[Engine] = []

    def factory(
        harness: dict[str, Any] | None = None, root: Path | None = None, **server: Any
    ) -> Engine:
        engine = Engine(make_config(harness, **server), state_root=root or state_root)
        engines.append(engine)
        return engine

    yield factory
    for engine in engines:
        engine.shutdown()


@pytest.fixture
def engine(engine_factory: Callable[..., Engine]) -> Engine:
    return engine_factory()


def run_to_end(
    engine: Engine, instance_id: str, prompt: str, timeout: float = 30, **kw: Any
) -> dict[str, Any]:
    """Submit a prompt and block until the run is terminal; returns the final window."""
    started = engine.prompt(instance_id, prompt, **kw)
    return wait_run(engine, instance_id, started["run_id"], timeout)


def wait_run(engine: Engine, instance_id: str, run_id: str, timeout: float = 30) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    events: list[dict[str, Any]] = []
    cursor = 0
    while time.monotonic() < deadline:
        window = engine.observe(instance_id, run_id, after=cursor, limit=256, wait_s=1)
        events += window["events"]
        cursor = window["next_cursor"]
        if window["done"] and not window["more"]:
            window["all_events"] = events
            return window
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def texts(window: dict[str, Any]) -> list[str]:
    return [e.get("text", "") for e in window["all_events"] if e["type"] == "text"]
