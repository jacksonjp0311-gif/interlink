"""The examples directory is documentation, so it must keep working."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

from conftest import run_to_end, texts
from interlink.config import parse

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_example_config_parses() -> None:
    data = tomllib.loads((EXAMPLES / "interlink.toml").read_text())
    config = parse(data)
    assert {"mock", "claude", "codex", "hermes", "aider"} <= set(config.harnesses)


def test_client_snippets_are_valid() -> None:
    mcp = json.loads((EXAMPLES / "claude-code" / ".mcp.json").read_text())
    assert mcp["mcpServers"]["interlink"]["args"][-1] == "serve"
    codex = tomllib.loads((EXAMPLES / "codex" / "config.toml").read_text())
    assert codex["mcp_servers"]["interlink"]["args"][-1] == "serve"


def test_drive_mock_example_runs() -> None:
    out = subprocess.run(
        [sys.executable, str(EXAMPLES / "drive_mock.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert "Hello from inside the sandbox" in out.stdout
    assert "added     hello.txt" in out.stdout


def test_custom_adapter_example(engine_factory, state_root, monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(EXAMPLES))
    engine = engine_factory({"shout": {"adapter": "custom_adapter:ShoutAdapter"}}, state_root)
    iid = engine.launch("shout")["instance_id"]
    run = run_to_end(engine, iid, "quiet please")
    assert "SHOUT: QUIET PLEASE" in texts(run)
