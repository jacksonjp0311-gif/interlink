from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from interlink import __version__
from interlink.cli import main, snippet


@pytest.fixture
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config = tmp_path / "interlink.toml"
    config.write_text("[server]\nauto_detect = false\n")
    monkeypatch.setenv("INTERLINK_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("INTERLINK_CONFIG", str(config))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "interlink", "--version"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == f"interlink {__version__}"


def test_run_complete(cli: Path, capsys) -> None:
    assert main(["run", "mock", "say hello cli", "-q"]) == 0
    assert "done turn 1" in capsys.readouterr().out


def test_run_streams_events(cli: Path, capsys) -> None:
    assert main(["run", "mock", "say streamed\nwrite x.txt 1"]) == 0
    out = capsys.readouterr().out
    assert "streamed" in out and "write_file" in out


def test_run_json_lines(cli: Path, capsys) -> None:
    assert main(["run", "mock", "say j", "--json"]) == 0
    lines = [
        json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")
    ]
    assert any(e.get("text") == "j" for e in lines)


def test_run_exit_codes(cli: Path) -> None:
    assert main(["run", "mock", "exit 3", "-q"]) == 1
    assert main(["run", "mock", "sleep 30", "--timeout", "1", "-q"]) == 124
    assert main(["run", "nope", "hi", "-q"]) == 2


def test_run_seed_file_and_evidence(cli: Path, capsys) -> None:
    local = cli / "local.txt"
    local.write_text("seeded")
    assert (
        main(["run", "mock", "read in/data.txt", "--file", f"in/data.txt={local}", "--evidence"])
        == 0
    )
    out = capsys.readouterr().out
    assert "seeded" in out
    exports = list((cli / "state" / "exports").glob("*.json"))
    assert len(exports) == 1


def test_run_reads_stdin(cli: Path, capsys, monkeypatch) -> None:
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("say from stdin\n"))
    assert main(["run", "mock", "-"]) == 0
    assert "from stdin" in capsys.readouterr().out


def test_run_discards_workspace_by_default(cli: Path, capsys) -> None:
    main(["run", "mock", "say bye", "-q"])
    capsys.readouterr()
    main(["ls", "--json"])
    listing = json.loads(capsys.readouterr().out)
    assert listing["instances"] == []


def test_doctor_and_harnesses(cli: Path, capsys) -> None:
    assert main(["doctor", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert main(["harnesses", "--json"]) == 0
    names = [h["name"] for h in json.loads(capsys.readouterr().out)["harnesses"]]
    assert names == ["mock"]


def test_init_writes_a_valid_config(cli: Path) -> None:
    target = cli / "new.toml"
    assert main(["init", str(target)]) == 0
    tomllib.loads(target.read_text())
    assert main(["init", str(target)]) != 0  # refuses to overwrite without --force
    assert main(["init", str(target), "--force"]) == 0


def test_snippets() -> None:
    cc = json.loads(snippet("claude-code"))
    server = cc["mcpServers"]["interlink"]
    assert server["args"][-1] == "serve" or "serve" in server["args"]
    codex = tomllib.loads(snippet("codex", "/cfg/interlink.toml"))
    assert "interlink" in codex["mcp_servers"]
    # the config path is made absolute in the platform's own form (D:\\cfg\\... on Windows)
    expected = str(Path("/cfg/interlink.toml").resolve())
    assert expected in codex["mcp_servers"]["interlink"]["args"]
    assert snippet("claude-code-cli").startswith("claude mcp add")


def test_cleanup_and_handshake(cli: Path, capsys) -> None:
    main(["run", "mock", "say keep", "--keep", "-q"])
    capsys.readouterr()
    # handshake spawns a real server; run it out of process so stdio is real.
    out = subprocess.run(
        [sys.executable, "-m", "interlink", "handshake", "--json"],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert out.returncode == 0, out.stderr
    info = json.loads(out.stdout)
    assert len(info["tools"]) == 9
    assert main(["cleanup"]) == 0
