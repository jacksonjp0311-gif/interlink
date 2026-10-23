"""Adapters: registry, argv building, and stream parsing against recorded/fake harnesses."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from conftest import FAKES, make_executable, replay_executable, run_to_end, texts
from interlink.adapters import available, resolve
from interlink.adapters.base import HarnessAdapter, substitute

# -- registry ------------------------------------------------------------------------------


def test_builtin_adapters_are_registered() -> None:
    names = set(available())
    assert {"mock", "command", "hermes", "claude-code", "codex", "pegasus"} <= names
    for name in ("mock", "command", "hermes", "claude-code", "codex", "pegasus"):
        assert issubclass(resolve(name), HarnessAdapter)


def test_resolve_accepts_import_paths() -> None:
    assert resolve("interlink.adapters.mock:MockAdapter").__name__ == "MockAdapter"
    with pytest.raises(TypeError):
        resolve("json:JSONDecoder")  # not a HarnessAdapter
    with pytest.raises(KeyError):
        resolve("definitely-not-registered")


# -- argv substitution ---------------------------------------------------------------------


def test_substitute_is_single_pass_and_shell_free() -> None:
    values = {"prompt": "rm -rf / {workspace}; $(boom)", "workspace": "/w"}
    assert substitute(["tool", "--q={prompt}", "{workspace}"], values) == [
        "tool",
        "--q=rm -rf / {workspace}; $(boom)",
        "/w",
    ]
    assert substitute(["{unknown}"], values) == ["{unknown}"]


# -- generic command adapter ---------------------------------------------------------------


def test_command_adapter_text_mode_with_argv_prompt(engine_factory) -> None:
    engine = engine_factory(
        {
            "echo": {
                "adapter": "command",
                "argv": [
                    sys.executable,
                    "-c",
                    "import sys; print('got:', sys.argv[1])",
                    "{prompt}",
                ],
            }
        }
    )
    iid = engine.launch("echo")["instance_id"]
    window = run_to_end(engine, iid, "hello; $(whoami)")
    assert texts(window) == ["got: hello; $(whoami)"]
    assert window["state"] == "complete"


def test_command_adapter_uses_stdin_without_placeholders(engine_factory) -> None:
    engine = engine_factory(
        {
            "upper": {
                "adapter": "command",
                "argv": [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
            }
        }
    )
    iid = engine.launch("upper")["instance_id"]
    assert texts(run_to_end(engine, iid, "quiet please")) == ["QUIET PLEASE"]


def test_command_adapter_jsonl_and_success_codes(engine_factory) -> None:
    code = "import json; print(json.dumps({'type':'text','text':'j'})); print('not json'); raise SystemExit(7)"
    engine = engine_factory(
        {
            "j": {
                "adapter": "command",
                "output": "jsonl",
                "success_exit_codes": [0, 7],
                "argv": [sys.executable, "-c", code],
            }
        }
    )
    iid = engine.launch("j")["instance_id"]
    window = run_to_end(engine, iid, "go")
    assert window["state"] == "complete" and window["exit_code"] == 7
    types = [e["type"] for e in window["all_events"]]
    assert "text" in types and "raw" in types


def test_missing_executable_is_an_error_not_a_crash(engine_factory) -> None:
    engine = engine_factory(
        {"ghost": {"adapter": "command", "argv": ["interlink-no-such-binary-xyz"]}}
    )
    iid = engine.launch("ghost")["instance_id"]
    window = run_to_end(engine, iid, "hi")
    assert window["state"] == "error"
    assert engine.inspect(iid)["state"] == "ready"


# -- claude code (recorded stream-json) -----------------------------------------------------


def _home(engine, iid) -> Path:
    return Path(engine.inspect(iid)["workspace"]).parent / "home"


def test_claude_code_stream_and_argv(engine_factory, tmp_path: Path) -> None:
    exe = replay_executable(tmp_path / "bin", "claude", "claude_stream.jsonl")
    engine = engine_factory(
        {
            "cc": {
                "adapter": "claude-code",
                "command": str(exe),
                "model": "sonnet",
                "permission_mode": "acceptEdits",
                "allowed_tools": ["Read", "Write"],
            }
        }
    )
    iid = engine.launch("cc")["instance_id"]
    window = run_to_end(engine, iid, "make hello.txt")
    assert window["state"] == "complete"
    types = [e["type"] for e in window["all_events"] if e["type"] != "interlink"]
    assert types[:5] == ["status", "text", "tool_use", "tool_result", "text"]
    tool = next(e for e in window["all_events"] if e["type"] == "tool_use")
    assert tool["tool"] == "Write" and tool["input"]["file_path"] == "hello.txt"
    assert window["final_text"] == "Done - hello.txt now says hi."
    home = _home(engine, iid)
    argv = json.loads((home / "argv.json").read_text())
    assert argv[:4] == ["-p", "--output-format", "stream-json", "--verbose"]
    assert argv[4:6] == ["--model", "sonnet"] and "--allowedTools" in argv and "Read,Write" in argv
    assert "make hello.txt" not in argv  # prompt goes over stdin, never argv
    assert (home / "stdin.txt").read_text() == "make hello.txt"
    # Second prompt resumes the recorded session.
    run_to_end(engine, iid, "again")
    argv = json.loads((home / "argv.json").read_text())
    assert argv[-2:] == ["--resume", "5f0c1e9a-2b1d-4c47-9d0e-2f7c8b1a0d11"]


def test_claude_code_is_error_result_fails_the_run(engine_factory, tmp_path: Path) -> None:
    exe = replay_executable(tmp_path / "bin", "claude", "claude_not_logged_in.jsonl")
    engine = engine_factory({"cc": {"adapter": "claude-code", "command": str(exe)}})
    iid = engine.launch("cc")["instance_id"]
    window = run_to_end(engine, iid, "hi")
    assert window["state"] == "failed"
    assert "Not logged in" in window["final_text"]


def test_claude_code_isolated_home_hides_real_login(engine_factory, tmp_path: Path) -> None:
    exe = replay_executable(tmp_path / "bin", "claude", "claude_stream.jsonl")
    engine = engine_factory({"cc": {"adapter": "claude-code", "command": str(exe)}})
    iid = engine.launch("cc")["instance_id"]
    run_to_end(engine, iid, "hi")
    env_names = json.loads((_home(engine, iid) / "env.json").read_text())
    assert "ANTHROPIC_API_KEY" not in env_names or os.environ.get("ANTHROPIC_API_KEY")


# -- codex (recorded exec --json) ----------------------------------------------------------


def test_codex_stream_argv_and_resume(engine_factory, tmp_path: Path) -> None:
    exe = replay_executable(tmp_path / "bin", "codex", "codex_stream.jsonl")
    engine = engine_factory({"cx": {"adapter": "codex", "command": str(exe), "model": "gpt-x"}})
    iid = engine.launch("cx")["instance_id"]
    window = run_to_end(engine, iid, "what is here?")
    assert window["state"] == "complete"
    assert window["final_text"] == "The repo contains README.md."
    tools = [e for e in window["all_events"] if e["type"] in ("tool_use", "tool_result")]
    assert [e["type"] for e in tools] == ["tool_use", "tool_result"]
    home = _home(engine, iid)
    assert (home / ".codex").is_dir()
    argv = json.loads((home / "argv.json").read_text())
    assert argv[:3] == ["exec", "--json", "--skip-git-repo-check"] and argv[-1] == "-"
    assert argv[argv.index("--sandbox") : argv.index("--sandbox") + 2] == [
        "--sandbox",
        "workspace-write",
    ]
    run_to_end(engine, iid, "more")
    argv = json.loads((home / "argv.json").read_text())
    assert argv[-3:] == ["resume", "0199a213-81c0-7800-8aa1-bbab2a035a53", "-"]


def test_codex_error_events(engine_factory, tmp_path: Path) -> None:
    exe = make_executable(
        tmp_path / "bin",
        "codex",
        """
        import json, sys
        print(json.dumps({"type": "thread.started", "thread_id": "t-1"}))
        print(json.dumps({"type": "error", "message": "unexpected status 401 Unauthorized"}))
        print(json.dumps({"type": "turn.failed", "error": {"message": "unexpected status 401 Unauthorized"}}))
        sys.exit(1)
        """,
    )
    engine = engine_factory({"cx": {"adapter": "codex", "command": str(exe)}})
    iid = engine.launch("cx")["instance_id"]
    window = run_to_end(engine, iid, "hi")
    assert window["state"] == "failed"
    errors = [e for e in window["all_events"] if e["type"] == "error"]
    assert len(errors) == 2 and all("401" in e["message"] for e in errors)


def test_codex_shared_home_uses_existing_login(engine_factory, tmp_path: Path) -> None:
    """isolate_home=false must not redirect CODEX_HOME, or codex can't see the user's login."""
    exe = make_executable(
        tmp_path / "bin",
        "codex",
        """
        import json, os, sys
        sys.stdin.read()
        print(json.dumps({"type": "thread.started", "thread_id": "t-1"}))
        seen = os.environ.get("CODEX_HOME", "<unset>")
        print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": seen}}))
        print(json.dumps({"type": "turn.completed", "usage": {}}))
        """,
    )
    shared = engine_factory(
        {"cx": {"adapter": "codex", "command": str(exe), "isolate_home": False}}
    )
    iid = shared.launch("cx")["instance_id"]
    window = run_to_end(shared, iid, "hi")
    assert window["state"] == "complete"
    assert window["final_text"] == os.environ.get("CODEX_HOME", "<unset>")

    isolated = engine_factory({"cx": {"adapter": "codex", "command": str(exe)}})
    iid = isolated.launch("cx")["instance_id"]
    window = run_to_end(isolated, iid, "hi")
    assert window["final_text"].endswith(".codex") and window["final_text"] != "<unset>"


# -- hermes (fake binary that validates flags) ---------------------------------------------


def _hermes(engine_factory, tmp_path: Path, **options):
    exe = make_executable(tmp_path / "bin", "hermes", (FAKES / "fake_hermes.py").read_text())
    return engine_factory({"h": {"adapter": "hermes", "command": str(exe), **options}})


def test_hermes_oneshot_and_resume(engine_factory, tmp_path: Path) -> None:
    engine = _hermes(engine_factory, tmp_path, model="fake/model-1")
    iid = engine.launch("h")["instance_id"]
    window = run_to_end(engine, iid, "list files")
    assert window["state"] == "complete", window
    assert "hermes says: list files" in texts(window)
    assert [e["type"] for e in window["all_events"]].count("tool_use") == 1
    session = engine.inspect(iid)["session"]["session_id"]
    assert (_home(engine, iid) / ".hermes" / "sessions.json").is_file()
    run_to_end(engine, iid, "again")
    assert engine.inspect(iid)["session"]["session_id"] == session


def test_hermes_failure_and_interrupt(engine_factory, tmp_path: Path) -> None:
    engine = _hermes(engine_factory, tmp_path)
    iid = engine.launch("h")["instance_id"]
    assert run_to_end(engine, iid, "please FAIL")["state"] == "failed"
    assert run_to_end(engine, iid, "INTERRUPT now")["state"] == "cancelled"


def test_hermes_timeout(engine_factory, tmp_path: Path) -> None:
    engine = _hermes(engine_factory, tmp_path)
    iid = engine.launch("h")["instance_id"]
    assert run_to_end(engine, iid, "SLOW", timeout_s=1)["state"] == "timed_out"


def test_hermes_doctor_reports_missing_binary(engine_factory) -> None:
    engine = engine_factory({"h": {"adapter": "hermes", "command": "hermes-not-installed-xyz"}})
    item = next(h for h in engine.harnesses()["harnesses"] if h["name"] == "h")
    assert item["doctor"]["ok"] is False


# -- custom adapter plug-in ----------------------------------------------------------------


def test_custom_adapter_by_import_path(engine_factory, tmp_path: Path, monkeypatch) -> None:
    module = tmp_path / "my_adapter.py"
    module.write_text(
        "from interlink.adapters.base import HarnessAdapter, RunOutcome\n"
        "class Echo(HarnessAdapter):\n"
        "    summary = 'echo'\n"
        "    def run(self, ctx):\n"
        "        ctx.emit('text', text=ctx.prompt[::-1])\n"
        "        return RunOutcome('complete', 0)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    engine = engine_factory({"rev": {"adapter": "my_adapter:Echo"}})
    iid = engine.launch("rev")["instance_id"]
    assert texts(run_to_end(engine, iid, "abc")) == ["cba"]
