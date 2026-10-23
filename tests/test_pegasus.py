"""PEGASUS adapter against a fake host that enforces the pegasus-interlink/1 rules.

The real host listens on a Windows named pipe; on POSIX the adapter speaks the same
framing over a Unix socket, which is the seam these tests use.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from conftest import FAKES, run_to_end, texts
from interlink.engine import InterlinkError

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX socket seam (Windows uses a named pipe)"
)


@pytest.fixture
def source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "pegasus-src"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.rs").write_text("fn main() {}\n")
    (root / "README.md").write_text("disposable copy\n")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "ignored.js").write_text("x")
    return root


def pegasus(engine_factory, source_tree: Path, **options):
    harness = {
        "adapter": "pegasus",
        "executable": sys.executable,
        "argv": [str(FAKES / "fake_pegasus_host.py")],
        "source_root": str(source_tree),
        "startup_timeout_s": 20,
        "poll_interval_s": 0.05,
        **options,
    }
    return engine_factory({"pg": harness})


MODEL = {"id": "m1", "name": "Fake", "path": "/models/fake.gguf", "endpoint": "http://127.0.0.1:1"}


def ops(engine, iid) -> list[dict]:
    path = Path(engine.inspect(iid)["workspace"]).parent / "profile" / "fake-ops.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_boot_acquire_prompt_observe(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    launched = engine.launch("pg")
    assert launched["state"] == "ready", launched
    iid = launched["instance_id"]
    window = run_to_end(engine, iid, "hello pegasus")
    assert window["state"] == "complete", window
    assert "".join(texts(window)).strip() == "PEGASUS heard 13 chars"
    names = [o["op"] for o in ops(engine, iid)]
    assert (
        names[:3] == ["inspect", "acquire", "session"]
        or names[:2] == ["acquire", "session"]
        or "acquire" in names
    )
    assert "prompt" in names and "observe" in names
    assert all(o["args"].get("ttl_ms", 60_000) <= 60_000 for o in ops(engine, iid))
    # The same session is reused for the next turn.
    run_to_end(engine, iid, "again")
    assert [o["op"] for o in ops(engine, iid)].count("session") == 1


def test_inference_disabled_is_refused(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree)
    iid = engine.launch("pg")["instance_id"]
    window = run_to_end(engine, iid, "hello")
    assert window["state"] in ("failed", "error")
    blob = json.dumps(window["all_events"]) + json.dumps(window.get("detail", {}))
    assert "inference_disabled" in blob


def test_failed_turn(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    iid = engine.launch("pg")["instance_id"]
    assert run_to_end(engine, iid, "please FAIL")["state"] == "failed"


def test_cancel_sends_control(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    iid = engine.launch("pg")["instance_id"]
    run_id = engine.prompt(iid, "SLOW stream")["run_id"]
    time.sleep(0.6)
    result = engine.cancel(iid, run_id)
    assert result["settled"] and result["state"] == "cancelled"
    assert "control" in [o["op"] for o in ops(engine, iid)]


def test_timeout_cancels_on_host(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    iid = engine.launch("pg")["instance_id"]
    assert run_to_end(engine, iid, "SLOW", timeout_s=1)["state"] == "timed_out"


def test_stop_shuts_the_host_down(engine_factory, source_tree: Path) -> None:
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    iid = engine.launch("pg")["instance_id"]
    host_pid = engine.inspect(iid)["host"]["pid"]
    engine.stop(iid)
    assert "shutdown" in [o["op"] for o in ops(engine, iid)]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(host_pid, 0)
            os.waitpid(host_pid, os.WNOHANG)
        except (ProcessLookupError, ChildProcessError):
            break
        time.sleep(0.1)
    else:
        pytest.fail("host still running after stop")


def test_source_is_only_read(engine_factory, source_tree: Path) -> None:
    before = (source_tree / "src" / "main.rs").read_text()
    engine = pegasus(engine_factory, source_tree, inference=True, model=MODEL)
    iid = engine.launch("pg")["instance_id"]
    run_to_end(engine, iid, "hi")
    assert (source_tree / "src" / "main.rs").read_text() == before


def test_refuses_personal_install(engine_factory, tmp_path: Path) -> None:
    engine = pegasus(engine_factory, Path.home() / "PEGASUS")
    with pytest.raises(InterlinkError) as info:
        engine.launch("pg")
    assert info.value.code == "refused_by_policy"


def test_bad_startup_fails_cleanly(engine_factory, source_tree: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("import sys; sys.exit(9)\n")
    engine = pegasus(engine_factory, source_tree, argv=[str(broken)], startup_timeout_s=5)
    with pytest.raises(InterlinkError) as info:
        engine.launch("pg")
    assert info.value.code == "launch_failed"
