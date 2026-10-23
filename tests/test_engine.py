"""Engine behaviour end to end against the mock harness (no network, no keys)."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

import pytest

from conftest import run_to_end, texts, wait_run
from interlink.engine import Engine, InterlinkError
from interlink.process import pid_alive


def launch(engine: Engine, **kw) -> str:
    return engine.launch("mock", **kw)["instance_id"]


def test_launch_prompt_observe_roundtrip(engine: Engine) -> None:
    iid = launch(engine, files={"README.md": "hello\n"}, label="demo")
    window = run_to_end(engine, iid, "say hi there\nwrite out/a.txt done\nls")
    assert window["state"] == "complete" and window["exit_code"] == 0
    assert "hi there" in texts(window)
    assert window["final_text"].startswith("done turn 1")
    assert engine.files(iid, "out/a.txt")["text"] == "done\n"
    info = engine.inspect(iid)
    assert info["label"] == "demo" and info["changes"]["added"] == ["out/a.txt"]


def test_session_resumes_across_prompts(engine: Engine) -> None:
    iid = launch(engine)
    first = run_to_end(engine, iid, "say one")
    second = run_to_end(engine, iid, "say two")
    assert first["final_text"] == "done turn 1" and second["final_text"] == "done turn 2"
    assert engine.inspect(iid)["session"]["session_id"]


def test_prompt_wait_returns_finished_window(engine: Engine) -> None:
    iid = launch(engine)
    result = engine.prompt(iid, "say quick", wait_s=20)
    assert result["done"] and result["state"] == "complete" and result["run_id"]


def test_failure_exit_code(engine: Engine) -> None:
    iid = launch(engine)
    window = run_to_end(engine, iid, "exit 3")
    assert window["state"] == "failed" and window["exit_code"] == 3
    assert engine.inspect(iid)["state"] == "ready"  # an instance survives a failed run


def test_timeout_kills_the_run(engine: Engine) -> None:
    iid = launch(engine)
    started = time.monotonic()
    window = run_to_end(engine, iid, "sleep 30", timeout_s=1)
    assert window["state"] == "timed_out"
    assert time.monotonic() - started < 15


def test_cancel(engine: Engine) -> None:
    iid = launch(engine)
    run_id = engine.prompt(iid, "say before\nsleep 30")["run_id"]
    time.sleep(0.5)
    result = engine.cancel(iid, run_id)
    assert result["settled"] and result["state"] == "cancelled"
    assert result["effects_reversed"] is False
    assert engine.cancel(iid, run_id)["effect"] == "already_finished"
    assert engine.cancel(iid)["state"] == "nothing_to_cancel"


@pytest.mark.skipif(os.name == "nt", reason="grandchild tracking via process groups is POSIX")
def test_timeout_kills_grandchildren(engine: Engine) -> None:
    iid = launch(engine)
    run_to_end(engine, iid, "spawn 60\nsleep 30", timeout_s=2)
    pid = int(engine.files(iid, "grandchild.pid")["text"])
    for _ in range(100):
        if not pid_alive(pid) or _zombie(pid):
            break
        time.sleep(0.05)
    assert not pid_alive(pid) or _zombie(pid)


def _zombie(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ")[1].startswith("Z")
    except OSError:
        return True


def test_one_run_per_instance_is_held(engine: Engine) -> None:
    iid = launch(engine)
    run_id = engine.prompt(iid, "sleep 30")["run_id"]
    with pytest.raises(InterlinkError) as info:
        engine.prompt(iid, "say again")
    assert info.value.code == "run_active" and info.value.status == "held"
    engine.cancel(iid, run_id)


def test_concurrency_limit(engine_factory) -> None:
    engine = engine_factory(max_concurrent_runs=1)
    a, b = launch(engine), launch(engine)
    run_id = engine.prompt(a, "sleep 30")["run_id"]
    with pytest.raises(InterlinkError) as info:
        engine.prompt(b, "say hi")
    assert info.value.code == "concurrency_limit" and info.value.status == "held"
    engine.cancel(a, run_id)
    assert run_to_end(engine, b, "say hi")["state"] == "complete"


def test_parallel_instances_run_concurrently(engine_factory) -> None:
    engine = engine_factory(max_concurrent_runs=4)
    ids = [launch(engine) for _ in range(4)]
    started = time.monotonic()
    runs = [(iid, engine.prompt(iid, "sleep 1.5\nsay ok")["run_id"]) for iid in ids]
    windows = [wait_run(engine, iid, rid) for iid, rid in runs]
    assert all(w["state"] == "complete" for w in windows)
    assert time.monotonic() - started < 5.5  # not 4 x 1.5s serially (plus startup)


def test_instance_limit(engine_factory) -> None:
    engine = engine_factory(max_instances=1)
    launch(engine)
    with pytest.raises(InterlinkError) as info:
        launch(engine)
    assert info.value.code == "instance_limit"


def test_unknown_harness_and_bad_prompts(engine: Engine) -> None:
    with pytest.raises(InterlinkError, match="available: mock"):
        engine.launch("nope")
    iid = launch(engine)
    for prompt, code in (("   ", "empty_prompt"), ("x" * 200_001, "prompt_too_long")):
        with pytest.raises(InterlinkError) as info:
            engine.prompt(iid, prompt)
        assert info.value.code == code
    with pytest.raises(InterlinkError) as info:
        engine.prompt(iid, "say hi", timeout_s=10**9)
    assert info.value.code == "invalid_timeout"


def test_idempotent_launch_replays(engine: Engine) -> None:
    rid = str(uuid.uuid4())
    first = engine.launch("mock", label="x", request_id=rid)
    again = engine.launch("mock", label="x", request_id=rid)
    assert again["instance_id"] == first["instance_id"] and again["replayed"] is True
    assert len(engine.inspect()["instances"]) == 1


def test_request_id_collision_and_validation(engine: Engine) -> None:
    rid = str(uuid.uuid4())
    engine.launch("mock", label="a", request_id=rid)
    with pytest.raises(InterlinkError) as info:
        engine.launch("mock", label="b", request_id=rid)
    assert info.value.code == "request_collision"
    with pytest.raises(InterlinkError) as info:
        engine.launch("mock", request_id="not-a-uuid")
    assert info.value.code == "invalid_request_id"


def test_errors_are_replayed_not_reexecuted(engine: Engine) -> None:
    rid = str(uuid.uuid4())
    for _ in range(2):
        with pytest.raises(InterlinkError) as info:
            engine.launch("nope", request_id=rid)
        assert info.value.code == "unknown_harness"
    assert info.value.data.get("replayed") is True


def test_home_and_tmp_are_isolated(engine: Engine) -> None:
    iid = launch(engine)
    window = run_to_end(engine, iid, "whereami")
    where = json.loads(texts(window)[0])
    root = Path(engine.inspect(iid)["workspace"]).parent
    for key in ("cwd", "home", "tmp"):
        assert Path(where[key]).resolve().is_relative_to(root.resolve()), key
    assert (root / "home" / ".mock-agent" / "session.json").is_file()
    assert not (Path.home() / ".mock-agent").exists() or Path.home().resolve().is_relative_to(root)


def test_env_allow_list_blocks_unlisted_vars(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INTERLINK_TEST_UNLISTED", "visible?")
    monkeypatch.setenv("FAKE_SERVICE_API_KEY", "sk-should-never-cross")
    iid = launch(engine)
    window = run_to_end(
        engine, iid, "env INTERLINK_TEST_UNLISTED\nenv FAKE_SERVICE_API_KEY\nenv PATH"
    )
    assert texts(window) == [
        "INTERLINK_TEST_UNLISTED=unset",
        "FAKE_SERVICE_API_KEY=unset",
        "PATH=set",
    ]


def test_secrets_cross_only_when_declared_and_are_redacted(engine_factory, monkeypatch) -> None:
    secret = "sk-test-" + uuid.uuid4().hex
    monkeypatch.setenv("FAKE_SERVICE_API_KEY", secret)
    engine = engine_factory({"keyed": {"adapter": "mock", "secrets": ["FAKE_SERVICE_API_KEY"]}})
    iid = engine.launch("keyed")["instance_id"]
    window = run_to_end(engine, iid, "printenv FAKE_SERVICE_API_KEY\nstderr leak " + "x")
    assert texts(window) == ["FAKE_SERVICE_API_KEY=[REDACTED:FAKE_SERVICE_API_KEY]"]
    root = Path(engine.inspect(iid)["workspace"]).parent
    for path in root.rglob("*"):
        if path.is_file() and path.name != "prompt.txt":
            assert secret not in path.read_text(errors="replace"), path
    exported = engine.evidence(iid, include_transcript=True)
    assert secret not in Path(exported["path"]).read_text()


def test_pass_env_refuses_credentials(engine_factory) -> None:
    from interlink.config import ConfigError

    with pytest.raises((InterlinkError, ConfigError, ValueError)):
        engine = engine_factory({"bad": {"adapter": "mock", "pass_env": ["GITHUB_TOKEN"]}})
        engine.launch("bad")


def test_project_is_copied_never_modified(engine: Engine, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("v1")
    iid = engine.launch("mock", project=str(project))["instance_id"]
    run_to_end(engine, iid, "write app.py v2\ndelete missing.txt")
    assert (project / "app.py").read_text() == "v1"
    assert engine.files(iid, "app.py")["text"] == "v2\n"
    assert engine.inspect(iid)["changes"]["modified"] == ["app.py"]


def test_files_listing_status_and_confinement(engine: Engine) -> None:
    iid = launch(engine, files={"keep.txt": "k", "gone.txt": "g"})
    run_to_end(engine, iid, "write new.txt n\ndelete gone.txt")
    listing = engine.files(iid)
    status = {f["path"]: f["status"] for f in listing["files"]}
    assert status == {"keep.txt": "unchanged", "new.txt": "added"}
    assert listing["deleted"] == ["gone.txt"]
    for bad in ("../instance.json", "/etc/passwd", "../../ledger.sqlite3"):
        with pytest.raises(InterlinkError) as info:
            engine.files(iid, bad)
        assert info.value.code == "path_refused"
    assert engine.files(iid, "keep.txt", max_bytes=1)["truncated"] is False


def test_evidence_bundle(engine: Engine) -> None:
    iid = launch(engine, files={"a.txt": "1"})
    run_to_end(engine, iid, "write a.txt 2\nwrite b.txt 3")
    result = engine.evidence(iid)
    bundle = json.loads(Path(result["path"]).read_text())
    assert result["summary"]["receipt_chain_valid"] is True
    assert result["summary"]["added"] == 1 and result["summary"]["modified"] == 1
    assert bundle["runs"][0]["prompt_sha256"] and "prompt" not in bundle["runs"][0]
    kinds = [r["kind"] for r in bundle["receipts"]]
    assert kinds[:3] == ["launched", "prompt_submitted", "run_finished"]
    assert "prompt text (sha256 only)" in bundle["omitted"]


def test_evidence_respects_byte_budget(engine: Engine) -> None:
    iid = launch(engine)
    run_to_end(engine, iid, "\n".join(f"say line {n} " + "y" * 200 for n in range(300)))
    result = engine.evidence(iid, include_transcript=True, max_bytes=20_000)
    assert result["bytes"] <= 20_000 + 2_000
    assert result["summary"]["truncated"]


def test_stop_and_discard(engine: Engine) -> None:
    iid = launch(engine)
    run_id = engine.prompt(iid, "sleep 30")["run_id"]
    stopped = engine.stop(iid)
    assert stopped["state"] == "stopped" and stopped["detail"]["cancel"]["run_id"] == run_id
    with pytest.raises(InterlinkError) as info:
        engine.prompt(iid, "say hi")
    assert info.value.code == "instance_not_ready"
    root = Path(engine.inspect(iid)["workspace"]).parent
    assert engine.stop(iid, discard=True)["state"] == "discarded"
    assert not root.exists()


def test_cleanup_removes_stopped(engine: Engine) -> None:
    keep, gone = launch(engine), launch(engine)
    engine.stop(gone)
    assert engine.cleanup()["removed"] == [gone]
    assert [i["instance_id"] for i in engine.inspect()["instances"]] == [keep]


def test_history_is_readable_by_a_new_server(engine_factory, state_root: Path) -> None:
    first = engine_factory()
    iid = launch(first)
    run_to_end(first, iid, "say persisted")
    first.shutdown()
    second = engine_factory()
    window = second.observe(iid)
    assert window["source"] == "disk" and window["state"] == "complete"
    assert any(e.get("text") == "persisted" for e in window["events"])
    assert second.inspect(iid)["owned_by_this_server"] is False
    assert second.evidence(iid)["summary"]["receipt_chain_valid"]


def test_orphans_are_recovered(engine_factory, state_root: Path) -> None:
    first = engine_factory()
    iid = launch(first)
    record_path = state_root / "instances" / iid / "instance.json"
    record = json.loads(record_path.read_text())
    record["server_pid"] = 2**22 + 12345  # a server that no longer exists
    record["runs"] = [
        {"id": "r1", "state": "running", "processes": [{"pid": 2**22 + 12346, "identity": None}]}
    ]
    first.instances.clear()  # simulate a crash: this server forgets the instance
    record_path.write_text(json.dumps(record))
    second = engine_factory()
    recovered = second.inspect()["server"]["recovered_orphans"]
    assert recovered == 1
    after = json.loads(record_path.read_text())
    assert after["state"] == "orphaned" and after["runs"][0]["state"] == "interrupted"
    assert second.stop(iid, discard=True)["state"] == "discarded"


def test_refuses_home_as_project(engine: Engine) -> None:
    with pytest.raises(InterlinkError) as info:
        engine.launch("mock", project=str(Path.home()))
    assert info.value.code == "refused_by_policy"


def test_launch_cap_on_seed_files(engine: Engine) -> None:
    with pytest.raises(InterlinkError) as info:
        engine.launch("mock", files={"../x": "no"})
    assert info.value.code == "refused_by_policy"
