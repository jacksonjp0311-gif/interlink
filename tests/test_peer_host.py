"""Adversarial tests for the sharing side. Every request here is really signed."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlink.peer.crypto import Identity, b64e
from interlink.peer.host import MAX_BODY, safe_relative_path, sanitize_config
from interlink.peer.protocol import (
    AUTH_HEADER,
    SIG_HEADER,
    ProtocolError,
    request_digest,
    sign_request,
    sign_result,
    verify_result,
)
from interlink.peer.store import verify_chain
from interlink.security import canonical
from peerkit import Pair, make_pair


@pytest.fixture
def pair(tmp_path: Path) -> Iterator[Pair]:
    p = make_pair(tmp_path)
    yield p
    p.host.shutdown()


def error(body: dict) -> str:
    assert body["ok"] is False, body
    return body["error"]["code"]


# -- happy path ----------------------------------------------------------------------
def test_signed_result_round_trip(pair: Pair) -> None:
    task = {
        "task_id": str(uuid.uuid4()),
        "harness": "writer",
        "prompt": "make it loud",
        "files": {"notes/seed.txt": "seed"},
        "timeout_s": 30,
    }
    status, body, headers = pair.raw("/v1/tasks", task)
    assert status == 202 and body["data"]["state"] == "queued" and SIG_HEADER in headers
    envelope = pair.wait(task["task_id"])
    report = verify_result(
        envelope,
        host_public=pair.bob.public_raw,
        host_fp=pair.bob.fingerprint,
        own_fp=pair.alice.fingerprint,
        task=task,
    )
    statement = envelope["statement"]
    assert report["verified"] and statement["state"] == "complete"
    assert [(f["path"], f["text"]) for f in statement["files"]] == [("out.txt", "MAKE IT LOUD")]
    events = [e["event"] for e in statement["chain"]]
    assert events == ["received", "approved", "started", "finished"]
    assert statement["evidence"]["bundle"]["schema"] == "interlink-evidence/1"
    # the workspace is discarded once the result is signed
    assert not any((pair.tmp / "bob-state" / "engine" / "instances").glob("*/work"))


def test_hello_reports_only_what_this_peer_may_use(pair: Pair) -> None:
    status, body, _ = pair.raw("/v1/hello", {})
    assert status == 200
    assert body["data"]["harnesses"] == ["mock", "writer"]  # not envdump/sleeper
    assert body["data"]["you"] == pair.alice.fingerprint


# -- authentication --------------------------------------------------------------------
def test_forged_signature_is_rejected(pair: Pair) -> None:
    mallory = Identity.generate()
    body = json.dumps({}).encode()
    _headers, claims = sign_request(mallory, pair.bob.fingerprint, "POST", "/v1/hello", body)
    claims["from"] = pair.alice.fingerprint  # claim to be alice, sign with mallory's key
    raw = canonical(claims).encode()
    forged = {AUTH_HEADER: b64e(raw), SIG_HEADER: b64e(mallory.sign("request", raw))}
    status, out, _response_headers = pair.host.handle("POST", "/v1/hello", forged, body)
    assert status == 401 and json.loads(out)["error"]["code"] == "bad_signature"
    garbage = {AUTH_HEADER: forged[AUTH_HEADER], SIG_HEADER: "!!!"}
    assert pair.host.handle("POST", "/v1/hello", garbage, body)[0] == 401
    assert pair.host.handle("POST", "/v1/hello", {}, body)[0] == 401


def test_tampered_body_is_rejected(pair: Pair) -> None:
    good = json.dumps({"task_id": str(uuid.uuid4()), "harness": "mock", "prompt": "a"}).encode()
    headers, _ = sign_request(pair.alice, pair.bob.fingerprint, "POST", "/v1/tasks", good)
    evil = good.replace(b'"a"', b'"rm -rf /"')
    status, out, _ = pair.host.handle("POST", "/v1/tasks", headers, evil)
    assert status == 401 and json.loads(out)["error"]["code"] == "bad_binding"


def test_replay_is_rejected(pair: Pair) -> None:
    body = b"{}"
    headers, _ = sign_request(pair.alice, pair.bob.fingerprint, "POST", "/v1/hello", body)
    assert pair.host.handle("POST", "/v1/hello", headers, body)[0] == 200
    status, out, _ = pair.host.handle("POST", "/v1/hello", headers, body)
    assert status == 401 and json.loads(out)["error"]["code"] == "replay"


def test_unknown_and_revoked_peers(pair: Pair) -> None:
    stranger = Identity.generate()
    status, body, _ = pair.raw("/v1/hello", {}, identity=stranger)
    assert status == 401 and error(body) == "unknown_peer"
    pair.bob_book.revoke("alice")
    status, body, _ = pair.raw("/v1/hello", {})
    assert status == 403 and error(body) == "revoked"
    status, body = pair.submit()
    assert status == 403 and error(body) == "revoked"


def test_request_meant_for_another_host(pair: Pair) -> None:
    status, body, _ = pair.raw("/v1/hello", {}, to=Identity.generate().fingerprint)
    assert status == 401 and error(body) == "wrong_recipient"


def test_expired_future_and_overlong_requests(pair: Pair) -> None:
    now = int(time.time() * 1000)
    cases = {
        "expired": {"iat": now - 120_000, "exp": now - 60_000},
        "clock_skew": {"iat": now + 600_000, "exp": now + 660_000},
        "bad_validity": {"iat": now, "exp": now + 3_600_000},
    }
    for code, claims in cases.items():
        status, body, _ = pair.raw("/v1/hello", {}, claims=claims)
        assert (status, error(body)) == (401, code)


def test_signed_path_must_match(pair: Pair) -> None:
    status, body, _ = pair.raw("/v1/tasks", {}, claims={"path": "/v1/hello"})
    assert status == 401 and error(body) == "bad_binding"
    status, _out, _ = pair.host.handle("GET", "/v1/hello", {}, b"")
    assert status == 404
    status, _out, _ = pair.host.handle("POST", "/etc/passwd", {}, b"")
    assert status == 404


def test_failed_auth_is_rate_limited_per_address(pair: Pair) -> None:
    stranger = Identity.generate()
    codes = [pair.raw("/v1/hello", {}, identity=stranger, remote="10.0.0.9")[0] for _ in range(35)]
    assert codes[:30] == [401] * 30 and codes[-1] == 429


def test_responses_are_signed_for_the_requester(pair: Pair) -> None:
    from interlink.peer.protocol import check_response

    body = b"{}"
    headers, claims = sign_request(pair.alice, pair.bob.fingerprint, "POST", "/v1/hello", body)
    status, out, response_headers = pair.host.handle("POST", "/v1/hello", headers, body)
    args = (pair.bob.fingerprint, pair.alice.fingerprint, claims["nonce"], status, out)
    check_response(pair.bob.public_raw, *args, response_headers[SIG_HEADER])
    with pytest.raises(ProtocolError):
        check_response(Identity.generate().public_raw, *args, response_headers[SIG_HEADER])
    with pytest.raises(ProtocolError):
        check_response(pair.bob.public_raw, *args[:-1], out + b" ", response_headers[SIG_HEADER])


# -- policy ------------------------------------------------------------------------------
def test_disallowed_harnesses(pair: Pair) -> None:
    for harness in ("envdump", "sleeper", "does-not-exist"):
        status, body = pair.submit(harness=harness)
        assert (status, error(body)) == (403, "harness_not_allowed")


def test_oversized_payloads(pair: Pair, tmp_path: Path) -> None:
    status, _out, _ = pair.host.handle("POST", "/v1/tasks", {}, b"x" * (MAX_BODY + 1))
    assert status == 413
    status, body = pair.submit(prompt="x" * 20_001)
    assert (status, error(body)) == (413, "prompt_too_long")
    status, body = pair.submit(files={f"f{i}.txt": "x" for i in range(21)})
    assert (status, error(body)) == (413, "too_many_files")
    status, body = pair.submit(files={"big.txt": "x" * (256 * 1024 + 1)})
    assert (status, error(body)) == (413, "file_too_large")
    status, body = pair.submit(
        files={f"f{i}.txt": "x" * 256 * 1024 for i in range(10)}, prompt="y" * 20_000
    )
    assert status in (200, 202)  # exactly at the allowance is fine


@pytest.mark.parametrize(
    "path",
    [
        "../escape.txt",
        "/etc/passwd",
        "a/../../b",
        "C:/Windows/x",
        "a\\..\\b",
        "./a",
        "a//b",
        "a/\x00b",
        "",
    ],
)
def test_path_traversal_in_seed_files(pair: Pair, path: str) -> None:
    status, body = pair.submit(files={path: "x"})
    assert status == 400 and error(body) in ("path_refused", "bad_request")
    assert not safe_relative_path(path)


def test_unknown_fields_and_bad_ids(pair: Pair) -> None:
    status, body = pair.submit(project="/home/bob")
    assert (status, error(body)) == (400, "bad_request")
    status, body = pair.submit(task_id="../../x")
    assert (status, error(body)) == (400, "bad_request")
    status, body, _ = pair.raw("/v1/tasks", None, body=b"not json")
    assert (status, error(body)) == (400, "bad_request")


def test_env_and_secrets_never_reach_inbound_tasks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("INTERLINK_LEAK_TOKEN", "s3cr3t-token-value")
    monkeypatch.setenv("INTERLINK_LEAK_PLAIN", "plain-host-value")
    pair = make_pair(tmp_path, {"harnesses": ["envdump"]})
    try:
        task_id = str(uuid.uuid4())
        assert pair.submit(task_id=task_id, harness="envdump", timeout_s=30)[0] == 202
        statement = pair.wait(task_id)["statement"]
        assert statement["state"] == "complete"
        env = json.loads(statement["final_text"])
        dumped = json.dumps(statement)
        assert "s3cr3t-token-value" not in dumped and "plain-host-value" not in dumped
        assert "INTERLINK_LEAK_TOKEN" not in env and "INTERLINK_INJECTED" not in env
        assert str(Path.home()) != env.get("HOME")
        assert "bob-state" in env["HOME"] and "instances" in env["HOME"]
    finally:
        pair.host.shutdown()


def test_sanitized_config_strips_secrets() -> None:
    from conftest import make_config
    from peerkit import HARNESSES

    clean = sanitize_config(make_config(HARNESSES), 2)
    options = clean.harnesses["envdump"].options
    assert options.pass_env == [] and options.secrets == [] and options.env == {}
    assert options.isolate_home is True
    assert clean.server.keep_workspaces is False and clean.server.auto_detect is False


def test_timeout_abuse(tmp_path: Path) -> None:
    pair = make_pair(tmp_path, {"harnesses": ["sleeper"], "max_timeout_s": 2})
    try:
        status, body = pair.submit(harness="sleeper", timeout_s=3600)
        assert (status, error(body)) == (400, "timeout_exceeds_policy")
        task_id = str(uuid.uuid4())
        started = time.monotonic()
        assert pair.submit(task_id=task_id, harness="sleeper", timeout_s=1)[0] == 202
        statement = pair.wait(task_id, timeout=30)["statement"]
        assert statement["state"] == "timed_out"
        assert time.monotonic() - started < 20
        # no timeout given -> the policy maximum applies, never the harness default
        other = str(uuid.uuid4())
        assert pair.submit(task_id=other, harness="sleeper")[0] == 202
        assert pair.host.tasks[f"{pair.alice.fingerprint}__{other}"].timeout_s == 2
        pair.wait(other, timeout=30)
    finally:
        pair.host.shutdown()


def test_concurrency_and_hourly_quota(tmp_path: Path) -> None:
    pair = make_pair(
        tmp_path, {"harnesses": ["sleeper", "mock"], "max_tasks_per_hour": 2, "approval": "prompt"}
    )
    try:
        assert pair.submit(harness="sleeper")[0] == 202
        status, body = pair.submit(harness="sleeper")
        assert (status, error(body)) == (429, "concurrency_limit")
        for task in list(pair.host.tasks.values()):
            pair.host.decide(task.task_id, False)
        assert pair.submit()[0] == 202
        for task in list(pair.host.tasks.values()):
            if task.state == "pending_approval":
                pair.host.decide(task.task_id, False)
        status, body = pair.submit()
        assert (status, error(body)) == (429, "quota_exceeded")
    finally:
        pair.host.shutdown()


def test_request_rate_limit(tmp_path: Path) -> None:
    pair = make_pair(tmp_path, {"max_requests_per_minute": 10})
    try:
        codes = [pair.raw("/v1/hello", {})[0] for _ in range(12)]
        assert codes[:10] == [200] * 10 and codes[10:] == [429, 429]
    finally:
        pair.host.shutdown()


def test_idempotent_resubmit_and_collision(pair: Pair) -> None:
    task_id = str(uuid.uuid4())
    assert pair.submit(task_id=task_id)[0] == 202
    status, body = pair.submit(task_id=task_id)
    assert status == 200 and body["data"]["task_id"] == task_id
    status, body = pair.submit(task_id=task_id, prompt="something else")
    assert (status, error(body)) == (409, "task_collision")
    pair.wait(task_id)


def test_tasks_are_private_to_their_sender(pair: Pair) -> None:
    carol = Identity.generate()
    pair.bob_book.add("carol", carol.public_raw)
    task_id = str(uuid.uuid4())
    assert pair.submit(task_id=task_id)[0] == 202
    for path in ("/v1/tasks/status", "/v1/tasks/result", "/v1/tasks/cancel"):
        status, body, _ = pair.raw(path, {"task_id": task_id}, identity=carol)
        assert (status, error(body)) == (404, "unknown_task")
    pair.wait(task_id)


# -- approval ------------------------------------------------------------------------------
def test_prompt_approval_deny_approve_and_expiry(tmp_path: Path) -> None:
    from interlink.peer.host import list_pending, write_decision

    pair = make_pair(tmp_path, {"approval": "prompt"}, approval_timeout_s=1.5)
    state = tmp_path / "bob-state"
    try:
        denied, approved, expired = (str(uuid.uuid4()) for _ in range(3))
        assert pair.submit(task_id=denied)[1]["data"]["state"] == "pending_approval"
        assert [t["task_id"] for t in list_pending(state)] == [denied]
        write_decision(state, denied, approve=False)  # what `interlink peer deny` does
        result = pair.wait(denied)
        assert result["statement"]["state"] == "denied" and result["statement"]["files"] == []
        assert verify_chain(result["statement"]["chain"])["valid"]

        pair.submit(task_id=approved)
        status, body, _ = pair.raw("/v1/tasks/result", {"task_id": approved})
        assert (status, error(body)) == (409, "not_finished")
        write_decision(state, approved, approve=True)
        assert pair.wait(approved)["statement"]["state"] == "complete"

        pair.submit(task_id=expired)
        assert pair.wait(expired, timeout=10)["statement"]["state"] == "expired"
        assert list_pending(state) == []
    finally:
        pair.host.shutdown()


def test_cancel_pending_task(tmp_path: Path) -> None:
    pair = make_pair(tmp_path, {"approval": "prompt"})
    try:
        task_id = str(uuid.uuid4())
        pair.submit(task_id=task_id)
        status, body, _ = pair.raw("/v1/tasks/cancel", {"task_id": task_id})
        assert status == 200 and body["data"]["state"] == "cancelled"
        assert pair.wait(task_id)["statement"]["state"] == "cancelled"
    finally:
        pair.host.shutdown()


def test_cancel_running_task(tmp_path: Path) -> None:
    pair = make_pair(tmp_path, {"harnesses": ["sleeper"], "max_timeout_s": 60})
    try:
        task_id = str(uuid.uuid4())
        pair.submit(task_id=task_id, harness="sleeper", timeout_s=60)
        deadline = time.monotonic() + 10
        while pair.host.tasks[f"{pair.alice.fingerprint}__{task_id}"].run_id is None:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        pair.raw("/v1/tasks/cancel", {"task_id": task_id})
        assert pair.wait(task_id, timeout=20)["statement"]["state"] == "cancelled"
    finally:
        pair.host.shutdown()


# -- results the requester must reject ----------------------------------------------------
def _finished(pair: Pair) -> tuple[dict, dict]:
    task = {
        "task_id": str(uuid.uuid4()),
        "harness": "mock",
        "prompt": "say hi",
        "files": {},
        "timeout_s": None,
    }
    pair.raw("/v1/tasks", task)
    return task, pair.wait(task["task_id"])


def test_tampered_results_are_detected(pair: Pair) -> None:
    task, envelope = _finished(pair)
    kwargs = {
        "host_public": pair.bob.public_raw,
        "host_fp": pair.bob.fingerprint,
        "own_fp": pair.alice.fingerprint,
    }
    assert verify_result(envelope, task=task, **kwargs)["verified"]

    edited = json.loads(json.dumps(envelope))
    edited["statement"]["final_text"] = "I am evil"
    with pytest.raises(ProtocolError, match="not signed"):
        verify_result(edited, task=task, **kwargs)

    mallory = Identity.generate()
    with pytest.raises(ProtocolError, match="not signed"):
        verify_result(sign_result(mallory, edited["statement"]), task=task, **kwargs)

    other_task = {**task, "prompt": "something else"}
    with pytest.raises(ProtocolError, match="does not match the task"):
        verify_result(envelope, task=other_task, **kwargs)
    with pytest.raises(ProtocolError, match="different host or requester"):
        verify_result(envelope, task=task, **{**kwargs, "own_fp": mallory.fingerprint})

    # even a statement signed by the real host is rejected if its own chain is broken
    broken = json.loads(json.dumps(envelope["statement"]))
    broken["chain"][1]["event"] = "skipped"
    with pytest.raises(ProtocolError, match="chain"):
        verify_result(sign_result(pair.bob, broken), task=task, **kwargs)
    wrong_evidence = json.loads(json.dumps(envelope["statement"]))
    wrong_evidence["evidence"]["bundle"]["runs"] = []
    with pytest.raises(ProtocolError, match="evidence"):
        verify_result(sign_result(pair.bob, wrong_evidence), task=task, **kwargs)
    assert request_digest(task) == envelope["statement"]["request_sha256"]


def test_audit_log_records_rejections(pair: Pair) -> None:
    pair.raw("/v1/hello", {}, identity=Identity.generate())
    _finished(pair)
    entries = pair.host.audit.entries()
    events = [e["event"] for e in entries]
    assert "request_rejected" in events and "task_finished" in events
    assert pair.host.audit.verify()["valid"]
    assert not any("say hi" in json.dumps(e) for e in entries)  # prompts aren't logged in clear
