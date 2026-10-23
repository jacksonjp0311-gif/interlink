"""Real MCP over stdio: spawn `python -m interlink serve` and drive it as a client would."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from interlink.client import handshake, server_params
from interlink.server import TOOL_NAMES


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "interlink.toml"
    path.write_text("[server]\nauto_detect = false\nmax_concurrent_runs = 2\n")
    return path


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 90))


async def call(client: Client, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    result = await client.call_tool(tool, args)
    assert not result.is_error, result
    return result.structured_content


def test_handshake(config_file: Path, tmp_path: Path) -> None:
    info = run(handshake(str(config_file), str(tmp_path / "state")))
    assert info["server"] == "Interlink"
    assert sorted(info["tools"]) == sorted(TOOL_NAMES) and len(info["tools"]) == 9
    assert info["harnesses"] == ["mock"]


def test_full_loop_over_stdio(config_file: Path, tmp_path: Path) -> None:
    async def scenario() -> None:
        params = server_params(str(config_file), str(tmp_path / "state"))
        async with Client(params, read_timeout_seconds=60) as client:
            launched = await call(
                client,
                "interlink_launch",
                {"harness": "mock", "files": {"a.txt": "1"}, "label": "e2e"},
            )
            assert launched["status"] == "complete" and launched["schema"] == "interlink/1"
            iid = launched["data"]["instance_id"]

            done = await call(
                client,
                "interlink_prompt",
                {"instance_id": iid, "prompt": "say hi\nwrite b.txt 2", "wait_s": 30},
            )
            assert done["data"]["state"] == "complete", done
            run_id = done["data"]["run_id"]

            observed = await call(
                client, "interlink_observe", {"instance_id": iid, "run_id": run_id, "limit": 256}
            )
            assert any(e.get("text") == "hi" for e in observed["data"]["events"])

            files = await call(client, "interlink_files", {"instance_id": iid})
            assert {f["path"]: f["status"] for f in files["data"]["files"]} == {
                "a.txt": "unchanged",
                "b.txt": "added",
            }
            refused = await call(
                client, "interlink_files", {"instance_id": iid, "path": "../instance.json"}
            )
            assert refused["status"] == "refused" and refused["error"]["code"] == "path_refused"

            evidence = await call(client, "interlink_evidence", {"instance_id": iid})
            assert evidence["data"]["summary"]["receipt_chain_valid"]
            assert json.loads(Path(evidence["data"]["path"]).read_text())["schema"]

            inspected = await call(client, "interlink_inspect", {"instance_id": iid})
            assert inspected["data"]["label"] == "e2e"

            stopped = await call(client, "interlink_stop", {"instance_id": iid, "discard": True})
            assert stopped["data"]["state"] == "discarded"

    run(scenario())


def test_held_cancel_and_idempotency_over_stdio(config_file: Path, tmp_path: Path) -> None:
    async def scenario() -> None:
        params = server_params(str(config_file), str(tmp_path / "state"))
        async with Client(params, read_timeout_seconds=60) as client:
            rid = str(uuid.uuid4())
            first = await call(client, "interlink_launch", {"harness": "mock", "request_id": rid})
            again = await call(client, "interlink_launch", {"harness": "mock", "request_id": rid})
            assert (
                again["data"]["instance_id"] == first["data"]["instance_id"]
                and again["data"]["replayed"]
            )
            iid = first["data"]["instance_id"]

            started = await call(
                client, "interlink_prompt", {"instance_id": iid, "prompt": "sleep 30"}
            )
            held = await call(client, "interlink_prompt", {"instance_id": iid, "prompt": "say hi"})
            assert held["status"] == "held" and held["error"]["code"] == "run_active"

            cancelled = await call(
                client,
                "interlink_cancel",
                {"instance_id": iid, "run_id": started["data"]["run_id"]},
            )
            assert cancelled["data"]["state"] == "cancelled"

            unknown = await call(client, "interlink_launch", {"harness": "nope"})
            assert unknown["status"] == "refused" and unknown["error"]["code"] == "unknown_harness"

    run(scenario())


def test_schema_validation_errors_are_tool_errors(config_file: Path, tmp_path: Path) -> None:
    async def scenario() -> None:
        params = server_params(str(config_file), str(tmp_path / "state"))
        async with Client(params, read_timeout_seconds=60) as client:
            result = await client.call_tool(
                "interlink_launch", {"harness": "mock", "request_id": "short"}
            )
            assert result.is_error
            result = await client.call_tool(
                "interlink_observe", {"instance_id": "x" * 36, "limit": 10_000}
            )
            assert result.is_error

    run(scenario())


def test_server_shutdown_stops_running_harnesses(config_file: Path, tmp_path: Path) -> None:
    state = tmp_path / "state"

    async def scenario() -> str:
        async with Client(
            server_params(str(config_file), str(state)), read_timeout_seconds=60
        ) as client:
            iid = (await call(client, "interlink_launch", {"harness": "mock"}))["data"][
                "instance_id"
            ]
            await call(client, "interlink_prompt", {"instance_id": iid, "prompt": "sleep 60"})
            return iid

    iid = run(scenario())
    record = json.loads((state / "instances" / iid / "instance.json").read_text())
    assert record["state"] in ("stopped", "orphaned")
    assert record["runs"][0]["state"] in ("cancelled", "interrupted")
