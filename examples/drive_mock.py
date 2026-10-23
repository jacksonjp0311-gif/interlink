"""Drive Interlink from Python exactly like an MCP client (Claude Code, Codex...) would.

    python examples/drive_mock.py

Starts `interlink serve` over stdio, launches the scripted mock agent in a throwaway
workspace, sends it a prompt, then reads back its events, its file changes and an
evidence bundle. No network or API keys needed.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from mcp import Client

from interlink.client import server_params


async def call(client: Client, tool: str, **args):
    result = await client.call_tool(tool, args)
    reply = result.structured_content
    print(f"-> {tool:22} {reply['status']}")
    return reply


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp, "interlink.toml")
        config.write_text("[server]\nauto_detect = false\n")
        params = server_params(str(config), str(Path(tmp, "state")))

        async with Client(params, read_timeout_seconds=60) as client:
            tools = (await client.list_tools()).tools
            print(f"connected: {len(tools)} tools")

            launched = await call(
                client, "interlink_launch", harness="mock", files={"notes.md": "# hi\n"}
            )
            iid = launched["data"]["instance_id"]

            prompt = "say Hello from inside the sandbox\nwrite hello.txt written by the mock agent"
            done = await call(client, "interlink_prompt", instance_id=iid, prompt=prompt, wait_s=30)
            print(f"   run {done['data']['run_id']} -> {done['data']['state']}")

            events = await call(client, "interlink_observe", instance_id=iid, limit=50)
            for event in events["data"]["events"]:
                if event["type"] in ("text", "tool_use", "result"):
                    print(f"   [{event['type']}] {event.get('text') or event.get('tool') or ''}")

            files = await call(client, "interlink_files", instance_id=iid)
            for item in files["data"]["files"]:
                print(f"   {item['status']:9} {item['path']}")

            evidence = await call(client, "interlink_evidence", instance_id=iid)
            print(f"   evidence: {evidence['data']['path']}")

            await call(client, "interlink_stop", instance_id=iid, discard=True)


if __name__ == "__main__":
    asyncio.run(main())
