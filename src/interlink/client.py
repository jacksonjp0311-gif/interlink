"""A tiny MCP client used by ``interlink handshake`` and the end-to-end tests."""

from __future__ import annotations

import os
import sys
from typing import Any

from mcp import Client, StdioServerParameters


def server_params(
    config: str | None = None, state_root: str | None = None, env: dict[str, str] | None = None
) -> StdioServerParameters:
    """stdio parameters that launch ``python -m interlink serve`` as an MCP server."""
    args = ["-m", "interlink", "serve"]
    if config:
        args += ["--config", config]
    if state_root:
        args += ["--state-root", state_root]
    child_env = {**os.environ, **(env or {})}
    return StdioServerParameters(command=sys.executable, args=args, env=child_env)


async def handshake(config: str | None = None, state_root: str | None = None) -> dict[str, Any]:
    """Start a server, list its tools and call ``interlink_harnesses`` over real MCP."""
    async with Client(server_params(config, state_root), read_timeout_seconds=30) as client:
        tools = await client.list_tools()
        listing = await client.call_tool("interlink_harnesses", {"check": False})
        info = client.server_info
        return {
            "server": getattr(info, "name", "?"),
            "version": getattr(info, "version", "?"),
            "protocol": client.protocol_version,
            "tools": [tool.name for tool in tools.tools],
            "harnesses": [
                h["name"]
                for h in (listing.structured_content or {}).get("data", {}).get("harnesses", [])
            ],
        }
