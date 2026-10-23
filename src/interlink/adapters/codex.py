"""OpenAI Codex CLI as the harness under test, via ``codex exec --json``.

``CODEX_HOME`` is pointed into the sandbox, so your real ~/.codex (auth, history,
config) is untouched; supply ``CODEX_API_KEY``/``OPENAI_API_KEY`` via ``secrets``.
Follow-up prompts use ``codex exec resume <thread_id>``. Status: argv checked against
codex-cli 0.163 (``exec --help``/``exec resume --help``) and a live unauthenticated run;
authenticated turns are covered by recorded-fixture tests only.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field

from interlink.adapters.base import AdapterOptions, InstanceView, RunContext
from interlink.adapters.command import CommandAdapter, CommandOptions, _json_object
from interlink.sandbox import Workspace


class CodexOptions(CommandOptions):
    command: str = "codex"
    argv: list[str] = Field(default_factory=lambda: ["codex"])  # derived; see build_argv
    model: str | None = None
    sandbox: str | None = Field("workspace-write", description="codex --sandbox mode")
    extra_args: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=lambda: ["CODEX_API_KEY", "OPENAI_API_KEY"])
    output: str = "jsonl"  # type: ignore[assignment]


class CodexAdapter(CommandAdapter):
    summary: ClassVar[str] = "Codex CLI non-interactive (`codex exec --json`)."
    Options: ClassVar[type[AdapterOptions]] = CodexOptions
    options: CodexOptions

    def environment(self, workspace: Workspace) -> dict[str, str]:
        return {"CODEX_HOME": str(workspace.home / ".codex")}

    def prepare(self, instance: InstanceView) -> None:
        # codex refuses to start if CODEX_HOME does not exist yet.
        (instance.workspace.home / ".codex").mkdir(parents=True, exist_ok=True)

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = self.options
        argv = [o.command, "exec", "--json", "--skip-git-repo-check"]
        if o.model:
            argv += ["--model", o.model]
        if o.sandbox:
            argv += ["--sandbox", o.sandbox]
        argv += list(o.extra_args)
        session = ctx.instance.session.get("session_id")
        if session:
            argv += ["resume", str(session)]
        return [*argv, "-"]  # "-" reads the prompt from stdin

    def uses_stdin(self, ctx: RunContext) -> bool:
        return True

    def parse_line(self, line: str, ctx: RunContext) -> None:
        value = _json_object(line)
        if value is None:
            if line.strip():
                ctx.emit("raw", text=line)
            return
        kind = value.get("type")
        if kind == "thread.started" and value.get("thread_id"):
            ctx.instance.session["session_id"] = value["thread_id"]
            ctx.emit("status", event="thread.started", session_id=value["thread_id"])
        elif kind in ("item.started", "item.completed", "item.updated"):
            item = value.get("item") or {}
            item_type = item.get("type")
            if kind == "item.completed" and item_type == "agent_message":
                ctx.emit("text", text=str(item.get("text", "")))
            elif item_type in ("command_execution", "mcp_tool_call", "web_search", "file_change"):
                ctx.emit(
                    "tool_use" if kind == "item.started" else "tool_result",
                    tool=item_type,
                    data=item,
                )
            elif kind == "item.completed" and item_type == "error":
                ctx.emit("error", message=str(item.get("message", "")), source="item")
            elif kind == "item.completed":
                ctx.emit("status", event=item_type, data=item)
        elif kind == "turn.completed":
            ctx.emit("result", usage=value.get("usage"))
        elif kind in ("turn.failed", "error"):
            error = value.get("error") if isinstance(value.get("error"), dict) else {}
            message = value.get("message") or error.get("message") or ""
            ctx.emit("error", message=str(message), source=kind)
        else:
            ctx.emit("status", event=kind, data=value)

    def doctor(self) -> dict[str, Any]:
        found = self.which(self.options.command)
        return {
            "ok": bool(found),
            "checks": [self.check("executable", bool(found), found or "codex not on PATH")],
        }
