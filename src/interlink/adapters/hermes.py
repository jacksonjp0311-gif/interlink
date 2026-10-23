"""Hermes Agent (NousResearch) via its non-interactive one-shot mode.

Each prompt runs::

    hermes chat --oneshot --query-file <prompt.txt> --format stream-json \
        --source tool --ignore-user-config --ignore-rules [--model ...] [--resume <id>]

with ``HERMES_HOME`` pointing into the sandbox, so the run never reads or writes your
real ``~/.hermes`` (config, memories, sessions). ``--query-file`` keeps the prompt off
the command line. The ``stream-json`` events (``system`` / ``text`` / ``tool_use`` /
``tool_result`` / ``result``) map 1:1 onto Interlink events, and the ``session_id``
from the stream is reused with ``--resume`` so multi-turn conversations work.

Credentials: a fresh HERMES_HOME has none. Either list provider keys under
``secrets`` (e.g. ``OPENROUTER_API_KEY``), point ``base_url`` at a local
OpenAI-compatible server, or copy a vetted ``config_yaml`` in.

Exit codes follow the Hermes docs: 0 ok, 1 failed, 130 interrupted.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, ClassVar

from pydantic import Field

from interlink.adapters.base import AdapterOptions, HarnessAdapter, InstanceView, RunContext
from interlink.adapters.command import CommandAdapter, CommandOptions, _json_object
from interlink.sandbox import Workspace


class HermesOptions(CommandOptions):
    command: str = "hermes"
    argv: list[str] = Field(default_factory=lambda: ["hermes"])  # derived; see build_argv
    model: str | None = None
    provider: str | None = None
    base_url: str | None = None
    toolsets: str | None = None
    skills: str | None = None
    max_turns: int | None = Field(None, ge=1, le=500)
    safe_mode: bool = False
    continue_session: bool = True
    config_yaml: str | None = Field(
        None, description="Optional config.yaml copied into the sandbox HERMES_HOME."
    )
    extra_args: list[str] = Field(default_factory=list)
    output: str = "jsonl"  # type: ignore[assignment]


class HermesAdapter(CommandAdapter):
    summary: ClassVar[str] = "Hermes Agent one-shot (`hermes chat --oneshot --format stream-json`)."
    Options: ClassVar[type[AdapterOptions]] = HermesOptions
    options: HermesOptions

    def environment(self, workspace: Workspace) -> dict[str, str]:
        return {"HERMES_HOME": str(workspace.home / ".hermes")}

    def prepare(self, instance: InstanceView) -> None:
        home = instance.workspace.home / ".hermes"
        home.mkdir(parents=True, exist_ok=True)
        if self.options.config_yaml:
            source = Path(self.options.config_yaml).expanduser()
            shutil.copyfile(source, home / "config.yaml")

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = self.options
        argv = [o.command, "chat", "--oneshot", "--query-file", str(ctx.prompt_file)]
        argv += ["--format", "stream-json", "--source", "tool"]
        if not o.config_yaml:
            argv += ["--ignore-user-config", "--ignore-rules"]
        if o.safe_mode:
            argv.append("--safe-mode")
        for flag, value in (
            ("--model", o.model),
            ("--provider", o.provider),
            ("--base-url", o.base_url),
            ("--toolsets", o.toolsets),
            ("--skills", o.skills),
            ("--max-turns", str(o.max_turns) if o.max_turns else None),
        ):
            if value:
                argv += [flag, value]
        session = ctx.instance.session.get("session_id")
        if o.continue_session and session:
            argv += ["--resume", str(session)]
        return argv + list(o.extra_args)

    def uses_stdin(self, ctx: RunContext) -> bool:
        return False

    def parse_line(self, line: str, ctx: RunContext) -> None:
        value = _json_object(line)
        if value is None:
            if line.strip():
                ctx.emit("raw", text=line)
            return
        kind = value.get("type")
        if isinstance(value.get("session_id"), str) and value["session_id"]:
            ctx.instance.session["session_id"] = value["session_id"]
        if kind == "system":
            ctx.emit("status", **_without(value, "type"))
        elif kind == "text":
            ctx.emit("text", text=str(value.get("text", "")), partial=True)
        elif kind == "tool_use":
            ctx.emit(
                "tool_use", tool=value.get("name"), input=value.get("input"), id=value.get("id")
            )
        elif kind == "tool_result":
            ctx.emit("tool_result", **_without(value, "type"))
        elif kind == "result":
            ctx.emit("result", **_without(value, "type"))
        else:
            ctx.emit("raw", data=value)

    def classify(self, exit_code: int | None, reason: str, ctx: RunContext):  # type: ignore[override]
        outcome = super().classify(exit_code, reason, ctx)
        if exit_code == 130 and reason == "exited":
            outcome.state = "cancelled"
            outcome.detail["hermes"] = "interrupted"
        return outcome

    def doctor(self) -> dict[str, Any]:
        found = self.which(self.options.command)
        checks = [
            self.check("executable", bool(found), found or f"{self.options.command} not on PATH")
        ]
        if self.options.config_yaml:
            exists = Path(self.options.config_yaml).expanduser().is_file()
            checks.append(self.check("config_yaml", exists, self.options.config_yaml))
        return {"ok": all(c["ok"] for c in checks), "checks": checks}


def _without(value: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k not in keys and k not in ("seq", "at")}


__all__ = ["HarnessAdapter", "HermesAdapter", "HermesOptions"]
