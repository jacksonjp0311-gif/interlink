"""The adapter contract. Implement this to plug any agent harness into Interlink.

Two shapes cover everything we have met so far:

* **Command harnesses** run one process per prompt (``hermes chat --oneshot``,
  ``claude -p``, ``codex exec``, your own script). Subclass
  :class:`interlink.adapters.command.CommandAdapter` and usually only override
  ``build_argv`` and ``parse_line``.
* **Host harnesses** keep a long-lived process and talk to it over a channel
  (PEGASUS's named pipe). Subclass :class:`HarnessAdapter` directly and implement
  ``start`` / ``run`` / ``stop``.

Interlink owns everything around the adapter: the throwaway workspace, the filtered
environment, timeouts, cancellation, killing the process tree, event storage,
idempotency and evidence. An adapter only translates.
"""

from __future__ import annotations

import re
import shutil
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from interlink.events import RunLog

if TYPE_CHECKING:
    from interlink.process import ManagedProcess
    from interlink.sandbox import Workspace


class AdapterOptions(BaseModel):
    """Options every harness table in ``interlink.toml`` accepts."""

    model_config = ConfigDict(extra="forbid")

    adapter: str
    description: str = ""
    pass_env: list[str] = Field(default_factory=list, description="Extra env names to inherit.")
    secrets: list[str] = Field(
        default_factory=list, description="Credential env names to inherit; values are redacted."
    )
    env: dict[str, str] = Field(default_factory=dict, description="Literal env values to set.")
    timeout_s: float = Field(600, gt=0, le=86_400, description="Default per-prompt timeout.")
    isolate_home: bool = Field(
        True, description="Point HOME/XDG/APPDATA into the sandbox (recommended)."
    )


@dataclass
class InstanceView:
    """What an adapter may see and remember about its instance."""

    id: str
    harness: str
    workspace: Workspace
    env: dict[str, str]
    session: dict[str, Any] = field(default_factory=dict)  # adapter-owned, persisted
    state: dict[str, Any] = field(default_factory=dict)  # adapter-owned, in-memory only


@dataclass
class RunOutcome:
    state: str  # complete | failed | cancelled | timed_out | error
    exit_code: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)


Spawner = Callable[..., "ManagedProcess"]


@dataclass
class RunContext:
    instance: InstanceView
    run_id: str
    prompt: str
    prompt_file: Path
    run_dir: Path
    log: RunLog
    deadline: float  # time.monotonic() value
    cancelled: threading.Event
    spawn: Spawner

    def emit(self, type_: str, **fields: Any) -> None:
        self.log.emit(type_, **fields)


class HarnessAdapter(ABC):
    """Base class for all adapters."""

    kind: ClassVar[str] = "command"
    summary: ClassVar[str] = ""
    Options: ClassVar[type[AdapterOptions]] = AdapterOptions

    def __init__(self, name: str, options: dict[str, Any] | AdapterOptions) -> None:
        self.name = name
        self.options = (
            options if isinstance(options, AdapterOptions) else self.Options.model_validate(options)
        )

    # -- optional hooks ------------------------------------------------------------------

    def doctor(self) -> dict[str, Any]:
        """Cheap, side-effect-free readiness checks."""
        return {"ok": True, "checks": []}

    def environment(self, workspace: Workspace) -> dict[str, str]:
        """Extra sandbox-specific env (e.g. HERMES_HOME). Applied after the allow-list."""
        return {}

    def prepare(self, instance: InstanceView) -> None:
        """Provision the fresh workspace (write config files, etc.)."""

    def start(self, instance: InstanceView) -> dict[str, Any]:
        """Host harnesses start their long-lived process here."""
        return {}

    @abstractmethod
    def run(self, ctx: RunContext) -> RunOutcome:
        """Deliver ``ctx.prompt`` and stream normalized events until the turn ends.

        Must return promptly once ``ctx.cancelled`` is set or ``ctx.deadline`` passes.
        """

    def stop(self, instance: InstanceView) -> dict[str, Any]:
        return {}

    # -- helpers -------------------------------------------------------------------------

    @staticmethod
    def which(command: str) -> str | None:
        return shutil.which(command)

    @staticmethod
    def check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
        return {"name": name, "ok": bool(ok), "detail": detail}

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "adapter": self.options.adapter,
            "kind": self.kind,
            "description": self.options.description or self.summary,
            "timeout_s": self.options.timeout_s,
            "secrets": list(self.options.secrets),
            "pass_env": list(self.options.pass_env),
        }


def substitute(template: Sequence[str], values: dict[str, str]) -> list[str]:
    """Replace ``{name}`` placeholders inside argv tokens. Unknown braces are left alone.

    Substitution is plain string replacement on a token list - no shell is involved, so
    a prompt can never become extra arguments or a command.
    """
    if not values:
        return list(template)
    pattern = re.compile(r"\{(" + "|".join(re.escape(key) for key in values) + r")\}")
    # One pass per token, so a prompt that itself contains "{workspace}" stays literal.
    return [pattern.sub(lambda match: values[match.group(1)], token) for token in template]
