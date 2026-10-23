"""Adapter registry.

Built-ins are registered here; third-party packages can add their own through the
``interlink.adapters`` entry-point group, or a config can name one directly with
``adapter = "my_package.module:MyAdapter"``.
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points

from interlink.adapters.base import (
    AdapterOptions,
    HarnessAdapter,
    InstanceView,
    RunContext,
    RunOutcome,
)

BUILTIN: dict[str, str] = {
    "mock": "interlink.adapters.mock:MockAdapter",
    "command": "interlink.adapters.command:CommandAdapter",
    "hermes": "interlink.adapters.hermes:HermesAdapter",
    "claude-code": "interlink.adapters.claude_code:ClaudeCodeAdapter",
    "codex": "interlink.adapters.codex:CodexAdapter",
    "pegasus": "interlink.adapters.pegasus:PegasusAdapter",
}


def _load(target: str) -> type[HarnessAdapter]:
    module_name, _, attribute = target.partition(":")
    if not module_name or not attribute:
        raise ValueError(f"adapter reference must look like 'package.module:Class', got {target!r}")
    cls = getattr(importlib.import_module(module_name), attribute)
    if not (isinstance(cls, type) and issubclass(cls, HarnessAdapter)):
        raise TypeError(f"{target} is not a HarnessAdapter subclass")
    return cls


def available() -> dict[str, str]:
    """Adapter name -> import target, including installed plugins."""
    found = dict(BUILTIN)
    for entry in entry_points(group="interlink.adapters"):
        found.setdefault(entry.name, entry.value)
    return found


def resolve(name: str) -> type[HarnessAdapter]:
    registry = available()
    if name in registry:
        return _load(registry[name])
    if ":" in name:
        return _load(name)
    raise KeyError(f"unknown adapter {name!r}; known: {', '.join(sorted(registry))}")


__all__ = [
    "BUILTIN",
    "AdapterOptions",
    "HarnessAdapter",
    "InstanceView",
    "RunContext",
    "RunOutcome",
    "available",
    "resolve",
]
