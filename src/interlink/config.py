"""``interlink.toml``: which harnesses exist and how the server behaves.

Lookup order: ``--config`` > ``$INTERLINK_CONFIG`` > ``./interlink.toml`` >
``<user config dir>/interlink/config.toml``. With no file at all you still get the
built-in ``mock`` harness, plus ``hermes``/``claude-code``/``codex`` when those CLIs
are on PATH.
"""

from __future__ import annotations

import os
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from interlink.adapters import HarnessAdapter, resolve
from interlink.security import IS_WINDOWS

AUTO_DETECT = {"hermes": "hermes", "claude-code": "claude", "codex": "codex"}


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state_root: str | None = None
    max_instances: int = Field(8, ge=1, le=256)
    max_concurrent_runs: int = Field(4, ge=1, le=64)
    max_run_timeout_s: float = Field(3600, gt=0, le=86_400)
    keep_workspaces: bool = Field(True, description="Keep stopped workspaces for inspection.")
    auto_detect: bool = Field(True, description="Offer installed hermes/claude/codex CLIs.")


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    server: ServerSettings
    harnesses: dict[str, HarnessAdapter]
    source: Path | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def state_root(self) -> Path:
        if self.server.state_root:
            return Path(os.path.expandvars(self.server.state_root)).expanduser().resolve()
        return default_state_root()


def default_state_root() -> Path:
    if env := os.environ.get("INTERLINK_STATE"):
        return Path(env).expanduser().resolve()
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "interlink"
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "interlink"


def user_config_path() -> Path:
    if IS_WINDOWS:
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "interlink" / "config.toml"


def find_config(explicit: str | os.PathLike[str] | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return path.resolve()
    if env := os.environ.get("INTERLINK_CONFIG"):
        return find_config(env)
    for candidate in (Path.cwd() / "interlink.toml", user_config_path()):
        if candidate.is_file():
            return candidate.resolve()
    return None


def parse(data: dict[str, Any], source: Path | None = None) -> Config:
    unknown = set(data) - {"server", "harness"}
    if unknown:
        raise ConfigError(f"unknown top-level table(s): {', '.join(sorted(unknown))}")
    try:
        server = ServerSettings.model_validate(data.get("server", {}))
    except ValidationError as exc:
        raise ConfigError(f"[server]: {exc}") from exc
    harnesses: dict[str, HarnessAdapter] = {}
    tables = data.get("harness", {})
    if not isinstance(tables, dict):
        raise ConfigError("[harness] must be a table of tables")
    for name, table in tables.items():
        if not isinstance(table, dict) or "adapter" not in table:
            raise ConfigError(f'[harness.{name}] needs an `adapter = "..."` key')
        try:
            cls = resolve(str(table["adapter"]))
            harnesses[name] = cls(name, dict(table))
        except (KeyError, TypeError, ValueError, ImportError) as exc:
            raise ConfigError(f"[harness.{name}]: {exc}") from exc
    notes = []
    if "mock" not in harnesses:
        harnesses["mock"] = resolve("mock")("mock", {"adapter": "mock"})
    if server.auto_detect:
        for adapter, program in AUTO_DETECT.items():
            if adapter not in harnesses and shutil.which(program):
                harnesses[adapter] = resolve(adapter)(adapter, {"adapter": adapter})
                notes.append(f"auto-detected {program} -> harness '{adapter}'")
    return Config(server=server, harnesses=harnesses, source=source, notes=notes)


def load(explicit: str | os.PathLike[str] | None = None) -> Config:
    path = find_config(explicit)
    if path is None:
        return parse({})
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return parse(data, path)


EXAMPLE = """\
# interlink.toml - which agent harnesses Interlink may launch, and how.
# Docs: https://github.com/jacksonjp0311-gif/interlink#configuration

[server]
# state_root = "~/.local/state/interlink"   # where throwaway workspaces live
max_instances = 8
max_concurrent_runs = 4

# Always available: a scripted fake agent. Great for a first run.
[harness.mock]
adapter = "mock"

# Hermes Agent (pip install hermes-agent / see NousResearch docs)
[harness.hermes]
adapter = "hermes"
# model = "anthropic/claude-sonnet-4"
# provider = "openrouter"
secrets = ["OPENROUTER_API_KEY"]   # passed through, and redacted from transcripts
timeout_s = 900

# Any CLI agent: one process per prompt.
# [harness.my-agent]
# adapter = "command"
# argv = ["my-agent", "--prompt-file", "{prompt_file}"]
# output = "text"
"""
