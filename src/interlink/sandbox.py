"""Throwaway workspaces.

Every instance gets its own directory tree under the Interlink state root::

    <state_root>/instances/<instance_id>/
        instance.json      who/what/when (no secrets)
        work/              the harness's cwd; a *copy* of your project, never the original
        home/              HOME / USERPROFILE / XDG_* / APPDATA point here
        tmp/               TMP / TEMP / TMPDIR point here
        runs/<run_id>/     prompt.txt, events.jsonl, stdout.log, stderr.log

Isolation is filesystem-and-environment level: the harness starts in a copy, sees a
fake home and a filtered environment. It is *not* an OS sandbox - a harness that
deliberately reaches for absolute paths can still touch them. Wrap the harness in a
container/VM (or bubblewrap / sandbox-exec) if you need a hard boundary.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interlink.security import (
    IS_WINDOWS,
    SecurityError,
    confine,
    is_link,
    protected_home_paths,
    sha256_file,
    within,
)

DEFAULT_COPY_EXCLUDES = (
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "target",
    ".DS_Store",
)
MAX_COPY_FILES = 20_000
MAX_COPY_BYTES = 512 * 1024 * 1024
MAX_SEED_FILE = 1024 * 1024
MAX_SNAPSHOT_FILES = 20_000
HASH_LIMIT = 64 * 1024 * 1024


@dataclass
class Workspace:
    root: Path

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def runs(self) -> Path:
        return self.root / "runs"

    def run_dir(self, run_id: str) -> Path:
        path = self.runs / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create(self) -> Workspace:
        self.root.mkdir(parents=True, exist_ok=False)
        for path in (self.work, self.home, self.tmp, self.runs):
            path.mkdir()
        if IS_WINDOWS:
            (self.home / "AppData" / "Roaming").mkdir(parents=True)
            (self.home / "AppData" / "Local").mkdir(parents=True)
        for xdg in (".config", ".local/share", ".cache", ".local/state"):
            (self.home / xdg).mkdir(parents=True, exist_ok=True)
        return self

    def redirects(self) -> dict[str, str]:
        """Environment that points every "where do I keep my stuff" variable inside."""
        home, tmp = str(self.home), str(self.tmp)
        env = {
            "HOME": home,
            "USERPROFILE": home,
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local" / "share"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_STATE_HOME": str(self.home / ".local" / "state"),
            "TMPDIR": tmp,
            "TMP": tmp,
            "TEMP": tmp,
        }
        if IS_WINDOWS:
            env["APPDATA"] = str(self.home / "AppData" / "Roaming")
            env["LOCALAPPDATA"] = str(self.home / "AppData" / "Local")
        return env

    # -- seeding -------------------------------------------------------------------------

    def seed_project(
        self, project: Path, excludes: Iterable[str] = DEFAULT_COPY_EXCLUDES
    ) -> dict[str, int]:
        """Copy ``project`` into ``work/``. The original is only ever read."""
        source = Path(project).expanduser()
        if not source.is_absolute():
            raise SecurityError("project path must be absolute")
        source = source.resolve()
        if not source.is_dir():
            raise SecurityError("project must be an existing directory")
        refuse_protected(source, purpose="copied into a sandbox")
        if within(self.root, source):
            raise SecurityError("project contains the Interlink state root")
        excluded = set(excludes)
        files = 0
        total = 0
        for current, dirs, names in os.walk(source):
            here = Path(current)
            dirs[:] = sorted(d for d in dirs if d not in excluded and not is_link(here / d))
            relative = here.relative_to(source)
            (self.work / relative).mkdir(parents=True, exist_ok=True)
            for name in sorted(names):
                if name in excluded:
                    continue
                path = here / name
                if is_link(path) or not path.is_file():
                    continue  # links and specials are never followed out of the project
                files += 1
                total += path.stat().st_size
                if files > MAX_COPY_FILES or total > MAX_COPY_BYTES:
                    raise SecurityError(
                        f"project exceeds copy bounds ({MAX_COPY_FILES} files / "
                        f"{MAX_COPY_BYTES // (1024 * 1024)} MiB); point at a smaller fixture"
                    )
                shutil.copy2(path, self.work / relative / name)
        return {"files": files, "bytes": total}

    def seed_files(self, files: Mapping[str, str]) -> int:
        """Write small text fixtures (relative path -> content) into ``work/``."""
        for relative, content in files.items():
            if len(content.encode("utf-8")) > MAX_SEED_FILE:
                raise SecurityError(f"seed file too large: {relative}")
            target = confine(relative, self.work)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return len(files)

    # -- observation ---------------------------------------------------------------------

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Relative path -> {size, sha256} for every regular file in ``work/``."""
        result: dict[str, dict[str, Any]] = {}
        for current, dirs, names in os.walk(self.work):
            here = Path(current)
            dirs[:] = sorted(d for d in dirs if not is_link(here / d))
            for name in sorted(names):
                path = here / name
                if is_link(path) or not path.is_file():
                    continue
                if len(result) >= MAX_SNAPSHOT_FILES:
                    return result
                relative = path.relative_to(self.work).as_posix()
                try:
                    result[relative] = {
                        "size": path.stat().st_size,
                        "sha256": sha256_file(path, HASH_LIMIT),
                    }
                except (OSError, SecurityError):
                    result[relative] = {"size": -1, "sha256": None}
        return result

    def destroy(self, state_root: Path) -> None:
        """Delete this workspace. Refuses anything not under ``state_root/instances``."""
        instances = (state_root / "instances").resolve()
        target = self.root.resolve()
        if instances not in target.parents:
            raise SecurityError("refusing to delete outside the Interlink state root")
        if sys.version_info >= (3, 12):
            shutil.rmtree(target, onexc=_force_remove)
        else:  # pragma: no cover
            shutil.rmtree(target, onerror=_force_remove)


def diff_snapshots(
    before: Mapping[str, Mapping[str, Any]], after: Mapping[str, Mapping[str, Any]]
) -> dict[str, list[str]]:
    added = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(
        path
        for path in set(before) & set(after)
        if before[path].get("sha256") != after[path].get("sha256")
    )
    return {"added": added, "modified": modified, "deleted": deleted}


def refuse_protected(path: Path, *, purpose: str) -> None:
    """Refuse the home directory (or anything containing it) and credential stores."""
    resolved = path.resolve()
    home, *stores = protected_home_paths()
    if within(home, resolved):
        raise SecurityError(f"{resolved} contains your home directory and cannot be {purpose}")
    for store in stores:
        target = store.resolve()
        if within(target, resolved) or within(resolved, target):
            raise SecurityError(f"{resolved} overlaps {target} and cannot be {purpose}")


def _force_remove(function: Any, path: str, _info: Any) -> None:
    os.chmod(path, 0o700)
    function(path)
