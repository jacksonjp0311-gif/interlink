"""Small, boring, security-relevant helpers.

Ported from PEGASUS Interlink and made cross-platform:

* ``canonical`` / ``sha256_*``   - stable JSON and content hashing for receipts.
* ``confine``                    - resolve a path and prove it stays inside a root,
                                   refusing symlinks/junctions on the way.
* ``atomic_write_json``          - write-then-rename so readers never see half a file.
* ``build_environment``          - the env *allow-list*: children get only what is named.
* ``Redactor``                   - scrub known secret values out of captured output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

IS_WINDOWS = os.name == "nt"

# Keys a child process needs to function at all. Nothing else is inherited unless the
# harness config names it explicitly in ``pass_env`` or ``secrets``.
BASE_ENV_POSIX = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM")
BASE_ENV_WINDOWS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)
FIXED_ENV = {
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "NO_COLOR": "1",
}
# Names that look like credentials. They may only cross into a sandbox when listed
# under ``secrets`` (so their values are also redacted from transcripts).
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY)", re.I)
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class SecurityError(ValueError):
    """A request tried to cross a boundary Interlink enforces."""


def canonical(value: Any) -> str:
    """Compact JSON with sorted keys: the same value always hashes the same."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_value(value: Any) -> str:
    return sha256_text(canonical(value))


def sha256_file(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    seen = 0
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            seen += len(block)
            if limit is not None and seen > limit:
                raise SecurityError(f"file exceeds hashing bound: {path.name}")
            digest.update(block)
    return digest.hexdigest()


def is_link(path: Path) -> bool:
    """True for symlinks and, on Windows, any reparse point (junctions included)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def confine(value: str | os.PathLike[str], root: Path, *, must_exist: bool = False) -> Path:
    """Resolve ``value`` (absolute, or relative to ``root``) and require it inside ``root``.

    Refuses NUL bytes, Windows alternate data streams, ``..`` escapes, and any symlink or
    junction between ``root`` and the target. This is how every agent-supplied path is
    checked before Interlink reads or writes it.
    """
    text = os.fspath(value)
    if not text or "\x00" in text:
        raise SecurityError("empty or NUL path refused")
    if IS_WINDOWS and ":" in text[2:]:
        raise SecurityError("alternate data stream path refused")
    base = root.resolve()
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = base / candidate
    # Walk the lexical path first so a link anywhere along the way is caught before
    # resolve() silently follows it.
    lexical = Path(os.path.normpath(candidate))
    relative = None
    for anchor in (Path(os.path.abspath(root)), base):
        try:
            relative = lexical.relative_to(anchor)
            break
        except ValueError:
            continue
    if relative is None:
        raise SecurityError("path escapes its sandbox root")
    current = base
    for part in relative.parts:
        if part in ("..", ""):
            raise SecurityError("path traversal refused")
        current = current / part
        if is_link(current):
            raise SecurityError(f"linked path refused: {part}")
    resolved = current.resolve()
    if resolved != base and base not in resolved.parents:
        raise SecurityError("path escapes its sandbox root")
    if must_exist and not resolved.exists():
        raise SecurityError("path does not exist")
    return resolved


def within(child: Path, parent: Path) -> bool:
    child, parent = child.resolve(), parent.resolve()
    return child == parent or parent in child.parents


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def read_json(path: Path, limit: int = 4 * 1024 * 1024) -> Any:
    if is_link(path):
        raise SecurityError("linked file refused")
    if path.stat().st_size > limit:
        raise SecurityError(f"{path.name} exceeds {limit} bytes")
    return json.loads(path.read_text(encoding="utf-8"))


def base_env_keys() -> tuple[str, ...]:
    return BASE_ENV_WINDOWS if IS_WINDOWS else BASE_ENV_POSIX


def build_environment(
    *,
    pass_env: Iterable[str] = (),
    secrets: Iterable[str] = (),
    set_env: Mapping[str, str] | None = None,
    redirects: Mapping[str, str] | None = None,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a fresh child environment built only from named keys.

    Order of precedence (later wins): base allow-list, ``pass_env``, ``secrets``,
    fixed Python/UTF-8 settings, literal ``set_env`` values, and finally sandbox
    ``redirects`` (HOME, TMP, ...), which nothing can override.
    """
    source = os.environ if source is None else source
    lookup = {key.upper(): key for key in source} if IS_WINDOWS else {key: key for key in source}
    child: dict[str, str] = {}

    def copy(name: str) -> None:
        real = lookup.get(name.upper() if IS_WINDOWS else name)
        if real is not None:
            child[name] = source[real]

    for name in base_env_keys():
        copy(name)
    secret_names = set(secrets)
    for name in pass_env:
        validate_env_name(name)
        if SECRET_NAME.search(name) and name not in secret_names:
            raise SecurityError(
                f"{name} looks like a credential; list it under `secrets` so it is redacted"
            )
        copy(name)
    for name in secret_names:
        validate_env_name(name)
        copy(name)
    child.update(FIXED_ENV)
    for key, value in (set_env or {}).items():
        validate_env_name(key)
        child[key] = str(value)
    for key, value in (redirects or {}).items():
        child[key] = str(value)
    return child


def validate_env_name(name: str) -> None:
    if not ENV_NAME.match(name):
        raise SecurityError(f"invalid environment variable name: {name!r}")


class Redactor:
    """Replace known secret values with ``[REDACTED:NAME]`` in captured text."""

    MIN_LENGTH = 6

    def __init__(self, secrets: Mapping[str, str] | None = None) -> None:
        self._pairs = sorted(
            (
                (value, name)
                for name, value in (secrets or {}).items()
                if len(value) >= self.MIN_LENGTH
            ),
            key=lambda pair: -len(pair[0]),
        )

    @classmethod
    def for_environment(cls, env: Mapping[str, str], names: Iterable[str]) -> Redactor:
        return cls({name: env[name] for name in names if env.get(name)})

    def __bool__(self) -> bool:
        return bool(self._pairs)

    def scrub(self, text: str) -> str:
        for value, name in self._pairs:
            if value in text:
                text = text.replace(value, f"[REDACTED:{name}]")
        return text

    def scrub_value(self, value: Any) -> Any:
        if not self._pairs:
            return value
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.scrub_value(item) for key, item in value.items()}
        return value


def protected_home_paths() -> list[Path]:
    """Directories a sandbox must never be rooted in or copied wholesale from."""
    home = Path.home()
    names = [".ssh", ".aws", ".gnupg", ".codex", ".claude", ".hermes", ".config"]
    paths = [home, *(home / name for name in names)]
    if IS_WINDOWS:
        paths.append(home / "PEGASUS")
    return paths


def platform_label() -> str:
    return f"{sys.platform}-py{sys.version_info.major}.{sys.version_info.minor}"
