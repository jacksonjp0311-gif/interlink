from __future__ import annotations

import os
from pathlib import Path

import pytest

from interlink.security import (
    Redactor,
    SecurityError,
    build_environment,
    canonical,
    confine,
    sha256_value,
)


def test_confine_accepts_paths_inside(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    assert confine("a/b.txt", tmp_path) == (tmp_path / "a" / "b.txt").resolve()
    assert confine(tmp_path / "a", tmp_path) == (tmp_path / "a").resolve()


@pytest.mark.parametrize("bad", ["../x", "a/../../x", "", "a\x00b"])
def test_confine_refuses_escapes(tmp_path: Path, bad: str) -> None:
    with pytest.raises(SecurityError):
        confine(bad, tmp_path)


def test_confine_refuses_absolute_outside(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        confine(tmp_path.parent / "elsewhere", tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_confine_refuses_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(SecurityError, match="linked"):
        confine("link/secret.txt", tmp_path)


def test_confine_must_exist(tmp_path: Path) -> None:
    with pytest.raises(SecurityError, match="does not exist"):
        confine("missing", tmp_path, must_exist=True)


def test_environment_is_allow_list_only() -> None:
    source = {
        "PATH": "/bin",
        "HOME": "/real/home",
        "RANDOM_THING": "x",
        "OPENAI_API_KEY": "sk-zzzzzz",
    }
    env = build_environment(source=source, redirects={"HOME": "/sandbox/home"})
    assert env["PATH"] == "/bin"
    assert env["HOME"] == "/sandbox/home"
    assert "RANDOM_THING" not in env
    assert "OPENAI_API_KEY" not in env
    assert env["PYTHONUTF8"] == "1"


def test_pass_env_and_secrets() -> None:
    source = {"PATH": "/bin", "FOO": "1", "OPENAI_API_KEY": "sk-zzzzzz"}
    env = build_environment(source=source, pass_env=["FOO"], secrets=["OPENAI_API_KEY"])
    assert env["FOO"] == "1"
    assert env["OPENAI_API_KEY"] == "sk-zzzzzz"


def test_credential_names_must_be_declared_as_secrets() -> None:
    with pytest.raises(SecurityError, match="secrets"):
        build_environment(source={"GITHUB_TOKEN": "x"}, pass_env=["GITHUB_TOKEN"])


def test_redirects_beat_literal_env() -> None:
    env = build_environment(source={}, set_env={"HOME": "/evil"}, redirects={"HOME": "/sandbox"})
    assert env["HOME"] == "/sandbox"


@pytest.mark.parametrize("name", ["1BAD", "has space", "a=b", ""])
def test_invalid_env_names(name: str) -> None:
    with pytest.raises(SecurityError):
        build_environment(source={}, set_env={name: "x"})


def test_redactor_scrubs_nested_values() -> None:
    redactor = Redactor({"API_KEY": "supersecretvalue", "SHORT": "abc"})
    assert redactor.scrub("token=supersecretvalue!") == "token=[REDACTED:API_KEY]!"
    assert redactor.scrub_value({"a": ["supersecretvalue"], "b": 3}) == {
        "a": ["[REDACTED:API_KEY]"],
        "b": 3,
    }
    assert redactor.scrub("abc") == "abc"  # too short to redact safely


def test_canonical_hash_is_order_independent() -> None:
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})
    assert sha256_value({"b": 1, "a": 2}) == sha256_value({"a": 2, "b": 1})
