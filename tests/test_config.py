from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from interlink.config import EXAMPLE, ConfigError, find_config, load, parse


def test_mock_is_always_available() -> None:
    config = parse({"server": {"auto_detect": False}})
    assert set(config.harnesses) == {"mock"}


def test_harness_requires_adapter() -> None:
    with pytest.raises(ConfigError):
        parse({"server": {"auto_detect": False}, "harness": {"x": {"argv": ["a"]}}})


def test_unknown_server_keys_are_rejected() -> None:
    with pytest.raises(ConfigError):
        parse({"server": {"bogus": 1}})


def test_limits_are_validated() -> None:
    with pytest.raises(ConfigError):
        parse({"server": {"max_instances": 0}})


def test_auto_detect_adds_harnesses_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conftest import make_executable

    make_executable(tmp_path / "bin", "hermes", "print('hi')")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    config = parse({})
    assert "hermes" in config.harnesses
    assert "codex" not in config.harnesses


def test_explicit_config_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "a.toml"
    explicit.write_text("[server]\nauto_detect = false\n")
    env_cfg = tmp_path / "b.toml"
    env_cfg.write_text("")
    monkeypatch.setenv("INTERLINK_CONFIG", str(env_cfg))
    assert find_config(explicit) == explicit
    assert find_config(None) == env_cfg


def test_example_template_parses() -> None:
    data = tomllib.loads(EXAMPLE)
    data.setdefault("server", {})["auto_detect"] = False
    parse(data)


def test_load_reads_toml(tmp_path: Path) -> None:
    path = tmp_path / "interlink.toml"
    path.write_text(
        "[server]\nauto_detect = false\nmax_instances = 3\n"
        '[harness.echo]\nadapter = "command"\nargv = ["echo", "{prompt}"]\n'
    )
    config = load(path)
    assert config.server.max_instances == 3
    assert "echo" in config.harnesses


def test_state_root_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTERLINK_STATE", str(tmp_path / "s"))
    assert parse({"server": {"auto_detect": False}}).state_root == (tmp_path / "s")
