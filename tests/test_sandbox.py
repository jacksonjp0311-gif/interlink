from __future__ import annotations

import os
from pathlib import Path

import pytest

from interlink.sandbox import Workspace, diff_snapshots, refuse_protected
from interlink.security import SecurityError


def make(tmp_path: Path) -> Workspace:
    (tmp_path / "state" / "instances").mkdir(parents=True)
    return Workspace(tmp_path / "state" / "instances" / "i1").create()


def test_layout_and_redirects(tmp_path: Path) -> None:
    ws = make(tmp_path)
    for path in (ws.work, ws.home, ws.tmp, ws.runs):
        assert path.is_dir()
    env = ws.redirects()
    assert env["HOME"] == str(ws.home) and env["TMPDIR"] == str(ws.tmp)
    assert env["XDG_CONFIG_HOME"].startswith(str(ws.home))


def test_seed_project_copies_and_excludes(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    (project / "src" / "a.py").write_text("print(1)")
    (project / ".git").mkdir()
    (project / ".git" / "HEAD").write_text("ref")
    (project / "node_modules").mkdir()
    (project / "node_modules" / "x.js").write_text("x")
    ws = make(tmp_path)
    assert ws.seed_project(project)["files"] == 2  # .git is kept: agents use git
    assert (ws.work / "src" / "a.py").read_text() == "print(1)"
    assert (ws.work / ".git" / "HEAD").exists() and not (ws.work / "node_modules").exists()
    assert (project / "src" / "a.py").read_text() == "print(1)"  # original untouched


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_seed_project_never_follows_links(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("s")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "leak").symlink_to(secret)
    ws = make(tmp_path)
    ws.seed_project(project)
    assert not (ws.work / "leak").exists()


def test_seed_project_requires_absolute_dir(tmp_path: Path) -> None:
    ws = make(tmp_path)
    with pytest.raises(SecurityError):
        ws.seed_project(Path("relative/dir"))
    with pytest.raises(SecurityError):
        ws.seed_project(tmp_path / "missing")


def test_home_is_never_a_project(tmp_path: Path) -> None:
    with pytest.raises(SecurityError, match="home"):
        refuse_protected(Path.home(), purpose="copied")


def test_seed_files_are_confined(tmp_path: Path) -> None:
    ws = make(tmp_path)
    assert ws.seed_files({"a/b.txt": "hi"}) == 1
    with pytest.raises(SecurityError):
        ws.seed_files({"../escape.txt": "x"})


def test_snapshot_and_diff(tmp_path: Path) -> None:
    ws = make(tmp_path)
    ws.seed_files({"keep.txt": "1", "change.txt": "1", "gone.txt": "1"})
    before = ws.snapshot()
    (ws.work / "change.txt").write_text("2")
    (ws.work / "gone.txt").unlink()
    (ws.work / "new.txt").write_text("n")
    assert diff_snapshots(before, ws.snapshot()) == {
        "added": ["new.txt"],
        "modified": ["change.txt"],
        "deleted": ["gone.txt"],
    }


def test_destroy_refuses_outside_state_root(tmp_path: Path) -> None:
    ws = make(tmp_path)
    with pytest.raises(SecurityError):
        ws.destroy(tmp_path / "other")
    ws.destroy(tmp_path / "state")
    assert not ws.root.exists()


def test_seed_files_are_byte_exact(tmp_path: Path) -> None:
    ws = make(tmp_path)
    ws.seed_files({"lf.txt": "a\nb\n", "crlf.txt": "a\r\nb\r\n"})
    assert (ws.work / "lf.txt").read_bytes() == b"a\nb\n"  # no CRLF on Windows
    assert (ws.work / "crlf.txt").read_bytes() == b"a\r\nb\r\n"  # and no LF elsewhere
