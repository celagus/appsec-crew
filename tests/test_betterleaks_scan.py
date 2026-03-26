"""Betterleaks CLI construction."""

from __future__ import annotations

from pathlib import Path

from appsec_crew.scanners.betterleaks_scan import build_betterleaks_command


def test_build_betterleaks_default_uses_git(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    rep = tmp_path / "out.json"
    cmd = build_betterleaks_command(repo, "betterleaks", None, rep)
    assert cmd[1] == "git"
    assert str(rep) in cmd
    assert str(repo) in cmd


def test_build_betterleaks_dir_subcommand(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    rep = tmp_path / "out.json"
    cmd = build_betterleaks_command(repo, "betterleaks", None, rep, scan_kind="dir")
    assert cmd[1] == "dir"


def test_build_betterleaks_unknown_scan_kind_falls_back_to_dir(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    rep = tmp_path / "out.json"
    cmd = build_betterleaks_command(repo, "betterleaks", None, rep, scan_kind="bogus")
    assert cmd[1] == "dir"
