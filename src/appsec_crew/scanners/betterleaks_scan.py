"""Run Betterleaks and parse JSON report."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from appsec_crew.scanners.subprocess_run import run_scanner


def build_betterleaks_command(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
    *,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
) -> list[str]:
    """
    Default: recursive scan of the repo tree via ``betterleaks dir … <repo>`` (Betterleaks walks directories).
    Override with ``command_template`` (placeholders: ``{binary}``, ``{repo}``, ``{report}``, ``{config}``).
    """
    cfg = str(config_path) if config_path and config_path.is_file() else ""
    if command_template and str(command_template).strip():
        s = str(command_template).format(
            binary=binary,
            repo=str(repo),
            report=str(report_path),
            config=cfg,
        )
        return shlex.split(s)
    cmd = [binary, "dir", "--no-banner"]
    if extra_args:
        cmd += list(extra_args)
    if cfg:
        cmd += ["-c", cfg]
    cmd += ["-f", "json", "-r", str(report_path), str(repo)]
    return cmd


def run_betterleaks_scan(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
    *,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
    commands_log: list[str] | None = None,
) -> list[dict[str, Any]]:
    cmd = build_betterleaks_command(
        repo,
        binary,
        config_path,
        report_path,
        extra_args=extra_args,
        command_template=command_template,
    )
    run_scanner(cmd, cwd=repo, tool_label="betterleaks", commands_log=commands_log)
    # exit 1 = leaks found; still write report
    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "leaks", "results", "Issues"):
            v = data.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []
