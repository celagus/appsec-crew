"""Run OSV-Scanner (v1-style CLI) and flatten package vulnerability rows."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from appsec_crew.scanners.subprocess_run import run_scanner
from appsec_crew.utils.cvss import max_cvss_score


def _flatten_osv_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for block in data.get("results") or []:
        if not isinstance(block, dict):
            continue
        packages = block.get("packages")
        if isinstance(packages, list):
            for pkg_block in packages:
                if isinstance(pkg_block, dict):
                    rows.append(pkg_block)
        else:
            pkg = block.get("package")
            vulns = block.get("vulnerabilities")
            if isinstance(pkg, dict) and isinstance(vulns, list):
                rows.append({"package": pkg, "vulnerabilities": vulns})
    return rows


def build_osv_scan_command(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
    *,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
) -> list[str]:
    """
    Default: ``osv-scanner scan -r`` recursively scans the repository workspace.
    Override with ``command_template`` (``{binary}``, ``{repo}``, ``{report}``, ``{config}``).
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
    cmd = [binary, "scan"]
    if extra_args:
        cmd += list(extra_args)
    if cfg:
        cmd += ["--config", cfg]
    cmd += ["-r", "-f", "json", "--output", str(report_path), str(repo)]
    return cmd


def run_osv_scan(
    repo: Path,
    binary: str,
    config_path: Path | None,
    report_path: Path,
    *,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
    commands_log: list[str] | None = None,
) -> list[dict[str, Any]]:
    cmd = build_osv_scan_command(
        repo,
        binary,
        config_path,
        report_path,
        extra_args=extra_args,
        command_template=command_template,
    )
    run_scanner(cmd, cwd=repo, tool_label="osv-scanner", commands_log=commands_log)

    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if not isinstance(data, dict):
        return []
    return _flatten_osv_results(data)


def high_critical_rows(rows: list[dict[str, Any]], cvss_min: float) -> list[dict[str, Any]]:
    """Keep rows that have at least one vulnerability with CVSS >= cvss_min."""
    out: list[dict[str, Any]] = []
    for row in rows:
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)]
        scores = [max_cvss_score(v) for v in vulns]
        scores = [s for s in scores if s is not None]
        if scores and max(scores) >= cvss_min:
            out.append(row)
    return out


def discover_remediation_targets(repo: Path) -> list[tuple[str, Path]]:
    """
    Return (strategy_hint, path) for osv-scanner fix.
    strategy_hint: lockfile | manifest
    """
    targets: list[tuple[str, Path]] = []
    for pattern, hint in (
        ("package-lock.json", "lockfile"),
        ("pnpm-lock.yaml", "lockfile"),
        ("yarn.lock", "lockfile"),
        ("pom.xml", "manifest"),
    ):
        for p in repo.rglob(pattern):
            if ".git" in p.parts or "node_modules" in p.parts:
                continue
            targets.append((hint, p))
    return targets


def run_osv_fix_inplace(
    lockfile: Path,
    binary: str,
    min_severity: float,
    *,
    extra_args: list[str] | None = None,
    commands_log: list[str] | None = None,
) -> Any:
    cmd = [
        binary,
        "fix",
        "--non-interactive",
        "--strategy",
        "in-place",
        "--min-severity",
        str(min_severity),
    ]
    if extra_args:
        cmd += list(extra_args)
    cmd += ["-L", str(lockfile)]
    return run_scanner(cmd, cwd=lockfile.parent, tool_label="osv-scanner-fix", commands_log=commands_log)


def run_osv_fix_override_pom(
    pom: Path,
    binary: str,
    min_severity: float,
    *,
    extra_args: list[str] | None = None,
    commands_log: list[str] | None = None,
) -> Any:
    cmd = [
        binary,
        "fix",
        "--non-interactive",
        "--strategy",
        "override",
        "--min-severity",
        str(min_severity),
    ]
    if extra_args:
        cmd += list(extra_args)
    cmd += ["-M", str(pom)]
    return run_scanner(cmd, cwd=pom.parent, tool_label="osv-scanner-fix", commands_log=commands_log)
