"""Semgrep scan, severity filtering, and primary language hint."""

from __future__ import annotations

import json
import shlex
from collections import Counter
from pathlib import Path
from typing import Any

from appsec_crew.scanners.subprocess_run import run_scanner


LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": (".py", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go": (".go",),
    "java": (".java",),
    "kotlin": (".kt", ".kts"),
    "ruby": (".rb",),
    "php": (".php",),
    "csharp": (".cs",),
    "rust": (".rs",),
}


def detect_primary_language(repo: Path, max_files: int = 8000) -> str:
    counts: Counter[str] = Counter()
    n = 0
    for path in repo.rglob("*"):
        if not path.is_file() or n >= max_files:
            break
        if ".git" in path.parts or "node_modules" in path.parts or "vendor" in path.parts:
            continue
        suf = path.suffix.lower()
        for lang, exts in LANG_EXTENSIONS.items():
            if suf in exts:
                counts[lang] += 1
                n += 1
                break
    if not counts:
        return "python"
    return counts.most_common(1)[0][0]


def build_semgrep_config_args(repo: Path, configured: Path | None, extras: list[str]) -> list[str]:
    """Return flattened `--config` CLI args (repo YAML first, then registry packs from `extras`)."""
    args: list[str] = []
    if configured and configured.is_file():
        args += ["--config", str(configured)]
    else:
        for candidate in (repo / ".semgrep.yml", repo / ".semgrep.yaml"):
            if candidate.is_file():
                args += ["--config", str(candidate)]
                break
    for e in extras:
        if e:
            args += ["--config", str(e)]
    return args


def build_semgrep_command(
    repo: Path,
    binary: str,
    config_args: list[str],
    report_path: Path,
    *,
    autofix: bool = False,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
) -> list[str]:
    """
    Default: ``semgrep scan`` over ``repo`` (recursive workspace scan by Semgrep).
    Optional ``command_template``: placeholders ``{binary}``, ``{repo}``, ``{report}``,
    ``{config_args}`` (single string of quoted ``--config …`` tokens), ``{autofix}`` (``--autofix `` or empty).
    """
    cfg_flat = " ".join(shlex.quote(x) for x in config_args)
    autofix_part = "--autofix " if autofix else ""
    if command_template and str(command_template).strip():
        s = str(command_template).format(
            binary=binary,
            repo=str(repo),
            report=str(report_path),
            config_args=cfg_flat,
            autofix=autofix_part,
        )
        return shlex.split(s)
    cmd = [binary, "scan"]
    if autofix:
        cmd.append("--autofix")
    cmd += list(config_args)
    if extra_args:
        cmd += list(extra_args)
    cmd += ["--json", "-o", str(report_path), str(repo)]
    return cmd


def run_semgrep(
    repo: Path,
    binary: str,
    config_args: list[str],
    report_path: Path,
    autofix: bool = False,
    *,
    extra_args: list[str] | None = None,
    command_template: str | None = None,
    commands_log: list[str] | None = None,
) -> list[dict[str, Any]]:
    cmd = build_semgrep_command(
        repo,
        binary,
        config_args,
        report_path,
        autofix=autofix,
        extra_args=extra_args,
        command_template=command_template,
    )
    run_scanner(cmd, cwd=repo, tool_label="semgrep", commands_log=commands_log)
    if not report_path.is_file():
        return []
    raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    res = data.get("results")
    if isinstance(res, list):
        return [x for x in res if isinstance(x, dict)]
    return []
