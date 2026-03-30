#!/usr/bin/env python3
"""
Fail CI if OSV-Scanner reports package rows at or above a min_severity floor (default: medium / CVSS 4.0).

Uses the same CVSS handling as AppSec Crew (``max_cvss_score`` + ``filter_osv_by_min_cvss``).
On failure, prints actionable detail to stderr for developers (package, lockfile path, IDs, scores).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from appsec_crew.scanners.osv_scan import _flatten_osv_results
from appsec_crew.utils.cvss import max_cvss_score
from appsec_crew.utils.filters import filter_osv_by_min_cvss
from appsec_crew.utils.severity import cvss_floor_for_min_severity, include_osv_vuln_without_cvss

_MAX_ROWS_PRINT = 60
_MAX_VULNS_PER_ROW = 15
# osv-scanner path or basename only; disallow shell metacharacters / injection.
_OSV_BINARY_RE = re.compile(r"^[\w./+~-]+$")


def _validated_osv_binary(name: str) -> str:
    s = name.strip()
    if not s or len(s) > 512 or not _OSV_BINARY_RE.fullmatch(s):
        raise SystemExit(
            "Invalid --binary: use a short path or basename with only letters, digits, "
            "._-~/+ (no spaces or shell metacharacters)."
        )
    return s


def _osv_dev_link(vuln_id: str) -> str:
    vid = (vuln_id or "").strip()
    if not vid or vid == "?":
        return ""
    return f"https://osv.dev/vulnerability/{vid}"


def _print_findings_detail(rows: list[dict[str, Any]], *, floor: float, min_label: str) -> None:
    w = sys.stderr.write
    w("\n")
    w("=" * 72 + "\n")
    w(f"OSV-Scanner: {len(rows)} package row(s) at or above min severity {min_label!r} (CVSS floor {floor})\n")
    w("Fix: upgrade dependencies, or allowlist in osv-scanner.toml (see https://google.github.io/osv-scanner/configuration/)\n")
    w("=" * 72 + "\n")

    shown = 0
    for row in rows:
        if shown >= _MAX_ROWS_PRINT:
            break
        pkg = row.get("package") if isinstance(row.get("package"), dict) else {}
        name = pkg.get("name") or "?"
        eco = pkg.get("ecosystem") or "?"
        version = pkg.get("version")
        ver_s = f"@{version}" if version not in (None, "") else ""

        loc = ""
        src = row.get("source")
        if isinstance(src, dict):
            p = src.get("path")
            if isinstance(p, str) and p.strip():
                loc = f"\n  source: {p.strip()}"
        group = row.get("group")
        if isinstance(group, str) and group.strip():
            loc += f"\n  group: {group.strip()}"

        w(f"\n--- {shown + 1}. {name}{ver_s} ({eco}){loc}\n")

        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)]
        for j, v in enumerate(vulns[:_MAX_VULNS_PER_ROW]):
            vid = str(v.get("id") or "?")
            sc = max_cvss_score(v)
            sc_s = f"CVSS max {sc:.1f}" if sc is not None else "CVSS n/a"
            link = _osv_dev_link(vid)
            line = f"  - {vid} ({sc_s})"
            if link:
                line += f"\n    {link}"
            summary = v.get("summary")
            if isinstance(summary, str) and summary.strip():
                short = summary.strip().replace("\n", " ")
                if len(short) > 160:
                    short = short[:157] + "..."
                line += f"\n    {short}"
            w(line + "\n")

        if len(vulns) > _MAX_VULNS_PER_ROW:
            w(f"  … and {len(vulns) - _MAX_VULNS_PER_ROW} more vuln(s) in this row\n")
        shown += 1

    if len(rows) > _MAX_ROWS_PRINT:
        w(f"\n… and {len(rows) - _MAX_ROWS_PRINT} more package row(s) not listed (raise _MAX_ROWS_PRINT in script if needed)\n")
    w("\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path.cwd(), help="Repository root to scan")
    p.add_argument(
        "--min-severity",
        default="medium",
        choices=("low", "medium", "high", "critical"),
        help="Minimum CVSS band (default: medium ≈ 4.0)",
    )
    p.add_argument("--binary", default="osv-scanner", help="osv-scanner executable on PATH")
    args = p.parse_args()

    repo = args.repo.resolve()
    if not repo.is_dir():
        raise SystemExit(f"Not a directory: {repo}")
    binary = _validated_osv_binary(args.binary)
    report = Path(tempfile.mkdtemp(prefix="osv-ci-")) / "osv.json"
    cfg = repo / "osv-scanner.toml"
    cmd = [binary, "scan"]
    if cfg.is_file():
        cmd += ["--config", str(cfg)]
    cmd += ["-r", "-f", "json", "--output", str(report), str(repo)]
    proc = subprocess.run(cmd, cwd=repo, text=True, capture_output=True) # nosemgrep
    if proc.returncode not in (0, 1):
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode

    if not report.is_file():
        print("OSV-Scanner: no report file written.", file=sys.stderr)
        return 2

    raw = report.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        print("OSV-Scanner: empty report.", file=sys.stderr)
        return 0

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"OSV-Scanner: invalid JSON: {e}", file=sys.stderr)
        return 2

    rows = _flatten_osv_results(data) if isinstance(data, dict) else []
    floor = cvss_floor_for_min_severity(args.min_severity)
    inc = include_osv_vuln_without_cvss(args.min_severity)
    bad = filter_osv_by_min_cvss(rows, floor, max_cvss_score, inc)

    if bad:
        _print_findings_detail(bad, floor=floor, min_label=args.min_severity)
        return 1

    print(
        f"OSV-Scanner: no rows at or above {args.min_severity!r} (CVSS floor {floor}).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
