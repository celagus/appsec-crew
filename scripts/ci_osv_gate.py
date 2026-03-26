#!/usr/bin/env python3
"""
Fail CI if OSV-Scanner reports package rows at or above a min_severity floor (default: medium / CVSS 4.0).

Uses the same CVSS handling as AppSec Crew (``max_cvss_score`` + ``filter_osv_by_min_cvss``).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from appsec_crew.scanners.osv_scan import _flatten_osv_results
from appsec_crew.utils.cvss import max_cvss_score
from appsec_crew.utils.filters import filter_osv_by_min_cvss
from appsec_crew.utils.severity import cvss_floor_for_min_severity, include_osv_vuln_without_cvss


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
    report = Path(tempfile.mkdtemp(prefix="osv-ci-")) / "osv.json"
    cmd = [args.binary, "scan", "-r", "-f", "json", "--output", str(report), str(repo)]
    proc = subprocess.run(cmd, cwd=str(repo), text=True, capture_output=True)
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
        print(
            f"OSV-Scanner: {len(bad)} package row(s) at or above min severity "
            f"{args.min_severity!r} (CVSS floor {floor}).",
            file=sys.stderr,
        )
        return 1

    print(
        f"OSV-Scanner: no rows at or above {args.min_severity!r} (CVSS floor {floor}).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
