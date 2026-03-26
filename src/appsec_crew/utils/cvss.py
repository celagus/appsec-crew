"""Extract numeric CVSS scores from OSV-style severity blobs."""

from __future__ import annotations

import math
from typing import Any

# GitHub advisory `database_specific.severity` labels → approximate numeric score for min_severity floors.
_GITHUB_SEVERITY_LABEL_SCORE: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MODERATE": 5.5,
    "MEDIUM": 5.5,
    "LOW": 2.5,
}


def _roundup1(x: float) -> float:
    """CVSS Roundup: smallest value ≥ x with one decimal (FIRST v3.1)."""
    return math.ceil(x * 10.0) / 10.0


def _cvss31_base_score_from_vector(vector: str) -> float | None:
    """
    Compute CVSS v3.0/v3.1 base score from a vector string (e.g. ``CVSS:3.1/AV:N/...``).

    OSV often stores vectors in ``severity[].score`` instead of a numeric score; GitHub may use CVSS_V4 vectors
    only while still providing ``database_specific.severity``.
    """
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    tail = vector.split("/", 1)
    if len(tail) != 2:
        return None
    metrics: dict[str, str] = {}
    for part in tail[1].split("/"):
        if ":" not in part:
            continue
        k, _, v = part.partition(":")
        metrics[k] = v
    need = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metrics for k in need):
        return None
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    scope = metrics["S"]
    pr_n = metrics["PR"]
    if av is None or ac is None or ui is None or scope not in ("U", "C"):
        return None
    if scope == "U":
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    else:
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
    pr = pr_map.get(pr_n)
    if pr is None:
        return None
    cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    c = cia_map.get(metrics["C"])
    i = cia_map.get(metrics["I"])
    a = cia_map.get(metrics["A"])
    if c is None or i is None or a is None:
        return None
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.29) if iss > 0.139 else 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    base = _roundup1(min(impact + exploitability, 10.0))
    return base


def _score_from_severity_entry(entry: dict[str, Any]) -> float | None:
    typ = entry.get("type")
    score = entry.get("score")
    if typ in ("CVSS_V3", "CVSS_V31", "CVSS_V30", "CVSS_V3.1"):
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            score = score.strip()
            try:
                return float(score)
            except ValueError:
                if score.startswith("CVSS:3"):
                    return _cvss31_base_score_from_vector(score)
    return None


def max_cvss_score(vuln: dict[str, Any]) -> float | None:
    """Return the highest CVSS score found on an OSV vulnerability object."""
    severities = vuln.get("severity") or []
    best: float | None = None
    for s in severities:
        if not isinstance(s, dict):
            continue
        cand = _score_from_severity_entry(s)
        if cand is not None:
            best = cand if best is None else max(best, cand)
    if best is None:
        ds = vuln.get("database_specific")
        if isinstance(ds, dict):
            lbl = ds.get("severity")
            if isinstance(lbl, str):
                key = lbl.strip().upper()
                best = _GITHUB_SEVERITY_LABEL_SCORE.get(key)
    return best


def severity_bucket(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def is_high_or_critical(score: float | None, minimum: float = 7.0) -> bool:
    if score is None:
        return False
    return score >= minimum
