"""Map user-facing min_severity (critical|high|medium|low) to CVSS floors and Semgrep ranks."""

from __future__ import annotations

# CVSS v3 approximate bands: LOW 0.1–3.9, MEDIUM 4.0–6.9, HIGH 7.0–8.9, CRITICAL 9.0–10.0
MIN_SEVERITY_CVSS_FLOOR: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.0,
}


def cvss_floor_for_min_severity(level: str) -> float:
    return MIN_SEVERITY_CVSS_FLOOR.get(level.lower(), 7.0)


def include_osv_vuln_without_cvss(level: str) -> bool:
    """When minimum is `low`, keep OSV entries that have no CVSS score."""
    return level.lower() == "low"


# Semgrep: rank findings; higher = more severe.
# WARNING is rank 4 (same band as HIGH/ERROR): many security rules use WARNING for real issues; mapping it to 2
# caused almost everything below CRITICAL to disappear when global.min_severity was ``high``.
_SEMGREP_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "ERROR": 4,
    "WARNING": 4,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}

# Minimum user level -> minimum rank required (inclusive)
_MIN_SEVERITY_SEMGREP_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 0,
}


def semgrep_finding_rank(finding: dict) -> int:
    """
    Map Semgrep JSON finding to a numeric rank.

    ``WARNING`` is treated like HIGH/ERROR (rank 4) for ``min_severity: high`` — Semgrep uses WARNING for many
    security findings. Missing / unknown labels default to HIGH (rank 4). Explicit ``INFO`` / ``LOW`` / ``MEDIUM``
    use the table above.
    """
    raw_ex = finding.get("extra")
    extra = raw_ex if isinstance(raw_ex, dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    sev = (extra.get("severity") or "").strip().upper()
    if not sev and meta.get("severity") is not None:
        sev = str(meta["severity"]).strip().upper()
    if not sev and finding.get("severity") is not None:
        sev = str(finding["severity"]).strip().upper()
    if not sev:
        return _SEMGREP_RANK["HIGH"]
    return _SEMGREP_RANK.get(sev, _SEMGREP_RANK["HIGH"])


def min_rank_for_semgrep(level: str) -> int:
    return _MIN_SEVERITY_SEMGREP_RANK.get(level.lower(), 4)


def human_severity_label(level: str) -> str:
    return level.upper()
