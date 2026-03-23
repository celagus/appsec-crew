from appsec_crew.utils.filters import filter_semgrep_by_min_severity
from appsec_crew.utils.severity import cvss_floor_for_min_severity, min_rank_for_semgrep


def test_cvss_floors() -> None:
    assert cvss_floor_for_min_severity("critical") == 9.0
    assert cvss_floor_for_min_severity("high") == 7.0
    assert cvss_floor_for_min_severity("medium") == 4.0
    assert cvss_floor_for_min_severity("low") == 0.0


def test_semgrep_min_rank() -> None:
    assert min_rank_for_semgrep("low") == 0
    assert min_rank_for_semgrep("critical") == 5


def test_filter_semgrep_high_excludes_medium() -> None:
    findings = [
        {"extra": {"severity": "MEDIUM"}},
        {"extra": {"severity": "HIGH"}},
        {"extra": {"severity": "CRITICAL"}},
        {"extra": {"severity": "WARNING"}},
        {"extra": {"severity": "ERROR"}},
    ]
    out = filter_semgrep_by_min_severity(findings, "high")
    assert len(out) == 4


def test_filter_semgrep_high_keeps_missing_severity() -> None:
    """Registry rules often omit severity; they must not be dropped at min_severity high."""
    findings = [
        {"extra": {"message": "no severity field"}},
        {"extra": {"severity": "INFO"}},
        {"extra": {"severity": "HIGH"}},
    ]
    out = filter_semgrep_by_min_severity(findings, "high")
    assert len(out) == 2
    assert out[0]["extra"]["message"] == "no severity field"
    assert out[1]["extra"]["severity"] == "HIGH"


def test_filter_semgrep_critical_only_critical() -> None:
    findings = [
        {"extra": {"severity": "CRITICAL"}},
        {"extra": {"severity": "HIGH"}},
        {"extra": {"severity": "ERROR"}},
    ]
    out = filter_semgrep_by_min_severity(findings, "critical")
    assert len(out) == 1
