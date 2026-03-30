"""Tests for CVSS helpers."""

from __future__ import annotations

from appsec_crew.utils.cvss import is_high_or_critical, max_cvss_score, severity_bucket


def test_max_cvss_score_cvss_v3() -> None:
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert max_cvss_score(vuln) == 7.5


def test_max_cvss_score_picks_highest() -> None:
    vuln = {
        "severity": [
            {"type": "CVSS_V3", "score": "5.0"},
            {"type": "CVSS_V31", "score": "8.1"},
        ]
    }
    assert max_cvss_score(vuln) == 8.1


def test_max_cvss_score_none_when_missing() -> None:
    assert max_cvss_score({}) is None
    assert max_cvss_score({"severity": [{"type": "OTHER", "score": "9"}]}) is None


def test_max_cvss_score_skips_non_dict_entries() -> None:
    vuln = {"severity": [None, "x", {"type": "CVSS_V3", "score": "6.0"}]}
    assert max_cvss_score(vuln) == 6.0


def test_max_cvss_score_invalid_numeric() -> None:
    vuln = {"severity": [{"type": "CVSS_V3", "score": "not-a-float"}]}
    assert max_cvss_score(vuln) is None


def test_max_cvss_score_cvss_v3_vector_string() -> None:
    """OSV / GitHub often store a CVSS:3.1 vector in ``score`` instead of a float."""
    vuln = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            }
        ]
    }
    assert max_cvss_score(vuln) == 7.5


def test_max_cvss_score_database_specific_github_label() -> None:
    """GHSA entries use CVSS_V4 vectors; use ``database_specific.severity`` when numeric score is absent."""
    vuln = {
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H"}],
        "database_specific": {"severity": "HIGH"},
    }
    assert max_cvss_score(vuln) == 8.0


def test_is_high_or_critical() -> None:
    assert is_high_or_critical(None) is False
    assert is_high_or_critical(6.9) is False
    assert is_high_or_critical(7.0) is True


def test_severity_bucket() -> None:
    assert severity_bucket(None) == "UNKNOWN"
    assert severity_bucket(9.5) == "CRITICAL"
    assert severity_bucket(7.0) == "HIGH"
    assert severity_bucket(4.0) == "MEDIUM"
    assert severity_bucket(3.9) == "LOW"
