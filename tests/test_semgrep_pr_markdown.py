"""Semgrep PR comment helpers: repo-relative paths and curated finding text."""

from __future__ import annotations

import pytest

from appsec_crew.pipelines import (
    _semgrep_findings_curated_section,
    _semgrep_repo_relative_path,
)


def test_semgrep_repo_relative_path_strips_github_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_WORKSPACE", "/home/runner/work/sec-patecatl/sec-patecatl")
    p = "/home/runner/work/sec-patecatl/sec-patecatl/.github/actions/x/action.yml"
    assert _semgrep_repo_relative_path(p) == ".github/actions/x/action.yml"


def test_semgrep_repo_relative_path_strips_work_segment_without_env() -> None:
    p = "/home/runner/work/owner/repo/sub/file.yaml"
    assert _semgrep_repo_relative_path(p) == "sub/file.yaml"


def test_semgrep_findings_curated_section_shows_rule_severity_message_fix() -> None:
    f = {
        "check_id": "yaml.github-actions.security.x",
        "path": ".github/workflows/w.yml",
        "start": {"line": 12},
        "extra": {
            "message": "Shell injection risk from interpolated expression.",
            "severity": "ERROR",
            "fix": "run: echo fixed",
            "metadata": {"cwe": ["CWE-78"], "references": ["https://example.com/rule"]},
        },
    }
    md = _semgrep_findings_curated_section([f], max_items=5)
    assert ".github/workflows/w.yml:12" in md
    assert "yaml.github-actions.security.x" in md
    assert "ERROR" in md
    assert "Shell injection risk" in md
    assert "echo fixed" in md
    assert "CWE-78" in md
    assert "https://example.com/rule" in md


def test_semgrep_findings_curated_truncates_long_lists() -> None:
    findings = [
        {
            "check_id": f"r{i}",
            "path": "p.py",
            "start": {"line": i},
            "extra": {"message": "m", "severity": "WARNING"},
        }
        for i in range(1, 31)
    ]
    md = _semgrep_findings_curated_section(findings, max_items=5)
    assert md.count("### ") == 5
    assert "**5** of **30**" in md
