"""PR scan mode vs batch: GitHub Issues, PR reviews, and remediation PRs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import yaml

from appsec_crew.pipelines import (
    _effective_betterleaks_scan_kind,
    _github_output_urls,
    _is_pr_scan_mode,
    pr_scan_actionable_findings_counts,
    pr_scan_has_actionable_findings,
    pr_scan_summary_for_ci,
    run_code_pipeline,
    run_dependencies_pipeline,
    run_reporter_pipeline,
    run_secrets_pipeline,
)
from appsec_crew.runtime import RuntimeContext
from appsec_crew.settings import load_settings


def _cfg(tmp: Path, agents: dict) -> Path:
    p = tmp / "appsec_crew.yaml"
    p.write_text(
        yaml.safe_dump({"global": {"github": {"token": "file-token"}}, "agents": agents}),
        encoding="utf-8",
    )
    return p


def _ctx(tmp: Path, settings_path: Path, *, pr_number: int | None, event_name: str | None) -> RuntimeContext:
    s = load_settings(settings_path)
    return RuntimeContext(
        settings=s,
        repo_path=tmp,
        state={},
        github_event={},
        pr_number=pr_number,
        github_event_name=event_name,
    )


def test_is_pr_scan_mode_true_for_pull_request_with_pr_number(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=42, event_name="pull_request")
    assert _is_pr_scan_mode(ctx) is True


def test_is_pr_scan_mode_false_without_pr_number(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name=None)
    assert _is_pr_scan_mode(ctx) is False


def test_github_output_urls_merges_issue_pr_review(tmp_path: Path) -> None:
    assert _github_output_urls(
        {
            "issue_urls": ["https://i/1"],
            "pr_url": "https://p/1",
            "semgrep_review_url": "https://r/1",
        }
    ) == ["https://i/1", "https://p/1", "https://r/1"]


def test_secrets_pr_mode_no_issues(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"betterleaks": {"llm_triage": False}},
            },
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=7, event_name="pull_request")
    mock_gh = MagicMock()
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)
    monkeypatch.setattr(
        "appsec_crew.pipelines.run_betterleaks_scan",
        lambda *_a, **_kw: [{"RuleID": "aws-key", "File": "x.env", "StartLine": 2}],
    )
    run_secrets_pipeline(ctx)
    mock_gh.create_issue_deduped.assert_not_called()
    assert ctx.state["secrets_reviewer"]["issue_urls"] == []
    assert ctx.state["secrets_reviewer"]["pr_scan_mode"] is True
    assert ctx.state["secrets_reviewer"]["betterleaks_scan_kind_used"] == "git"


def test_secrets_batch_creates_issue(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"betterleaks": {"llm_triage": False}},
            },
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="schedule")
    mock_gh = MagicMock()
    mock_gh.create_issue_deduped.return_value = ({"html_url": "https://github.com/o/r/issues/99"}, True)
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)
    monkeypatch.setattr(
        "appsec_crew.pipelines.run_betterleaks_scan",
        lambda *_a, **_kw: [{"RuleID": "aws-key", "File": "x.env", "StartLine": 2}],
    )
    run_secrets_pipeline(ctx)
    mock_gh.create_issue_deduped.assert_called_once()
    assert ctx.state["secrets_reviewer"]["issue_urls"] == ["https://github.com/o/r/issues/99"]
    assert ctx.state["secrets_reviewer"]["pr_scan_mode"] is False
    assert ctx.state["secrets_reviewer"]["betterleaks_scan_kind_used"] == "git"


def test_dependencies_pr_mode_no_issue(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"osv_scanner": {"llm_triage": False}},
            },
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=3, event_name="pull_request")
    mock_gh = MagicMock()
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)
    row = {
        "package": {"name": "lodash", "ecosystem": "npm"},
        "vulnerabilities": [
            {"id": "GHSA-xxx", "severity": [{"type": "CVSS_V3", "score": 8.5}]},
        ],
    }
    monkeypatch.setattr("appsec_crew.pipelines.run_osv_scan", lambda *_a, **_kw: [row])
    run_dependencies_pipeline(ctx)
    mock_gh.create_issue_deduped.assert_not_called()
    assert ctx.state["dependencies_reviewer"]["issue_urls"] == []


def test_dependencies_batch_opens_issue_not_pr(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"osv_scanner": {"llm_triage": False}},
            },
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="workflow_dispatch")
    mock_gh = MagicMock()
    mock_gh.create_issue_deduped.return_value = ({"html_url": "https://github.com/o/r/issues/55"}, True)
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)
    row = {
        "package": {"name": "lodash", "ecosystem": "npm"},
        "vulnerabilities": [
            {"id": "GHSA-xxx", "severity": [{"type": "CVSS_V3", "score": 8.5}]},
        ],
    }
    monkeypatch.setattr("appsec_crew.pipelines.run_osv_scan", lambda *_a, **_kw: [row])
    run_dependencies_pipeline(ctx)
    mock_gh.create_issue_deduped.assert_called_once()
    mock_gh.create_pull_request.assert_not_called()
    assert ctx.state["dependencies_reviewer"]["issue_urls"] == ["https://github.com/o/r/issues/55"]


def test_code_pr_mode_review_not_autofix_pr(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"semgrep": {"llm_triage": False}},
            },
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=8, event_name="pull_request")
    mock_gh = MagicMock()
    mock_gh.get_pull_request.return_value = {"head": {"sha": "deadbeef"}}
    mock_gh.create_pull_request_review.return_value = {"html_url": "https://github.com/o/r/pull/8#pullrequestreview-1"}
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)

    finding = {
        "check_id": "python.lang.security",
        "path": "app.py",
        "start": {"line": 4},
        "extra": {"message": "unsafe"},
    }

    def fake_semgrep(*_a, autofix: bool = False, **_k):
        return [] if autofix else [finding]

    monkeypatch.setattr("appsec_crew.pipelines.run_semgrep", fake_semgrep)
    run_code_pipeline(ctx)
    mock_gh.create_pull_request.assert_not_called()
    mock_gh.create_issue_deduped.assert_not_called()
    mock_gh.create_pull_request_review.assert_called_once()
    assert ctx.state["code_reviewer"]["semgrep_review_url"] == "https://github.com/o/r/pull/8#pullrequestreview-1"
    body = mock_gh.create_pull_request_review.call_args.kwargs["body"]
    assert "**Why:**" in body or "unsafe" in body
    assert "findings_markdown" in ctx.state["code_reviewer"]
    assert "app.py:4" in ctx.state["code_reviewer"]["findings_markdown"]


def test_code_batch_opens_issue_when_no_autofix_commit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"semgrep": {"llm_triage": False}},
            },
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="schedule")
    mock_gh = MagicMock()
    mock_gh.create_issue_deduped.return_value = ({"html_url": "https://github.com/o/r/issues/77"}, True)
    mock_gh.get_default_branch.return_value = "main"
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: mock_gh)

    finding = {"check_id": "x", "path": "b.py", "start": {"line": 1}, "extra": {"message": "m"}}

    def fake_semgrep(*_a, autofix: bool = False, **_k):
        return [] if autofix else [finding]

    monkeypatch.setattr("appsec_crew.pipelines.run_semgrep", fake_semgrep)
    monkeypatch.setattr("appsec_crew.pipelines.create_branch", lambda *a, **k: None)
    monkeypatch.setattr("appsec_crew.pipelines.ensure_identity", lambda *a, **k: None)
    monkeypatch.setattr("appsec_crew.pipelines.commit_all", lambda *a, **k: False)

    run_code_pipeline(ctx)
    mock_gh.create_pull_request.assert_not_called()
    mock_gh.create_issue_deduped.assert_called_once()
    assert ctx.state["code_reviewer"]["issue_urls"] == ["https://github.com/o/r/issues/77"]


def _reporter_agents_all_disabled_webhook_on() -> dict:
    return {
        "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
        "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
        "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
        "reporter": {
            "enabled": True,
            "llm": {"api_key": "k"},
            "tools": {
                "jira": {"enabled": False},
                "webhook": {"enabled": True, "url": "https://hooks.example.com/appsec"},
                "splunk": {"enabled": False},
            },
        },
    }


def test_reporter_skips_webhook_in_pr_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(tmp_path, _reporter_agents_all_disabled_webhook_on())
    ctx = _ctx(tmp_path, cfg, pr_number=2, event_name="pull_request")
    mock_post = MagicMock()
    monkeypatch.setattr("appsec_crew.pipelines.post_json", mock_post)
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: MagicMock())
    run_reporter_pipeline(ctx)
    mock_post.assert_not_called()


def test_reporter_calls_webhook_in_batch_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(tmp_path, _reporter_agents_all_disabled_webhook_on())
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="schedule")
    mock_post = MagicMock()
    monkeypatch.setattr("appsec_crew.pipelines.post_json", mock_post)
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: None)
    run_reporter_pipeline(ctx)
    mock_post.assert_called_once()


def test_pr_scan_actionable_findings_counts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": True, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": True, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": True, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=1, event_name="pull_request")
    ctx.state["secrets_reviewer"] = {"executed": True, "skipped": False, "findings_after_triage": 2}
    ctx.state["dependencies_reviewer"] = {"executed": True, "skipped": False, "vulnerable_rows": 3}
    ctx.state["code_reviewer"] = {"executed": True, "skipped": False, "findings": 0}
    assert pr_scan_actionable_findings_counts(ctx) == {"secrets": 2, "dependencies": 3}
    assert pr_scan_has_actionable_findings(ctx) is True


def test_pr_reporter_markdown_includes_failure_appendix(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": True, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=5, event_name="pull_request")
    ctx.state["secrets_reviewer"] = {
        "executed": True,
        "skipped": False,
        "findings_after_triage": 1,
        "issue_urls": [],
        "scanner_findings_total": 1,
        "dismissed_findings": [],
        "commands_executed": [],
        "pr_scan_mode": True,
    }
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: MagicMock())
    run_reporter_pipeline(ctx)
    md = ctx.state["reporter"]["markdown"]
    assert "Pull request check failed" in md
    assert ".betterleaks.toml" in md


def test_pr_scan_summary_for_ci_without_reporter(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {"enabled": True, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=9, event_name="pull_request")
    ctx.state["secrets_reviewer"] = {"executed": True, "skipped": False, "findings_after_triage": 1}
    md = pr_scan_summary_for_ci(ctx)
    assert "Pull request check failed" in md
    assert ".betterleaks.toml" in md


def _agents_all_disabled() -> dict:
    return {
        "secrets_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"betterleaks": {}}},
        "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
        "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
        "reporter": {
            "enabled": False,
            "llm": {"api_key": "k"},
            "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
        },
    }


def test_effective_betterleaks_scan_kind_workflow_dispatch_forces_git(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    cfg = _cfg(tmp_path, _agents_all_disabled())
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="workflow_dispatch")
    assert _effective_betterleaks_scan_kind(ctx, "dir") == "git"


def test_effective_betterleaks_scan_kind_pull_request_forces_git(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    cfg = _cfg(tmp_path, _agents_all_disabled())
    ctx = _ctx(tmp_path, cfg, pr_number=1, event_name="pull_request")
    assert _effective_betterleaks_scan_kind(ctx, "dir") == "git"


def test_effective_betterleaks_scan_kind_falls_back_to_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    cfg = _cfg(tmp_path, _agents_all_disabled())
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name=None)
    assert _effective_betterleaks_scan_kind(ctx, "dir") == "git"


def test_effective_betterleaks_scan_kind_schedule_uses_config(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    cfg = _cfg(tmp_path, _agents_all_disabled())
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="schedule")
    assert _effective_betterleaks_scan_kind(ctx, "dir") == "dir"
    assert _effective_betterleaks_scan_kind(ctx, "git") == "git"


def test_secrets_workflow_dispatch_passes_git_to_betterleaks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    cfg = _cfg(
        tmp_path,
        {
            "secrets_reviewer": {
                "enabled": True,
                "llm": {"api_key": "k"},
                "tools": {"betterleaks": {"llm_triage": False}},
            },
            "dependencies_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"osv_scanner": {}}},
            "code_reviewer": {"enabled": False, "llm": {"api_key": "k"}, "tools": {"semgrep": {}}},
            "reporter": {
                "enabled": False,
                "llm": {"api_key": "k"},
                "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
            },
        },
    )
    ctx = _ctx(tmp_path, cfg, pr_number=None, event_name="workflow_dispatch")
    captured: dict[str, str] = {}

    def capture(_repo, *_a, **kw):
        captured["scan_kind"] = str(kw.get("scan_kind") or "")
        return []

    monkeypatch.setattr("appsec_crew.pipelines.run_betterleaks_scan", capture)
    monkeypatch.setattr("appsec_crew.pipelines._github_client", lambda _s: None)
    run_secrets_pipeline(ctx)
    assert captured["scan_kind"] == "git"
    assert ctx.state["secrets_reviewer"]["betterleaks_scan_kind_used"] == "git"
