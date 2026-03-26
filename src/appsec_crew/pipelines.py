"""Deterministic scan → GitHub issue/PR workflows (invoked by Crew tools)."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from appsec_crew.git_ops import (
    commit_all,
    create_branch,
    ensure_identity,
    push_with_token,
)
from appsec_crew.integrations.github_api import GitHubApi
from appsec_crew.integrations.jira_api import JiraApi, upsert_appsec_ticket
from appsec_crew.integrations.splunk_hec import send_event
from appsec_crew.integrations.webhook_client import post_json
from appsec_crew.runtime import RuntimeContext
from appsec_crew.scanners.betterleaks_scan import run_betterleaks_scan
from appsec_crew.scanners.osv_scan import run_osv_scan
from appsec_crew.scanners.semgrep_scan import build_semgrep_config_args, detect_primary_language, run_semgrep
from appsec_crew.triage_llm import llm_triage_batch, partition_by_dismiss_indices
from appsec_crew.settings import (
    AppSecSettings,
    CodeReviewerSettings,
    DependenciesReviewerSettings,
    SecretsReviewerSettings,
)
from appsec_crew.utils.cvss import max_cvss_score
from appsec_crew.utils.filters import filter_osv_by_min_cvss, filter_semgrep_by_min_severity
from appsec_crew.utils.severity import (
    cvss_floor_for_min_severity,
    human_severity_label,
    include_osv_vuln_without_cvss,
)


def _git_remote_host() -> str:
    u = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return u.replace("https://", "").replace("http://", "").rstrip("/")


def _effective_betterleaks_scan_kind(ctx: RuntimeContext, configured: str) -> str:
    """
    Use ``betterleaks git`` on ``workflow_dispatch`` and ``pull_request`` (full history).

    Otherwise use the configured ``scan_kind`` from YAML (default ``git``; set ``dir`` for working-tree only).
    """
    event = (ctx.github_event_name or os.environ.get("GITHUB_EVENT_NAME") or "").strip()
    if event in ("workflow_dispatch", "pull_request"):
        return "git"
    return configured if configured in ("dir", "git") else "git"


def _is_pr_scan_mode(ctx: RuntimeContext) -> bool:
    """
    True for ``pull_request`` / ``pull_request_target`` with a resolved PR number.

    In this mode we only annotate the **current PR** (summary comment + optional inline Semgrep review);
    we do **not** open GitHub Issues or AppSec-owned remediation PRs. The process **exits non-zero** if any
    enabled scanner still has actionable findings after filters/triage. Jira, webhook, and Splunk are **not**
    invoked (those run only in batch / scheduled mode).
    """
    name = (ctx.github_event_name or os.environ.get("GITHUB_EVENT_NAME") or "").strip()
    if name not in ("pull_request", "pull_request_target"):
        return False
    return ctx.pr_number is not None


def pr_scan_actionable_findings_counts(ctx: RuntimeContext) -> dict[str, int]:
    """
    Per-agent actionable counts in PR context (after severity filters and LLM triage when enabled).

    Only includes enabled agents that executed and were not skipped. Used to fail PR checks and to build
    suppression hints.
    """
    out: dict[str, int] = {}
    s = ctx.settings
    sr = ctx.state.get("secrets_reviewer") or {}
    if s.secrets_reviewer.enabled and sr.get("executed") and not sr.get("skipped"):
        n = int(sr.get("findings_after_triage", sr.get("findings_total", 0)) or 0)
        if n > 0:
            out["secrets"] = n
    dr = ctx.state.get("dependencies_reviewer") or {}
    if s.dependencies_reviewer.enabled and dr.get("executed") and not dr.get("skipped"):
        n = int(dr.get("vulnerable_rows", 0) or 0)
        if n > 0:
            out["dependencies"] = n
    cr = ctx.state.get("code_reviewer") or {}
    if s.code_reviewer.enabled and cr.get("executed") and not cr.get("skipped"):
        n = int(cr.get("findings", 0) or 0)
        if n > 0:
            out["code"] = n
    return out


def pr_scan_has_actionable_findings(ctx: RuntimeContext) -> bool:
    return bool(pr_scan_actionable_findings_counts(ctx))


def pr_scan_summary_for_ci(ctx: RuntimeContext) -> str:
    """
    Markdown for logs when a PR scan fails or when the reporter is disabled.

    Prefer the reporter's body (includes failure appendix when findings) if present.
    """
    rep = ctx.state.get("reporter") or {}
    existing = (rep.get("markdown") or "").strip()
    if existing:
        return str(rep["markdown"])
    text = _markdown_report(ctx)
    if _is_pr_scan_mode(ctx) and pr_scan_has_actionable_findings(ctx):
        text += _pr_scan_findings_failure_appendix(ctx)
    return text


def _pr_scan_findings_failure_appendix(ctx: RuntimeContext) -> str:
    """Markdown block appended to the PR summary when checks must fail on findings."""
    counts = pr_scan_actionable_findings_counts(ctx)
    lines = [
        "",
        "---",
        "",
        "### Pull request check failed",
        "",
        "This run reported **actionable findings** (after `global.min_severity` and optional LLM triage). "
        "Resolve them in code or dependencies, or add **tool-native** allowlists if you accept the risk:",
    ]
    if "secrets" in counts:
        lines.append(
            f"- **Secrets (Betterleaks)** — {counts['secrets']} finding(s): edit **`.betterleaks.toml`** "
            "or **`.gitleaks.toml`** in this repository (paths, rules, allowlists)."
        )
    if "dependencies" in counts:
        lines.append(
            f"- **Dependencies (OSV-Scanner)** — {counts['dependencies']} vulnerable row(s): edit **`osv-scanner.toml`** "
            "(ignore packages or vulnerability IDs per [OSV configuration](https://google.github.io/osv-scanner/configuration/))."
        )
    if "code" in counts:
        lines.append(
            f"- **Code (Semgrep)** — {counts['code']} finding(s): open the **Semgrep PR review** on this PR for "
            "rule, file, line, explanation, and suggested fix (or **Semgrep — detail** in this thread if the review did not post); "
            "suppress via **`.semgrep.yml`** or `# nosemgrep` where appropriate."
        )
    lines += [
        "",
        "AppSec Crew does not encode suppressions in `appsec_crew.yaml`; use each scanner’s native config in the repo.",
    ]
    return "\n".join(lines)


def _format_osv_rows_for_issue(rows: list[dict[str, Any]], cvss_min: float, label: str) -> str:
    lines: list[str] = [
        f"Automated **OSV-Scanner** report from AppSec Crew (minimum severity **{label}**, "
        f"CVSS floor **{cvss_min}** when scored).\n",
        "Ignored packages / IDs: configure `osv-scanner.toml` in this repository.\n",
        "### Vulnerable package rows\n",
    ]
    for row in rows[:100]:
        pkg = row.get("package") if isinstance(row.get("package"), dict) else {}
        name = pkg.get("name") or "?"
        eco = pkg.get("ecosystem") or "?"
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)][:20]
        vids = [str(v.get("id") or "?") for v in vulns]
        lines.append(f"- **{name}** (`{eco}`): {', '.join(vids) if vids else '(no id)'}")
    if len(rows) > 100:
        lines.append(f"\n… and **{len(rows) - 100}** more row(s).")
    return "\n".join(lines)


def _semgrep_finding_line(finding: dict[str, Any]) -> int | None:
    start = finding.get("start")
    if isinstance(start, dict):
        line = start.get("line")
        if isinstance(line, int) and line > 0:
            return line
    return None


def _semgrep_repo_relative_path(path: str | None) -> str:
    """Strip GITHUB_WORKSPACE / Actions `.../work/owner/repo/` so PR comments show repo-relative paths."""
    if not path:
        return ""
    p = str(path).replace("\\", "/")
    ws = os.environ.get("GITHUB_WORKSPACE")
    if ws:
        w = str(ws).rstrip("/").replace("\\", "/")
        if p == w:
            return ""
        if p.startswith(w + "/"):
            return p[len(w) + 1 :]
    if "/work/" in p:
        tail = p.split("/work/", 1)[1]
        parts = tail.split("/")
        if len(parts) >= 3:
            return "/".join(parts[2:])
    return p


def _semgrep_finding_severity(finding: dict[str, Any]) -> str:
    extra = finding.get("extra")
    if not isinstance(extra, dict):
        return "UNKNOWN"
    s = extra.get("severity")
    if isinstance(s, str) and s.strip():
        return s.strip().upper()
    return "UNKNOWN"


def _semgrep_finding_fix(extra: dict[str, Any]) -> str | None:
    fix = extra.get("fix")
    if isinstance(fix, str) and fix.strip():
        return fix.strip()
    return None


def _semgrep_finding_references(extra: dict[str, Any]) -> list[str]:
    meta = extra.get("metadata")
    if not isinstance(meta, dict):
        return []
    out: list[str] = []
    refs = meta.get("references")
    if isinstance(refs, list):
        for r in refs[:6]:
            if isinstance(r, str) and r.strip():
                out.append(r.strip())
            elif isinstance(r, dict):
                u = r.get("url")
                if isinstance(u, str) and u.strip():
                    out.append(u.strip())
    elif isinstance(refs, str) and refs.strip():
        out.append(refs.strip())
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        for c in cwe[:4]:
            if isinstance(c, str) and c.strip():
                out.append(c.strip())
    elif isinstance(cwe, str) and cwe.strip():
        out.append(cwe.strip())
    return out[:6]


def _semgrep_fix_fence_lang(display_path: str) -> str:
    pl = display_path.lower()
    if pl.endswith((".yml", ".yaml")):
        return "yaml"
    if pl.endswith(".py"):
        return "python"
    if pl.endswith((".js", ".ts", ".tsx", ".jsx")):
        return "typescript"
    return ""


def _semgrep_inline_comment_body(finding: dict[str, Any]) -> str:
    chk = finding.get("check_id") or "?"
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    msg = (extra.get("message") or "").strip()
    sev = _semgrep_finding_severity(finding)
    fix = _semgrep_finding_fix(extra)
    disp = _semgrep_repo_relative_path(str(finding.get("path") or ""))
    lines = [
        f"**Semgrep** · `{chk}` · **{sev}**",
        "",
        msg or "_No rule description._",
    ]
    if fix:
        lang = _semgrep_fix_fence_lang(disp)
        fx = fix if len(fix) <= 2000 else fix[:1997] + "..."
        fence = lang or "text"
        lines.extend(["", "**Suggested fix:**", "", f"```{fence}", fx, "```"])
    else:
        lines.extend(
            [
                "",
                "**Suggested fix:** Semgrep did not emit one. Narrow rules in `.semgrep.yml`, use `# nosemgrep` on the "
                "flagged line, or refactor so user-controlled values are not expanded into `run:` / `script:` steps.",
            ]
        )
    return "\n".join(lines)


def _semgrep_findings_curated_section(findings: list[dict[str, Any]], *, max_items: int = 25) -> str:
    """Human-oriented Semgrep report (same core fields Semgrep shows, without runner absolute paths)."""
    chunks: list[str] = []
    for i, f in enumerate(findings[:max_items], start=1):
        disp = _semgrep_repo_relative_path(str(f.get("path") or ""))
        line = _semgrep_finding_line(f)
        loc = f"`{disp}:{line}`" if (disp and line) else (f"`{disp}`" if disp else "`(unknown path)`")
        chk = f.get("check_id") or "?"
        extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        msg = (extra.get("message") or "").strip() or "_No description._"
        sev = _semgrep_finding_severity(f)
        fix = _semgrep_finding_fix(extra)
        refs = _semgrep_finding_references(extra)
        block = [
            f"### {i}. {loc}",
            "",
            f"- **Rule:** `{chk}`",
            f"- **Severity:** {sev}",
            f"- **Why:** {msg}",
        ]
        if fix:
            lang = _semgrep_fix_fence_lang(disp)
            fx = fix if len(fix) <= 4000 else fix[:3997] + "..."
            fence = lang or "text"
            block.extend(["- **Suggested fix:**", "", f"```{fence}", fx, "```"])
        else:
            block.append(
                "- **Suggested fix:** _None from Semgrep._ Adjust the workflow or YAML, add `# nosemgrep`, or exclude the "
                "rule/path in `.semgrep.yml` if you accept the risk."
            )
        if refs:
            ref_bits: list[str] = []
            for r in refs:
                if r.startswith("http://") or r.startswith("https://"):
                    ref_bits.append(f"<{r}>")
                else:
                    ref_bits.append(f"`{r}`")
            block.append("- **References:** " + " · ".join(ref_bits))
        chunks.append("\n".join(block))
    more = ""
    if len(findings) > max_items:
        more = f"\n\n_Showing **{max_items}** of **{len(findings)}** findings; see the workflow log for the full JSON._\n"
    return "\n\n".join(chunks) + more


def _post_semgrep_pr_review(
    gh: GitHubApi,
    pr_number: int,
    findings: list[dict[str, Any]],
) -> str | None:
    """Post a PR review with inline comments where possible; fall back to issue comment. Returns review URL or None."""
    try:
        pr_data = gh.get_pull_request(pr_number)
        commit_id = (pr_data.get("head") or {}).get("sha")
        if not commit_id:
            return None
    except Exception:
        return None

    max_inline = 25
    curated = _semgrep_findings_curated_section(findings, max_items=25)
    comments: list[dict[str, Any]] = []
    for f in findings[:max_inline]:
        raw_path = f.get("path")
        line = _semgrep_finding_line(f)
        rel = _semgrep_repo_relative_path(str(raw_path) if raw_path else "")
        if not rel or line is None:
            continue
        comments.append(
            {
                "path": rel,
                "line": line,
                "body": _semgrep_inline_comment_body(f),
            }
        )

    body = (
        "### AppSec Crew — Semgrep\n\n"
        f"**{len(findings)}** finding(s) after severity filter and triage. "
        f"**{len(comments)}** inline comment(s) on lines that are part of this PR diff (max {max_inline}).\n\n"
        + curated
    )
    try:
        review = gh.create_pull_request_review(
            pr_number,
            commit_id=str(commit_id),
            body=body,
            comments=comments if comments else None,
        )
        url = review.get("html_url")
        return str(url) if url else None
    except Exception:
        try:
            gh.create_pr_comment(pr_number, body)
        except Exception:
            pass
        return None


def _github_output_urls(agent: dict[str, Any]) -> list[str]:
    """Collect non-empty GitHub URLs from agent state (issues, PRs, PR reviews)."""
    out: list[str] = []
    for u in agent.get("issue_urls") or []:
        if u:
            out.append(str(u))
    for key in ("pr_url", "semgrep_review_url"):
        v = agent.get(key)
        if v:
            out.append(str(v))
    return out


def _triage_secrets_findings(
    sr: SecretsReviewerSettings, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not findings or not sr.llm_triage_findings or not sr.llm.api_key:
        return findings, []
    items = []
    for i, f in enumerate(findings):
        rid = f.get("RuleID") or f.get("rule_id") or "?"
        path = f.get("File") or f.get("file") or "?"
        line = f.get("StartLine") or f.get("line") or "?"
        items.append({"index": i, "rule_id": rid, "path": str(path), "line": line})
    guidance = (
        "Dismiss likely false positives: mocks/examples/placeholders, test fixtures, sample `.env` in docs, "
        "strings clearly labeled fake, or paths that cannot hold production secrets."
    )
    meta = llm_triage_batch(
        sr.llm,
        agent_role="secrets reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(findings, meta)


def _triage_osv_rows(
    dr: DependenciesReviewerSettings, rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not rows or not dr.llm_triage_findings or not dr.llm.api_key:
        return rows, []
    items = []
    for i, row in enumerate(rows):
        pkg = row.get("package") if isinstance(row.get("package"), dict) else {}
        vulns = [v for v in (row.get("vulnerabilities") or []) if isinstance(v, dict)][:10]
        vid = [str(v.get("id") or "?") for v in vulns]
        items.append(
            {
                "index": i,
                "package": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "vuln_ids": vid,
            }
        )
    guidance = (
        "Dismiss likely false positives: dependency not reachable from shipped code, dev-only tooling with no prod path, "
        "duplicate advisory rows, or package versions not actually built into the artifact."
    )
    meta = llm_triage_batch(
        dr.llm,
        agent_role="dependency vulnerability reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(rows, meta)


def _triage_semgrep_findings(
    cr: CodeReviewerSettings, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not findings or not cr.llm_triage_findings or not cr.llm.api_key:
        return findings, []
    items = []
    for i, f in enumerate(findings):
        extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        items.append(
            {
                "index": i,
                "check_id": f.get("check_id"),
                "path": f.get("path"),
                "message": str(extra.get("message") or "")[:450],
            }
        )
    guidance = (
        "Dismiss likely false positives: test-only code, dead branches, benign patterns, framework boilerplate, "
        "or findings inconsistent with how the application actually uses the flagged code."
    )
    meta = llm_triage_batch(
        cr.llm,
        agent_role="static analysis reviewer",
        items=items,
        guidance=guidance,
    )
    return partition_by_dismiss_indices(findings, meta)


def _public_secret_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        out.append(
            {
                "rule_id": d.get("RuleID") or d.get("rule_id"),
                "path": d.get("File") or d.get("file"),
                "line": d.get("StartLine") or d.get("line"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


def _public_osv_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        pkg = d.get("package") if isinstance(d.get("package"), dict) else {}
        out.append(
            {
                "package": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


def _public_semgrep_dismissals(dismissed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in dismissed:
        out.append(
            {
                "check_id": d.get("check_id"),
                "path": d.get("path"),
                "reason": d.get("_dismiss_reason"),
            }
        )
    return out


def _github_client(settings: AppSecSettings) -> GitHubApi | None:
    tok = settings.github_token()
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not tok or not repo:
        return None
    api = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    return GitHubApi(tok, repo, api)


def run_secrets_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.secrets_reviewer.enabled:
        ctx.state["secrets_reviewer"] = {"executed": True, "skipped": True, "issue_urls": []}
        return json.dumps(ctx.state["secrets_reviewer"], indent=2)
    repo = ctx.repo_path
    sr = s.secrets_reviewer
    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "betterleaks.json"
    cfg = Path(sr.betterleaks_config_path) if sr.betterleaks_config_path else None
    commands: list[str] = []
    scan_kind = _effective_betterleaks_scan_kind(ctx, sr.betterleaks_scan_kind)
    raw_findings = run_betterleaks_scan(
        repo,
        sr.betterleaks_binary,
        cfg,
        report,
        scan_kind=scan_kind,
        extra_args=sr.betterleaks_extra_args,
        command_template=sr.betterleaks_command,
        commands_log=commands,
    )
    scanner_total = len(raw_findings)
    findings, dismissed_raw = _triage_secrets_findings(sr, raw_findings)
    dismissed_pub = _public_secret_dismissals(dismissed_raw)
    gh = _github_client(s)
    issue_urls: list[str] = []
    pr_mode = _is_pr_scan_mode(ctx)
    issues_new = 0
    issues_reused = 0
    if gh and findings and not pr_mode:
        for f in findings:
            rid = f.get("RuleID") or f.get("rule_id") or "unknown-rule"
            path = f.get("File") or f.get("file") or "?"
            line = f.get("StartLine") or f.get("line") or "?"
            title = f"[AppSec] Secret finding: {rid}"
            body = (
                "Automated report from **AppSec Crew** (Betterleaks).\n\n"
                f"- **Rule**: `{rid}`\n"
                f"- **Location**: `{path}` line {line}\n"
                "- Secret value is **not** included in this issue.\n"
                "- Ignore paths / allowlists: configure `.betterleaks.toml` / `.gitleaks.toml` in this repository.\n"
            )
            iss, created = gh.create_issue_deduped(title, body, labels=["security", "appsec-crew"])
            if created:
                issues_new += 1
            else:
                issues_reused += 1
            url = iss.get("html_url", "")
            if url and url not in issue_urls:
                issue_urls.append(url)
    ctx.state["secrets_reviewer"] = {
        "betterleaks_scan_kind_used": scan_kind,
        "commands_executed": commands,
        "issue_urls": [u for u in issue_urls if u],
        "pr_scan_mode": pr_mode,
        "scanner_findings_total": scanner_total,
        "findings_after_triage": len(findings),
        "dismissed_findings": dismissed_pub,
        "findings_total": len(findings),
        "github_issues_created_new": issues_new,
        "github_issues_reused_existing": issues_reused,
        "executed": True,
    }
    return json.dumps(ctx.state["secrets_reviewer"], indent=2)


def run_dependencies_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.dependencies_reviewer.enabled:
        ctx.state["dependencies_reviewer"] = {
            "executed": True,
            "skipped": True,
            "pr_url": None,
            "issue_urls": [],
        }
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)
    dr = s.dependencies_reviewer
    repo = ctx.repo_path
    min_lvl = s.min_severity()
    cvss_min = cvss_floor_for_min_severity(min_lvl)
    include_unknown = include_osv_vuln_without_cvss(min_lvl)

    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "osv.json"
    cfg = Path(dr.osv_config_path) if dr.osv_config_path else (repo / "osv-scanner.toml")
    cfg_path = cfg if cfg.is_file() else None
    commands: list[str] = []
    rows = run_osv_scan(
        repo,
        dr.osv_scanner_binary,
        cfg_path,
        report,
        extra_args=dr.osv_scan_extra_args,
        command_template=dr.osv_scan_command,
        commands_log=commands,
    )
    rows = filter_osv_by_min_cvss(rows, cvss_min, max_cvss_score, include_unknown)
    after_cvss = len(rows)
    rows, dismissed_raw = _triage_osv_rows(dr, rows)
    dismissed_pub = _public_osv_dismissals(dismissed_raw)
    ctx.state["dependencies_reviewer"] = {
        "vulnerable_rows": len(rows),
        "scanner_rows_after_cvss": after_cvss,
        "dismissed_findings": dismissed_pub,
        "commands_executed": commands,
        "pr_url": None,
        "issue_urls": [],
        "github_issue_reused_existing": False,
        "executed": True,
    }

    if not rows:
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["dependencies_reviewer"]["error"] = "No GitHub token/repo; skipped GitHub output."
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    if _is_pr_scan_mode(ctx):
        ctx.state["dependencies_reviewer"]["note"] = (
            "PR scan mode: dependency findings are only in the PR summary comment (no GitHub Issue)."
        )
        return json.dumps(ctx.state["dependencies_reviewer"], indent=2)

    label = human_severity_label(min_lvl)
    title = f"[AppSec] OSV-Scanner: {len(rows)} vulnerable package row(s) (min {label})"
    body = _format_osv_rows_for_issue(rows, cvss_min, label)
    iss, created_new = gh.create_issue_deduped(title, body, labels=["security", "appsec-crew", "dependencies"])
    url = iss.get("html_url", "")
    ctx.state["dependencies_reviewer"]["issue_urls"] = [u for u in [url] if u]
    ctx.state["dependencies_reviewer"]["github_issue_reused_existing"] = not created_new
    return json.dumps(ctx.state["dependencies_reviewer"], indent=2)


def run_code_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.code_reviewer.enabled:
        ctx.state["code_reviewer"] = {
            "executed": True,
            "skipped": True,
            "pr_url": None,
            "issue_urls": [],
            "semgrep_review_url": None,
            "findings_markdown": "",
        }
        return json.dumps(ctx.state["code_reviewer"], indent=2)
    cr = s.code_reviewer
    repo = ctx.repo_path
    min_lvl = s.min_severity()
    lang = detect_primary_language(repo)
    cfg_path = Path(cr.semgrep_config_path) if cr.semgrep_config_path else None
    config_args = build_semgrep_config_args(repo, cfg_path, cr.semgrep_extra_configs)
    tmp = Path(tempfile.mkdtemp(prefix="appsec-crew-"))
    report = tmp / "semgrep.json"
    commands: list[str] = []
    findings = run_semgrep(
        repo,
        cr.semgrep_binary,
        config_args,
        report,
        autofix=False,
        extra_args=cr.semgrep_extra_args,
        command_template=cr.semgrep_command,
        commands_log=commands,
    )
    before_min_severity = len(findings)
    findings = filter_semgrep_by_min_severity(findings, min_lvl)
    after_filter = len(findings)
    findings, dismissed_raw = _triage_semgrep_findings(cr, findings)
    dismissed_pub = _public_semgrep_dismissals(dismissed_raw)
    ctx.state["code_reviewer"] = {
        "primary_language": lang,
        "findings": len(findings),
        "semgrep_findings_before_min_severity": before_min_severity,
        "scanner_findings_after_severity": after_filter,
        "dismissed_findings": dismissed_pub,
        "commands_executed": commands,
        "pr_url": None,
        "issue_urls": [],
        "semgrep_review_url": None,
        "findings_markdown": "",
        "github_issue_reused_existing": False,
        "executed": True,
    }

    if not findings:
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    gh = _github_client(s)
    if not gh:
        ctx.state["code_reviewer"]["error"] = "No GitHub token/repo; skipped GitHub output."
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    label = human_severity_label(min_lvl)
    reasons = "\n".join(
        f"- `{f.get('check_id')}` @ `{_semgrep_repo_relative_path(str(f.get('path') or ''))}` — "
        f"{((f.get('extra') or {}).get('message') or '')[:200]}"
        for f in findings[:40]
    )
    if len(findings) > 40:
        reasons += f"\n- … and {len(findings) - 40} more."

    if _is_pr_scan_mode(ctx) and ctx.pr_number is not None:
        ctx.state["code_reviewer"]["findings_markdown"] = _semgrep_findings_curated_section(
            findings, max_items=25
        )
        review_url = _post_semgrep_pr_review(gh, ctx.pr_number, findings)
        ctx.state["code_reviewer"]["semgrep_review_url"] = review_url
        ctx.state["code_reviewer"]["pr_scan_mode"] = True
        ctx.state["code_reviewer"]["note"] = (
            "PR scan mode: Semgrep posted as PR review / comment (no autofix branch or Issues)."
        )
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    ctx.state["code_reviewer"]["pr_scan_mode"] = False
    # Use a flat branch name: a branch named "appsec-crew" blocks "appsec-crew/anything"
    # (Git stores refs as files; parent ref and directory namespace cannot coexist).
    branch = f"appsec-crew-semgrep-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ensure_identity(
        repo,
        os.environ.get("GIT_COMMITTER_NAME", "appsec-crew"),
        os.environ.get("GIT_COMMITTER_EMAIL", "appsec-crew@users.noreply.github.com"),
    )
    create_branch(repo, branch)
    run_semgrep(
        repo,
        cr.semgrep_binary,
        config_args,
        tmp / "semgrep-autofix.json",
        autofix=True,
        extra_args=cr.semgrep_extra_args,
        command_template=cr.semgrep_command,
        commands_log=commands,
    )

    if not commit_all(
        repo,
        f"fix(appsec): Semgrep autofix (min severity {label})\n\nOpened by AppSec Crew.",
    ):
        title = f"[AppSec] Semgrep: {len(findings)} finding(s), no autofix (min {label})"
        body = (
            "Scheduled **AppSec Crew** run: Semgrep reported findings but **no writable autofix** was produced "
            "(rules may not support `--autofix`, or edits did not change tracked files).\n\n"
            f"Primary language: **{lang}**. Minimum severity: **{label}**.\n\n"
            "### Findings (sample)\n"
            f"{reasons}\n\n"
            "Configure ignores in `.semgrep.yml` and severity via `global.min_severity` in `appsec_crew.yaml`.\n"
        )
        iss, created_new = gh.create_issue_deduped(title, body, labels=["security", "appsec-crew", "semgrep"])
        url = iss.get("html_url", "")
        ctx.state["code_reviewer"]["issue_urls"] = [u for u in [url] if u]
        ctx.state["code_reviewer"]["github_issue_reused_existing"] = not created_new
        ctx.state["code_reviewer"]["note"] = (
            "Semgrep did not produce writable autofixes; "
            + (
                "linked existing open GitHub Issue (same title)."
                if not created_new
                else "opened a tracking GitHub Issue."
            )
        )
        return json.dumps(ctx.state["code_reviewer"], indent=2)

    push_with_token(repo, branch, gh.token, gh.owner + "/" + gh.repo, api_host=_git_remote_host())
    base = gh.get_default_branch()
    pr = gh.create_pull_request(
        title=f"fix(appsec): Semgrep autofix (min {label})",
        body=(
            f"Primary detected language: **{lang}**.\n\n"
            f"Minimum severity filter: **{label}** (configure `global.min_severity` in `appsec_crew.yaml`).\n\n"
            "### Findings addressed (sample)\n"
            f"{reasons}\n\n"
            "Rule ignores and paths: use `.semgrep.yml` in this repository.\n\n"
            "Changes were generated with `semgrep scan --autofix`. Please review."
        ),
        head=branch,
        base=base,
    )
    ctx.state["code_reviewer"]["pr_url"] = pr.get("html_url")
    return json.dumps(ctx.state["code_reviewer"], indent=2)


def _markdown_report_pr_scan(ctx: RuntimeContext) -> str:
    """Short PR comment: counts + Semgrep detail; omit long CLI echoes (they stay in the Actions log)."""
    repo = os.environ.get("GITHUB_REPOSITORY") or "unknown/repo"
    min_s = ctx.settings.min_severity().upper()
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    s = ctx.settings
    lines: list[str] = [
        "## AppSec Crew summary",
        "",
        f"`{repo}` · **PR scan** · min severity **{min_s}** · {when}",
        "",
        "### Results",
        "",
    ]
    sr = ctx.state.get("secrets_reviewer") or {}
    if s.secrets_reviewer.enabled and sr.get("executed") and not sr.get("skipped"):
        n = int(sr.get("findings_after_triage", sr.get("findings_total", 0)) or 0)
        raw = sr.get("scanner_findings_total", "n/a")
        bk = sr.get("betterleaks_scan_kind_used")
        bl_suffix = f" (scan: `{bk}`)" if bk else ""
        lines.append(
            f"- **Betterleaks:** {n} finding(s) after triage (scanner raw: **{raw}**){bl_suffix}."
        )
    dr = ctx.state.get("dependencies_reviewer") or {}
    if s.dependencies_reviewer.enabled and dr.get("executed") and not dr.get("skipped"):
        lines.append(f"- **OSV-Scanner:** **{dr.get('vulnerable_rows', 0)}** vulnerable row(s) after CVSS filter + triage.")
    cr = ctx.state.get("code_reviewer") or {}
    if s.code_reviewer.enabled and cr.get("executed") and not cr.get("skipped"):
        lines.append(
            f"- **Semgrep:** **{cr.get('findings', 0)}** finding(s) after filter + triage "
            f"(post-severity, pre-triage: **{cr.get('scanner_findings_after_severity', 'n/a')}**)."
        )
        if cr.get("semgrep_review_url"):
            lines.append(
                f"  - [Semgrep PR review]({cr['semgrep_review_url']}) — **rule, file, line, message, and suggested fix** "
                "(same detail as below, plus inline comments on the diff)."
            )
        fm = (cr.get("findings_markdown") or "").strip()
        if fm and not cr.get("semgrep_review_url"):
            lines.extend(["", "### Semgrep — detail", "", fm])
    lines.extend(
        [
            "",
            "---",
            "",
            "_Tool versions and full scanner commands: see this workflow run’s **log** on GitHub Actions._",
        ]
    )
    return "\n".join(lines)


def _markdown_report_batch(ctx: RuntimeContext) -> str:
    repo = os.environ.get("GITHUB_REPOSITORY") or "unknown/repo"
    min_s = ctx.settings.min_severity().upper()
    run_mode = "**Batch / scheduled** — Issues for secrets & OSV; Semgrep autofix PR or a tracking Issue."
    lines = [
        "## AppSec Crew summary",
        "",
        f"- **Repository**: `{repo}`",
        f"- **Run mode**: {run_mode}",
        f"- **Minimum severity (global)**: **{min_s}**",
        f"- **UTC time**: {datetime.now(timezone.utc).isoformat()}",
        "",
        "- **Tool versions (config)**: "
        f"Betterleaks `{ctx.settings.tool_versions.betterleaks}`, "
        f"OSV-Scanner `{ctx.settings.tool_versions.osv_scanner}`, "
        f"Semgrep `{ctx.settings.tool_versions.semgrep}`",
        "",
    ]
    sr = ctx.state.get("secrets_reviewer") or {}
    bk = sr.get("betterleaks_scan_kind_used")
    if bk:
        lines.append(
            f"- **Betterleaks scan kind (this run)**: `{bk}` — `workflow_dispatch` and `pull_request` "
            "use **`git`** (full history); other events use YAML `scan_kind` (default `git`; set `dir` for tree-only)."
        )
    else:
        lines.append(
            "- **Betterleaks**: not run here (secrets reviewer disabled or skipped before scan). "
            "When it runs, default is `git`; use YAML `scan_kind: dir` for working-tree only."
        )
    lines.extend(
        [
            "- **OSV / Semgrep**: recursive workspace scan (`-r` / `scan` on repo root).",
            "",
            "### secrets-reviewer",
            "",
        ]
    )
    if sr.get("pr_scan_mode"):
        lines.append(
            "- **PR scan mode**: Betterleaks is summarized here only (**no** GitHub Issues opened)."
        )
    sec_new = int(sr.get("github_issues_created_new") or 0)
    sec_reuse = int(sr.get("github_issues_reused_existing") or 0)
    nu = len(sr.get("issue_urls") or [])
    if sec_new or sec_reuse:
        lines.append(
            f"- GitHub Issues linked: **{nu}** unique URL(s) — **{sec_new}** newly created, "
            f"**{sec_reuse}** skipped (open issue with same title already exists) "
            f"(after triage: **{sr.get('findings_after_triage', sr.get('findings_total', 'n/a'))}** actionable; "
            f"scanner raw: **{sr.get('scanner_findings_total', 'n/a')}**)"
        )
    else:
        lines.append(
            f"- Issues opened: {nu} "
            f"(after triage: **{sr.get('findings_after_triage', sr.get('findings_total', 'n/a'))}** actionable; "
            f"scanner raw: **{sr.get('scanner_findings_total', 'n/a')}**)"
        )
    for u in sr.get("issue_urls") or []:
        lines.append(f"  - {u}")
    cmds = sr.get("commands_executed") or []
    if cmds:
        lines.append("- **Tool commands executed:**")
        for c in cmds:
            lines.append(f"  - `{c}`")
    dis = sr.get("dismissed_findings") or []
    if dis:
        lines.append(f"- **Dismissed as likely false positives ({len(dis)}):**")
        for d in dis[:30]:
            lines.append(f"  - {d}")
        if len(dis) > 30:
            lines.append(f"  - … and {len(dis) - 30} more")

    lines += ["", "### dependencies-reviewer", ""]
    dr = ctx.state.get("dependencies_reviewer") or {}
    lines.append(
        f"- Vulnerable dependency rows (after CVSS filter + triage): **{dr.get('vulnerable_rows', 'n/a')}** "
        f"(pre-triage post-filter: **{dr.get('scanner_rows_after_cvss', 'n/a')}**)"
    )
    if dr.get("note"):
        lines.append(f"- Note: {dr['note']}")
    diu = dr.get("issue_urls") or []
    if diu:
        lines.append(f"- **GitHub Issues**: {len(diu)}")
        for u in diu:
            lines.append(f"  - {u}")
        if dr.get("github_issue_reused_existing"):
            lines.append("  - _Reused an existing **open** issue with the same title (no duplicate created)._")
    if dr.get("pr_url"):
        lines.append(f"- PR: {dr['pr_url']}")
    dcmds = dr.get("commands_executed") or []
    if dcmds:
        lines.append("- **Tool commands executed:**")
        for c in dcmds:
            lines.append(f"  - `{c}`")
    ddis = dr.get("dismissed_findings") or []
    if ddis:
        lines.append(f"- **Dismissed dependency rows ({len(ddis)}):**")
        for d in ddis[:25]:
            lines.append(f"  - {d}")

    lines += ["", "### code-reviewer", ""]
    cr = ctx.state.get("code_reviewer") or {}
    lines.append(f"- Primary language: `{cr.get('primary_language', '?')}`")
    lines.append(
        f"- Semgrep findings (after min severity + triage): **{cr.get('findings', 'n/a')}** "
        f"(after severity filter, pre-triage: **{cr.get('scanner_findings_after_severity', 'n/a')}**; "
        f"raw from scan: **{cr.get('semgrep_findings_before_min_severity', 'n/a')}**)"
    )
    if cr.get("pr_scan_mode"):
        lines.append(
            "- **PR scan mode**: Semgrep as PR review / comment (**no** autofix branch or Issue from this run)."
        )
    if cr.get("semgrep_review_url"):
        lines.append(f"- **Semgrep PR review**: {cr['semgrep_review_url']}")
    ciu = cr.get("issue_urls") or []
    if ciu:
        lines.append(f"- **GitHub Issues**: {len(ciu)}")
        for u in ciu:
            lines.append(f"  - {u}")
        if cr.get("github_issue_reused_existing"):
            lines.append("  - _Reused an existing **open** issue with the same title (no duplicate created)._")
    if cr.get("pr_url"):
        lines.append(f"- **Autofix PR**: {cr['pr_url']}")
    if cr.get("note") and not cr.get("pr_scan_mode"):
        lines.append(f"- Note: {cr['note']}")
    ccmds = cr.get("commands_executed") or []
    if ccmds:
        lines.append("- **Tool commands executed:**")
        for c in ccmds:
            lines.append(f"  - `{c}`")
    cdis = cr.get("dismissed_findings") or []
    if cdis:
        lines.append(f"- **Dismissed Semgrep findings ({len(cdis)}):**")
        for d in cdis[:25]:
            lines.append(f"  - {d}")
    return "\n".join(lines)


def _markdown_report(ctx: RuntimeContext) -> str:
    if _is_pr_scan_mode(ctx):
        return _markdown_report_pr_scan(ctx)
    return _markdown_report_batch(ctx)


def run_reporter_pipeline(ctx: RuntimeContext) -> str:
    s = ctx.settings
    if not s.reporter.enabled:
        ctx.state["reporter"] = {"executed": True, "skipped": True, "markdown": ""}
        return "reporter disabled"
    text = _markdown_report(ctx)
    if _is_pr_scan_mode(ctx) and pr_scan_has_actionable_findings(ctx):
        text += _pr_scan_findings_failure_appendix(ctx)
    ctx.state["reporter"] = {"markdown": text, "executed": True}

    gh = _github_client(s)
    if gh and ctx.pr_number:
        gh.create_pr_comment(ctx.pr_number, text)

    repo_name = os.environ.get("GITHUB_REPOSITORY") or "unknown"
    rep = s.reporter
    jira_key = ""
    batch_integrations = not _is_pr_scan_mode(ctx)
    if batch_integrations and rep.jira.enabled and rep.jira.base_url and rep.jira.project_key and rep.jira.email and rep.jira.api_token:
        client = JiraApi(rep.jira.base_url, rep.jira.email, rep.jira.api_token)
        jira_key = upsert_appsec_ticket(
            client,
            rep.jira.project_key,
            repo_name,
            text,
            rep.jira.issue_type,
        )
    ctx.state["reporter"]["jira_ticket"] = jira_key

    sr_st = ctx.state.get("secrets_reviewer") or {}
    dr_st = ctx.state.get("dependencies_reviewer") or {}
    cr_st = ctx.state.get("code_reviewer") or {}
    payload = {
        "date": datetime.now(timezone.utc).isoformat(),
        "repo": repo_name,
        "results": {
            "secrets-reviewer": _github_output_urls(sr_st),
            "dependencies-reviewer": _github_output_urls(dr_st),
            "code-reviewer": _github_output_urls(cr_st),
        },
        "dismissed_counts": {
            "secrets-reviewer": len(sr_st.get("dismissed_findings") or []),
            "dependencies-reviewer": len(dr_st.get("dismissed_findings") or []),
            "code-reviewer": len(cr_st.get("dismissed_findings") or []),
        },
        "jira_ticket": jira_key,
    }

    if batch_integrations and rep.webhook.enabled and rep.webhook.url:
        headers = dict(rep.webhook.headers)
        for hk, ev in (rep.webhook.header_secrets or {}).items():
            val = os.environ.get(ev)
            if val:
                headers[hk] = val
        post_json(rep.webhook.url, payload, headers=headers or None)

    if batch_integrations and rep.splunk.enabled and rep.splunk.hec_url and rep.splunk.token:
        send_event(rep.splunk.hec_url, rep.splunk.token, payload, rep.splunk.source, rep.splunk.sourcetype)

    ctx.state["reporter"]["webhook_payload"] = payload
    return text


def validate_postconditions(ctx: RuntimeContext) -> list[str]:
    errs: list[str] = []
    s = ctx.settings
    for name, enabled in (
        ("secrets_reviewer", s.secrets_reviewer.enabled),
        ("dependencies_reviewer", s.dependencies_reviewer.enabled),
        ("code_reviewer", s.code_reviewer.enabled),
        ("reporter", s.reporter.enabled),
    ):
        if not enabled:
            continue
        st = ctx.state.get(name)
        if not st or not st.get("executed"):
            errs.append(f"Enabled agent '{name}' did not record execution in state.")
    return errs
