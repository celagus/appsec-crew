"""CrewAI tools that invoke deterministic security pipelines."""

from __future__ import annotations

from crewai.tools import BaseTool

from appsec_crew.pipelines import (
    run_code_pipeline,
    run_dependencies_pipeline,
    run_reporter_pipeline,
    run_secrets_pipeline,
)
from appsec_crew.runtime import get_ctx


class SecretsReviewerTool(BaseTool):
    name: str = "secrets_reviewer_workflow"
    description: str = (
        "Runs Betterleaks recursively over the repo workspace, logs the exact CLI to stderr, "
        "optionally LLM-triages if llm_triage is true in YAML, then opens one GitHub issue per remaining finding. "
        "Returns JSON with commands_executed and dismissed_findings. Call once."
    )

    def _run(self) -> str:
        return run_secrets_pipeline(get_ctx())


class DependenciesReviewerTool(BaseTool):
    name: str = "dependencies_reviewer_workflow"
    description: str = (
        "Runs OSV-Scanner recursively on the repo (-r), logs argv (scan + fix), filters by min CVSS, "
        "optional LLM triage if enabled in YAML, applies osv-scanner fix where supported, opens one PR. "
        "Returns JSON with commands_executed and dismissed_findings. Call once."
    )

    def _run(self) -> str:
        return run_dependencies_pipeline(get_ctx())


class CodeReviewerTool(BaseTool):
    name: str = "code_reviewer_workflow"
    description: str = (
        "Detects the dominant source language, runs Semgrep scan on the repo tree (recursive), logs argv, "
        "filters by min severity, optional LLM triage if enabled, applies autofix, opens a PR. "
        "Returns JSON with commands_executed and dismissed_findings. Call once."
    )

    def _run(self) -> str:
        return run_code_pipeline(get_ctx())


class ReporterTool(BaseTool):
    name: str = "reporter_workflow"
    description: str = (
        "Builds Markdown including executed scanner commands and dismissed/triaged findings from prior steps; "
        "optionally comments on the PR, upserts Jira, POSTs webhook (with dismissed_counts), and Splunk HEC. Call once."
    )

    def _run(self) -> str:
        return run_reporter_pipeline(get_ctx())
