"""Load `appsec_crew.yaml` and merge secrets (env default; non-empty YAML overrides)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def bundled_default_config_path() -> Path:
    """Packaged fallback when the scanned repo has no `appsec_crew.yaml` (reporter tools off)."""
    return Path(__file__).resolve().parent / "bundled_appsec_crew.yaml"


def resolve_appsec_config_path(repo: Path, explicit: Path | None) -> tuple[Path, bool]:
    """
    Resolve which YAML to load.

    Order: explicit CLI path (must exist) → ``<repo>/appsec_crew.yaml``
    → ``APPSEC_CREW_CONFIG`` if that file exists → bundled default.

    Returns (path, used_bundled_fallback).
    """
    repo = repo.resolve()

    if explicit is not None:
        exp = explicit.expanduser()
        if not exp.is_file():
            msg = f"Config file not found: {exp}"
            raise FileNotFoundError(msg)
        return exp.resolve(), False

    local = repo / "appsec_crew.yaml"
    if local.is_file():
        return local.resolve(), False

    env_raw = os.environ.get("APPSEC_CREW_CONFIG", "").strip()
    if env_raw:
        env_p = Path(env_raw).expanduser()
        if env_p.is_file():
            return env_p.resolve(), False

    bundled = bundled_default_config_path()
    if bundled.is_file():
        return bundled.resolve(), True

    raise FileNotFoundError(
        f"No appsec_crew.yaml in {repo} and bundled default missing: {bundled}"
    )


def _env_override(key: str) -> str | None:
    v = os.environ.get(key)
    return v if v is not None and v != "" else None


DEFAULT_SEMGREP_EXTRA_CONFIGS: tuple[str, ...] = (
    "auto",
    "p/security-audit",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/java",
    "p/go",
    "p/rust",
)

VALID_MIN_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass
class LlmAgentConfig:
    """
    LLM options for every agent (`secrets_reviewer`, `dependencies_reviewer`, `code_reviewer`, `reporter`).

    YAML keys under ``agents.<role>.llm`` (all roles use the same schema):

    - ``model`` — model id passed to CrewAI ``LLM``
    - ``provider`` — optional CrewAI provider name
    - ``base_url`` — optional API base URL (OpenAI-compatible endpoints)
    - ``api_key`` / ``api_key_env`` — inline key or env var (env used when ``api_key`` empty)
    - ``temperature`` — float
    - Any other keys are kept in ``extra`` and forwarded to ``LLM(...)`` by ``build_llm``
    """

    model: str = "gpt-4o-mini"
    provider: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class GlobalSettings:
    """Repository and API host come from GitHub Actions (`GITHUB_REPOSITORY`, `GITHUB_API_URL`)."""

    min_severity: str = "high"
    github_token: str | None = None
    github_token_env: str = "GITHUB_TOKEN"


@dataclass
class SecretsReviewerSettings:
    enabled: bool = True
    llm: LlmAgentConfig = field(default_factory=LlmAgentConfig)
    betterleaks_binary: str = "betterleaks"
    betterleaks_config_path: str | None = None


@dataclass
class DependenciesReviewerSettings:
    enabled: bool = True
    llm: LlmAgentConfig = field(default_factory=LlmAgentConfig)
    osv_scanner_binary: str = "osv-scanner"
    osv_config_path: str | None = None


@dataclass
class CodeReviewerSettings:
    enabled: bool = True
    llm: LlmAgentConfig = field(default_factory=LlmAgentConfig)
    semgrep_binary: str = "semgrep"
    semgrep_config_path: str | None = None
    semgrep_extra_configs: list[str] = field(default_factory=list)


@dataclass
class JiraToolConfig:
    enabled: bool = False
    base_url: str = ""
    email: str | None = None
    email_env: str = "JIRA_EMAIL"
    api_token: str | None = None
    api_token_env: str = "JIRA_API_TOKEN"
    project_key: str = ""
    issue_type: str = "Task"


@dataclass
class WebhookToolConfig:
    enabled: bool = False
    url: str = ""
    url_env: str = "APPSEC_WEBHOOK_URL"
    headers: dict[str, str] = field(default_factory=dict)
    header_secrets: dict[str, str] = field(default_factory=dict)


@dataclass
class SplunkToolConfig:
    enabled: bool = False
    hec_url: str = ""
    hec_url_env: str = "SPLUNK_HEC_URL"
    token: str | None = None
    token_env: str = "SPLUNK_HEC_TOKEN"
    source: str = "appsec_crew"
    sourcetype: str = "_json"


@dataclass
class ReporterSettings:
    enabled: bool = True
    llm: LlmAgentConfig = field(default_factory=LlmAgentConfig)
    jira: JiraToolConfig = field(default_factory=JiraToolConfig)
    webhook: WebhookToolConfig = field(default_factory=WebhookToolConfig)
    splunk: SplunkToolConfig = field(default_factory=SplunkToolConfig)


@dataclass
class AppSecSettings:
    global_settings: GlobalSettings
    secrets_reviewer: SecretsReviewerSettings
    dependencies_reviewer: DependenciesReviewerSettings
    code_reviewer: CodeReviewerSettings
    reporter: ReporterSettings
    raw: dict[str, Any] = field(default_factory=dict)

    def github_token(self) -> str | None:
        return self.global_settings.github_token

    def min_severity(self) -> str:
        return self.global_settings.min_severity


def _parse_llm(data: dict[str, Any] | None) -> LlmAgentConfig:
    if not data:
        return LlmAgentConfig()
    return LlmAgentConfig(
        model=data.get("model", "gpt-4o-mini"),
        provider=data.get("provider"),
        base_url=data.get("base_url"),
        api_key=data.get("api_key"),
        api_key_env=data.get("api_key_env", "OPENAI_API_KEY"),
        temperature=float(data.get("temperature", 0.0)),
        extra={
            k: v
            for k, v in data.items()
            if k not in {"model", "provider", "base_url", "api_key", "api_key_env", "temperature"}
        },
    )


def _resolve_secret(optional_value: str | None, env_name: str) -> str | None:
    env_val = _env_override(env_name)
    if optional_value is not None and str(optional_value).strip() != "":
        return str(optional_value)
    return env_val


def _load_secrets_reviewer(block: dict[str, Any]) -> SecretsReviewerSettings:
    tools = block.get("tools") or {}
    bl = tools.get("betterleaks") or {}
    return SecretsReviewerSettings(
        enabled=bool(block.get("enabled", True)),
        llm=_parse_llm(block.get("llm")),
        betterleaks_binary=str(bl.get("binary", "betterleaks")),
        betterleaks_config_path=bl.get("config_path"),
    )


def _load_dependencies_reviewer(block: dict[str, Any]) -> DependenciesReviewerSettings:
    tools = block.get("tools") or {}
    osv = tools.get("osv_scanner") or {}
    return DependenciesReviewerSettings(
        enabled=bool(block.get("enabled", True)),
        llm=_parse_llm(block.get("llm")),
        osv_scanner_binary=str(osv.get("binary", "osv-scanner")),
        osv_config_path=osv.get("config_path"),
    )


def _load_code_reviewer(block: dict[str, Any]) -> CodeReviewerSettings:
    tools = block.get("tools") or {}
    sg = tools.get("semgrep") or {}
    raw_extras = sg.get("extra_configs")
    if raw_extras is None:
        extras = list(DEFAULT_SEMGREP_EXTRA_CONFIGS)
    else:
        extras = list(raw_extras)
    return CodeReviewerSettings(
        enabled=bool(block.get("enabled", True)),
        llm=_parse_llm(block.get("llm")),
        semgrep_binary=str(sg.get("binary", "semgrep")),
        semgrep_config_path=sg.get("config_path"),
        semgrep_extra_configs=extras,
    )


def _load_jira_tool(j: dict[str, Any]) -> JiraToolConfig:
    return JiraToolConfig(
        enabled=bool(j.get("enabled", False)),
        base_url=str(j.get("base_url", "") or ""),
        email=j.get("email"),
        email_env=j.get("email_env", "JIRA_EMAIL"),
        api_token=j.get("api_token"),
        api_token_env=j.get("api_token_env", "JIRA_API_TOKEN"),
        project_key=str(j.get("project_key", "") or ""),
        issue_type=str(j.get("issue_type", "Task") or "Task"),
    )


def _load_webhook_tool(w: dict[str, Any]) -> WebhookToolConfig:
    return WebhookToolConfig(
        enabled=bool(w.get("enabled", False)),
        url=str(w.get("url", "") or ""),
        url_env=w.get("url_env", "APPSEC_WEBHOOK_URL"),
        headers=dict(w.get("headers") or {}),
        header_secrets=dict(w.get("header_secrets") or {}),
    )


def _load_splunk_tool(s: dict[str, Any]) -> SplunkToolConfig:
    return SplunkToolConfig(
        enabled=bool(s.get("enabled", False)),
        hec_url=str(s.get("hec_url", "") or ""),
        hec_url_env=s.get("hec_url_env", "SPLUNK_HEC_URL"),
        token=s.get("token"),
        token_env=s.get("token_env", "SPLUNK_HEC_TOKEN"),
        source=str(s.get("source", "appsec_crew") or "appsec_crew"),
        sourcetype=str(s.get("sourcetype", "_json") or "_json"),
    )


def _load_reporter(block: dict[str, Any]) -> ReporterSettings:
    tools = block.get("tools") or {}
    return ReporterSettings(
        enabled=bool(block.get("enabled", True)),
        llm=_parse_llm(block.get("llm")),
        jira=_load_jira_tool(tools.get("jira") or {}),
        webhook=_load_webhook_tool(tools.get("webhook") or {}),
        splunk=_load_splunk_tool(tools.get("splunk") or {}),
    )


def load_settings(path: Path) -> AppSecSettings:
    raw: dict[str, Any] = {}
    if path.is_file():
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raw = {}

    g = raw.get("global") or {}
    gh = g.get("github") or {}
    min_sev = str(g.get("min_severity", "high") or "high").lower()
    if min_sev not in VALID_MIN_SEVERITIES:
        min_sev = "high"

    global_settings = GlobalSettings(
        min_severity=min_sev,
        github_token=gh.get("token"),
        github_token_env=str(gh.get("token_env", "GITHUB_TOKEN") or "GITHUB_TOKEN"),
    )

    agents_block = raw.get("agents") or {}

    settings = AppSecSettings(
        global_settings=global_settings,
        secrets_reviewer=_load_secrets_reviewer(agents_block.get("secrets_reviewer") or {}),
        dependencies_reviewer=_load_dependencies_reviewer(agents_block.get("dependencies_reviewer") or {}),
        code_reviewer=_load_code_reviewer(agents_block.get("code_reviewer") or {}),
        reporter=_load_reporter(agents_block.get("reporter") or {}),
        raw=raw,
    )

    settings.global_settings.github_token = _resolve_secret(
        settings.global_settings.github_token,
        settings.global_settings.github_token_env,
    )

    r = settings.reporter
    if r.jira.enabled:
        r.jira.email = _resolve_secret(r.jira.email, r.jira.email_env)
        r.jira.api_token = _resolve_secret(r.jira.api_token, r.jira.api_token_env)

    if r.webhook.enabled:
        if not str(r.webhook.url or "").strip():
            ev = _env_override(r.webhook.url_env)
            if ev:
                r.webhook.url = ev

    if r.splunk.enabled:
        if not str(r.splunk.hec_url or "").strip():
            ev = _env_override(r.splunk.hec_url_env)
            if ev:
                r.splunk.hec_url = ev
        r.splunk.token = _resolve_secret(r.splunk.token, r.splunk.token_env)

    for block in (
        settings.secrets_reviewer,
        settings.dependencies_reviewer,
        settings.code_reviewer,
        settings.reporter,
    ):
        block.llm.api_key = _resolve_secret(block.llm.api_key, block.llm.api_key_env)

    return settings


def ensure_tool_config_files(repo: Path, settings: AppSecSettings, package_defaults: Path) -> dict[str, str]:
    """
    Copy packaged defaults only when required (Betterleaks placeholder).
    Tool-specific ignores live in the scanned repo (e.g. `.betterleaks.toml`, `osv-scanner.toml`, `.semgrep.yml`).
    """
    _ = settings
    used: dict[str, str] = {}

    bl_repo = repo / ".betterleaks.toml"
    gl_repo = repo / ".gitleaks.toml"
    if not bl_repo.is_file() and not gl_repo.is_file():
        src = package_defaults / ".betterleaks.toml"
        if src.is_file():
            bl_repo.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            used["betterleaks"] = str(bl_repo)

    return used
