from pathlib import Path

import yaml

from appsec_crew.settings import load_settings
from appsec_crew.utils.llm import crew_llm_ready


def _minimal_agents(**overrides) -> dict:
    base = {
        "secrets_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"betterleaks": {}},
        },
        "dependencies_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"osv_scanner": {}},
        },
        "code_reviewer": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"semgrep": {}},
        },
        "reporter": {
            "enabled": False,
            "llm": {"api_key": "x"},
            "tools": {"jira": {"enabled": False}, "webhook": {"enabled": False}, "splunk": {"enabled": False}},
        },
    }
    base.update(overrides)
    return base


def test_global_github_token_file_overrides_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    cfg = tmp_path / "appsec_crew.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "global": {"github": {"token": "from-file"}},
                "agents": _minimal_agents(),
            }
        ),
        encoding="utf-8",
    )
    s = load_settings(cfg)
    assert s.global_settings.github_token == "from-file"


def test_global_github_token_from_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "env-token")
    cfg = tmp_path / "appsec_crew.yaml"
    cfg.write_text(
        yaml.safe_dump({"global": {"github": {}}, "agents": _minimal_agents()}),
        encoding="utf-8",
    )
    s = load_settings(cfg)
    assert s.global_settings.github_token == "env-token"


def test_min_severity_default_high(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    cfg = tmp_path / "appsec_crew.yaml"
    cfg.write_text(yaml.safe_dump({"global": {"github": {}}, "agents": _minimal_agents()}), encoding="utf-8")
    s = load_settings(cfg)
    assert s.min_severity() == "high"


def test_reporter_jira_nested_under_tools(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    agents = _minimal_agents()
    agents["reporter"]["tools"]["jira"] = {
        "enabled": True,
        "base_url": "https://x.atlassian.net",
        "project_key": "SEC",
        "email": "a@b.com",
        "api_token": "tok",
    }
    cfg = tmp_path / "appsec_crew.yaml"
    cfg.write_text(yaml.safe_dump({"global": {"github": {}}, "agents": agents}), encoding="utf-8")
    s = load_settings(cfg)
    assert s.reporter.jira.enabled is True
    assert s.reporter.jira.project_key == "SEC"


def test_llm_yaml_schema_same_for_all_agents(tmp_path: Path, monkeypatch) -> None:
    """Every agent block uses _parse_llm + LlmAgentConfig; fields must match across roles."""
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("CUSTOM_LLM_KEY", "k")
    llm_yaml = {
        "model": "deepseek-chat",
        "api_key_env": "CUSTOM_LLM_KEY",
        "base_url": "https://api.deepseek.com",
        "temperature": 0.25,
        "max_tokens": 4096,
    }
    agents = _minimal_agents()
    for name in ("secrets_reviewer", "dependencies_reviewer", "code_reviewer", "reporter"):
        agents[name]["llm"] = dict(llm_yaml)
    cfg = tmp_path / "appsec_crew.yaml"
    cfg.write_text(yaml.safe_dump({"global": {"github": {}}, "agents": agents}), encoding="utf-8")
    s = load_settings(cfg)
    for block in (s.secrets_reviewer, s.dependencies_reviewer, s.code_reviewer, s.reporter):
        assert block.llm.model == "deepseek-chat"
        assert block.llm.api_key == "k"
        assert block.llm.base_url == "https://api.deepseek.com"
        assert block.llm.temperature == 0.25
        assert block.llm.extra == {"max_tokens": 4096}


def test_crew_llm_ready_respects_disabled_agents(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = Path(__file__).resolve().parent.parent / "appsec_crew.yaml.example"
    s = load_settings(cfg)
    for block in (s.secrets_reviewer, s.dependencies_reviewer, s.code_reviewer, s.reporter):
        block.enabled = False
        block.llm.api_key = None
    assert crew_llm_ready(s) is False

    s.secrets_reviewer.enabled = True
    s.secrets_reviewer.llm.api_key = "x"
    assert crew_llm_ready(s) is True
