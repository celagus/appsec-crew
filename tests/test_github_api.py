"""GitHub REST client helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from appsec_crew.integrations.github_api import GitHubApi


def test_create_issue_deduped_reuses_open_issue_with_same_title() -> None:
    api = GitHubApi("tok", "o/r", "https://api.github.com")
    get_resp = MagicMock()
    get_resp.raise_for_status = MagicMock()
    get_resp.json.return_value = [
        {"title": "Dup title", "html_url": "https://github.com/o/r/issues/9", "number": 9},
    ]
    with patch("httpx.get", return_value=get_resp) as g:
        with patch("httpx.post") as p:
            issue, created = api.create_issue_deduped("Dup title", "body", labels=["security"])
    assert created is False
    assert issue["html_url"] == "https://github.com/o/r/issues/9"
    p.assert_not_called()
    g.assert_called_once()


def test_create_issue_deduped_creates_when_no_open_match() -> None:
    api = GitHubApi("tok", "o/r", "https://api.github.com")
    get_resp = MagicMock()
    get_resp.raise_for_status = MagicMock()
    get_resp.json.return_value = []
    post_resp = MagicMock()
    post_resp.raise_for_status = MagicMock()
    post_resp.json.return_value = {"html_url": "https://github.com/o/r/issues/10", "title": "New"}
    with patch("httpx.get", return_value=get_resp):
        with patch("httpx.post", return_value=post_resp) as p:
            issue, created = api.create_issue_deduped("New", "b", labels=None)
    assert created is True
    assert issue["html_url"] == "https://github.com/o/r/issues/10"
    p.assert_called_once()


def test_find_open_issue_skips_pull_request_entries() -> None:
    api = GitHubApi("tok", "o/r", "https://api.github.com")
    get_resp = MagicMock()
    get_resp.raise_for_status = MagicMock()
    get_resp.json.return_value = [
        {"title": "Same", "html_url": "https://github.com/o/r/pull/3", "pull_request": {"url": "x"}},
    ]
    post_resp = MagicMock()
    post_resp.raise_for_status = MagicMock()
    post_resp.json.return_value = {"html_url": "https://github.com/o/r/issues/11"}
    with patch("httpx.get", return_value=get_resp):
        with patch("httpx.post", return_value=post_resp):
            issue, created = api.create_issue_deduped("Same", "b", labels=None)
    assert created is True
