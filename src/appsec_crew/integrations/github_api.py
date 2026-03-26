"""Minimal GitHub REST v3 client for issues and pull requests."""

from __future__ import annotations

from typing import Any

import httpx


class GitHubApi:
    def __init__(self, token: str, repository: str, api_url: str | None = None) -> None:
        self.token = token
        self.owner, self.repo = repository.split("/", 1)
        self.api_url = (api_url or "https://api.github.com").rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def get_default_branch(self) -> str:
        r = httpx.get(
            self._url(f"/repos/{self.owner}/{self.repo}"),
            headers=self._headers,
            timeout=60.0,
        )
        r.raise_for_status()
        return str(r.json().get("default_branch") or "main")

    def create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/issues"),
            headers=self._headers,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def find_open_issue_with_exact_title(
        self, title: str, *, max_pages: int = 10
    ) -> dict[str, Any] | None:
        """Return the newest matching **open** issue (not a PR) with this exact title, or ``None``."""
        for page in range(1, max_pages + 1):
            r = httpx.get(
                self._url(f"/repos/{self.owner}/{self.repo}/issues"),
                headers=self._headers,
                params={"state": "open", "per_page": 100, "page": page},
                timeout=60.0,
            )
            r.raise_for_status()
            batch = r.json()
            if not isinstance(batch, list) or not batch:
                return None
            for item in batch:
                if item.get("pull_request"):
                    continue
                if item.get("title") == title:
                    return item
            if len(batch) < 100:
                break
        return None

    def create_issue_deduped(
        self, title: str, body: str, labels: list[str] | None = None
    ) -> tuple[dict[str, Any], bool]:
        """
        Create an issue unless an open issue with the same **exact title** already exists.

        Returns ``(issue_json, created_new)``.
        """
        existing = self.find_open_issue_with_exact_title(title)
        if existing is not None:
            return existing, False
        return self.create_issue(title, body, labels), True

    def create_pull_request(
        self,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, Any]:
        payload = {"title": title, "body": body, "head": head, "base": base}
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls"),
            headers=self._headers,
            json=payload,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def create_pr_comment(self, pr_number: int, body: str) -> dict[str, Any]:
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/issues/{pr_number}/comments"),
            headers=self._headers,
            json={"body": body},
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def get_pull_request(self, pr_number: int) -> dict[str, Any]:
        r = httpx.get(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}"),
            headers=self._headers,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()

    def create_pull_request_review(
        self,
        pr_number: int,
        *,
        commit_id: str,
        body: str,
        comments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Submit a PR review (``event=COMMENT``). Optional inline ``comments``: ``path``, ``line``, ``body``."""
        payload: dict[str, Any] = {
            "commit_id": commit_id,
            "event": "COMMENT",
            "body": body,
        }
        if comments:
            payload["comments"] = comments
        r = httpx.post(
            self._url(f"/repos/{self.owner}/{self.repo}/pulls/{pr_number}/reviews"),
            headers=self._headers,
            json=payload,
            timeout=120.0,
        )
        r.raise_for_status()
        return r.json()
