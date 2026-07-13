"""Where a `PullRequestPlan` actually gets turned into a follow-up PR.

Three implementations, from fully-offline to real:

* `FakeGitHubClient`  -- in-memory recorder, used by the test suite.
* `LocalGitClient`    -- creates a real branch + commit in a local git repo
  (no network, no remote push). Used by the CLI's `--local` demo mode and by
  tests that want to assert real git plumbing without touching the network.
* `RestGitHubClient`  -- pushes the branch and opens a real PR via the GitHub
  REST API. Requires `GITHUB_TOKEN` and network access; never invoked by
  the unit test suite.
"""
from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .autofix import PullRequestPlan


class GitHubClient(ABC):
    @abstractmethod
    def open_pull_request(self, plan: PullRequestPlan, base_branch: str = "main") -> str:
        """Apply `plan` and return a URL (or local ref) identifying the result."""


@dataclass
class FakeGitHubClient(GitHubClient):
    """Records calls instead of touching git/network. Used in tests."""

    opened: list[PullRequestPlan] = field(default_factory=list)
    next_url: str = "https://github.com/example/pipeline-guard-demo/pull/1"

    def open_pull_request(self, plan: PullRequestPlan, base_branch: str = "main") -> str:
        self.opened.append(plan)
        return self.next_url


class LocalGitClient(GitHubClient):
    """Applies a PullRequestPlan as a real branch + commit in a local repo.

    No network access and no remote push -- fully offline, so this is safe
    to exercise in unit tests as an integration-style check of the plumbing
    that a real push/PR would sit on top of.
    """

    def __init__(self, repo_dir: Path):
        self.repo_dir = Path(repo_dir)

    def _git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def open_pull_request(self, plan: PullRequestPlan, base_branch: str = "main") -> str:
        if plan.is_empty:
            raise ValueError("Refusing to open a PR with an empty patch set")

        current = self._git("rev-parse", "--abbrev-ref", "HEAD")
        self._git("checkout", "-B", plan.branch)
        try:
            for rel_path, content in plan.patches.items():
                target = Path(rel_path)
                if not target.is_absolute():
                    target = self.repo_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
                self._git("add", str(target))
            self._git("commit", "-m", plan.title, "-m", plan.body)
            commit_sha = self._git("rev-parse", "HEAD")
        finally:
            self._git("checkout", current)

        return f"local-branch:{plan.branch}@{commit_sha[:12]}"


class RestGitHubClient(GitHubClient):
    """Real GitHub REST API PR creation. Requires network + a token.

    Not covered by the unit test suite -- exercising it would need a live
    GitHub repo and a token, which violates the offline-verifiable
    constraint. It exists so the GitHub Action's real run path is a small,
    reviewable amount of code rather than a TODO.
    """

    API_ROOT = "https://api.github.com"

    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo

    def open_pull_request(self, plan: PullRequestPlan, base_branch: str = "main") -> str:
        import requests  # imported lazily: not a hard dependency for offline use

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }
        base_url = f"{self.API_ROOT}/repos/{self.owner}/{self.repo}"

        base_ref = requests.get(f"{base_url}/git/ref/heads/{base_branch}", headers=headers, timeout=30)
        base_ref.raise_for_status()
        base_sha = base_ref.json()["object"]["sha"]

        requests.post(
            f"{base_url}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{plan.branch}", "sha": base_sha},
            timeout=30,
        ).raise_for_status()

        for path, content in plan.patches.items():
            existing = requests.get(
                f"{base_url}/contents/{path}",
                headers=headers,
                params={"ref": plan.branch},
                timeout=30,
            )
            sha = existing.json().get("sha") if existing.status_code == 200 else None
            payload = {
                "message": f"{plan.title}: update {path}",
                "content": _b64(content),
                "branch": plan.branch,
            }
            if sha:
                payload["sha"] = sha
            requests.put(
                f"{base_url}/contents/{path}", headers=headers, json=payload, timeout=30
            ).raise_for_status()

        pr = requests.post(
            f"{base_url}/pulls",
            headers=headers,
            json={
                "title": plan.title,
                "head": plan.branch,
                "base": base_branch,
                "body": plan.body,
            },
            timeout=30,
        )
        pr.raise_for_status()
        return pr.json()["html_url"]


def _b64(content: str) -> str:
    import base64

    return base64.b64encode(content.encode("utf-8")).decode("ascii")
