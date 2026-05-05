import subprocess
from pathlib import Path

import pytest

from pipeline_guard.autofix import PullRequestPlan
from pipeline_guard.github_client import FakeGitHubClient, LocalGitClient


def _git(repo_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_dir, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def local_repo(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init", "-q", "-b", "main")
    _git(repo_dir, "config", "user.email", "test@example.com")
    _git(repo_dir, "config", "user.name", "pipeline-guard tests")
    (repo_dir / "README.md").write_text("hello\n")
    _git(repo_dir, "add", "README.md")
    _git(repo_dir, "commit", "-q", "-m", "initial commit")
    return repo_dir


def test_fake_github_client_records_the_plan():
    client = FakeGitHubClient()
    plan = PullRequestPlan(branch="pg/fix", title="t", body="b", patches={"a.txt": "x"})
    url = client.open_pull_request(plan)
    assert url == client.next_url
    assert client.opened == [plan]


def test_local_git_client_creates_branch_and_commit(local_repo):
    plan = PullRequestPlan(
        branch="pipeline-guard/auto-fix",
        title="pipeline-guard: mechanical security fixes",
        body="fixed stuff",
        patches={"config/app.txt": "encrypted = true\n"},
    )
    client = LocalGitClient(local_repo)
    ref = client.open_pull_request(plan)

    assert ref.startswith("local-branch:pipeline-guard/auto-fix@")

    branches = _git(local_repo, "branch", "--list", "pipeline-guard/auto-fix")
    assert "pipeline-guard/auto-fix" in branches

    committed_content = _git(
        local_repo, "show", "pipeline-guard/auto-fix:config/app.txt"
    )
    assert committed_content == "encrypted = true"

    commit_msg = _git(local_repo, "log", "-1", "--format=%s", "pipeline-guard/auto-fix")
    assert commit_msg == "pipeline-guard: mechanical security fixes"


def test_local_git_client_returns_to_original_branch(local_repo):
    plan = PullRequestPlan(
        branch="pipeline-guard/auto-fix",
        title="t",
        body="b",
        patches={"x.txt": "y"},
    )
    LocalGitClient(local_repo).open_pull_request(plan)
    current = _git(local_repo, "rev-parse", "--abbrev-ref", "HEAD")
    assert current == "main"


def test_local_git_client_rejects_empty_plan(local_repo):
    plan = PullRequestPlan(branch="pg/empty", title="t", body="b", patches={})
    with pytest.raises(ValueError):
        LocalGitClient(local_repo).open_pull_request(plan)
