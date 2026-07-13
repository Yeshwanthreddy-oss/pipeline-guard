import json
import subprocess
import sys

from pipeline_guard.cli import main


def test_scan_clean_inputs_passes_and_exits_zero(fixtures_dir, tmp_path):
    report_out = tmp_path / "report.md"
    exit_code = main(
        [
            "scan",
            "--dockerfile",
            str(fixtures_dir / "docker" / "Dockerfile.clean"),
            "--terraform-plan",
            str(fixtures_dir / "terraform" / "clean" / "plan.json"),
            "--k8s",
            str(fixtures_dir / "k8s" / "deployment-clean.yaml"),
            "--report-out",
            str(report_out),
        ]
    )
    assert exit_code == 0
    assert "PASSED" in report_out.read_text()


def test_scan_vulnerable_inputs_blocks_and_exits_nonzero(fixtures_dir, tmp_path):
    report_out = tmp_path / "report.md"
    exit_code = main(
        [
            "scan",
            "--dockerfile",
            str(fixtures_dir / "docker" / "Dockerfile.vulnerable"),
            "--trivy-report",
            str(fixtures_dir / "trivy" / "report-vulnerable.json"),
            "--terraform-plan",
            str(fixtures_dir / "terraform" / "vulnerable" / "plan.json"),
            "--k8s",
            str(fixtures_dir / "k8s" / "deployment-vulnerable.yaml"),
            "--report-out",
            str(report_out),
            "--threshold",
            "30",
        ]
    )
    assert exit_code == 1
    text = report_out.read_text()
    assert "BLOCKED" in text
    assert "TF-SG-OPEN-INGRESS" in text


def test_scan_no_fail_always_exits_zero(fixtures_dir, tmp_path):
    exit_code = main(
        [
            "scan",
            "--trivy-report",
            str(fixtures_dir / "trivy" / "report-vulnerable.json"),
            "--report-out",
            str(tmp_path / "report.md"),
            "--threshold",
            "1",
            "--no-fail",
        ]
    )
    assert exit_code == 0


def test_scan_json_out_round_trips_into_scan_result(fixtures_dir, tmp_path):
    json_out = tmp_path / "scan.json"
    main(
        [
            "scan",
            "--dockerfile",
            str(fixtures_dir / "docker" / "Dockerfile.vulnerable"),
            "--terraform-plan",
            str(fixtures_dir / "terraform" / "vulnerable" / "plan.json"),
            "--report-out",
            str(tmp_path / "report.md"),
            "--json-out",
            str(json_out),
            "--no-fail",
        ]
    )
    data = json.loads(json_out.read_text())
    assert data["threshold"] == 30
    assert data["passed"] is False
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "BASE-IMAGE-OUTDATED" in rule_ids
    assert "TF-ENCRYPTION-MISSING" in rule_ids
    # findings carry `raw` so autofix can consume them without re-scanning
    encryption_finding = next(f for f in data["findings"] if f["rule_id"] == "TF-ENCRYPTION-MISSING")
    assert "attribute" in encryption_finding["raw"]


def test_autofix_end_to_end_from_scan_json(fixtures_dir, tmp_fixture_copy, tmp_path):
    dockerfile = tmp_fixture_copy / "docker" / "Dockerfile.vulnerable"
    tf_dir = tmp_fixture_copy / "terraform" / "vulnerable"

    json_out = tmp_path / "scan.json"
    scan_exit = main(
        [
            "scan",
            "--dockerfile",
            str(dockerfile),
            "--terraform-plan",
            str(tf_dir / "plan.json"),
            "--report-out",
            str(tmp_path / "report.md"),
            "--json-out",
            str(json_out),
            "--no-fail",
        ]
    )
    assert scan_exit == 0

    plan_out = tmp_path / "plan.json.summary"
    autofix_exit = main(
        [
            "autofix",
            "--scan-json",
            str(json_out),
            "--terraform-dir",
            str(tf_dir),
            "--plan-out",
            str(plan_out),
        ]
    )
    assert autofix_exit == 0

    summary = json.loads(plan_out.read_text())
    assert str(dockerfile) in summary["files"]
    assert str(tf_dir / "main.tf") in summary["files"]

    # Dry run: nothing should have been written to disk yet.
    assert "FROM python:3.9" in dockerfile.read_text()


def test_autofix_apply_commits_to_local_repo(fixtures_dir, tmp_fixture_copy, tmp_path):
    dockerfile = tmp_fixture_copy / "docker" / "Dockerfile.vulnerable"

    repo_dir = tmp_fixture_copy
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo_dir, check=True)

    json_out = tmp_path / "scan.json"
    main(
        [
            "scan",
            "--dockerfile",
            str(dockerfile),
            "--report-out",
            str(tmp_path / "report.md"),
            "--json-out",
            str(json_out),
            "--no-fail",
        ]
    )

    exit_code = main(
        [
            "autofix",
            "--scan-json",
            str(json_out),
            "--repo-dir",
            str(repo_dir),
            "--apply",
        ]
    )
    assert exit_code == 0

    result = subprocess.run(
        ["git", "branch", "--list", "pipeline-guard/auto-fix"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    assert "pipeline-guard/auto-fix" in result.stdout

    # Original branch's working tree is untouched.
    assert "FROM python:3.9" in dockerfile.read_text()

    show = subprocess.run(
        ["git", "show", f"pipeline-guard/auto-fix:{dockerfile.relative_to(repo_dir)}"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "FROM python:3.12-slim" in show.stdout


def test_cli_entry_point_installed_and_runs_help():
    result = subprocess.run(
        [sys.executable, "-m", "pipeline_guard.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "autofix" in result.stdout
