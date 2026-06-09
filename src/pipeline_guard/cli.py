"""pipeline-guard CLI.

    pipeline-guard scan --dockerfile Dockerfile --terraform-plan plan.json \\
        --k8s deploy.yaml --trivy-report trivy.json --threshold 30

    pipeline-guard autofix --scan-json report.json --terraform-dir infra/ \\
        --apply --repo-dir .

Both subcommands are pure orchestration over the library modules in this
package; see `run_scan()` / `run_autofix()` for the parts that are also
called directly (and covered) by the test suite.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .aggregator import GateDecision, evaluate_gate
from .config import PipelineGuardConfig
from .models import ScanResult
from .reporting import render_pr_comment
from .scanners.k8s_policy import evaluate_manifest_file
from .scanners.terraform_policy import evaluate_terraform_plan
from .scanners.trivy import DockerfileImageAdvisor, load_trivy_report
from .autofix import AutoFixOrchestrator, PullRequestPlan
from .github_client import FakeGitHubClient, LocalGitClient


def run_scan(config: PipelineGuardConfig) -> tuple[ScanResult, GateDecision]:
    """Execute every configured scanner and return the combined result + gate."""
    result = ScanResult()

    if config.trivy_report:
        result.extend(load_trivy_report(config.trivy_report))

    if config.dockerfile and Path(config.dockerfile).exists():
        result.extend(DockerfileImageAdvisor().inspect(config.dockerfile))

    if config.terraform_plan:
        plan = json.loads(Path(config.terraform_plan).read_text())
        result.extend(evaluate_terraform_plan(plan))

    for manifest in config.k8s_manifests:
        result.extend(evaluate_manifest_file(manifest))

    decision = evaluate_gate(result, config.threshold)
    return result, decision


def run_autofix(
    findings_result: ScanResult,
    terraform_dir: str | None,
    branch: str,
    repo_dir: str | None,
    apply: bool,
) -> tuple[PullRequestPlan, str | None]:
    """Build (and optionally apply) the mechanical auto-fix plan.

    Returns (plan, pr_url). `pr_url` is None in dry-run mode (apply=False)
    or when the plan has no applicable fixes.
    """
    orchestrator = AutoFixOrchestrator(terraform_dir=terraform_dir)
    plan = orchestrator.build_plan(findings_result.fixable_findings(), branch=branch)

    if not apply or plan.is_empty:
        return plan, None

    client = LocalGitClient(Path(repo_dir)) if repo_dir else FakeGitHubClient()
    url = client.open_pull_request(plan)
    return plan, url


def _build_config(args: argparse.Namespace) -> PipelineGuardConfig:
    base = PipelineGuardConfig.load(args.config) if args.config else PipelineGuardConfig()
    return base.merge_cli_overrides(
        threshold=args.threshold,
        dockerfile=args.dockerfile,
        terraform_dir=args.terraform_dir,
        terraform_plan=args.terraform_plan,
        k8s_manifests=args.k8s or [],
        trivy_report=args.trivy_report,
        image=args.image,
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _build_config(args)
    result, decision = run_scan(config)

    comment = render_pr_comment(result, decision, repo_ref=args.image or config.dockerfile)
    Path(args.report_out).write_text(comment)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "score": decision.score,
                    "threshold": decision.threshold,
                    "passed": decision.passed,
                    "breakdown": decision.breakdown,
                    **result.to_dict(),
                },
                indent=2,
            )
        )

    print(comment)
    if not decision.passed and not args.no_fail:
        return 1
    return 0


def _cmd_autofix(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.scan_json).read_text())
    result = ScanResult.from_dict(data)

    plan, url = run_autofix(
        result,
        terraform_dir=args.terraform_dir,
        branch=args.branch,
        repo_dir=args.repo_dir,
        apply=args.apply,
    )

    if plan.is_empty:
        print("No mechanically fixable findings found; nothing to do.")
        return 0

    print(f"Auto-fix plan: {plan.title}")
    for fix in plan.fix_results:
        print(f"  - [{fix.rule_id}] {fix.file}: {fix.description}")

    if args.plan_out:
        Path(args.plan_out).write_text(
            json.dumps(
                {
                    "branch": plan.branch,
                    "title": plan.title,
                    "body": plan.body,
                    "files": list(plan.patches.keys()),
                },
                indent=2,
            )
        )

    if url:
        print(f"Opened: {url}")
    elif not args.apply:
        print("(dry run: pass --apply --repo-dir <path> to commit these fixes)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pipeline-guard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run scanners, score risk, gate the build")
    scan.add_argument("--config", help="path to pipeline-guard.yml")
    scan.add_argument("--dockerfile", help="Dockerfile to check for outdated base images")
    scan.add_argument("--trivy-report", help="pre-generated trivy JSON report")
    scan.add_argument("--terraform-plan", help="terraform plan JSON (terraform show -json)")
    scan.add_argument("--terraform-dir", help="terraform source dir (used by autofix)")
    scan.add_argument("--k8s", nargs="*", help="kubernetes manifest file(s)")
    scan.add_argument("--image", help="image reference, used for report labeling")
    scan.add_argument("--threshold", type=int, help="max acceptable risk score")
    scan.add_argument("--report-out", default="pipeline-guard-report.md")
    scan.add_argument("--json-out", help="write machine-readable findings JSON here")
    scan.add_argument(
        "--no-fail", action="store_true", help="always exit 0 (report-only mode)"
    )
    scan.set_defaults(func=_cmd_scan)

    autofix = sub.add_parser("autofix", help="build/apply the mechanical auto-fix PR")
    autofix.add_argument("--scan-json", required=True, help="JSON produced by `scan --json-out`")
    autofix.add_argument("--terraform-dir", help="terraform source dir to patch")
    autofix.add_argument("--branch", default="pipeline-guard/auto-fix")
    autofix.add_argument("--repo-dir", help="local git repo to commit fixes into")
    autofix.add_argument("--apply", action="store_true", help="actually commit the fixes")
    autofix.add_argument("--plan-out", help="write the fix plan summary as JSON here")
    autofix.set_defaults(func=_cmd_autofix)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
