"""Render an annotated Markdown PR comment from a scan result + gate decision."""
from __future__ import annotations

from .aggregator import GateDecision
from .models import SEVERITY_ORDER, ScanResult, Severity

# Present in every comment pipeline-guard posts so the CLI/action can find
# and update its own prior comment instead of spamming a new one each push.
COMMENT_MARKER = "<!-- pipeline-guard:report -->"

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001f7e5",  # red square
    Severity.HIGH: "\U0001f7e7",  # orange square
    Severity.MEDIUM: "\U0001f7e8",  # yellow square
    Severity.LOW: "\U0001f7e9",  # green square
    Severity.UNKNOWN: "⬜",  # white square
}


def _breakdown_table(decision: GateDecision) -> str:
    lines = ["| Severity | Count |", "| --- | --- |"]
    for sev in SEVERITY_ORDER:
        count = decision.breakdown.get(sev.value, 0)
        if count == 0 and sev is Severity.UNKNOWN:
            continue
        lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value} | {count} |")
    return "\n".join(lines)


def _findings_table(result: ScanResult, limit: int = 25) -> str:
    if not result.findings:
        return "_No findings._"
    ordered = sorted(
        result.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
    )
    lines = [
        "| Severity | Rule | Resource | Summary | Fix |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in ordered[:limit]:
        fix = f.fix_hint or ("manual" if not f.fixable else "-")
        lines.append(
            f"| {_SEVERITY_EMOJI[f.severity]} {f.severity.value} | `{f.rule_id}` | "
            f"`{f.resource}` | {f.title} | {fix} |"
        )
    remainder = len(result.findings) - limit
    if remainder > 0:
        lines.append(f"| … | | | *{remainder} more finding(s) truncated* | |")
    return "\n".join(lines)


def render_pr_comment(
    result: ScanResult,
    decision: GateDecision,
    autofix_pr_url: str | None = None,
    repo_ref: str | None = None,
) -> str:
    """Build the full Markdown body posted as a PR comment."""
    status = "✅ PASSED" if decision.passed else "❌ BLOCKED"
    header = f"## pipeline-guard security gate: {status}"
    subtitle = (
        f"Risk score **{decision.score}** "
        f"(threshold **{decision.threshold}**) across **{decision.total_findings}** finding(s)"
    )
    if repo_ref:
        subtitle += f" for `{repo_ref}`"

    sections = [
        COMMENT_MARKER,
        header,
        subtitle,
        "",
        "### Severity breakdown",
        _breakdown_table(decision),
        "",
        "### Findings",
        _findings_table(result),
    ]

    if decision.fixable_count:
        sections += [
            "",
            "### Mechanical auto-fix",
            (
                f"{decision.fixable_count} finding(s) are mechanically fixable "
                "(base image tag bumps, missing `encrypted`/`storage_encrypted` "
                "flags)."
            ),
        ]
        if autofix_pr_url:
            sections.append(f"An auto-fix PR has been opened: {autofix_pr_url}")
        else:
            sections.append(
                "Run `pipeline-guard autofix` (or re-run this action with "
                "`auto_fix: true`) to open a follow-up PR with the mechanical fixes."
            )

    if not decision.passed:
        sections += [
            "",
            (
                f"**This build is blocked** because the risk score ({decision.score}) "
                f"exceeds the configured threshold ({decision.threshold}). "
                "Resolve the CRITICAL/HIGH findings above, or raise the threshold "
                "in `pipeline-guard.yml` if this is an accepted risk."
            ),
        ]

    return "\n".join(sections) + "\n"
