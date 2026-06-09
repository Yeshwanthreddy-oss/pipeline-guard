from pipeline_guard.aggregator import evaluate_gate
from pipeline_guard.models import Finding, ScanResult, Severity
from pipeline_guard.reporting import COMMENT_MARKER, render_pr_comment


def _result_with(*severities):
    return ScanResult(
        findings=[
            Finding(
                source="trivy",
                rule_id=f"RULE-{i}",
                title=f"finding {i}",
                severity=sev,
                resource="demo/webapp:1.0",
            )
            for i, sev in enumerate(severities)
        ]
    )


def test_comment_includes_marker_for_idempotent_updates():
    result = _result_with(Severity.LOW)
    decision = evaluate_gate(result, threshold=100)
    comment = render_pr_comment(result, decision)
    assert comment.startswith(COMMENT_MARKER)


def test_passing_gate_shows_passed_status():
    result = _result_with(Severity.LOW)
    decision = evaluate_gate(result, threshold=100)
    comment = render_pr_comment(result, decision)
    assert "PASSED" in comment
    assert "BLOCKED" not in comment


def test_blocked_gate_shows_blocked_status_and_reason():
    result = _result_with(Severity.CRITICAL)
    decision = evaluate_gate(result, threshold=5)
    comment = render_pr_comment(result, decision)
    assert "BLOCKED" in comment
    assert "exceeds the configured threshold" in comment
    assert "20" in comment  # the risk score


def test_comment_lists_each_finding_rule_id():
    result = _result_with(Severity.HIGH, Severity.MEDIUM)
    decision = evaluate_gate(result, threshold=100)
    comment = render_pr_comment(result, decision)
    assert "RULE-0" in comment
    assert "RULE-1" in comment


def test_comment_mentions_autofix_when_fixable_findings_present():
    findings = [
        Finding(
            source="trivy",
            rule_id="BASE-IMAGE-OUTDATED",
            title="outdated",
            severity=Severity.HIGH,
            resource="Dockerfile",
            fixable=True,
            fix_kind="bump_base_image",
            fix_hint="Bump python:3.9 -> python:3.12-slim",
        )
    ]
    result = ScanResult(findings=findings)
    decision = evaluate_gate(result, threshold=100)
    comment = render_pr_comment(result, decision)
    assert "auto-fix" in comment.lower()
    assert "Bump python:3.9" in comment


def test_comment_includes_pr_url_when_autofix_already_opened():
    findings = [
        Finding(
            source="trivy",
            rule_id="BASE-IMAGE-OUTDATED",
            title="outdated",
            severity=Severity.HIGH,
            resource="Dockerfile",
            fixable=True,
            fix_kind="bump_base_image",
        )
    ]
    result = ScanResult(findings=findings)
    decision = evaluate_gate(result, threshold=100)
    comment = render_pr_comment(
        result, decision, autofix_pr_url="https://github.com/example/repo/pull/42"
    )
    assert "https://github.com/example/repo/pull/42" in comment


def test_no_findings_renders_cleanly():
    result = ScanResult()
    decision = evaluate_gate(result, threshold=10)
    comment = render_pr_comment(result, decision)
    assert "No findings" in comment
    assert "PASSED" in comment


def test_findings_table_truncates_beyond_limit():
    result = _result_with(*([Severity.LOW] * 30))
    decision = evaluate_gate(result, threshold=1000)
    comment = render_pr_comment(result, decision)
    assert "more finding(s) truncated" in comment
