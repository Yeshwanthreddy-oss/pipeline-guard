from pipeline_guard.aggregator import compute_risk_score, evaluate_gate, severity_breakdown
from pipeline_guard.models import Finding, ScanResult, Severity


def _finding(severity: Severity, rule_id: str = "R") -> Finding:
    return Finding(
        source="test",
        rule_id=rule_id,
        title="t",
        severity=severity,
        resource="res",
    )


def test_compute_risk_score_sums_weights():
    result = ScanResult(
        findings=[
            _finding(Severity.CRITICAL),  # 20
            _finding(Severity.HIGH),  # 10
            _finding(Severity.MEDIUM),  # 4
            _finding(Severity.LOW),  # 1
        ]
    )
    assert compute_risk_score(result) == 35


def test_empty_result_has_zero_score():
    assert compute_risk_score(ScanResult()) == 0


def test_severity_breakdown_counts_each_bucket():
    result = ScanResult(
        findings=[_finding(Severity.HIGH), _finding(Severity.HIGH), _finding(Severity.LOW)]
    )
    breakdown = severity_breakdown(result)
    assert breakdown["HIGH"] == 2
    assert breakdown["LOW"] == 1
    assert breakdown["CRITICAL"] == 0


def test_gate_passes_when_score_at_or_below_threshold():
    result = ScanResult(findings=[_finding(Severity.MEDIUM)])  # score 4
    decision = evaluate_gate(result, threshold=4)
    assert decision.passed is True
    assert decision.score == 4


def test_gate_blocks_when_score_exceeds_threshold():
    result = ScanResult(findings=[_finding(Severity.CRITICAL)])  # score 20
    decision = evaluate_gate(result, threshold=10)
    assert decision.passed is False
    assert decision.score == 20
    assert decision.threshold == 10


def test_single_critical_outweighs_several_highs():
    """One CRITICAL (20) should exceed a threshold that several HIGHs (10 each) wouldn't."""
    highs_only = ScanResult(findings=[_finding(Severity.HIGH) for _ in range(2)])  # 20
    one_critical = ScanResult(findings=[_finding(Severity.CRITICAL)])  # 20
    assert compute_risk_score(highs_only) == compute_risk_score(one_critical)


def test_gate_decision_reports_fixable_count():
    fixable = Finding(
        source="trivy",
        rule_id="X",
        title="x",
        severity=Severity.MEDIUM,
        resource="r",
        fixable=True,
    )
    not_fixable = _finding(Severity.MEDIUM)
    decision = evaluate_gate(ScanResult(findings=[fixable, not_fixable]), threshold=100)
    assert decision.fixable_count == 1
    assert decision.total_findings == 2
