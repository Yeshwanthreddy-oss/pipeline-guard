"""Combine findings from every scanner into one risk score and gate decision."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import SEVERITY_ORDER, ScanResult, Severity


@dataclass
class GateDecision:
    score: int
    threshold: int
    breakdown: dict[str, int]
    total_findings: int
    fixable_count: int
    passed: bool = field(init=False)

    def __post_init__(self) -> None:
        self.passed = self.score <= self.threshold


def compute_risk_score(result: ScanResult) -> int:
    """Sum of per-finding severity weights.

    Weights (see `Severity.weight`): CRITICAL=20, HIGH=10, MEDIUM=4, LOW=1.
    A single CRITICAL therefore outweighs several HIGHs, which is the
    intent: one open security group to the internet should gate a build even
    if the rest of the report is quiet.
    """
    return sum(f.severity.weight for f in result.findings)


def severity_breakdown(result: ScanResult) -> dict[str, int]:
    buckets = result.by_severity()
    return {s.value: len(buckets[s]) for s in SEVERITY_ORDER}


def evaluate_gate(result: ScanResult, threshold: int) -> GateDecision:
    """Decide whether this scan result should block the build.

    `threshold` is the maximum acceptable risk score (inclusive) -- a build
    is blocked when `compute_risk_score(result) > threshold`.
    """
    score = compute_risk_score(result)
    return GateDecision(
        score=score,
        threshold=threshold,
        breakdown=severity_breakdown(result),
        total_findings=len(result.findings),
        fixable_count=len(result.fixable_findings()),
    )
