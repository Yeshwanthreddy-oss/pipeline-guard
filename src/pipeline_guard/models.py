"""Shared data model for every finding pipeline-guard produces.

Trivy image findings and OPA/Conftest policy violations both get normalized
into a single `Finding` shape so the aggregator, reporter and autofixer only
ever have to deal with one type.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def weight(self) -> int:
        """Points a single finding of this severity contributes to the risk score."""
        return {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.UNKNOWN: 1,
        }[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().upper())
        except ValueError:
            return cls.UNKNOWN


# Ordered worst-to-best, used for sorting and for choosing the "highest" severity.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.UNKNOWN,
]


@dataclass
class Finding:
    """A single normalized security finding from any scanner."""

    source: str  # "trivy" | "policy:terraform" | "policy:kubernetes"
    rule_id: str
    title: str
    severity: Severity
    resource: str  # image ref, file path, or manifest name the finding applies to
    description: str = ""
    fixable: bool = False
    fix_kind: Optional[str] = None  # e.g. "bump_image_tag", "add_encryption_flag"
    fix_hint: Optional[str] = None
    location: Optional[str] = None  # e.g. "resource.aws_s3_bucket.data" or "line 12"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "fixable": self.fixable,
            "fix_kind": self.fix_kind,
            "fix_hint": self.fix_hint,
            "location": self.location,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            source=d["source"],
            rule_id=d["rule_id"],
            title=d["title"],
            severity=Severity.from_str(d["severity"]),
            resource=d["resource"],
            description=d.get("description", ""),
            fixable=d.get("fixable", False),
            fix_kind=d.get("fix_kind"),
            fix_hint=d.get("fix_hint"),
            location=d.get("location"),
            raw=d.get("raw") or {},
        )


@dataclass
class ScanResult:
    """The combined output of every scanner that ran for a given PR/commit."""

    findings: list[Finding] = field(default_factory=list)

    def by_severity(self) -> dict[Severity, list[Finding]]:
        buckets: dict[Severity, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
        for f in self.findings:
            buckets[f.severity].append(f)
        return buckets

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def fixable_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.fixable]

    def extend(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)

    def to_dict(self) -> dict[str, Any]:
        return {"findings": [f.to_dict() for f in self.findings]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        return cls(findings=[Finding.from_dict(fd) for fd in d.get("findings", [])])
