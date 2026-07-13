"""Policy-as-code checks for Terraform, expressed as pure Python.

Input is the standard `terraform show -json <planfile>` structure (the same
shape conftest is normally pointed at), so a fixture here is exactly what a
real `terraform plan` would emit -- no bespoke schema.

Every rule below has a hand-written counterpart in `policies/terraform/*.rego`
using the exact same resource addresses and thresholds, so a team that has
`conftest` installed can run the canonical OPA version, while pipeline-guard
itself runs this dependency-free reimplementation by default (see
`policy_engine.py` for why).
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Union

from ..models import Finding, ScanResult, Severity

# Ports where 0.0.0.0/0 ingress is treated as CRITICAL rather than HIGH.
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}
ANY_CIDR = {"0.0.0.0/0", "::/0"}

# Resources where the fix is a mechanical boolean/scalar flag -- these are
# eligible for the "add_encryption_flag" auto-fix (see autofix.py).
RESOURCES_REQUIRING_ENCRYPTION_FLAG = {
    "aws_ebs_volume": "encrypted",
    "aws_db_instance": "storage_encrypted",
    "aws_sqs_queue": "kms_master_key_id",
}


def _iter_resource_changes(plan: dict) -> Iterable[dict]:
    for rc in plan.get("resource_changes", []) or []:
        change = rc.get("change", {})
        actions = change.get("actions", ["create"])
        if actions == ["delete"]:
            continue
        after = change.get("after")
        if after is None:
            continue
        yield rc, after


def _port_range_includes(rule: dict, port: int) -> bool:
    try:
        return int(rule.get("from_port", -1)) <= port <= int(rule.get("to_port", -1))
    except (TypeError, ValueError):
        return False


def check_open_security_groups(plan: dict) -> list[Finding]:
    findings: list[Finding] = []
    for rc, after in _iter_resource_changes(plan):
        if rc.get("type") != "aws_security_group":
            continue
        address = rc.get("address", "aws_security_group")
        for rule in after.get("ingress", []) or []:
            cidrs = set(rule.get("cidr_blocks") or [])
            if not cidrs & ANY_CIDR:
                continue
            hit_sensitive = [p for p in SENSITIVE_PORTS if _port_range_includes(rule, p)]
            wide_open = int(rule.get("from_port", 0)) == 0 and int(rule.get("to_port", 0)) >= 65535
            if hit_sensitive or wide_open:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH
            findings.append(
                Finding(
                    source="policy:terraform",
                    rule_id="TF-SG-OPEN-INGRESS",
                    title=f"Security group '{address}' allows ingress from the public internet",
                    severity=severity,
                    resource=address,
                    description=(
                        f"Ingress rule {rule.get('from_port')}-{rule.get('to_port')}/"
                        f"{rule.get('protocol')} is open to {sorted(cidrs & ANY_CIDR)}."
                    ),
                    fixable=False,
                    location=address,
                    raw=rule,
                )
            )
    return findings


def check_public_storage(plan: dict) -> list[Finding]:
    findings: list[Finding] = []
    for rc, after in _iter_resource_changes(plan):
        rtype = rc.get("type")
        address = rc.get("address", rtype)
        if rtype == "aws_s3_bucket" and after.get("acl") in {"public-read", "public-read-write"}:
            findings.append(
                Finding(
                    source="policy:terraform",
                    rule_id="TF-S3-PUBLIC-ACL",
                    title=f"S3 bucket '{address}' has a public ACL",
                    severity=Severity.CRITICAL,
                    resource=address,
                    description=f"acl = \"{after.get('acl')}\" grants public read access.",
                    fixable=False,
                    location=address,
                )
            )
        if rtype == "aws_s3_bucket_public_access_block":
            blocked = all(
                after.get(flag) is True
                for flag in (
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                )
            )
            if not blocked:
                findings.append(
                    Finding(
                        source="policy:terraform",
                        rule_id="TF-S3-PUBLIC-ACCESS-BLOCK",
                        title=f"'{address}' does not fully block public access",
                        severity=Severity.HIGH,
                        resource=address,
                        description="All four block_public_* / restrict_* flags must be true.",
                        fixable=False,
                        location=address,
                    )
                )
        if rtype == "aws_db_instance" and after.get("publicly_accessible") is True:
            findings.append(
                Finding(
                    source="policy:terraform",
                    rule_id="TF-RDS-PUBLIC",
                    title=f"RDS instance '{address}' is publicly accessible",
                    severity=Severity.CRITICAL,
                    resource=address,
                    description="publicly_accessible = true exposes the database to the internet.",
                    fixable=False,
                    location=address,
                )
            )
    return findings


def check_missing_encryption(plan: dict) -> list[Finding]:
    """Flag-style encryption checks (e.g. `encrypted = true`).

    These are mechanically fixable: the auto-fixer just needs to set a
    scalar attribute to `true` (see `autofix.add_terraform_attribute`).
    """
    findings: list[Finding] = []
    for rc, after in _iter_resource_changes(plan):
        rtype = rc.get("type")
        attr = RESOURCES_REQUIRING_ENCRYPTION_FLAG.get(rtype)
        if not attr:
            continue
        address = rc.get("address", rtype)
        if not after.get(attr):
            findings.append(
                Finding(
                    source="policy:terraform",
                    rule_id="TF-ENCRYPTION-MISSING",
                    title=f"'{address}' is not encrypted at rest",
                    severity=Severity.MEDIUM,
                    resource=address,
                    description=f"Resource of type {rtype} is missing `{attr}`.",
                    fixable=True,
                    fix_kind="add_encryption_flag",
                    fix_hint=f"Set {attr} = true on {address}",
                    location=address,
                    raw={"resource_type": rtype, "attribute": attr, "address": address},
                )
            )
    return findings


def check_s3_encryption_config(plan: dict) -> list[Finding]:
    """S3 server-side encryption is a nested config block, not a scalar flag,
    so unlike `check_missing_encryption` this is *not* mechanically fixable
    -- writing a correct SSE block requires a human to pick a KMS key/algorithm.
    """
    findings: list[Finding] = []
    for rc, after in _iter_resource_changes(plan):
        if rc.get("type") != "aws_s3_bucket":
            continue
        address = rc.get("address", "aws_s3_bucket")
        sse = after.get("server_side_encryption_configuration")
        if not sse:
            findings.append(
                Finding(
                    source="policy:terraform",
                    rule_id="TF-S3-SSE-MISSING",
                    title=f"'{address}' has no server-side encryption configured",
                    severity=Severity.MEDIUM,
                    resource=address,
                    description=(
                        "Missing `server_side_encryption_configuration` block "
                        "(SSE-S3 or SSE-KMS)."
                    ),
                    fixable=False,
                    location=address,
                )
            )
    return findings


def evaluate_terraform_plan(plan: dict, source_name: str = "terraform-plan") -> ScanResult:
    """Run every Terraform policy rule against a parsed plan and return findings.

    `source_name` is only used to tag findings when the plan itself provides
    no better resource address (kept for symmetry with the k8s engine).
    """
    findings: list[Finding] = []
    findings.extend(check_open_security_groups(plan))
    findings.extend(check_public_storage(plan))
    findings.extend(check_missing_encryption(plan))
    findings.extend(check_s3_encryption_config(plan))
    return ScanResult(findings=findings)
