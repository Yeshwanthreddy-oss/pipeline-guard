"""Policy-as-code checks for Kubernetes manifests, expressed as pure Python.

Mirrors `policies/kubernetes/pod_security.rego` rule-for-rule; see
`policy_engine.py` for why the default execution path is this
dependency-free reimplementation rather than a real `conftest` invocation.

Handles both bare `Pod` manifests and any workload that nests a pod template
(`Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Union

import yaml

from ..models import Finding, ScanResult, Severity

_WORKLOAD_KINDS_WITH_TEMPLATE = {"Deployment", "StatefulSet", "DaemonSet", "Job"}


def _extract_pod_spec(doc: dict) -> tuple[Union[dict, None], str]:
    """Return (pod_spec, human-readable manifest name) for a k8s document."""
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", "unnamed")
    label = f"{kind}/{name}"
    if kind == "Pod":
        return doc.get("spec"), label
    if kind == "CronJob":
        try:
            return (
                doc["spec"]["jobTemplate"]["spec"]["template"]["spec"],
                label,
            )
        except (KeyError, TypeError):
            return None, label
    if kind in _WORKLOAD_KINDS_WITH_TEMPLATE:
        try:
            return doc["spec"]["template"]["spec"], label
        except (KeyError, TypeError):
            return None, label
    return None, label


def _containers(pod_spec: dict) -> Iterable[dict]:
    yield from pod_spec.get("containers", []) or []
    yield from pod_spec.get("initContainers", []) or []


def check_privileged_containers(pod_spec: dict, manifest_label: str) -> list[Finding]:
    findings = []
    for c in _containers(pod_spec):
        sc = c.get("securityContext") or {}
        if sc.get("privileged") is True:
            findings.append(
                Finding(
                    source="policy:kubernetes",
                    rule_id="K8S-PRIVILEGED-CONTAINER",
                    title=f"Container '{c.get('name')}' runs privileged",
                    severity=Severity.CRITICAL,
                    resource=manifest_label,
                    description="securityContext.privileged = true grants full host access.",
                    fixable=False,
                    location=f"{manifest_label}/{c.get('name')}",
                )
            )
    return findings


def check_host_network(pod_spec: dict, manifest_label: str) -> list[Finding]:
    if pod_spec.get("hostNetwork") is True:
        return [
            Finding(
                source="policy:kubernetes",
                rule_id="K8S-HOST-NETWORK",
                title=f"'{manifest_label}' shares the host network namespace",
                severity=Severity.HIGH,
                resource=manifest_label,
                description="hostNetwork: true bypasses network policy isolation.",
                fixable=False,
                location=manifest_label,
            )
        ]
    return []


def check_privilege_escalation(pod_spec: dict, manifest_label: str) -> list[Finding]:
    findings = []
    for c in _containers(pod_spec):
        sc = c.get("securityContext") or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(
                Finding(
                    source="policy:kubernetes",
                    rule_id="K8S-ALLOW-PRIVILEGE-ESCALATION",
                    title=(
                        f"Container '{c.get('name')}' does not set "
                        "allowPrivilegeEscalation: false"
                    ),
                    severity=Severity.MEDIUM,
                    resource=manifest_label,
                    description=(
                        "Without an explicit `allowPrivilegeEscalation: false`, a "
                        "container process can gain more privileges than its parent."
                    ),
                    fixable=False,
                    location=f"{manifest_label}/{c.get('name')}",
                )
            )
    return findings


def check_missing_resource_limits(pod_spec: dict, manifest_label: str) -> list[Finding]:
    findings = []
    for c in _containers(pod_spec):
        limits = (c.get("resources") or {}).get("limits") or {}
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(
                Finding(
                    source="policy:kubernetes",
                    rule_id="K8S-MISSING-RESOURCE-LIMITS",
                    title=f"Container '{c.get('name')}' has no cpu/memory limits",
                    severity=Severity.MEDIUM,
                    resource=manifest_label,
                    description=(
                        "Missing resources.limits.cpu/memory lets one pod starve "
                        "the node under load."
                    ),
                    fixable=False,
                    location=f"{manifest_label}/{c.get('name')}",
                )
            )
    return findings


def check_mutable_image_tags(pod_spec: dict, manifest_label: str) -> list[Finding]:
    findings = []
    for c in _containers(pod_spec):
        image = c.get("image", "")
        tag = image.split(":")[-1] if ":" in image.split("/")[-1] else None
        if tag is None or tag == "latest":
            findings.append(
                Finding(
                    source="policy:kubernetes",
                    rule_id="K8S-MUTABLE-IMAGE-TAG",
                    title=f"Container '{c.get('name')}' uses a mutable image tag",
                    severity=Severity.LOW,
                    resource=manifest_label,
                    description=(
                        f"image '{image}' has no tag (defaults to :latest) or is "
                        "explicitly :latest, which is not reproducible."
                    ),
                    fixable=False,
                    location=f"{manifest_label}/{c.get('name')}",
                )
            )
    return findings


_ALL_CHECKS = (
    check_privileged_containers,
    check_host_network,
    check_privilege_escalation,
    check_missing_resource_limits,
    check_mutable_image_tags,
)


def evaluate_manifest_docs(docs: Iterable[dict]) -> ScanResult:
    findings: list[Finding] = []
    for doc in docs:
        if not doc:
            continue
        pod_spec, label = _extract_pod_spec(doc)
        if pod_spec is None:
            continue
        for check in _ALL_CHECKS:
            findings.extend(check(pod_spec, label))
    return ScanResult(findings=findings)


def evaluate_manifest_yaml(text: str) -> ScanResult:
    docs = [d for d in yaml.safe_load_all(text) if d]
    return evaluate_manifest_docs(docs)


def evaluate_manifest_file(path: Union[str, Path]) -> ScanResult:
    return evaluate_manifest_yaml(Path(path).read_text())
