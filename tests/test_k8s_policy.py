from pipeline_guard.models import Severity
from pipeline_guard.scanners.k8s_policy import evaluate_manifest_file, evaluate_manifest_yaml


def test_vulnerable_manifest_flags_privileged_container(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-vulnerable.yaml")
    privileged = [f for f in result.findings if f.rule_id == "K8S-PRIVILEGED-CONTAINER"]
    assert len(privileged) == 1
    assert privileged[0].severity == Severity.CRITICAL
    assert privileged[0].resource == "Deployment/webapp"


def test_vulnerable_manifest_flags_host_network(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-vulnerable.yaml")
    host_net = [f for f in result.findings if f.rule_id == "K8S-HOST-NETWORK"]
    assert len(host_net) == 1
    assert host_net[0].severity == Severity.HIGH


def test_vulnerable_manifest_flags_privilege_escalation_across_both_docs(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-vulnerable.yaml")
    esc = [f for f in result.findings if f.rule_id == "K8S-ALLOW-PRIVILEGE-ESCALATION"]
    # webapp container has no securityContext.allowPrivilegeEscalation -> flagged
    # debug-shell Pod sets it to true explicitly -> also flagged
    resources = {f.resource for f in esc}
    assert resources == {"Deployment/webapp", "Pod/debug-shell"}


def test_vulnerable_manifest_flags_missing_resource_limits(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-vulnerable.yaml")
    limits = [f for f in result.findings if f.rule_id == "K8S-MISSING-RESOURCE-LIMITS"]
    # both webapp and debug-shell containers omit resources.limits
    assert len(limits) == 2


def test_vulnerable_manifest_flags_mutable_tag(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-vulnerable.yaml")
    tags = [f for f in result.findings if f.rule_id == "K8S-MUTABLE-IMAGE-TAG"]
    resources = {f.resource for f in tags}
    # webapp uses :latest explicitly; debug-shell's "busybox" has no tag at all
    assert resources == {"Deployment/webapp", "Pod/debug-shell"}


def test_clean_manifest_has_no_findings(fixtures_dir):
    result = evaluate_manifest_file(fixtures_dir / "k8s" / "deployment-clean.yaml")
    assert result.findings == []


def test_statefulset_and_daemonset_templates_are_inspected():
    text = """
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
        - name: db
          image: postgres:16
          securityContext:
            privileged: true
"""
    result = evaluate_manifest_yaml(text)
    assert len(result.findings) >= 1
    assert any(f.rule_id == "K8S-PRIVILEGED-CONTAINER" for f in result.findings)
    assert result.findings[0].resource == "StatefulSet/db"


def test_unrecognized_kind_is_ignored():
    text = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  foo: bar
"""
    result = evaluate_manifest_yaml(text)
    assert result.findings == []


def test_empty_yaml_documents_are_skipped():
    result = evaluate_manifest_yaml("---\n---\n")
    assert result.findings == []
