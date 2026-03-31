package kubernetes.pod_security

# Canonical OPA form of scanners/k8s_policy.py's checks. Run for real with:
#   conftest test --policy policies/kubernetes deployment.yaml
#
# Handles bare Pods and the common pod-template-nesting workloads.

pod_spec(input_doc) = spec {
	input_doc.kind == "Pod"
	spec := input_doc.spec
}

pod_spec(input_doc) = spec {
	templated_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job"}
	templated_kinds[input_doc.kind]
	spec := input_doc.spec.template.spec
}

pod_spec(input_doc) = spec {
	input_doc.kind == "CronJob"
	spec := input_doc.spec.jobTemplate.spec.template.spec
}

deny[msg] {
	spec := pod_spec(input)
	container := spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("%s/%s: container runs privileged", [input.kind, container.name])
}

deny[msg] {
	spec := pod_spec(input)
	spec.hostNetwork == true
	msg := sprintf("%s/%s: hostNetwork is true", [input.kind, input.metadata.name])
}

warn[msg] {
	spec := pod_spec(input)
	container := spec.containers[_]
	container.securityContext.allowPrivilegeEscalation != false
	msg := sprintf(
		"%s/%s: allowPrivilegeEscalation is not explicitly false",
		[input.kind, container.name],
	)
}

warn[msg] {
	spec := pod_spec(input)
	container := spec.containers[_]
	not container.resources.limits.cpu
	msg := sprintf("%s/%s: missing cpu resource limit", [input.kind, container.name])
}

warn[msg] {
	spec := pod_spec(input)
	container := spec.containers[_]
	not container.resources.limits.memory
	msg := sprintf("%s/%s: missing memory resource limit", [input.kind, container.name])
}
