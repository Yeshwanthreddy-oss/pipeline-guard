"""pipeline-guard: a reusable security gate for container images and IaC.

Aggregates Trivy image-scan findings with OPA/Conftest-style policy checks
on Terraform and Kubernetes manifests, scores the combined risk, and gates
a CI run above a configurable threshold.
"""

__version__ = "0.1.0"
