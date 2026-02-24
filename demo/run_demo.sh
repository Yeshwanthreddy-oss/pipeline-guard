#!/usr/bin/env bash
# Reproduces the "gate blocks a real PR" walkthrough described in demo/README.md.
# Run from the repo root: bash demo/run_demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== 1. Simulated PR: a clean change (passes) =========================="
pipeline-guard scan \
  --dockerfile fixtures/docker/Dockerfile.clean \
  --terraform-plan fixtures/terraform/clean/plan.json \
  --k8s fixtures/k8s/deployment-clean.yaml \
  --report-out demo/sample-passing-pr-comment.md
echo "  -> demo/sample-passing-pr-comment.md (exit 0, merge allowed)"

echo
echo "== 2. Simulated PR: introduces the vulnerable fixtures (blocked) ======"
set +e
pipeline-guard scan \
  --dockerfile fixtures/docker/Dockerfile.vulnerable \
  --trivy-report fixtures/trivy/report-vulnerable.json \
  --terraform-plan fixtures/terraform/vulnerable/plan.json \
  --k8s fixtures/k8s/deployment-vulnerable.yaml \
  --report-out demo/sample-blocked-pr-comment.md \
  --json-out demo/sample-scan.json
exit_code=$?
set -e
echo "  -> demo/sample-blocked-pr-comment.md (exit $exit_code, merge blocked)"

echo
echo "== 3. Build the mechanical auto-fix PR plan ==========================="
workdir="$(mktemp -d)"
cp fixtures/terraform/vulnerable/main.tf "$workdir/"
pipeline-guard autofix --scan-json demo/sample-scan.json --terraform-dir "$workdir"
rm -rf "$workdir"

echo
echo "Done. Open demo/sample-blocked-pr-comment.md to see the annotated comment."
