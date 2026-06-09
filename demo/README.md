# Demo: the gate blocking a real PR, end to end

This walks through exactly what happens when a PR introduces the intentionally-vulnerable fixtures in fixtures/, using the real CLI (no mocking) against the real Trivy/Terraform/Kubernetes fixture data. Run it yourself with:

```bash
pip install -e .
bash demo/run_demo.sh
```

## The scenario

A PR changes three things at once:

1. Dockerfile bumps nothing, but still pins FROM python:3.9 (EOL).
2. main.tf opens aws_security_group.web to 0.0.0.0/0 on port 22, makes an S3 bucket public, and leaves an EBS volume + RDS instance unencrypted.
3. deployment.yaml adds a Deployment with a privileged container and hostNetwork: true.

## Step 1 -- baseline PR (passes)

fixtures/docker/Dockerfile.clean + fixtures/terraform/clean/plan.json + fixtures/k8s/deployment-clean.yaml represent the PR before those changes. Running the gate produces sample-passing-pr-comment.md:

```
## pipeline-guard security gate: PASSED
Risk score 0 (threshold 30) across 0 finding(s)
```

Exit code 0 -- the PR is mergeable.

## Step 2 -- the vulnerable PR (blocked)

Now point the gate at the vulnerable fixtures (what the PR actually changed). This is the exact command the GitHub Action runs on every push:

```bash
pipeline-guard scan \
  --dockerfile fixtures/docker/Dockerfile.vulnerable \
  --trivy-report fixtures/trivy/report-vulnerable.json \
  --terraform-plan fixtures/terraform/vulnerable/plan.json \
  --k8s fixtures/k8s/deployment-vulnerable.yaml \
  --report-out demo/sample-blocked-pr-comment.md \
  --json-out demo/sample-scan.json
```

Real output, captured in sample-blocked-pr-comment.md:

* Risk score 179 against a threshold of 30 (5 CRITICAL, 4 HIGH, 9 MEDIUM, 3 LOW across 21 findings from Trivy + both policy engines combined).
* The process exits 1 -- in CI this fails the check and blocks merge.
* The rendered Markdown is exactly what the GitHub Action posts as a PR comment (see action.yml's "Post PR comment" step), including the severity table and a row per finding with its rule ID and remediation hint.

## Step 3 -- the auto-fix PR

7 of the 21 findings are mechanically fixable (the outdated base image tag, plus the two flag-style Terraform encryption settings). --json-out from step 2 is exactly the input autofix consumes, so no re-scan is needed:

```bash
pipeline-guard autofix --scan-json demo/sample-scan.json --terraform-dir <path-to-main.tf>
```

```
Auto-fix plan: pipeline-guard: mechanical security fixes
  - [BASE-IMAGE-OUTDATED] Dockerfile: Bump python:3.9 -> python:3.12-slim
  - [TF-ENCRYPTION-MISSING] main.tf: Set encrypted = true on aws_ebs_volume.data
  - [TF-ENCRYPTION-MISSING] main.tf: Set storage_encrypted = true on aws_db_instance.primary
```

Add --apply --repo-dir <repo> and it commits those exact patches to a real pipeline-guard/auto-fix branch (see tests/test_cli.py::test_autofix_apply_commits_to_local_repo for this running against a real local git repo). In the GitHub Action, that branch is pushed and opened as a PR via RestGitHubClient (auto-fix: true input).

## What's not auto-fixed, and why

The open security group, the public S3 ACL, the privileged container, and the missing resource limits are all left for a human. Each requires a judgment call pipeline-guard deliberately refuses to make silently: what the intended network topology is, whether public access is actually required, or what resource ceiling is safe for that workload. See src/pipeline_guard/autofix.py's module docstring for the exact criteria.

## Maintainer

This project is maintained by Yeshwanth Reddy Aleti. Yeshwanth is a Network Engineer with over 4 years of experience in designing, implementing, and supporting secure enterprise network infrastructures. He specializes in network security, cloud networking, and infrastructure automation using Python, PowerShell, and Bash to deliver resilient and compliant network services.

For questions or support regarding this project, please contact:
- Email: yeshwanth.ra61@gmail.com
- GitHub: https://github.com/yeshwanth-aleti