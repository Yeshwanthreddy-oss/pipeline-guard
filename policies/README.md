# pipeline-guard policy set

This directory holds the OPA/Conftest policies enforced by pipeline-guard's IaC scanner, curated to ensure secure network and infrastructure configurations:

| File | Covers |
| --- | --- |
| `terraform/network.rego` | Security groups open to `0.0.0.0/0`, public RDS instances |
| `terraform/encryption.rego` | Unencrypted EBS/RDS/SQS, public S3 buckets/ACLs |
| `kubernetes/pod_security.rego` | Privileged containers, `hostNetwork`, missing `allowPrivilegeEscalation: false`, missing resource limits |

## Two ways to run these rules

1. **With `conftest` installed** (real OPA evaluation):
   ```bash
   terraform show -json plan.tfplan > plan.json
   conftest test --policy policies/terraform plan.json
   conftest test --policy policies/kubernetes k8s/deployment.yaml
   ```
   `pipeline_guard.scanners.policy_engine.ConftestRunner` wraps this exact invocation and is what a full CI runner with `conftest` on `PATH` uses.

2. **Built in, no external binary** (what `pipeline-guard scan` uses by default, and what the test suite exercises): the same rules, same thresholds, same resource addresses, reimplemented as plain Python in `src/pipeline_guard/scanners/terraform_policy.py` and `.../k8s_policy.py`. This is what makes pipeline-guard usable in environments where installing a Go binary isn't an option, and what keeps the test suite fully offline. Whenever a `.rego` rule changes, its Python counterpart must change too - `tests/test_terraform_policy.py` and `tests/test_k8s_policy.py` pin both to the fixtures in `fixtures/`.

## Adding a new rule

1. Write the `.rego` rule here for documentation/real-conftest use.
2. Add the matching pure-Python check next to the others in `terraform_policy.py` / `k8s_policy.py`.
3. Add a fixture (or extend an existing one) under `fixtures/` that exercises both the "violates" and "passes" cases.
4. Add a unit test asserting the exact `rule_id` and `severity` produced.

## Maintainer

This project is maintained by Yeshwanth Reddy Aleti, a Network Engineer with over 4 years of experience in designing and supporting enterprise network infrastructures. With a focus on network security, cloud connectivity, and automation using Python and Bash, he ensures these policies reflect current industry standards for secure and resilient infrastructure.

Contact:
- Name: Yeshwanth Reddy Aleti
- Email: yeshwanth.ra61@gmail.com