<!-- pipeline-guard:report -->
## pipeline-guard security gate: ❌ BLOCKED
Risk score **179** (threshold **30**) across **21** finding(s) for `fixtures/docker/Dockerfile.vulnerable`

### Severity breakdown
| Severity | Count |
| --- | --- |
| 🟥 CRITICAL | 5 |
| 🟧 HIGH | 4 |
| 🟨 MEDIUM | 9 |
| 🟩 LOW | 3 |

### Findings
| Severity | Rule | Resource | Summary | Fix |
| --- | --- | --- | --- | --- |
| 🟥 CRITICAL | `CVE-2023-4863` | `demo/webapp:1.4.0 (debian 10.13)` | CVE-2023-4863: libwebp7 0.6.1-2 | Upgrade libwebp7 from 0.6.1-2 to 0.6.1-2+deb10u1 |
| 🟥 CRITICAL | `TF-SG-OPEN-INGRESS` | `aws_security_group.web` | Security group 'aws_security_group.web' allows ingress from the public internet | manual |
| 🟥 CRITICAL | `TF-S3-PUBLIC-ACL` | `aws_s3_bucket.assets` | S3 bucket 'aws_s3_bucket.assets' has a public ACL | manual |
| 🟥 CRITICAL | `TF-RDS-PUBLIC` | `aws_db_instance.primary` | RDS instance 'aws_db_instance.primary' is publicly accessible | manual |
| 🟥 CRITICAL | `K8S-PRIVILEGED-CONTAINER` | `Deployment/webapp` | Container 'webapp' runs privileged | manual |
| 🟧 HIGH | `CVE-2022-37434` | `demo/webapp:1.4.0 (debian 10.13)` | CVE-2022-37434: zlib1g 1:1.2.11.dfsg-1 | Upgrade zlib1g from 1:1.2.11.dfsg-1 to 1:1.2.11.dfsg-1+deb10u2 |
| 🟧 HIGH | `BASE-IMAGE-OUTDATED` | `fixtures/docker/Dockerfile.vulnerable` | Outdated base image: python:3.9 | Bump python:3.9 -> python:3.12-slim |
| 🟧 HIGH | `TF-SG-OPEN-INGRESS` | `aws_security_group.web` | Security group 'aws_security_group.web' allows ingress from the public internet | manual |
| 🟧 HIGH | `K8S-HOST-NETWORK` | `Deployment/webapp` | 'Deployment/webapp' shares the host network namespace | manual |
| 🟨 MEDIUM | `CVE-2021-3999` | `demo/webapp:1.4.0 (debian 10.13)` | CVE-2021-3999: glibc 2.28-10 | Upgrade glibc from 2.28-10 to 2.28-10+deb10u2 |
| 🟨 MEDIUM | `CVE-2023-32681` | `demo/webapp:1.4.0 (requirements.txt)` | CVE-2023-32681: requests 2.25.1 | Upgrade requests from 2.25.1 to 2.31.0 |
| 🟨 MEDIUM | `TF-ENCRYPTION-MISSING` | `aws_ebs_volume.data` | 'aws_ebs_volume.data' is not encrypted at rest | Set encrypted = true on aws_ebs_volume.data |
| 🟨 MEDIUM | `TF-ENCRYPTION-MISSING` | `aws_db_instance.primary` | 'aws_db_instance.primary' is not encrypted at rest | Set storage_encrypted = true on aws_db_instance.primary |
| 🟨 MEDIUM | `TF-S3-SSE-MISSING` | `aws_s3_bucket.assets` | 'aws_s3_bucket.assets' has no server-side encryption configured | manual |
| 🟨 MEDIUM | `K8S-ALLOW-PRIVILEGE-ESCALATION` | `Deployment/webapp` | Container 'webapp' does not set allowPrivilegeEscalation: false | manual |
| 🟨 MEDIUM | `K8S-MISSING-RESOURCE-LIMITS` | `Deployment/webapp` | Container 'webapp' has no cpu/memory limits | manual |
| 🟨 MEDIUM | `K8S-ALLOW-PRIVILEGE-ESCALATION` | `Pod/debug-shell` | Container 'shell' does not set allowPrivilegeEscalation: false | manual |
| 🟨 MEDIUM | `K8S-MISSING-RESOURCE-LIMITS` | `Pod/debug-shell` | Container 'shell' has no cpu/memory limits | manual |
| 🟩 LOW | `CVE-2020-16135` | `demo/webapp:1.4.0 (debian 10.13)` | CVE-2020-16135: libbluetooth3 5.50-1.2~deb10u1 | manual |
| 🟩 LOW | `K8S-MUTABLE-IMAGE-TAG` | `Deployment/webapp` | Container 'webapp' uses a mutable image tag | manual |
| 🟩 LOW | `K8S-MUTABLE-IMAGE-TAG` | `Pod/debug-shell` | Container 'shell' uses a mutable image tag | manual |

### Mechanical auto-fix
7 finding(s) are mechanically fixable (base image tag bumps, missing `encrypted`/`storage_encrypted` flags).
Run `pipeline-guard autofix` (or re-run this action with `auto_fix: true`) to open a follow-up PR with the mechanical fixes.

**This build is blocked** because the risk score (179) exceeds the configured threshold (30). Resolve the CRITICAL/HIGH findings above, or raise the threshold in `pipeline-guard.yml` if this is an accepted risk.
