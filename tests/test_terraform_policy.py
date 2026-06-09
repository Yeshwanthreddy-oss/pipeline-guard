import json

from pipeline_guard.models import Severity
from pipeline_guard.scanners.terraform_policy import evaluate_terraform_plan


def _load(fixtures_dir, name):
    return json.loads((fixtures_dir / "terraform" / name / "plan.json").read_text())


def test_vulnerable_plan_flags_open_security_group(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)

    sg_findings = [f for f in result.findings if f.rule_id == "TF-SG-OPEN-INGRESS"]
    assert len(sg_findings) == 2  # port 22 (sensitive) and port 443 (not sensitive)

    by_port = {f.raw["from_port"]: f for f in sg_findings}
    assert by_port[22].severity == Severity.CRITICAL
    assert by_port[443].severity == Severity.HIGH
    assert all(f.resource == "aws_security_group.web" for f in sg_findings)


def test_vulnerable_plan_flags_public_s3_bucket(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)

    s3_findings = [f for f in result.findings if f.rule_id == "TF-S3-PUBLIC-ACL"]
    assert len(s3_findings) == 1
    assert s3_findings[0].severity == Severity.CRITICAL
    assert s3_findings[0].resource == "aws_s3_bucket.assets"


def test_vulnerable_plan_flags_public_rds(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)

    rds_findings = [f for f in result.findings if f.rule_id == "TF-RDS-PUBLIC"]
    assert len(rds_findings) == 1
    assert rds_findings[0].severity == Severity.CRITICAL


def test_vulnerable_plan_flags_missing_encryption(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)

    enc_findings = {f.resource: f for f in result.findings if f.rule_id == "TF-ENCRYPTION-MISSING"}
    assert set(enc_findings) == {"aws_ebs_volume.data", "aws_db_instance.primary"}
    for f in enc_findings.values():
        assert f.severity == Severity.MEDIUM
        assert f.fixable is True
        assert f.fix_kind == "add_encryption_flag"

    assert enc_findings["aws_ebs_volume.data"].raw["attribute"] == "encrypted"
    assert enc_findings["aws_db_instance.primary"].raw["attribute"] == "storage_encrypted"


def test_vulnerable_plan_flags_missing_s3_encryption_as_not_mechanically_fixable(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)

    sse_findings = [f for f in result.findings if f.rule_id == "TF-S3-SSE-MISSING"]
    assert len(sse_findings) == 1
    assert sse_findings[0].resource == "aws_s3_bucket.assets"
    assert sse_findings[0].fixable is False


def test_vulnerable_plan_total_finding_count(fixtures_dir):
    plan = _load(fixtures_dir, "vulnerable")
    result = evaluate_terraform_plan(plan)
    # 2 open-ingress + 1 public bucket + 1 public rds + 2 missing-encryption
    # (flag-style) + 1 missing s3 SSE config
    assert len(result.findings) == 7


def test_clean_plan_has_no_findings(fixtures_dir):
    plan = _load(fixtures_dir, "clean")
    result = evaluate_terraform_plan(plan)
    assert result.findings == []


def test_deleted_resources_are_ignored():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.gone",
                "type": "aws_s3_bucket",
                "change": {"actions": ["delete"], "after": None},
            }
        ]
    }
    result = evaluate_terraform_plan(plan)
    assert result.findings == []


def test_public_access_block_with_false_flag_is_flagged():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket_public_access_block.partial",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "block_public_acls": True,
                        "block_public_policy": True,
                        "ignore_public_acls": True,
                        "restrict_public_buckets": False,
                    },
                },
            }
        ]
    }
    result = evaluate_terraform_plan(plan)
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "TF-S3-PUBLIC-ACCESS-BLOCK"
    assert result.findings[0].severity == Severity.HIGH
