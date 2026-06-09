import json
import re

from pipeline_guard.autofix import (
    AutoFixOrchestrator,
    add_terraform_attribute,
    bump_dockerfile_base_image,
    find_terraform_resource_file,
)
from pipeline_guard.scanners.terraform_policy import evaluate_terraform_plan
from pipeline_guard.scanners.trivy import DockerfileImageAdvisor


def test_bump_dockerfile_base_image_rewrites_tag():
    original = "FROM python:3.9\nWORKDIR /app\n"
    patched = bump_dockerfile_base_image(original, "python", "3.9", "3.12-slim")
    assert patched == "FROM python:3.12-slim\nWORKDIR /app\n"


def test_bump_dockerfile_base_image_preserves_multistage_alias():
    original = "FROM node:16 AS build\nRUN npm ci\n"
    patched = bump_dockerfile_base_image(original, "node", "16", "20-slim")
    assert patched == "FROM node:20-slim AS build\nRUN npm ci\n"


def test_bump_dockerfile_base_image_noop_when_tag_absent():
    original = "FROM python:3.12-slim\n"
    patched = bump_dockerfile_base_image(original, "python", "3.9", "3.12-slim")
    assert patched == original


def test_add_terraform_attribute_flips_explicit_false_to_true():
    original = (
        'resource "aws_db_instance" "primary" {\n'
        "  engine = \"postgres\"\n"
        "  storage_encrypted = false\n"
        "}\n"
    )
    patched = add_terraform_attribute(original, "aws_db_instance", "primary", "storage_encrypted")
    assert "storage_encrypted = true" in patched
    assert "storage_encrypted = false" not in patched


def test_add_terraform_attribute_inserts_when_missing():
    original = (
        'resource "aws_ebs_volume" "data" {\n'
        "  size = 40\n"
        "}\n"
    )
    patched = add_terraform_attribute(original, "aws_ebs_volume", "data", "encrypted")
    assert "encrypted = true" in patched
    # original attribute untouched
    assert "size = 40" in patched


def test_add_terraform_attribute_is_idempotent_when_already_true():
    original = (
        'resource "aws_ebs_volume" "data" {\n'
        "  encrypted = true\n"
        "}\n"
    )
    patched = add_terraform_attribute(original, "aws_ebs_volume", "data", "encrypted")
    assert patched == original


def test_add_terraform_attribute_noop_for_unmatched_resource():
    original = 'resource "aws_s3_bucket" "other" {\n  bucket = "x"\n}\n'
    patched = add_terraform_attribute(original, "aws_ebs_volume", "data", "encrypted")
    assert patched == original


def test_find_terraform_resource_file_locates_correct_file(fixtures_dir):
    path = find_terraform_resource_file(
        fixtures_dir / "terraform" / "vulnerable", "aws_ebs_volume", "data"
    )
    assert path is not None
    assert path.name == "main.tf"


def test_find_terraform_resource_file_returns_none_when_absent(fixtures_dir):
    path = find_terraform_resource_file(
        fixtures_dir / "terraform" / "vulnerable", "aws_lambda_function", "nonexistent"
    )
    assert path is None


def test_orchestrator_builds_dockerfile_fix_plan(tmp_fixture_copy):
    dockerfile = tmp_fixture_copy / "docker" / "Dockerfile.vulnerable"
    findings = DockerfileImageAdvisor().inspect(dockerfile).findings

    orchestrator = AutoFixOrchestrator()
    plan = orchestrator.build_plan(findings)

    assert not plan.is_empty
    assert str(dockerfile) in plan.patches
    assert "FROM python:3.12-slim" in plan.patches[str(dockerfile)]
    assert len(plan.fix_results) == 1
    assert plan.fix_results[0].rule_id == "BASE-IMAGE-OUTDATED"


def test_orchestrator_builds_terraform_fix_plan(tmp_fixture_copy):
    tf_dir = tmp_fixture_copy / "terraform" / "vulnerable"
    plan_json = json.loads((tf_dir / "plan.json").read_text())
    findings = evaluate_terraform_plan(plan_json).fixable_findings()
    assert len(findings) == 2  # ebs volume + rds instance encryption

    orchestrator = AutoFixOrchestrator(terraform_dir=tf_dir)
    pr_plan = orchestrator.build_plan(findings)

    assert not pr_plan.is_empty
    main_tf = str(tf_dir / "main.tf")
    assert main_tf in pr_plan.patches
    patched_content = pr_plan.patches[main_tf]
    assert re.search(r"\bencrypted\s*=\s*true", patched_content)
    assert re.search(r"\bstorage_encrypted\s*=\s*true", patched_content)
    assert "storage_encrypted      = false" not in patched_content
    assert len(pr_plan.fix_results) == 2


def test_orchestrator_plan_is_empty_when_no_fixable_findings():
    orchestrator = AutoFixOrchestrator()
    plan = orchestrator.build_plan([])
    assert plan.is_empty
    assert "No mechanical fixes" in plan.body


def test_orchestrator_skips_terraform_fix_without_terraform_dir(tmp_fixture_copy):
    tf_dir = tmp_fixture_copy / "terraform" / "vulnerable"
    plan_json = json.loads((tf_dir / "plan.json").read_text())
    findings = evaluate_terraform_plan(plan_json).fixable_findings()

    orchestrator = AutoFixOrchestrator(terraform_dir=None)
    plan = orchestrator.build_plan(findings)
    assert plan.is_empty
