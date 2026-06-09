import pytest

from pipeline_guard.models import Severity
from pipeline_guard.scanners.trivy import (
    DockerfileImageAdvisor,
    TrivyNotAvailable,
    TrivyRunner,
    load_trivy_report,
    parse_trivy_report,
)


def test_parse_vulnerable_report_extracts_all_severities(fixtures_dir):
    result = load_trivy_report(fixtures_dir / "trivy" / "report-vulnerable.json")

    severities = {f.severity for f in result.findings}
    assert severities == {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    }
    assert len(result.findings) == 5


def test_parse_vulnerable_report_marks_fixed_versions_as_fixable(fixtures_dir):
    result = load_trivy_report(fixtures_dir / "trivy" / "report-vulnerable.json")
    by_id = {f.rule_id: f for f in result.findings}

    critical = by_id["CVE-2023-4863"]
    assert critical.fixable is True
    assert critical.fix_kind == "upgrade_package"
    assert "0.6.1-2+deb10u1" in critical.fix_hint

    # No FixedVersion in the fixture -> not fixable.
    no_fix = by_id["CVE-2020-16135"]
    assert no_fix.fixable is False
    assert no_fix.fix_kind is None


def test_parse_clean_report_has_no_findings(fixtures_dir):
    result = load_trivy_report(fixtures_dir / "trivy" / "report-clean.json")
    assert result.findings == []


def test_parse_trivy_report_accepts_dict_directly():
    data = {
        "ArtifactName": "inline:test",
        "Results": [
            {
                "Target": "inline:test",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-0000-0000",
                        "PkgName": "foo",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ],
    }
    result = parse_trivy_report(data)
    assert len(result.findings) == 1
    assert result.findings[0].resource == "inline:test"


def test_parse_report_handles_misconfigurations():
    data = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Image user should not be 'root'",
                        "Severity": "HIGH",
                        "Description": "Running as root is discouraged.",
                    }
                ],
            }
        ]
    }
    result = parse_trivy_report(data)
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "DS002"
    assert result.findings[0].fixable is False


def test_trivy_runner_raises_when_binary_missing():
    runner = TrivyRunner(binary="definitely-not-a-real-binary-xyz")
    with pytest.raises(TrivyNotAvailable):
        runner.scan_image("demo/webapp:1.0", output_path="/tmp/wont-be-created.json")


def test_dockerfile_advisor_flags_outdated_python_base(fixtures_dir):
    advisor = DockerfileImageAdvisor()
    result = advisor.inspect(fixtures_dir / "docker" / "Dockerfile.vulnerable")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "BASE-IMAGE-OUTDATED"
    assert finding.severity == Severity.HIGH
    assert finding.fixable is True
    assert finding.fix_kind == "bump_base_image"
    assert finding.raw["repo"] == "python"
    assert finding.raw["tag"] == "3.9"
    assert finding.raw["safe_tag"] == "3.12-slim"


def test_dockerfile_advisor_passes_clean_dockerfile(fixtures_dir):
    advisor = DockerfileImageAdvisor()
    result = advisor.inspect(fixtures_dir / "docker" / "Dockerfile.clean")
    assert result.findings == []
