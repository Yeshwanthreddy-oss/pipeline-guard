"""Container image scanning.

Two complementary sources feed into the same ScanResult:

1. `TrivyRunner` shells out to the real `trivy` CLI when it is installed and
   parses its native JSON report format. This is what actually runs in CI.
2. `DockerfileImageAdvisor` statically inspects a Dockerfile's `FROM` lines
   against a small curated table of known-vulnerable-tag -> safe-tag pairs.
   This is what powers the "bump the base image tag" mechanical auto-fix,
   since a raw Trivy CVE report has no notion of *which* tag to bump to.

Both paths are pure functions over data (a JSON blob / a Dockerfile's text),
so they are fully unit-testable without Docker, a daemon, or network access.
Only `TrivyRunner.scan_image` touches a subprocess, and it is never invoked
by the test suite by default.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional, Union

from ..models import Finding, ScanResult, Severity

JsonLike = Union[str, Path, dict]


class TrivyNotAvailable(RuntimeError):
    """Raised when the `trivy` binary is required but not on PATH."""


def is_trivy_installed() -> bool:
    return shutil.which("trivy") is not None


class TrivyRunner:
    """Thin wrapper around the `trivy` CLI for container image scanning."""

    def __init__(self, binary: str = "trivy"):
        self.binary = binary

    def scan_image(
        self,
        image: str,
        output_path: Path,
        timeout: int = 300,
        severities: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
    ) -> Path:
        """Run `trivy image` and write its JSON report to `output_path`.

        Requires Docker/the trivy binary and network access to pull the
        vulnerability DB, so this is never exercised by the unit test suite;
        it is exclusively an integration-time code path guarded by
        `is_trivy_installed()`.
        """
        if not shutil.which(self.binary):
            raise TrivyNotAvailable(
                f"'{self.binary}' is not installed or not on PATH. "
                "Install it (https://aquasecurity.github.io/trivy) or pass "
                "--trivy-report to scan a pre-generated JSON report instead."
            )
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.binary,
            "image",
            "--format",
            "json",
            "--severity",
            ",".join(severities),
            "--output",
            str(output_path),
            image,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode not in (0, 1):
            # trivy exits 1 when --exit-code is set and findings exist; we
            # don't set --exit-code so 0 is the only expected success code,
            # but tolerate 1 defensively across trivy versions.
            raise RuntimeError(
                f"trivy exited with {result.returncode}: {result.stderr.strip()}"
            )
        return output_path


def _load_json(data: JsonLike) -> dict:
    if isinstance(data, dict):
        return data
    path = Path(data)
    return json.loads(path.read_text())


def parse_trivy_report(data: JsonLike, image_ref: Optional[str] = None) -> ScanResult:
    """Parse a Trivy JSON report (native `trivy image --format json` schema)
    into a normalized ScanResult.
    """
    report = _load_json(data)
    findings: list[Finding] = []
    resolved_image = image_ref or report.get("ArtifactName") or "unknown-image"

    for result in report.get("Results", []) or []:
        target = result.get("Target", resolved_image)
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = Severity.from_str(vuln.get("Severity", "UNKNOWN"))
            fixed_version = vuln.get("FixedVersion")
            pkg = vuln.get("PkgName", "unknown-package")
            installed = vuln.get("InstalledVersion", "?")
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=vuln_id,
                    title=f"{vuln_id}: {pkg} {installed}",
                    severity=severity,
                    resource=target,
                    description=vuln.get("Title") or vuln.get("Description", "")[:280],
                    fixable=bool(fixed_version),
                    fix_kind="upgrade_package" if fixed_version else None,
                    fix_hint=(
                        f"Upgrade {pkg} from {installed} to {fixed_version}"
                        if fixed_version
                        else None
                    ),
                    location=target,
                    raw=vuln,
                )
            )

        # Misconfigurations block covers Dockerfile/IaC issues trivy itself
        # detects (e.g. HEALTHCHECK missing); folded into the same result
        # set since they are still "image scan" findings, not policy ones.
        for misconf in result.get("Misconfigurations", []) or []:
            severity = Severity.from_str(misconf.get("Severity", "UNKNOWN"))
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=misconf.get("ID", "UNKNOWN-MISCONF"),
                    title=misconf.get("Title", "Misconfiguration"),
                    severity=severity,
                    resource=target,
                    description=misconf.get("Description", ""),
                    fixable=False,
                    location=target,
                    raw=misconf,
                )
            )

    return ScanResult(findings=findings)


def load_trivy_report(path: Union[str, Path]) -> ScanResult:
    return parse_trivy_report(Path(path))


# ---------------------------------------------------------------------------
# Dockerfile base-image tag advisor (feeds the "bump base image" auto-fix)
# ---------------------------------------------------------------------------

# A tiny, curated "known vulnerable tag -> recommended safe tag" table.
# In a real deployment this would be informed by the Trivy report itself
# (the highest-fixed-version seen for OS packages) or a registry API; here it
# is intentionally explicit and offline so the advisor is deterministic and
# testable without any network calls.
KNOWN_UNSAFE_BASE_IMAGES: dict[str, dict[str, str]] = {
    "python": {"2.7": "3.12-slim", "3.8": "3.12-slim", "3.9": "3.12-slim"},
    "node": {"14": "20-slim", "16": "20-slim", "17": "20-slim"},
    "alpine": {"3.10": "3.19", "3.12": "3.19", "3.14": "3.19"},
    "ubuntu": {"18.04": "22.04", "16.04": "22.04"},
    "debian": {"9": "12-slim", "10": "12-slim", "buster": "12-slim"},
}

_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+):([\w.-]+)(\s+AS\s+\S+)?\s*$",
    re.IGNORECASE,
)


class DockerfileImageAdvisor:
    """Flags outdated/unsafe base image tags in a Dockerfile."""

    def inspect(self, dockerfile_path: Union[str, Path]) -> ScanResult:
        path = Path(dockerfile_path)
        text = path.read_text()
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _FROM_RE.match(line)
            if not match:
                continue
            repo, tag = match.group(1), match.group(2)
            image_key = repo.split("/")[-1]
            safe_tag = KNOWN_UNSAFE_BASE_IMAGES.get(image_key, {}).get(tag)
            if safe_tag:
                findings.append(
                    Finding(
                        source="trivy",
                        rule_id="BASE-IMAGE-OUTDATED",
                        title=f"Outdated base image: {repo}:{tag}",
                        severity=Severity.HIGH,
                        resource=str(path),
                        description=(
                            f"{repo}:{tag} is an end-of-life/unpatched tag with a "
                            f"known-safer successor available."
                        ),
                        fixable=True,
                        fix_kind="bump_base_image",
                        fix_hint=f"Bump {repo}:{tag} -> {repo}:{safe_tag}",
                        location=f"{path}:{lineno}",
                        raw={"repo": repo, "tag": tag, "safe_tag": safe_tag, "line": lineno},
                    )
                )
        return ScanResult(findings=findings)
