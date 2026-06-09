"""Mechanical remediation: turn a subset of findings into an actual patch.

Only two finding kinds are considered "mechanically fixable" -- meaning a
deterministic text transform closes them with no judgment call:

* `bump_base_image`  -- rewrite a Dockerfile `FROM repo:oldtag` line.
* `add_encryption_flag` -- insert the missing `encrypted`/`storage_encrypted`
  attribute into the matching Terraform resource block.

Everything else (open security groups, privileged containers, missing
resource limits, ...) requires a human judgment call about intended network
topology or capacity, so pipeline-guard deliberately never attempts to
auto-fix them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding

_FROM_LINE_RE_TEMPLATE = r"^(\s*FROM\s+(?:--platform=\S+\s+)?){repo}:{tag}(\s.*)?$"


@dataclass
class FixResult:
    rule_id: str
    file: str
    description: str
    original: str
    patched: str
    applied: bool = True

    @property
    def changed(self) -> bool:
        return self.original != self.patched


@dataclass
class PullRequestPlan:
    branch: str
    title: str
    body: str
    patches: dict[str, str] = field(default_factory=dict)  # path -> new file content
    fix_results: list[FixResult] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.patches


def bump_dockerfile_base_image(content: str, repo: str, old_tag: str, new_tag: str) -> str:
    """Rewrite `FROM repo:old_tag` -> `FROM repo:new_tag`, preserving `AS stage`."""
    pattern = re.compile(
        _FROM_LINE_RE_TEMPLATE.format(repo=re.escape(repo), tag=re.escape(old_tag)),
        re.MULTILINE | re.IGNORECASE,
    )
    return pattern.sub(rf"\g<1>{repo}:{new_tag}\2", content)


_RESOURCE_BLOCK_RE_TEMPLATE = (
    r'(resource\s+"{rtype}"\s+"{name}"\s*\{{)([^}}]*)(\}})'
)


def add_terraform_attribute(
    content: str, resource_type: str, resource_name: str, attribute: str, value: str = "true"
) -> str:
    """Ensure `attribute = value` is set in the named resource block.

    If the attribute is already present (e.g. explicitly `false`, which is
    exactly the state that triggers `TF-ENCRYPTION-MISSING`), its value is
    replaced. If it is entirely absent, a new line is appended before the
    closing brace. Uses a brace-balanced-ish regex suitable for the flat,
    single-level resource blocks pipeline-guard's fixtures (and most real
    IaC) use; it intentionally does not attempt to be a full HCL parser.
    """
    pattern = re.compile(
        _RESOURCE_BLOCK_RE_TEMPLATE.format(
            rtype=re.escape(resource_type), name=re.escape(resource_name)
        ),
        re.DOTALL,
    )

    match = pattern.search(content)
    if not match:
        return content

    body = match.group(2)
    attr_re = re.compile(rf"(\b{re.escape(attribute)}\s*=\s*)(\S+)")
    existing = attr_re.search(body)
    if existing:
        new_body = attr_re.sub(rf"\g<1>{value}", body, count=1)
    else:
        indent_match = re.search(r"\n(\s+)\S", body)
        indent = indent_match.group(1) if indent_match else "  "
        insertion = f"\n{indent}{attribute} = {value}"
        new_body = body.rstrip("\n") + insertion + "\n"

    return content[: match.start(2)] + new_body + content[match.end(2) :]


def find_terraform_resource_file(
    terraform_dir: Path, resource_type: str, resource_name: str
) -> Path | None:
    needle = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    for path in sorted(Path(terraform_dir).glob("**/*.tf")):
        if needle.search(path.read_text()):
            return path
    return None


class AutoFixOrchestrator:
    """Builds a `PullRequestPlan` of mechanical patches for a set of findings."""

    def __init__(self, terraform_dir: Path | None = None):
        self.terraform_dir = Path(terraform_dir) if terraform_dir else None

    def _fix_dockerfile_finding(
        self, finding: Finding, working: dict[str, str]
    ) -> FixResult | None:
        raw = finding.raw or {}
        repo, old_tag, new_tag = raw.get("repo"), raw.get("tag"), raw.get("safe_tag")
        if not (repo and old_tag and new_tag):
            return None
        path = Path(finding.resource)
        if not path.exists():
            return None
        key = str(path)
        original = working.get(key, path.read_text())
        patched = bump_dockerfile_base_image(original, repo, old_tag, new_tag)
        if patched == original:
            return None
        working[key] = patched
        return FixResult(
            rule_id=finding.rule_id,
            file=key,
            description=finding.fix_hint or "bump base image tag",
            original=original,
            patched=patched,
        )

    def _fix_terraform_finding(
        self, finding: Finding, working: dict[str, str]
    ) -> FixResult | None:
        if not self.terraform_dir:
            return None
        raw = finding.raw or {}
        rtype, attribute = raw.get("resource_type"), raw.get("attribute")
        address = raw.get("address", finding.resource)
        if not (rtype and attribute) or "." not in address:
            return None
        _, name = address.split(".", 1)
        path = find_terraform_resource_file(self.terraform_dir, rtype, name)
        if not path:
            return None
        key = str(path)
        original = working.get(key, path.read_text())
        patched = add_terraform_attribute(original, rtype, name, attribute)
        if patched == original:
            return None
        working[key] = patched
        return FixResult(
            rule_id=finding.rule_id,
            file=key,
            description=finding.fix_hint or f"set {attribute} = true",
            original=original,
            patched=patched,
        )

    def build_plan(
        self,
        findings: list[Finding],
        branch: str = "pipeline-guard/auto-fix",
        pr_title: str = "pipeline-guard: mechanical security fixes",
    ) -> PullRequestPlan:
        # Multiple findings can target the same file (e.g. two encryption
        # flags in the same .tf file); `working` accumulates patches per
        # file so the second fix builds on the first instead of clobbering
        # it with a fresh read from disk.
        working: dict[str, str] = {}
        fix_results: list[FixResult] = []
        for finding in findings:
            if not finding.fixable:
                continue
            result: FixResult | None = None
            if finding.fix_kind == "bump_base_image":
                result = self._fix_dockerfile_finding(finding, working)
            elif finding.fix_kind == "add_encryption_flag":
                result = self._fix_terraform_finding(finding, working)
            if result:
                fix_results.append(result)

        patches = dict(working)
        body_lines = ["This PR was opened automatically by pipeline-guard.", "", "Fixes applied:"]
        for r in fix_results:
            body_lines.append(f"- `{r.rule_id}` in `{r.file}`: {r.description}")
        if not fix_results:
            body_lines.append("_No mechanical fixes were applicable._")

        return PullRequestPlan(
            branch=branch,
            title=pr_title,
            body="\n".join(body_lines),
            patches=patches,
            fix_results=fix_results,
        )
