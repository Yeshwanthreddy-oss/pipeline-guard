"""Load `pipeline-guard.yml` (or CLI flags) into a single config object."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_THRESHOLD = 30


@dataclass
class PipelineGuardConfig:
    threshold: int = DEFAULT_THRESHOLD
    dockerfile: str | None = None
    terraform_dir: str | None = None
    terraform_plan: str | None = None
    k8s_manifests: list[str] = field(default_factory=list)
    trivy_report: str | None = None
    image: str | None = None
    autofix_enabled: bool = False
    autofix_branch: str = "pipeline-guard/auto-fix"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PipelineGuardConfig":
        known = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    @classmethod
    def load(cls, path: str | Path) -> "PipelineGuardConfig":
        text = Path(path).read_text()
        data = yaml.safe_load(text) or {}
        return cls.from_dict(data)

    def merge_cli_overrides(self, **overrides: Any) -> "PipelineGuardConfig":
        data = {**self.__dict__}
        for key, value in overrides.items():
            if value is not None and value != [] and key in data:
                data[key] = value
        return PipelineGuardConfig(**data)
