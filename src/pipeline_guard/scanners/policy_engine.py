"""Optional real `conftest` invocation.

The candidate-authored policies in `policies/*.rego` are meant to run for
real under `conftest test --policy policies/<kind> <input>`. That requires
the `conftest`/OPA binary, which we do not assume is present in this
environment (and must not require at unit-test time per the offline
constraint). `ConftestRunner` is the thin real-execution wrapper used when
conftest *is* available (e.g. a full CI runner); `terraform_policy.py` and
`k8s_policy.py` contain the pure-Python re-implementation of the exact same
rule set, which is what the test suite and the default CLI path exercise so
pipeline-guard works with zero external binaries.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Union


class ConftestNotAvailable(RuntimeError):
    """Raised when the `conftest` binary is required but not on PATH."""


def is_conftest_installed() -> bool:
    return shutil.which("conftest") is not None


class ConftestRunner:
    """Wrapper around the real `conftest` CLI, used only when installed."""

    def __init__(self, binary: str = "conftest"):
        self.binary = binary

    def test(
        self,
        input_path: Union[str, Path],
        policy_dir: Union[str, Path],
        timeout: int = 60,
    ) -> dict:
        """Run `conftest test --output json` and return the parsed report.

        Never called by the unit test suite; guarded behind
        `is_conftest_installed()` in the CLI's scanner-selection logic.
        """
        if not shutil.which(self.binary):
            raise ConftestNotAvailable(
                f"'{self.binary}' is not installed or not on PATH. "
                "pipeline-guard's built-in policy engine (--engine=builtin, "
                "the default) reimplements the same rules and needs no "
                "external binary."
            )
        cmd = [
            self.binary,
            "test",
            "--policy",
            str(policy_dir),
            "--output",
            "json",
            str(input_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # conftest exits 1 when there are policy failures, which is expected.
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"conftest exited with {result.returncode}: {result.stderr.strip()}"
            )
        return json.loads(result.stdout or "[]")
