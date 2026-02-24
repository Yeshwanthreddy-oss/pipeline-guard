import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_fixture_copy(tmp_path):
    """Copy the whole fixtures/ tree into a tmp dir so tests can mutate files
    (e.g. autofix patching a Dockerfile) without touching the real fixtures.
    """
    dest = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, dest)
    return dest
