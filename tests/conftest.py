"""Shared fixtures.

Every test uses deliberately cheap Argon2 parameters. A real vault calibrates
to about a second, which is the point of the design and the enemy of a test
suite; the KDF cost is orthogonal to everything being asserted here.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quenchkey import crypto  # noqa: E402
from quenchkey.vault import Vault  # noqa: E402

PASSPHRASE = "nine-copper-lanterns-above-the-quay"


@pytest.fixture()
def fast_kdf() -> crypto.KdfParams:
    return crypto.KdfParams.create(time_cost=1, memory_kib=8192, parallelism=1)


@pytest.fixture()
def workspace(tmp_path):
    (tmp_path / "documents").mkdir()
    (tmp_path / "locked").mkdir()
    return tmp_path


@pytest.fixture()
def vault(workspace, fast_kdf) -> Vault:
    opened = Vault.create(str(workspace / "vault.qkv"), PASSPHRASE, kdf_params=fast_kdf)
    yield opened
    opened.lock()


@pytest.fixture()
def sample_files(workspace) -> list[str]:
    """Three files with distinctive contents, in a deliberate order."""
    paths = []
    for name, size in (("zebra.txt", 2048), ("alpha.bin", 1_500_000), ("middle.md", 37)):
        path = workspace / "documents" / name
        path.write_bytes(os.urandom(size))
        paths.append(str(path))
    return paths
