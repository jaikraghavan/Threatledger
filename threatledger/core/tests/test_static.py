"""Vendored assets must survive production ManifestStaticFilesStorage post-processing."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings

VENDOR = Path(settings.BASE_DIR) / "static" / "vendor"


@pytest.mark.parametrize("path", sorted(VENDOR.glob("*.js")), ids=lambda p: p.name)
def test_vendored_js_has_no_source_map_reference(path):
    # Manifest storage resolves sourceMappingURL comments and fails on missing .map files.
    assert b"sourceMappingURL" not in path.read_bytes()


def test_vendored_files_are_versioned():
    names = [p.name for p in VENDOR.glob("*.js")]
    assert names
    assert all(any(ch.isdigit() for ch in n) for n in names), names
