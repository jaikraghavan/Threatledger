from __future__ import annotations

import hashlib
import io
from unittest import mock

import pytest
from django.test import override_settings

from threatledger.attack.importer import source
from threatledger.attack.importer.source import SourceError, bundle_url, download, read_file

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"


def test_bundle_url_latest_and_pinned():
    assert bundle_url("enterprise-attack") == BASE + "enterprise-attack.json"
    assert bundle_url("enterprise-attack", "20.1") == BASE + "enterprise-attack-20.1.json"


@pytest.mark.parametrize("version", ["20", "../../etc", "20.1/../x", "v20.1", "20.1.json", " 20.1"])
def test_bundle_url_rejects_bad_versions(version):
    with pytest.raises(SourceError, match="invalid ATT&CK version"):
        bundle_url("enterprise-attack", version)


def test_bundle_url_rejects_unknown_domain():
    with pytest.raises(SourceError, match="unsupported"):
        bundle_url("mobile-attack")


class FakeResponse(io.BytesIO):
    def __init__(
        self, body: bytes, url: str = BASE + "enterprise-attack.json", length: str | None = None
    ):
        super().__init__(body)
        self._url = url
        self.headers = {"Content-Length": length} if length else {}

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_returns_data_and_hash():
    body = b'{"type": "bundle"}'
    with mock.patch.object(source.urllib.request, "urlopen", return_value=FakeResponse(body)) as op:
        fetched = download("enterprise-attack")
    assert fetched.data == body
    assert fetched.sha256 == hashlib.sha256(body).hexdigest()
    request = op.call_args.args[0]
    assert request.full_url == BASE + "enterprise-attack.json"
    assert request.get_header("User-agent") == "ThreatLedger-ATTACK-importer"


def test_download_verifies_expected_hash():
    with (
        mock.patch.object(source.urllib.request, "urlopen", return_value=FakeResponse(b"{}")),
        pytest.raises(SourceError, match="SHA-256 mismatch"),
    ):
        download("enterprise-attack", expected_sha256="0" * 64)


def test_download_refuses_redirect_to_other_host():
    resp = FakeResponse(b"{}", url="https://evil.example/enterprise-attack.json")
    with (
        mock.patch.object(source.urllib.request, "urlopen", return_value=resp),
        pytest.raises(SourceError, match="refusing to fetch"),
    ):
        download("enterprise-attack")


@override_settings(ATTACK_MAX_BUNDLE_BYTES=10)
def test_download_refuses_declared_oversize():
    with (
        mock.patch.object(
            source.urllib.request, "urlopen", return_value=FakeResponse(b"{}", length="999")
        ),
        pytest.raises(SourceError, match="too large"),
    ):
        download("enterprise-attack")


@override_settings(ATTACK_MAX_BUNDLE_BYTES=10)
def test_download_refuses_streamed_oversize():
    with (
        mock.patch.object(source.urllib.request, "urlopen", return_value=FakeResponse(b"x" * 50)),
        pytest.raises(SourceError, match="exceeds size limit"),
    ):
        download("enterprise-attack")


def test_download_wraps_network_errors():
    with (
        mock.patch.object(source.urllib.request, "urlopen", side_effect=OSError("no route")),
        pytest.raises(SourceError, match="download failed: OSError"),
    ):
        download("enterprise-attack", "20.1")


def test_read_file(tmp_path):
    path = tmp_path / "b.json"
    path.write_bytes(b"{}")
    fetched = read_file(path)
    assert fetched.source == "file:b.json"
    with pytest.raises(SourceError, match="no such file"):
        read_file(tmp_path / "missing.json")


@override_settings(ATTACK_MAX_BUNDLE_BYTES=1)
def test_read_file_size_limit(tmp_path):
    path = tmp_path / "b.json"
    path.write_bytes(b"{}")
    with pytest.raises(SourceError, match="exceeds size limit"):
        read_file(path)
