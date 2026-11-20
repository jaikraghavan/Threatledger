from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

from threatledger.controls.uploads import clean_filename, validate_upload

PDF = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32


def ooxml(folder: str, macro: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(f"{folder}document.xml", "<doc/>")
        if macro:
            z.writestr(f"{folder}vbaProject.bin", b"\x00macro")
    return buf.getvalue()


def upload(name: str, content: bytes) -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content)


@pytest.mark.parametrize(
    ("name", "content", "ctype"),
    [
        ("policy.pdf", PDF, "application/pdf"),
        ("screenshot.PNG", PNG, "image/png"),
        ("photo.jpeg", JPEG, "image/jpeg"),
        ("export.csv", b"user,mfa\nalice,yes\n", "text/csv"),
        ("notes.txt", "Café résumé ✓".encode(), "text/plain"),
        ("config.json", b'{"mfa": true}', "application/json"),
        (
            "report.docx",
            ooxml("word/"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (
            "matrix.xlsx",
            ooxml("xl/"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        (
            "deck.pptx",
            ooxml("ppt/"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
    ],
)
def test_accepts_allowed_types(name, content, ctype):
    result = validate_upload(upload(name, content))
    assert result.content_type == ctype
    assert result.size == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("payload.exe", b"MZ\x90\x00", "not allowed"),
        ("page.html", b"<html></html>", "not allowed"),
        ("logo.svg", b"<svg onload=alert(1)>", "not allowed"),
        ("archive.zip", ooxml("word/"), "not allowed"),
        ("macro.docm", ooxml("word/", macro=True), "not allowed"),
        ("noextension", PDF, "not allowed"),
        ("fake.pdf", b"MZ\x90\x00 this is an exe", "does not match"),
        ("fake.pdf", b"<html><script>alert(1)</script>", "does not match"),
        ("fake.png", PDF, "does not match"),
        ("evil.txt", b"<!DOCTYPE html><script>alert(1)</script>", "does not match"),
        ("evil.txt", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "does not match"),
        ("binary.txt", b"abc\x00def", "does not match"),
        ("latin1.csv", "caf\xe9 one two three four five".encode("latin-1"), "does not match"),
        ("macro.docx", ooxml("word/", macro=True), "does not match"),
        ("wrong.xlsx", ooxml("word/"), "does not match"),
        ("notzip.docx", b"PK\x03\x04 not really a zip", "does not match"),
        ("empty.pdf", b"", "empty"),
    ],
)
def test_rejects_disallowed_or_spoofed_files(name, content, message):
    with pytest.raises(ValidationError, match=message):
        validate_upload(upload(name, content))


@override_settings(EVIDENCE_MAX_BYTES=10)
def test_rejects_oversize():
    with pytest.raises(ValidationError, match="too large"):
        validate_upload(upload("big.pdf", PDF))


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("../../etc/passwd.pdf", "passwd.pdf"),
        ("C:\\Users\\x\\evil.pdf", "evil.pdf"),
        ("in\x00voice\x1b.pdf", "invoice.pdf"),
        ("<script>.pdf", "_script_.pdf"),
        ("   ", "evidence"),
        ("a" * 300 + ".pdf", "a" * 200),
    ],
)
def test_clean_filename(raw, clean):
    assert clean_filename(raw) == clean


def test_traversal_name_is_cleaned_and_validated():
    result = validate_upload(upload("../../../policy.pdf", PDF))
    assert result.original_filename == "policy.pdf"
