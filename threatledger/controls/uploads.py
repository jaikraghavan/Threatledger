"""Evidence upload validation: size limit, extension allowlist AND content sniffing.

The extension says what the user claims; the magic bytes say what the file is. Both must
agree with the allowlist. Active content (HTML, SVG, scripts, executables, macro-enabled
Office files, archives) is never accepted. Stored files get random names (see
``models.evidence_path``) and are only ever served as attachments.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile

SNIFF_BYTES = 64 * 1024


def _is_pdf(head: bytes, f: UploadedFile) -> bool:
    return head.startswith(b"%PDF-")


def _is_png(head: bytes, f: UploadedFile) -> bool:
    return head.startswith(b"\x89PNG\r\n\x1a\n")


def _is_jpeg(head: bytes, f: UploadedFile) -> bool:
    return head.startswith(b"\xff\xd8\xff")


def _is_text(head: bytes, f: UploadedFile) -> bool:
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character may be cut at the sniff boundary; tolerate only that.
        if exc.start < len(head) - 4:
            return False
    lowered = head[:2048].lstrip().lower()
    return not lowered.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml", b"<script"))


def _ooxml(folder: str) -> Callable[[bytes, UploadedFile], bool]:
    def check(head: bytes, f: UploadedFile) -> bool:
        if not head.startswith(b"PK\x03\x04"):
            return False
        f.seek(0)
        try:
            with zipfile.ZipFile(f) as z:
                names = z.namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            return False
        finally:
            f.seek(0)
        if "[Content_Types].xml" not in names or not any(n.startswith(folder) for n in names):
            return False
        return not any(n.lower().endswith("vbaproject.bin") for n in names)  # no macros

    return check


@dataclass(frozen=True)
class FileType:
    content_type: str
    check: Callable[[bytes, UploadedFile], bool]


ALLOWED: dict[str, FileType] = {
    "pdf": FileType("application/pdf", _is_pdf),
    "png": FileType("image/png", _is_png),
    "jpg": FileType("image/jpeg", _is_jpeg),
    "jpeg": FileType("image/jpeg", _is_jpeg),
    "txt": FileType("text/plain", _is_text),
    "log": FileType("text/plain", _is_text),
    "md": FileType("text/plain", _is_text),
    "csv": FileType("text/csv", _is_text),
    "json": FileType("application/json", _is_text),
    "docx": FileType(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", _ooxml("word/")
    ),
    "xlsx": FileType(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _ooxml("xl/")
    ),
    "pptx": FileType(
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", _ooxml("ppt/")
    ),
}

_UNSAFE_NAME_CHARS = re.compile(r"[^\w .()\-+,@&]")


def clean_filename(name: str) -> str:
    """Display-safe original filename (never used as a filesystem path)."""
    base = PureWindowsPath(PurePosixPath(name).name).name  # strip any directory part
    base = unicodedata.normalize("NFKC", base)
    base = "".join(ch for ch in base if unicodedata.category(ch)[0] != "C")  # control chars
    base = _UNSAFE_NAME_CHARS.sub("_", base).strip(" .")
    return (base or "evidence")[:200]


@dataclass(frozen=True)
class ValidatedUpload:
    original_filename: str
    content_type: str
    size: int
    sha256: str


def max_bytes() -> int:
    return int(settings.EVIDENCE_MAX_BYTES)


def validate_upload(f: UploadedFile) -> ValidatedUpload:
    name = clean_filename(f.name or "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    file_type = ALLOWED.get(ext)
    if file_type is None:
        allowed = ", ".join(sorted(ALLOWED))
        raise ValidationError(f"File type “.{ext or '?'}” is not allowed. Allowed: {allowed}.")
    size = f.size or 0
    if size == 0:
        raise ValidationError("The file is empty.")
    if size > max_bytes():
        raise ValidationError(f"File is too large (max {max_bytes() // (1024 * 1024)} MB).")
    f.seek(0)
    head = f.read(SNIFF_BYTES)
    f.seek(0)
    if not file_type.check(head, f):
        raise ValidationError(f"The file content does not match a valid .{ext} file.")
    digest = hashlib.sha256()
    for chunk in f.chunks():
        digest.update(chunk)
    f.seek(0)
    return ValidatedUpload(name, file_type.content_type, size, digest.hexdigest())
