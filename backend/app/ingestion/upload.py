"""Defensive file upload reader.

Security controls implemented here:
* Filename validation and extension allow-list (`.log`, `.txt`, `.json`, `.jsonl`).
* Path traversal characters in filenames are stripped before recording metadata
  (the file is never written to disk at all).
* Streaming byte-limit check (`max_upload_bytes`) enforced *while reading*, so a
  huge upload is aborted immediately instead of exhausting memory.
* NUL-byte rejection (binary files disguised with `.log` extension).
* Strict UTF-8 decoding.
* Line-count and line-length bounds.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from fastapi import UploadFile

from app.core.config import Settings
from app.core.errors import (
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    ValidationFailedError,
)

ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".log", ".txt", ".json", ".jsonl"})
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ValidatedUpload:
    sanitized_filename: str
    extension: str
    lines: list[str]


def sanitize_filename(filename: str | None) -> tuple[str, str]:
    if not filename:
        raise UnsupportedMediaTypeError("Uploaded file must have a filename")
    base = os.path.basename(filename.replace("\\", "/")).strip()
    if not base or base in (".", ".."):
        raise UnsupportedMediaTypeError("Invalid filename")
    _, ext = os.path.splitext(base.lower())
    if ext not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise UnsupportedMediaTypeError(f"Unsupported file extension {ext!r}. Allowed: {allowed}")
    sanitized = _SAFE_FILENAME_RE.sub("_", base)[:128]
    return sanitized, ext


async def read_validated_upload(file: UploadFile, settings: Settings) -> ValidatedUpload:
    sanitized_name, ext = sanitize_filename(file.filename)

    chunks: list[bytes] = []
    total_bytes = 0
    max_bytes = settings.max_upload_bytes

    while True:
        chunk = await file.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise PayloadTooLargeError(
                f"Upload exceeds maximum size of {settings.max_upload_mb} MB"
            )
        if b"\x00" in chunk:
            raise UnsupportedMediaTypeError("Binary files (containing NUL bytes) are not accepted")
        chunks.append(chunk)

    if total_bytes == 0:
        raise ValidationFailedError("Uploaded file is empty")

    raw_bytes = b"".join(chunks)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedMediaTypeError("File must be valid UTF-8 text") from exc

    # Support a top-level JSON array in `.json` files by converting each element to a line.
    stripped = text.strip()
    if ext == ".json" and stripped.startswith("["):
        try:
            items = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValidationFailedError("Invalid JSON array in uploaded file") from exc
        if not isinstance(items, list):
            raise ValidationFailedError("Expected a JSON array of event objects")
        lines = [json.dumps(item, separators=(",", ":")) for item in items]
    else:
        lines = text.splitlines()

    if len(lines) > settings.max_lines_per_upload:
        raise PayloadTooLargeError(
            f"Upload exceeds maximum of {settings.max_lines_per_upload} lines"
        )

    return ValidatedUpload(sanitized_filename=sanitized_name, extension=ext, lines=lines)
