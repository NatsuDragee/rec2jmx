"""Load untrusted input bytes into a Recording: size check, decoding, detection, parsing."""

from __future__ import annotations

import hashlib
import os

from .detect import DEFAULT_MAX_BYTES, decode_text, detect_format, safe_display_name
from .errors import InputError
from .formats import FORMATS
from .ir import Issue, Recording
from .parsers import PARSERS


def load_bytes(data: bytes, filename: str = "", forced_format: str | None = None,
               max_bytes: int = DEFAULT_MAX_BYTES) -> Recording:
    if len(data) > max_bytes:
        raise InputError(f"The file is {len(data):,} bytes, above the {max_bytes:,}-byte limit. "
                         "Trim the recording or raise the limit with --max-size.")
    if not data.strip():
        raise InputError("The file is empty.")
    text = decode_text(data)
    det = detect_format(text, filename, forced_format)
    try:
        result = PARSERS[det.format](text, det.json_doc)
    except RecursionError:
        raise InputError("The input is nested too deeply to process safely.") from None
    width = max(4, len(str(len(result.requests))))
    for i, req in enumerate(result.requests, start=1):
        req.id = f"r{i:0{width}d}"
    issues = list(det.issues)
    issues.append(Issue("info", "detected-format", f"Detected {FORMATS[det.format].label}: {det.reason}."))
    issues.extend(result.issues)
    return Recording(
        source_format=det.format,
        source_name=safe_display_name(filename),
        requests=result.requests,
        issues=issues,
        variables=result.variables,
        grouping_source=result.grouping_source,
        fingerprint="sha256:" + hashlib.sha256(data).hexdigest(),
        metadata=result.metadata,
    )


def load_file(path: str, forced_format: str | None = None, max_bytes: int = DEFAULT_MAX_BYTES) -> Recording:
    if not os.path.isfile(path):
        raise InputError(f"Input file not found: {safe_display_name(path)}")
    size = os.path.getsize(path)
    if size > max_bytes:  # check before reading anything into memory
        raise InputError(f"The file is {size:,} bytes, above the {max_bytes:,}-byte limit. "
                         "Trim the recording or raise the limit with --max-size.")
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    return load_bytes(data, os.path.basename(path), forced_format, max_bytes)
