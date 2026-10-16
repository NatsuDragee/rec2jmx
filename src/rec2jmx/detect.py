"""Input decoding and content-based format detection.

Detection is content-first. A filename extension can only produce a warning when it
disagrees with the content; it never causes content to be reinterpreted. Unknown or
ambiguous content is rejected with an actionable message.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import InputError
from .formats import EXTENSION_HINTS, FORMATS
from .ir import Issue

DEFAULT_MAX_BYTES = 50 * 1024 * 1024

_SUPPORTED_LIST = ", ".join(f.label for f in FORMATS.values())


@dataclass
class Detection:
    format: str
    reason: str
    json_doc: Any = None
    issues: list[Issue] = field(default_factory=list)


def decode_text(data: bytes) -> str:
    """Decode input bytes strictly. Supports UTF-8 (with/without BOM) and UTF-16 with BOM."""
    if data.startswith(b"\xef\xbb\xbf"):
        encoding, payload = "utf-8", data[3:]
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding, payload = "utf-16", data
    else:
        encoding, payload = "utf-8", data
    try:
        text = payload.decode(encoding)
    except UnicodeDecodeError as exc:
        raise InputError(
            f"The file is not valid {encoding.upper()} text (invalid byte at offset {exc.start}). "
            "Export the recording as UTF-8 text and try again."
        ) from None
    if "\x00" in text:
        raise InputError("The file contains NUL characters and looks binary; only text formats are supported.")
    return text


def _first_command_line(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s
    return ""


def _detect_from_content(text: str) -> Detection:
    stripped = text.lstrip()
    if stripped.startswith("<"):
        if re.search(r"<jmeterTestPlan\b", stripped[:8192]):
            return Detection("jmx", "XML document with a <jmeterTestPlan> root")
        raise InputError(
            "The file is XML/HTML but not a JMeter test plan (no <jmeterTestPlan> element). "
            f"Supported formats: {_SUPPORTED_LIST}."
        )
    if stripped.startswith(("{", "[")):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(
                f"The file looks like JSON but is malformed at line {exc.lineno}, column {exc.colno}: {exc.msg}."
            ) from None
        except RecursionError:
            raise InputError("The JSON document is nested too deeply to process safely.") from None
        if isinstance(doc, dict):
            log = doc.get("log")
            if isinstance(log, dict) and "entries" in log:
                return Detection("har", "JSON object with log.entries (HAR)", json_doc=doc)
            info = doc.get("info")
            if isinstance(info, dict) and "schema.getpostman.com" in str(info.get("schema", "")):
                return Detection("postman", "JSON object with a Postman info.schema", json_doc=doc)
            if doc.get("format") == "rec2jmx-recording":
                return Detection("rec2jmx-json", 'JSON object with "format": "rec2jmx-recording"', json_doc=doc)
            keys = ", ".join(sorted(str(k) for k in list(doc)[:10]))
            raise InputError(
                "The JSON document does not match a supported schema (HAR needs log.entries, "
                "Postman needs info.schema, rec2jmx recordings need \"format\": \"rec2jmx-recording\"). "
                f"Top-level keys found: {keys or '(none)'}."
            )
        raise InputError(
            "The JSON document is an array; no supported format uses a top-level array. "
            f"Supported formats: {_SUPPORTED_LIST}."
        )
    first = _first_command_line(text)
    if re.match(r"^curl(\.exe)?(\s|\^|$)", first, re.IGNORECASE):
        return Detection("curl", "text starting with a curl command")
    raise InputError(
        "Unrecognized input. The content is not a JMeter plan, HAR, Postman collection, "
        "rec2jmx JSON recording, or curl command list. "
        f"Supported formats: {_SUPPORTED_LIST}."
    )


def detect_format(text: str, filename: str = "", forced: str | None = None) -> Detection:
    if forced is not None and forced not in FORMATS:
        raise InputError(f"Unknown format '{forced}'. Choose one of: {', '.join(FORMATS)}.")
    det = _detect_from_content(text)
    if forced is not None and forced != det.format:
        raise InputError(
            f"Format '{forced}' was requested, but the content looks like {FORMATS[det.format].label} "
            f"({det.reason}). The file will not be reinterpreted; check that you chose the right file."
        )
    ext = os.path.splitext(filename.lower())[1]
    hinted = EXTENSION_HINTS.get(ext)
    if hinted and hinted != det.format:
        det.issues.append(
            Issue(
                "warning",
                "extension-mismatch",
                f"The file extension '{ext}' suggests {FORMATS[hinted].label}, but the content is "
                f"{FORMATS[det.format].label} ({det.reason}). Content-based detection was used.",
            )
        )
    return det


def safe_display_name(filename: str) -> str:
    """Return a display-safe base name (no directories, control characters, or odd symbols)."""
    base = re.split(r"[\\/]", filename or "")[-1]
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    return base[:120] or "recording"
