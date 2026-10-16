"""HAR 1.1/1.2 parser (browser DevTools, Charles, Proxyman, HTTP Toolkit, mitmproxy exports)."""

from __future__ import annotations

import base64
import binascii
from collections import Counter
from typing import Any

from ..errors import InputError
from ..ir import Body, FormField, Issue, Response
from .common import (
    ParseResult,
    build_body,
    header_get,
    name_values,
    new_request,
    parse_datetime,
    split_url,
    truncate_body,
)

_TEXTUAL_MIME_HINTS = ("json", "xml", "text", "javascript", "html", "x-www-form-urlencoded")


class _Skip(Exception):
    def __init__(self, reason: str, code: str = "entry-skipped"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


def _decode_content(content: Any) -> str | None:
    if not isinstance(content, dict):
        return None
    text = content.get("text")
    if not isinstance(text, str):
        return None
    if content.get("encoding") == "base64":
        mime = str(content.get("mimeType") or "").lower()
        if not any(h in mime for h in _TEXTUAL_MIME_HINTS):
            return None
        try:
            text = base64.b64decode(text, validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return None
    return truncate_body(text)


def _parse_entry(entry: Any, ref: str, pages: dict[str, str], issues: list[Issue]):
    if not isinstance(entry, dict):
        raise _Skip("entry is not an object")
    r = entry.get("request")
    if not isinstance(r, dict):
        raise _Skip("missing 'request' object")
    method, url = r.get("method"), r.get("url")
    if not isinstance(method, str) or not method.strip():
        raise _Skip("missing request.method")
    if not isinstance(url, str) or not url:
        raise _Skip("missing request.url")
    scheme = url.split(":", 1)[0].lower()
    resp_raw = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    status = resp_raw.get("status")
    if scheme in ("ws", "wss") or entry.get("_webSocketMessages") or status == 101:
        raise _Skip("WebSocket connection (not convertible to HTTP samplers)", "websocket-skipped")
    if scheme not in ("http", "https"):
        raise _Skip(f"non-HTTP URL scheme '{scheme}'", "non-http-skipped")
    try:
        parts = split_url(url)
    except ValueError as exc:
        raise _Skip(f"invalid URL ({exc})") from None

    headers = name_values(r.get("headers"))
    if headers is None:
        raise _Skip("request.headers is malformed")

    body = Body("none")
    post = r.get("postData")
    if isinstance(post, dict):
        mime = post.get("mimeType") if isinstance(post.get("mimeType"), str) else header_get(headers, "content-type")
        text = post.get("text") if isinstance(post.get("text"), str) else None
        params = post.get("params") if isinstance(post.get("params"), list) else []
        is_multipart = bool(mime) and "multipart/form-data" in mime.lower()
        if is_multipart and params:
            fields = []
            for p in params:
                if isinstance(p, dict) and isinstance(p.get("name"), str):
                    fname = p.get("fileName") if isinstance(p.get("fileName"), str) else None
                    fields.append(FormField(p["name"], str(p.get("value", "")), fname,
                                            p.get("contentType") if isinstance(p.get("contentType"), str) else None))
            body = Body("multipart", content_type=mime, fields=fields)
        elif text:
            body = build_body(text, mime)
            if is_multipart:
                issues.append(Issue("warning", "multipart-raw",
                                    "Multipart body kept as raw text with the recorded boundary; file "
                                    "contents may be missing from the recording.", None))
        elif params:
            fields = [FormField(p["name"], str(p.get("value", ""))) for p in params
                      if isinstance(p, dict) and isinstance(p.get("name"), str)]
            body = Body("form", content_type=mime, fields=fields)

    response = None
    if resp_raw:
        rheaders = name_values(resp_raw.get("headers")) or []
        content = resp_raw.get("content")
        ctype = content.get("mimeType") if isinstance(content, dict) and isinstance(content.get("mimeType"), str) else None
        response = Response(
            status=status if isinstance(status, int) else None,
            headers=rheaders,
            body_text=_decode_content(content),
            content_type=ctype or header_get(rheaders, "content-type"),
        )

    duration = entry.get("time")
    pageref = entry.get("pageref")
    req = new_request(
        method,
        parts,
        headers=headers,
        body=body,
        started_at=parse_datetime(entry.get("startedDateTime")),
        duration_ms=float(duration) if isinstance(duration, (int, float)) and duration >= 0 else None,
        response=response,
        group_hint=pages.get(pageref) if isinstance(pageref, str) else None,
        source_ref=ref,
        resource_type=entry.get("_resourceType") if isinstance(entry.get("_resourceType"), str) else None,
    )
    if parts.had_userinfo:
        issues.append(Issue("warning", "url-credentials-dropped",
                            "Credentials embedded in a URL (user:pass@host) were removed.", None))
    return req


_SANITIZED_HEADERS = {"authorization", "cookie"}


def _looks_sanitized(requests) -> bool:
    """True when no request carries Authorization/Cookie and no response sets cookies."""
    for r in requests:
        if any(h.name.lower() in _SANITIZED_HEADERS for h in r.headers):
            return False
        if r.response and any(h.name.lower() == "set-cookie" for h in r.response.headers):
            return False
    return True


def parse_har(text: str, doc: Any) -> ParseResult:
    if not isinstance(doc, dict) or not isinstance(doc.get("log"), dict):
        raise InputError("HAR: the top-level 'log' object is missing.")
    log = doc["log"]
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise InputError("HAR: 'log.entries' must be an array.")
    if not entries:
        raise InputError("HAR: 'log.entries' is empty; the recording contains no requests.")
    issues: list[Issue] = []
    version = log.get("version")
    if version not in ("1.1", "1.2"):
        issues.append(Issue("warning", "har-version", f"HAR version {version!r} is not 1.1 or 1.2; parsed as HAR 1.2."))

    pages: dict[str, str] = {}
    for p in log.get("pages") or []:
        if isinstance(p, dict) and isinstance(p.get("id"), str):
            pages[p["id"]] = str(p.get("title") or p["id"])

    requests = []
    skipped: Counter[tuple[str, str]] = Counter()
    for i, entry in enumerate(entries):
        ref = f"log.entries[{i}]"
        try:
            req = _parse_entry(entry, ref, pages, issues)
        except _Skip as s:
            skipped[(s.code, s.reason)] += 1
            continue
        requests.append(req)

    for (code, reason), count in sorted(skipped.items()):
        sev = "info" if code in ("non-http-skipped",) else "warning"
        issues.append(Issue(sev, code, f"Skipped {count} HAR entr{'y' if count == 1 else 'ies'}: {reason}."))
    if not requests:
        raise InputError("HAR: no usable HTTP(S) requests were found (all entries were skipped or malformed).")

    times = [r.started_at for r in requests if r.started_at is not None]
    try:
        out_of_order = any(b < a for a, b in zip(times, times[1:]))
    except TypeError:  # mixing naive and aware datetimes
        out_of_order = False
    if out_of_order:
        issues.append(Issue("info", "har-order",
                            "Entries are not in chronological order; the file order is preserved."))

    if len(requests) >= 3 and _looks_sanitized(requests):
        issues.append(Issue("warning", "har-sanitized",
                            "This HAR contains no Authorization, Cookie or Set-Cookie headers at all. Browsers remove "
                            "them when exporting a 'sanitized' HAR (Chrome's default 'Export HAR (sanitized)'), so "
                            "they cannot be converted. To keep them in Chrome: DevTools > Settings > Preferences > "
                            "Network > enable 'Allow to generate HAR with sensitive data', then in the Network panel "
                            "use 'Export HAR (with sensitive data)'."))

    has_hints = any(r.group_hint for r in requests)
    return ParseResult(
        requests,
        issues,
        grouping_source="HAR pages (pageref)" if has_hints else None,
        metadata={"creator": str((log.get("creator") or {}).get("name", ""))[:80] if isinstance(log.get("creator"), dict) else ""},
    )
