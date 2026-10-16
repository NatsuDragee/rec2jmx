"""Helpers shared by the format parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

from ..ir import Body, FormField, Issue, NameValue, QueryParam, Request

# Response bodies are kept (in memory only) for correlation analysis, truncated to this size.
MAX_ANALYSIS_BODY_CHARS = 1_000_000

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


@dataclass
class ParseResult:
    requests: list[Request]
    issues: list[Issue] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    grouping_source: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SplitUrl:
    scheme: str
    host: str
    port: int | None
    path: str
    raw_query: str
    had_userinfo: bool


def split_url(url: str) -> SplitUrl:
    """Split an absolute http(s) URL without lower-casing JMeter expressions.

    Raises ValueError with a message that does not echo the URL.
    """
    url = url.strip()
    m = _SCHEME_RE.match(url)
    if not m:
        raise ValueError("URL has no scheme (expected http:// or https://)")
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme '{scheme}'")
    rest = url[m.end():].split("#", 1)[0]
    cut = len(rest)
    for ch in "/?":
        i = rest.find(ch)
        if i != -1 and i < cut:
            cut = i
    authority, remainder = rest[:cut], rest[cut:]
    had_userinfo = False
    if "@" in authority:
        had_userinfo = True
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise ValueError("malformed IPv6 host")
        host, port_part = authority[: end + 1], authority[end + 1:]
        port_s = port_part[1:] if port_part.startswith(":") else ""
    else:
        host, _, port_s = authority.partition(":")
    if not host:
        raise ValueError("URL has no host")
    port = None
    if port_s:
        if not port_s.isdigit() or not 0 < int(port_s) < 65536:
            raise ValueError("URL has an invalid port")
        port = int(port_s)
    if "${" not in host:
        host = host.lower()
    path, _, raw_query = remainder.partition("?")
    return SplitUrl(scheme, host, port, path or "/", raw_query, had_userinfo)


def parse_pairs(raw: str) -> list[QueryParam]:
    """Parse an application/x-www-form-urlencoded string, keeping order and bare names."""
    params: list[QueryParam] = []
    for part in raw.split("&"):
        if part == "":
            continue
        name, eq, value = part.partition("=")
        params.append(QueryParam(unquote_plus(name), unquote_plus(value), bool(eq)))
    return params


def header_get(headers: list[NameValue], name: str) -> str | None:
    lname = name.lower()
    for h in headers:
        if h.name.lower() == lname:
            return h.value
    return None


def is_form_content_type(content_type: str | None) -> bool:
    return bool(content_type) and content_type.split(";")[0].strip().lower() == "application/x-www-form-urlencoded"


def build_body(text: str | None, content_type: str | None) -> Body:
    """Build a Body from raw text, turning url-encoded forms into structured fields."""
    if not text:
        return Body("none", content_type=content_type)
    if is_form_content_type(content_type) and "\n" not in text.strip():
        fields = [FormField(p.name, p.value) for p in parse_pairs(text.strip())]
        if fields:
            return Body("form", content_type=content_type, fields=fields)
    return Body("raw", text=text, content_type=content_type)


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def name_values(raw: Any) -> list[NameValue] | None:
    """Accept [{"name","value"}] lists or {"name": "value"} maps. Returns None if malformed."""
    if raw is None:
        return []
    out: list[NameValue] = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                return None
            out.append(NameValue(k, str(v)))
        return out
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                return None
            value = item.get("value")
            if value is None:  # some exporters write null for empty header values
                value = ""
            if not isinstance(value, (str, int, float, bool)):
                return None
            out.append(NameValue(item["name"], str(value)))
        return out
    return None


def new_request(method: str, url: SplitUrl, **kwargs: Any) -> Request:
    return Request(
        id="",
        method=method.upper(),
        scheme=url.scheme,
        host=url.host,
        port=url.port,
        path=url.path,
        query=parse_pairs(url.raw_query),
        **kwargs,
    )


def truncate_body(text: str | None) -> str | None:
    if text is None:
        return None
    return text[:MAX_ANALYSIS_BODY_CHARS]
