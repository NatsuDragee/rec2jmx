"""Request filtering (static resources, hosts) and grouping into flows."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..ir import Issue, Recording, Request

STATIC_EXTENSIONS = {
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav", "ogg", "m4a",
}
STATIC_RESOURCE_TYPES = {"image", "stylesheet", "script", "font", "media", "manifest", "texttrack"}
_STATIC_MIME_PREFIXES = ("image/", "font/", "video/", "audio/", "text/css", "application/javascript",
                         "text/javascript", "application/font", "application/x-font")


@dataclass
class Flow:
    name: str
    request_ids: list[str]
    basis: str  # "recorded" | "time-gap" | "single"
    note: str = ""  # the raw recorded group hint, for "recorded" flows


@dataclass
class GroupingSettings:
    group_by: str = "auto"  # auto | recorded | gap | single
    gap_seconds: float = 5.0
    include_static: bool = False
    include_hosts: list[str] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=list)


def static_reason(req: Request) -> str | None:
    rt = (req.resource_type or "").lower()
    if rt in STATIC_RESOURCE_TYPES:
        return f"static resource (type '{rt}')"
    last = req.path.rsplit("/", 1)[-1]
    if "." in last:
        ext = last.rsplit(".", 1)[-1].lower()
        if ext in STATIC_EXTENSIONS:
            return f"static resource (.{ext})"
    if req.response and req.response.content_type:
        ct = req.response.content_type.lower()
        if ct.startswith(_STATIC_MIME_PREFIXES):
            return f"static resource ({ct.split(';')[0]})"
    return None


def _host_matches(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns)


def select_requests(rec: Recording, settings: GroupingSettings) -> tuple[list[Request], dict[str, str]]:
    """Return (included requests, {excluded id: reason})."""
    included, excluded = [], {}
    for r in rec.requests:
        host = r.host.lower()
        if settings.include_hosts and not _host_matches(host, settings.include_hosts):
            excluded[r.id] = "host not in --include-host"
            continue
        if settings.exclude_hosts and _host_matches(host, settings.exclude_hosts):
            excluded[r.id] = "host matched --exclude-host"
            continue
        if rec.source_format == "har" and not settings.include_static:
            reason = static_reason(r)
            if reason:
                excluded[r.id] = reason
                continue
        included.append(r)
    return included, excluded


def flow_name_from_hint(hint: str) -> str:
    """Turn a page title / URL hint into a readable flow name."""
    hint = hint.strip()
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)([^?#]*)(\?[^#]*)?", hint, re.IGNORECASE)
    if not m:
        return hint
    path = unquote(m.group(2) or "")
    segments = [s for s in path.split("/") if s]
    query = m.group(3) or ""
    route = re.search(r"[?&]route=([^&]+)", query)
    if route:  # common for PHP-style front controllers
        segments.append(unquote(route.group(1)).replace("/", "_"))
    if not segments:
        return "Home"
    return "_".join(segments[-2:])


def group_flows(rec: Recording, included: list[Request], settings: GroupingSettings) -> tuple[list[Flow], list[Issue]]:
    issues: list[Issue] = []
    if not included:
        return [], [Issue("error", "no-requests", "No requests remain after filtering; nothing to generate.")]
    has_hints = any(r.group_hint for r in included)
    timed = all(r.started_at is not None for r in included)
    mode = settings.group_by
    if mode == "auto":
        mode = "recorded" if has_hints else ("gap" if timed and len(included) > 1 else "single")
    if mode == "recorded" and not has_hints:
        issues.append(Issue("warning", "no-recorded-groups",
                            "The recording has no grouping information; all requests were put into one flow."))
        mode = "single"
    if mode == "gap" and not timed:
        issues.append(Issue("warning", "no-timing",
                            "Some requests have no timestamps, so time-gap grouping is unavailable; one flow is used."))
        mode = "single"

    flows: list[Flow] = []
    if mode == "recorded":
        seen: dict[str, int] = {}
        for r in included:
            name = flow_name_from_hint(r.group_hint) if r.group_hint else "Ungrouped"
            if flows and flows[-1].note == (r.group_hint or ""):
                flows[-1].request_ids.append(r.id)
                continue
            seen[r.group_hint or ""] = seen.get(r.group_hint or "", 0) + 1
            flows.append(Flow(name, [r.id], "recorded", r.group_hint or ""))
        repeated = [h for h, n in seen.items() if n > 1]
        if repeated:
            issues.append(Issue("info", "split-groups",
                                f"{len(repeated)} recorded group(s) appear in non-consecutive segments and were kept "
                                "as separate flows to preserve request order."))
        if any(not r.group_hint for r in included):
            issues.append(Issue("warning", "ungrouped-requests",
                                "Some requests had no recorded group and were placed in 'Ungrouped' flows; review them."))
    elif mode == "gap":
        current: list[str] = []
        prev: Request | None = None
        for r in included:
            if prev is not None:
                prev_end = prev.started_at.timestamp() + (prev.duration_ms or 0) / 1000.0
                if r.started_at.timestamp() - prev_end >= settings.gap_seconds:
                    flows.append(Flow(f"Flow{len(flows) + 1}", current, "time-gap"))
                    current = []
            current.append(r.id)
            prev = r
        flows.append(Flow(f"Flow{len(flows) + 1}", current, "time-gap"))
        if len(flows) > 1:
            issues.append(Issue("warning", "heuristic-grouping",
                                f"Flows were split heuristically at idle gaps of {settings.gap_seconds:g}s or more. "
                                "Review, rename, and reorder them before generating."))
    else:
        name = rec.metadata.get("name") or "Flow1"
        flows.append(Flow(str(name), [r.id for r in included], "single"))
    return flows, issues
