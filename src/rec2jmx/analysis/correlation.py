"""Dynamic-value detection and correlation suggestions.

A *correlation* suggestion is produced only when a value used by a later request first
appears in an earlier recorded response (and in no request sent before that response).
The suggested extractor (JSON Extractor or Boundary Extractor) is derived from where
the value sits in that response. Nothing here is applied automatically: generation
applies a suggestion only when the user accepts it.

Other kinds:
* ``timestamp``  - an epoch value close to the request time; can be replaced with ``${__time()}``.
* ``unresolved`` - a value that looks dynamic (CSRF/nonce/state names) but has no recorded
  source. Reported for manual follow-up; cannot be accepted.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..ir import Request, Response
from .secrets import json_leaves, split_auth_scheme, try_json

_SKIP_HEADERS = {
    "host", "content-length", "content-type", "accept", "accept-encoding", "accept-language",
    "user-agent", "referer", "origin", "connection", "cookie", "cache-control", "pragma",
    "upgrade-insecure-requests", "dnt", "priority", "te", "if-modified-since", "if-none-match",
    "keep-alive", "x-requested-with",
}
_BORING = {"application", "undefined", "anonymous", "javascript", "unknown", "localhost"}
_DYNAMIC_NAME_RE = re.compile(r"csrf|xsrf|nonce|^state$|viewstate|eventvalidation|requestverificationtoken|"
                              r"authenticity|correlation|requestid|traceid|session", re.IGNORECASE)
_RAW_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=:-]{8,}")


@dataclass
class Usage:
    request_id: str
    location: str

    def to_dict(self) -> dict:
        return {"requestId": self.request_id, "location": self.location}


@dataclass
class Suggestion:
    id: str
    kind: str  # correlation | timestamp | unresolved
    var_name: str
    value: str  # never serialized
    source_request_id: str | None
    extractor: dict | None
    usages: list[Usage] = field(default_factory=list)
    confidence: str = "medium"
    reason: str = ""
    replacement: str = ""  # expression used when accepted

    @property
    def acceptable(self) -> bool:
        return self.kind in ("correlation", "timestamp")

    def to_dict(self) -> dict:
        ex = None
        if self.extractor:
            ex = dict(self.extractor)
            for k in ("left", "right"):
                if k in ex:
                    ex[k] = ex[k][-40:] if k == "left" else ex[k][:20]
        return {
            "id": self.id,
            "kind": self.kind,
            "variable": self.var_name,
            "replacement": self.replacement,
            "sourceRequestId": self.source_request_id,
            "extractor": ex,
            "usages": [u.to_dict() for u in self.usages],
            "confidence": self.confidence,
            "reason": self.reason,
            "valueLength": len(self.value),
            "acceptable": self.acceptable,
        }


def interesting(v: str) -> bool:
    if len(v) < 8 or len(v) > 4096 or any(c.isspace() for c in v):
        return False
    if v.lower() in _BORING or v.startswith(("http://", "https://", "/")) or "${" in v:
        return False
    return any(c.isdigit() for c in v) or len(v) >= 16


def request_candidates(req: Request) -> list[tuple[str, str, str]]:
    """(location, name, value) for values sent by a request."""
    out: list[tuple[str, str, str]] = []
    for q in req.query:
        out.append((f"query '{q.name}'", q.name, q.value))
    for h in req.headers:
        lname = h.name.lower()
        if lname in _SKIP_HEADERS or lname.startswith("sec-") or lname.startswith(":"):
            continue
        value = split_auth_scheme(h.value)[1] if lname in ("authorization", "proxy-authorization") else h.value
        out.append((f"header '{h.name}'", h.name, value))
    for seg in req.path.split("/"):
        seg = unquote(seg)
        if seg:
            out.append(("path", "path", seg))
    b = req.body
    for f in b.fields:
        if not f.is_file:
            out.append((f"form '{f.name}'", f.name, f.value))
    if b.kind == "raw" and b.text:
        doc = try_json(b.text)
        if doc is not None:
            for path, key, v in json_leaves(doc):
                if isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool)):
                    out.append((f"JSON {path}", key or "item", str(v)))
        else:
            for m in list(_RAW_TOKEN_RE.finditer(b.text))[:200]:
                out.append(("body", "value", m.group(0)))
    return out


def _request_text(req: Request) -> str:
    parts = [req.path, "&".join(f"{q.name}={q.value}" for q in req.query)]
    parts += [f"{h.name}: {h.value}" for h in req.headers]
    parts += [f.value for f in req.body.fields]
    parts.append(req.body.text or "")
    return "\n".join(parts)


def _variants(v: str) -> list[str]:
    out = [v]
    j = json.dumps(v)[1:-1]
    if j != v:
        out.append(j)
    if "/" in v:
        out.append(v.replace("/", "\\/"))
    h = html.escape(v)
    if h != v:
        out.append(h)
    return out


def _in_response(resp: Response | None, v: str) -> bool:
    if resp is None:
        return False
    body = resp.body_text or ""
    if any(x in body for x in _variants(v)):
        return True
    return any(v in h.value for h in resp.headers)


def _boundaries(text: str, pos: int, length: int) -> tuple[str, str, bool]:
    left, unique = "", False
    for size in (8, 12, 16, 24, 32, 48, 64):
        cand = text[max(0, pos - size):pos]
        if cand and text.find(cand) == pos - len(cand):
            left, unique = cand, True
            break
    if not left:
        left = text[max(0, pos - 16):pos]
    end = pos + length
    right = ""
    for size in (1, 2, 3, 4, 6, 8):
        cand = text[end:end + size]
        if not cand:
            break
        if text.find(cand, pos) == end:
            right = cand
            break
    if not right:
        right = text[end:end + 8]
        unique = False
    return left, right, unique and bool(left) and bool(right)


def build_extractor(resp: Response, v: str) -> tuple[dict | None, str, str | None]:
    """Return (extractor, confidence, json key name)."""
    body = resp.body_text or ""
    if body:
        doc = try_json(body)
        if doc is not None:
            for path, key, leaf in json_leaves(doc):
                if not isinstance(leaf, bool) and leaf is not None and str(leaf) == v:
                    return {"type": "json", "expression": path}, "high", key
        for variant in _variants(v):
            pos = body.find(variant)
            if pos >= 0:
                left, right, unique = _boundaries(body, pos, len(variant))
                return ({"type": "boundary", "scope": "body", "left": left, "right": right},
                        "medium" if unique else "low", None)
    for h in resp.headers:
        idx = h.value.find(v)
        if idx >= 0:
            rest = h.value[idx + len(v):]
            right = rest[:1] if rest else "\n"
            return ({"type": "boundary", "scope": "headers", "left": f"{h.name}: {h.value[:idx]}", "right": right},
                    "medium", h.name)
    return None, "low", None


def _var_name(basis: str, used: set[str]) -> str:
    base = "C_" + (re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9_]", "_", basis or "value")).strip("_") or "value")
    base = base[:40]
    name, n = base, 2
    while name in used:
        name = f"{base}_{n}"
        n += 1
    used.add(name)
    return name


def suggest(requests: list[Request]) -> list[Suggestion]:
    """Analyse requests in order. ``requests`` should be the included requests in recorded order."""
    texts = [_request_text(r) for r in requests]
    has_responses = any(r.response is not None and (r.response.body_text or r.response.headers) for r in requests)
    by_value: dict[str, Suggestion] = {}
    rejected: set[str] = set()
    suggestions: list[Suggestion] = []
    used_names: set[str] = set()

    for k, req in enumerate(requests):
        for loc, name, v in request_candidates(req):
            existing = by_value.get(v)
            if existing is not None:
                if existing.kind == "correlation" and not any(u.request_id == req.id and u.location == loc for u in existing.usages):
                    existing.usages.append(Usage(req.id, loc))
                continue
            if v in rejected:
                continue
            ts = _timestamp_replacement(v, req)
            if not interesting(v) and ts is None:
                continue
            first = next((i for i in range(k + 1) if v in texts[i]), k)
            source = None
            if has_responses:
                source = next((j for j in range(first) if _in_response(requests[j].response, v)), None)
            if source is not None:
                src = requests[source]
                extractor, confidence, key = build_extractor(src.response, v)
                if extractor is None:
                    rejected.add(v)
                    continue
                var = _var_name(key or name, used_names)
                s = Suggestion(f"C{len(suggestions) + 1:02d}", "correlation", var, v, src.id, extractor,
                               [Usage(req.id, loc)], confidence,
                               f"value first appears in the response of {src.id} and is sent again later",
                               "${" + var + "}")
            elif ts is not None:
                s = Suggestion(f"C{len(suggestions) + 1:02d}", "timestamp", "", v, None, None, [Usage(req.id, loc)],
                               "medium", "epoch timestamp close to the recorded request time", ts)
            elif _DYNAMIC_NAME_RE.search(name or "") and interesting(v):
                why = ("no recorded response contains this value" if has_responses
                       else "the input has no response data to correlate against")
                s = Suggestion(f"C{len(suggestions) + 1:02d}", "unresolved", "", v, None, None, [Usage(req.id, loc)],
                               "low", f"name suggests a dynamic value, but {why}; handle it manually")
            else:
                rejected.add(v)
                continue
            by_value[v] = s
            suggestions.append(s)
    return suggestions


def _timestamp_replacement(v: str, req: Request) -> str | None:
    if req.started_at is None or not v.isdigit() or len(v) not in (10, 13):
        return None
    t = int(v) / (1000.0 if len(v) == 13 else 1.0)
    if abs(t - req.started_at.timestamp()) > 2 * 86400:
        return None
    return "${__time()}" if len(v) == 13 else "${__time(/1000,)}"
