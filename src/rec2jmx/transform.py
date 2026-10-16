"""Prepare IR requests for generation (pure transformations on copies).

Order of operations (per plan execution order):
1. copy requests (responses are dropped; they are never written out)
2. accepted correlations: extractor on the source sampler, value -> ${C_name} in later requests
3. accepted timestamp suggestions: value -> ${__time()} at the recorded usage
4. secrets (policy "parameterize"): location-specific replacement, then value-wide
   replacement for values of 8+ characters
5. headers: every recorded header is kept, except the two kinds JMeter cannot send (verified
   against JMeter 5.6.3): Transfer-Encoding (the request fails) and HTTP/2 pseudo-headers
   (discarded by JMeter; :authority becomes Host, the others are the sampler's method/path/protocol)
6. think times
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

from .analysis.correlation import Suggestion
from .analysis.secrets import SecretFinding
from .ir import Issue, NameValue, Recording, Request
from .plan import Plan

UNSENDABLE_HEADERS = {"transfer-encoding"}  # JMeter fails to send a request that sets it
GLOBAL_REPLACE_MIN = 8
MIN_RECORDED_THINK_MS = 100
MAX_RECORDED_THINK_MS = 60_000


@dataclass
class Prepared:
    request: Request  # transformed copy
    flow_index: int
    extractors: list[dict] = field(default_factory=list)  # {"var", "type", ...}
    think_ms: int | None = None


@dataclass
class PreparedPlan:
    items: list[Prepared]
    issues: list[Issue]
    secret_vars: dict[str, str]  # var name -> finding id (only vars still referenced are declared later)
    correlation_vars: set[str]
    applied_suggestions: list[str]
    secret_values_parameterized: list[SecretFinding]


def _variants(value: str) -> list[str]:
    out = [value]
    for v in (quote(value, safe=""), quote(value, safe="-._~"), quote_plus(value)):
        if v not in out:
            out.append(v)
    return out


def _json_escaped(value: str) -> str:
    return json.dumps(value)[1:-1]


def replace_everywhere(req: Request, value: str, expr: str) -> int:
    """Replace a value in every outgoing field of a request. Returns the number of fields changed."""
    if not value:
        return 0
    count = 0
    for v in _variants(value):
        if v in req.path:
            req.path = req.path.replace(v, expr)
            count += 1
    for q in req.query:
        if value in q.value:
            q.value = q.value.replace(value, expr)
            count += 1
    for h in req.headers:
        if value in h.value:
            h.value = h.value.replace(value, expr)
            count += 1
    for f in req.body.fields:
        if value in f.value:
            f.value = f.value.replace(value, expr)
            count += 1
    if req.body.text:
        for v in [value, _json_escaped(value)] + _variants(value)[1:]:
            if v and v in req.body.text:
                req.body.text = req.body.text.replace(v, expr)
                count += 1
    return count


def _json_key_replace(text: str, key: str, value: str, expr: str) -> tuple[str, int]:
    pattern = re.compile(r'("' + re.escape(_json_escaped(key)) + r'"\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)')
    n = 0

    def repl(m: re.Match) -> str:
        nonlocal n
        literal = m.group(2)
        try:
            decoded = json.loads(literal)
        except json.JSONDecodeError:
            return m.group(0)
        if str(decoded) != value:
            return m.group(0)
        n += 1
        return m.group(1) + ('"' + expr + '"' if literal.startswith('"') else expr)

    return pattern.sub(repl, text), n


def _apply_secret_at_location(req: Request, s: SecretFinding, expr: str) -> int:
    n = 0
    if s.kind == "header":
        for h in req.headers:
            if h.name.lower() == s.field.lower():
                if s.scheme_prefix and h.value == s.scheme_prefix + s.value:
                    h.value = s.scheme_prefix + expr
                    n += 1
                elif s.value in h.value:
                    h.value = h.value.replace(s.value, expr)
                    n += 1
    elif s.kind == "query":
        for q in req.query:
            if q.name == s.field and s.value in q.value:
                q.value = q.value.replace(s.value, expr)
                n += 1
    elif s.kind == "form":
        for f in req.body.fields:
            if f.name == s.field and s.value in f.value:
                f.value = f.value.replace(s.value, expr)
                n += 1
    elif s.kind == "json" and req.body.text:
        req.body.text, n = _json_key_replace(req.body.text, s.field, s.value, expr)
    elif s.kind == "body" and req.body.text:
        if s.reason.startswith("sensitive field name"):
            for v in _variants(s.value):
                needle = f"{s.field}={v}"
                if needle in req.body.text:
                    req.body.text = req.body.text.replace(needle, f"{s.field}={expr}")
                    n += 1
        else:
            n += replace_everywhere(req, s.value, expr)
    elif s.kind == "path":
        n += replace_everywhere(req, s.value, expr)
    return n


def _copy_request(r: Request) -> Request:
    c = copy.copy(r)
    c.response = None
    c.query = copy.deepcopy(r.query)
    c.headers = copy.deepcopy(r.headers)
    c.body = copy.deepcopy(r.body)
    return c


def _note(issues: list[Issue], seen: set[str], code: str, severity: str, message: str) -> None:
    if code not in seen:
        seen.add(code)
        issues.append(Issue(severity, code, message))


def _clean_headers(req: Request, issues: list[Issue], seen: set[str]) -> None:
    """Keep every recorded header except those JMeter cannot send."""
    kept: list[NameValue] = []
    authority = None
    for h in req.headers:
        lname = h.name.lower()
        if lname.startswith(":"):
            if lname == ":authority":
                authority = h.value
            _note(issues, seen, "http2-pseudo-headers", "info",
                  "HTTP/2 pseudo-headers (:method, :path, :scheme, :authority) are not sent as headers by JMeter; "
                  "they are represented by the sampler's method, path and protocol, and :authority becomes a "
                  "Host header.")
            continue
        if lname in UNSENDABLE_HEADERS:
            _note(issues, seen, "transfer-encoding", "warning",
                  "Recorded Transfer-Encoding headers were not copied: JMeter fails to send a request that sets it "
                  "and frames the body itself.")
            continue
        if lname == "accept-encoding" and re.search(r"\b(br|zstd)\b", h.value, re.IGNORECASE):
            _note(issues, seen, "accept-encoding", "info",
                  "Accept-Encoding is kept as recorded and includes br/zstd. JMeter cannot decode those, so a server "
                  "that answers with them returns bodies that extractors and assertions cannot read; remove br/zstd "
                  "from that header if you need response checks.")
        if lname == "cookie":
            _note(issues, seen, "cookie-header", "info",
                  "Recorded Cookie headers are kept. JMeter sends them until the HTTP Cookie Manager holds cookies "
                  "for that URL (from Set-Cookie responses); from then on the Cookie Manager's cookies replace the "
                  "header. Disable the Cookie Manager to always send the recorded values.")
        kept.append(h)
    if authority and not any(h.name.lower() == "host" for h in kept):
        kept.insert(0, NameValue("Host", authority))
    req.headers = kept


def prepare(rec: Recording, plan: Plan, suggestions: list[Suggestion], secrets: list[SecretFinding]) -> PreparedPlan:
    by_id = rec.by_id()
    issues: list[Issue] = []
    items: list[Prepared] = []
    for fi, f in enumerate(plan.flows):
        for rid in f.request_ids:
            items.append(Prepared(_copy_request(by_id[rid]), fi))
    pos = {p.request.id: i for i, p in enumerate(items)}
    included = set(pos)

    # 2 + 3: accepted suggestions
    applied: list[str] = []
    correlation_vars: set[str] = set()
    sugg_by_id = {s.id: s for s in suggestions}
    for sid in plan.accepted:
        s = sugg_by_id[sid]
        if s.kind == "correlation":
            if s.source_request_id not in included:
                issues.append(Issue("warning", "correlation-skipped",
                                    f"{sid} was not applied: its source request {s.source_request_id} is not in the plan."))
                continue
            src_pos = pos[s.source_request_id]
            first_use = min((pos[u.request_id] for u in s.usages if u.request_id in pos), default=None)
            if first_use is None:
                issues.append(Issue("warning", "correlation-skipped", f"{sid} was not applied: none of its usages are in the plan."))
                continue
            if first_use <= src_pos:
                issues.append(Issue("warning", "correlation-skipped",
                                    f"{sid} was not applied: in the current flow order a request uses the value before "
                                    f"its source {s.source_request_id} runs. Reorder the flows or leave it unaccepted."))
                continue
            changed = sum(replace_everywhere(p.request, s.value, s.replacement) for p in items[src_pos + 1:])
            ex = dict(s.extractor or {})
            ex["var"] = s.var_name
            ex["suggestion"] = sid
            items[src_pos].extractors.append(ex)
            correlation_vars.add(s.var_name)
            applied.append(sid)
            if s.confidence == "low":
                issues.append(Issue("warning", "correlation-low-confidence",
                                    f"{sid}: the extractor boundaries are not unique in the recorded response; verify "
                                    f"{s.var_name} is extracted correctly.", s.source_request_id))
            if not changed:
                issues.append(Issue("warning", "correlation-unused", f"{sid}: no later request contained the value."))
        elif s.kind == "timestamp":
            for u in s.usages:
                if u.request_id in pos:
                    replace_everywhere(items[pos[u.request_id]].request, s.value, s.replacement)
            applied.append(sid)

    # 4: secrets
    secret_vars: dict[str, str] = {}
    parameterized: list[SecretFinding] = []
    if plan.secret_policy == "parameterize":
        for s in secrets:
            if s.kind == "variable":
                secret_vars[s.var_name] = s.id
                parameterized.append(s)
                continue
            if s.request_id not in pos:
                continue
            expr = "${" + s.var_name + "}"
            _apply_secret_at_location(items[pos[s.request_id]].request, s, expr)
            secret_vars[s.var_name] = s.id
            parameterized.append(s)
        for s in parameterized:
            if s.kind != "variable" and len(s.value) >= GLOBAL_REPLACE_MIN:
                for p in items:
                    replace_everywhere(p.request, s.value, "${" + s.var_name + "}")
        long_values = [s.value for s in parameterized if len(s.value) >= GLOBAL_REPLACE_MIN]
        for p in items:
            for ex in p.extractors:
                for key in ("left", "right"):
                    text = ex.get(key, "")
                    for v in long_values:
                        if v in text:
                            ex[key] = text[text.rfind(v) + len(v):] if key == "left" else text[:text.find(v)]
                            issues.append(Issue("warning", "boundary-trimmed",
                                                f"{ex.get('suggestion')}: an extractor boundary contained a secret and "
                                                "was shortened; verify the extraction.", p.request.id))
    elif secrets:
        issues.append(Issue("warning", "secrets-included",
                            f"{len(secrets)} detected secret value(s) were INCLUDED as recorded because the secret policy "
                            "is 'include'. Treat the generated .jmx as confidential."))

    # 5: headers
    seen_codes: set[str] = set()
    for p in items:
        _clean_headers(p.request, issues, seen_codes)

    # 6: think time
    if plan.think_time == "recorded":
        missing = 0
        for i, p in enumerate(items):
            if i == 0 or items[i - 1].flow_index != p.flow_index:
                continue
            prev = by_id[items[i - 1].request.id]
            cur = by_id[p.request.id]
            if prev.started_at is None or cur.started_at is None:
                missing += 1
                continue
            try:
                gap = (cur.started_at - prev.started_at).total_seconds() * 1000 - (prev.duration_ms or 0)
            except TypeError:
                missing += 1
                continue
            if gap >= MIN_RECORDED_THINK_MS:
                p.think_ms = int(min(gap, MAX_RECORDED_THINK_MS))
        if missing:
            issues.append(Issue("warning", "think-time-missing",
                                f"Recorded think time is unavailable for {missing} request(s) without timestamps."))
    elif plan.think_time != "none":
        for i, p in enumerate(items):
            if i > 0:
                p.think_ms = int(plan.think_time)

    return PreparedPlan(items, issues, secret_vars, correlation_vars, applied, parameterized)
