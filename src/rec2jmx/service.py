"""Engine facade used by the CLI and the web UI.

    rec = loader.load_file(path)
    analysis = analyze(rec, GroupingSettings())
    plan = default_plan(analysis)           # or plan_from_dict(...) after review
    report = preview(analysis, plan)        # names, warnings, limitations (JSON-safe)
    result = generate(analysis, plan)       # .jmx text + structural/leak checks
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote

from .analysis.correlation import Suggestion, suggest
from .analysis.grouping import Flow, GroupingSettings, group_flows, select_requests
from .analysis.hosts import classify_host
from .analysis.secrets import SecretFinding, detect_secrets, is_sensitive_header, is_sensitive_name
from .errors import GenerationError
from .formats import FORMATS, GENERAL_LIMITATIONS
from .generator import generate_jmx
from .ir import Issue, Recording, Request
from .naming import NamedFlow, assign_names
from .plan import Plan, PlanFlow, validate_plan
from .transform import prepare
from .validate import ValidationReport, leak_check, structural_check


@dataclass
class Analysis:
    recording: Recording
    settings: GroupingSettings
    included: list[Request]
    excluded: dict[str, str]
    flows: list[Flow]
    secrets: list[SecretFinding]
    suggestions: list[Suggestion]
    issues: list[Issue] = field(default_factory=list)

    @property
    def secret_values(self) -> frozenset[str]:
        return frozenset(s.value for s in self.secrets)

    @property
    def masked_name_values(self) -> frozenset[str]:
        """Values that must not appear in element names: secrets and detected dynamic values."""
        return self.secret_values | frozenset(s.value for s in self.suggestions)


@dataclass
class GenerationResult:
    jmx: str
    names: list[NamedFlow]
    issues: list[Issue]
    validations: list[ValidationReport]
    report: dict


def analyze(rec: Recording, settings: GroupingSettings | None = None) -> Analysis:
    settings = settings or GroupingSettings()
    included, excluded = select_requests(rec, settings)
    flows, issues = group_flows(rec, included, settings)
    if excluded:
        reasons = Counter(excluded.values())
        issues.append(Issue("info", "excluded-requests", f"Excluded {len(excluded)} request(s): "
                            + "; ".join(f"{n} x {r}" for r, n in reasons.most_common(6))))
    for r in included:
        if (r.resource_type or "").lower() == "eventsource" or "text/event-stream" in (r.header("accept") or "").lower():
            issues.append(Issue("warning", "event-stream",
                                "Server-Sent Events (EventSource) request: the server keeps this response open, so the "
                                "JMeter sampler waits until the stream ends or a response timeout is reached. Set a "
                                "response timeout on it or remove it from the plan.", r.id))
    secrets = detect_secrets(rec)  # all requests, so re-included requests are covered too
    suggestions = suggest(included)
    if not any(r.response for r in rec.requests) and rec.source_format in ("curl", "postman", "jmx"):
        issues.append(Issue("info", "no-responses", f"{FORMATS[rec.source_format].label} has no recorded responses, "
                            "so no correlation sources can be identified."))
    return Analysis(rec, settings, included, excluded, flows, secrets, suggestions, issues)


def default_plan(analysis: Analysis) -> Plan:
    rec = analysis.recording
    name = rec.metadata.get("name") or rec.source_name.rsplit(".", 1)[0] or "Recorded scenario"
    return Plan(flows=[PlanFlow(f.name, list(f.request_ids)) for f in analysis.flows],
                test_plan_name=str(name)[:120], fingerprint=rec.fingerprint)


def _check(analysis: Analysis, plan: Plan) -> None:
    acceptable = {s.id for s in analysis.suggestions if s.acceptable}
    validate_plan(plan, analysis.recording, acceptable, {s.id for s in analysis.suggestions})


def name_plan(analysis: Analysis, plan: Plan) -> list[NamedFlow]:
    by_id = analysis.recording.by_id()
    flows = [(f.name, [(rid, by_id[rid].path) for rid in f.request_ids]) for f in plan.flows]
    return assign_names(flows, analysis.masked_name_values)


def display_url(req: Request, secret_values: frozenset[str]) -> str:
    """URL for previews with secret or sensitive query values and path segments masked."""
    segs = []
    for seg in req.path.split("/"):
        segs.append("***" if seg and (seg in secret_values or unquote(seg) in secret_values) else seg)
    q = "&".join(q.name + ("=***" if (is_sensitive_name(q.name) or q.value in secret_values) and q.value
                           else ("=" + q.value if q.has_equals else "")) for q in req.query)
    url = req.origin + "/".join(segs)
    return (url + "?" + q if q else url)[:300]


def preview(analysis: Analysis, plan: Plan) -> dict:
    """A JSON-safe report: no secret values, masked URLs."""
    _check(analysis, plan)
    rec = analysis.recording
    by_id = rec.by_id()
    names = name_plan(analysis, plan)
    sv = analysis.secret_values
    hint_basis = {rid: f.basis for f in analysis.flows for rid in f.request_ids}
    planned = set(plan.execution_order())
    flows = []
    for i, (pf, nf) in enumerate(zip(plan.flows, names), start=1):
        flows.append({
            "index": i,
            "name": pf.name,
            "txName": nf.tx_name,
            "basis": hint_basis.get(pf.request_ids[0], "user") if pf.request_ids else "user",
            "requests": [{
                "id": s.request_id,
                "samplerName": s.name,
                "method": by_id[s.request_id].method,
                "url": display_url(by_id[s.request_id], sv),
                "status": by_id[s.request_id].response.status if by_id[s.request_id].response else None,
                "bodyKind": by_id[s.request_id].body.kind,
                "source": by_id[s.request_id].source_ref[:80],
            } for s in nf.samplers],
        })
    hosts = Counter(r.origin for r in analysis.included)
    accepted = set(plan.accepted)
    return {
        "source": {
            "name": rec.source_name,
            "format": rec.source_format,
            "formatLabel": FORMATS[rec.source_format].label,
            "fingerprint": rec.fingerprint,
            "groupingSource": rec.grouping_source,
        },
        "summary": {
            "parsed": len(rec.requests),
            "included": len(analysis.included),
            "planned": len(planned),
            "excluded": [{"id": rid, "reason": reason, "method": by_id[rid].method, "url": display_url(by_id[rid], sv)}
                         for rid, reason in analysis.excluded.items()],
        },
        "hosts": [{"origin": o, "requests": n} for o, n in hosts.most_common()],
        "requestIndex": [{
            "id": r.id, "method": r.method, "url": display_url(r, sv), "host": r.host.lower(),
            "excludedReason": analysis.excluded.get(r.id),
            "issues": [i.code for i in analysis.issues if i.request_id == r.id],
        } for r in rec.requests],
        "hostInfo": {h: classify_host(h) for h in sorted({r.host.lower() for r in rec.requests})},
        "flows": flows,
        "secrets": [s.to_dict() for s in analysis.secrets],
        "suggestions": [dict(s.to_dict(), accepted=s.id in accepted) for s in analysis.suggestions],
        "issues": [i.to_dict() for i in rec.issues + analysis.issues],
        "limitations": list(FORMATS[rec.source_format].limitations) + list(GENERAL_LIMITATIONS),
        "plan": plan.to_dict({r.id: f"{r.method} {display_url(r, sv)}" for r in rec.requests}),
    }


def generate(analysis: Analysis, plan: Plan) -> GenerationResult:
    _check(analysis, plan)
    names = name_plan(analysis, plan)
    prepared = prepare(analysis.recording, plan, analysis.suggestions, analysis.secrets)
    jmx, gen_issues = generate_jmx(analysis.recording, plan, prepared, names)
    issues = list(prepared.issues) + gen_issues
    if plan.secret_policy == "parameterize":
        issues += leak_check(jmx, prepared.secret_values_parameterized)
    structure = structural_check(jmx)
    if not structure.passed:
        raise GenerationError("The generated plan failed the structural check: " + "; ".join(structure.details))
    report = preview(analysis, plan)
    report["generation"] = {
        "appliedSuggestions": prepared.applied_suggestions,
        "issues": [i.to_dict() for i in issues],
        "validations": [structure.to_dict()],
    }
    return GenerationResult(jmx, names, issues, [structure], report)


# ---------------------------------------------------------------- UI helpers

DETAIL_BODY_LIMIT = 200_000


def _sampler_elements(jmx: str) -> dict[str, tuple[ET.Element, ET.Element | None]]:
    root = ET.fromstring(jmx)
    out = {}
    for tree in root.iter("hashTree"):
        kids = list(tree)
        for i, el in enumerate(kids):
            if el.tag == "HTTPSamplerProxy":
                out[el.get("testname", "")] = (el, kids[i + 1] if i + 1 < len(kids) else None)
    return out


def _generated_headers(sub: ET.Element | None) -> list[tuple[str, str]]:
    if sub is None:
        return []
    return [(h.findtext("stringProp[@name='Header.name']") or "", h.findtext("stringProp[@name='Header.value']") or "")
            for hm in sub.iter("HeaderManager") for h in hm.iter("elementProp") if h.get("elementType") == "Header"]


def request_detail(analysis: Analysis, plan: Plan, request_id: str) -> dict:
    """Everything the UI shows for one request: recorded data next to what the generated JMX contains.

    Values are included (the UI masks sensitive ones until the user reveals them); this is only
    served by the local web UI, never written to reports or logs.
    """
    rec = analysis.recording
    req = rec.by_id().get(request_id)
    if req is None:
        raise GenerationError(f"Unknown request id '{str(request_id)[:20]}'.")
    sv = analysis.secret_values
    sampler_name, generated, sampler_info = None, None, None
    if request_id in plan.execution_order():
        result = generate(analysis, plan)
        sampler_name = next(s.name for nf in result.names for s in nf.samplers if s.request_id == request_id)
        el, sub = _sampler_elements(result.jmx)[sampler_name]
        generated = _generated_headers(sub)
        props = {p.get("name"): p.text or "" for p in el if p.tag in ("stringProp", "boolProp")}
        sampler_info = {k.split(".", 1)[1]: props.get(k, "") for k in (
            "HTTPSampler.method", "HTTPSampler.protocol", "HTTPSampler.domain", "HTTPSampler.port", "HTTPSampler.path")}

    def sensitive(name: str, value: str) -> bool:
        return is_sensitive_header(name) or name.lower() == "cookie" or any(v and v in value for v in sv)

    headers = []
    remaining = list(generated or [])
    for h in req.headers:
        lname = h.name.lower()
        row = {"name": h.name, "recorded": h.value, "jmx": None, "sensitive": sensitive(h.name, h.value)}
        if lname.startswith(":"):
            row.update(status="mapped", note="Host header" if lname == ":authority" else "sampler " + lname[1:])
        elif lname == "transfer-encoding":
            row.update(status="dropped", note="JMeter cannot send it")
        elif generated is None:
            row.update(status="excluded", note="request not in plan")
        else:
            idx = next((i for i, (n, _) in enumerate(remaining) if n.lower() == lname), None)
            if idx is None:
                row.update(status="dropped", note="not in generated plan")
            else:
                _, v = remaining.pop(idx)
                row.update(jmx=v, status="kept" if v == h.value else "changed")
        headers.append(row)
    for n, v in remaining:  # e.g. Host created from :authority
        headers.append({"name": n, "recorded": None, "jmx": v, "status": "added", "note": "from :authority",
                        "sensitive": sensitive(n, v)})

    body = req.body
    resp = req.response
    return {
        "id": req.id,
        "samplerName": sampler_name,
        "method": req.method,
        "url": req.origin + req.path + ("?" + "&".join(q.name + ("=" + q.value if q.has_equals else "") for q in req.query)
                                        if req.query else ""),
        "sampler": sampler_info,
        "source": req.source_ref[:120],
        "headers": headers,
        "query": [{"name": q.name, "value": q.value, "sensitive": is_sensitive_name(q.name) or q.value in sv}
                  for q in req.query],
        "body": {
            "kind": body.kind, "contentType": body.content_type,
            "text": (body.text or "")[:DETAIL_BODY_LIMIT], "truncated": len(body.text or "") > DETAIL_BODY_LIMIT,
            "sensitive": any(v and v in (body.text or "") for v in sv),
            "fields": [{"name": f.name, "value": f.value, "fileName": f.file_name,
                        "sensitive": is_sensitive_name(f.name) or f.value in sv} for f in body.fields],
        },
        "response": None if resp is None else {
            "status": resp.status, "contentType": resp.content_type,
            "headers": [{"name": h.name, "value": h.value} for h in resp.headers],
            "body": (resp.body_text or "")[:DETAIL_BODY_LIMIT],
            "sensitive": any(v and v in (resp.body_text or "") for v in sv),
        },
        "issues": [i.to_dict() for i in analysis.issues if i.request_id == request_id],
        "suggestions": [s.id for s in analysis.suggestions if s.source_request_id == request_id
                        or any(u.request_id == request_id for u in s.usages)],
    }


def jmx_summary(jmx: str) -> dict:
    root = ET.fromstring(jmx)
    flows = []
    for tree in root.iter("hashTree"):
        kids = list(tree)
        for i, el in enumerate(kids):
            if el.tag == "TransactionController":
                flows.append({"name": el.get("testname"),
                              "samplers": [s.get("testname") for s in kids[i + 1] if s.tag == "HTTPSamplerProxy"]})
    variables = [ep.get("name") for a in root.iter("Arguments") if a.get("testclass") == "Arguments"
                 for ep in a.iter("elementProp") if ep.get("elementType") == "Argument"]
    return {
        "transactions": flows,
        "samplers": sum(len(f["samplers"]) for f in flows),
        "headers": sum(1 for _ in root.iter("elementProp") if _.get("elementType") == "Header"),
        "extractors": sum(1 for el in root.iter() if el.tag in ("JSONPostProcessor", "BoundaryExtractor")),
        "timers": sum(1 for _ in root.iter("ConstantTimer")),
        "variables": variables,
        "bytes": len(jmx.encode("utf-8")),
    }
