"""Parser for the documented rec2jmx JSON recording schema, version 1.

Intended for captures from tools without HAR export (custom proxies, mobile test
harnesses) after a small conversion script. Schema (see docs/FORMATS.md)::

    {
      "format": "rec2jmx-recording", "version": 1, "name": "optional",
      "flows": [ {"name": "Login", "requests": [REQUEST, ...]}, ... ]
      // or "requests": [REQUEST, ...] for an ungrouped recording
    }

    REQUEST = {
      "method": "POST", "url": "https://host/path?q=1",          (required)
      "headers": [{"name": "...", "value": "..."}] | {"Name": "value"},
      "body": null | {"text": "...", "contentType": "..."} | {"json": <any>}
              | {"form": [{"name": "...", "value": "..."}]},
      "startedAt": "ISO-8601", "durationMs": 12.5,
      "response": {"status": 200, "headers": [...], "body": "text"}
    }
"""

from __future__ import annotations

import json
from typing import Any

from ..errors import InputError
from ..ir import Body, FormField, Issue, NameValue, Response
from .common import ParseResult, build_body, header_get, name_values, new_request, parse_datetime, split_url, truncate_body

_REQUEST_KEYS = {"method", "url", "headers", "body", "startedAt", "durationMs", "response", "comment"}


def _err(path: str, msg: str) -> InputError:
    return InputError(f"rec2jmx recording: {path}: {msg}")


def _parse_body(raw: Any, path: str, headers: list[NameValue]) -> Body:
    if raw is None:
        return Body("none")
    if not isinstance(raw, dict):
        raise _err(path, "expected null or an object with 'text', 'json', or 'form'")
    kinds = [k for k in ("text", "json", "form") if k in raw]
    if len(kinds) != 1:
        raise _err(path, "exactly one of 'text', 'json', or 'form' is required")
    ctype = raw.get("contentType")
    if ctype is not None and not isinstance(ctype, str):
        raise _err(path + ".contentType", "expected a string")
    ctype = ctype or header_get(headers, "content-type")
    kind = kinds[0]
    if kind == "text":
        if not isinstance(raw["text"], str):
            raise _err(path + ".text", "expected a string")
        return build_body(raw["text"], ctype)
    if kind == "json":
        text = json.dumps(raw["json"], ensure_ascii=False, separators=(",", ":"))
        return Body("raw", text=text, content_type=ctype or "application/json")
    fields = name_values(raw["form"])
    if fields is None or not isinstance(raw["form"], list):
        raise _err(path + ".form", "expected an array of {name, value} objects")
    return Body("form", content_type=ctype or "application/x-www-form-urlencoded",
                fields=[FormField(f.name, f.value) for f in fields])


def _parse_request(raw: Any, path: str, hint: str | None, issues: list[Issue]):
    if not isinstance(raw, dict):
        raise _err(path, "expected an object")
    unknown = sorted(set(raw) - _REQUEST_KEYS)
    if unknown:
        issues.append(Issue("warning", "unknown-field", f"rec2jmx recording: {path}: ignored unknown field(s): "
                            + ", ".join(str(k)[:30] for k in unknown[:5])))
    method, url = raw.get("method"), raw.get("url")
    if not isinstance(method, str) or not method.strip():
        raise _err(path + ".method", "required string is missing")
    if not isinstance(url, str) or not url:
        raise _err(path + ".url", "required string is missing")
    try:
        parts = split_url(url)
    except ValueError as exc:
        raise _err(path + ".url", str(exc)) from None
    headers = name_values(raw.get("headers"))
    if headers is None:
        raise _err(path + ".headers", "expected an array of {name, value} objects or a name->value object")
    body = _parse_body(raw.get("body"), path + ".body", headers)
    duration = raw.get("durationMs")
    if duration is not None and (not isinstance(duration, (int, float)) or duration < 0):
        raise _err(path + ".durationMs", "expected a non-negative number")
    started = raw.get("startedAt")
    started_at = parse_datetime(started)
    if started is not None and started_at is None:
        raise _err(path + ".startedAt", "expected an ISO-8601 date-time string")
    response = None
    rraw = raw.get("response")
    if rraw is not None:
        if not isinstance(rraw, dict):
            raise _err(path + ".response", "expected an object")
        status = rraw.get("status")
        if status is not None and not isinstance(status, int):
            raise _err(path + ".response.status", "expected an integer")
        rheaders = name_values(rraw.get("headers"))
        if rheaders is None:
            raise _err(path + ".response.headers", "expected headers as an array or object")
        rbody = rraw.get("body")
        if rbody is not None and not isinstance(rbody, str):
            rbody = json.dumps(rbody, ensure_ascii=False)
        response = Response(status, rheaders, truncate_body(rbody), header_get(rheaders, "content-type"))
    if parts.had_userinfo:
        issues.append(Issue("warning", "url-credentials-dropped", f"{path}.url: embedded credentials were removed."))
    return new_request(method, parts, headers=headers, body=body, started_at=started_at,
                       duration_ms=float(duration) if duration is not None else None,
                       response=response, group_hint=hint, source_ref=path)


def parse_native_json(text: str, doc: Any) -> ParseResult:
    if not isinstance(doc, dict) or doc.get("format") != "rec2jmx-recording":
        raise InputError('rec2jmx recording: "format" must be "rec2jmx-recording".')
    if doc.get("version") != 1:
        raise InputError(f"rec2jmx recording: unsupported version {doc.get('version')!r}; only version 1 is supported.")
    has_flows, has_requests = "flows" in doc, "requests" in doc
    if has_flows == has_requests:
        raise InputError("rec2jmx recording: provide exactly one of 'flows' or 'requests'.")
    issues: list[Issue] = []
    requests = []
    if has_flows:
        flows = doc["flows"]
        if not isinstance(flows, list) or not flows:
            raise _err("flows", "expected a non-empty array")
        for fi, flow in enumerate(flows):
            fpath = f"flows[{fi}]"
            if not isinstance(flow, dict):
                raise _err(fpath, "expected an object")
            name = flow.get("name")
            if not isinstance(name, str) or not name.strip():
                raise _err(fpath + ".name", "required string is missing")
            reqs = flow.get("requests")
            if not isinstance(reqs, list) or not reqs:
                raise _err(fpath + ".requests", "expected a non-empty array")
            for ri, r in enumerate(reqs):
                requests.append(_parse_request(r, f"{fpath}.requests[{ri}]", name.strip(), issues))
    else:
        reqs = doc["requests"]
        if not isinstance(reqs, list) or not reqs:
            raise _err("requests", "expected a non-empty array")
        for ri, r in enumerate(reqs):
            requests.append(_parse_request(r, f"requests[{ri}]", None, issues))
    return ParseResult(requests, issues, grouping_source="recording flows" if has_flows else None,
                       metadata={"name": str(doc.get("name", ""))[:120]})
