"""Postman Collection v2.0 / v2.1 parser.

* Folders become flows (nested folder names are joined with " / ").
* Collection variables (``{{name}}``) are inlined; unknown variables become JMeter
  expressions ``${name}`` and are declared as properties so they can be passed with
  ``-Jname=value``.
* A few Postman dynamic variables map to JMeter functions; others are reported.
* Scripts are never executed or converted.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from ..errors import InputError
from ..ir import Body, FormField, Issue, NameValue, QueryParam
from .common import ParseResult, build_body, header_get, new_request, split_url

_VAR_RE = re.compile(r"\{\{\s*([^{}\s][^{}]*?)\s*\}\}")
_DYNAMIC = {
    "$guid": "${__UUID()}",
    "$randomUUID": "${__UUID()}",
    "$timestamp": "${__time(/1000,)}",
    "$isoTimestamp": "${__time(yyyy-MM-dd'T'HH:mm:ss.SSS'Z',)}",
    "$randomInt": "${__Random(0,1000)}",
}
_RAW_LANG_TYPES = {"json": "application/json", "xml": "application/xml", "text": "text/plain",
                   "html": "text/html", "javascript": "application/javascript"}


class _Ctx:
    def __init__(self, variables: dict[str, str]):
        self.variables = variables
        self.unknown: set[str] = set()
        self.unmapped_dynamic: set[str] = set()
        self.issues: list[Issue] = []
        self.scripts = 0

    def sub(self, text: Any) -> str:
        if text is None:
            return ""
        text = str(text)

        def repl(m: re.Match) -> str:
            name = m.group(1)
            if name.startswith("$"):
                if name in _DYNAMIC:
                    return _DYNAMIC[name]
                self.unmapped_dynamic.add(name)
                return m.group(0)
            if name in self.variables:
                return self.variables[name]
            self.unknown.add(name)
            return "${" + re.sub(r"[^\w.-]", "_", name) + "}"

        # Variables may nest one level ({{base}} -> "{{host}}/v1"); resolve twice.
        return _VAR_RE.sub(repl, _VAR_RE.sub(repl, text))


def _kv_list(raw: Any) -> list[dict]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict) and not x.get("disabled")]
    return []


def _auth_map(auth: dict, key: str) -> dict[str, Any]:
    raw = auth.get(key)
    if isinstance(raw, dict):  # v2.0
        return raw
    if isinstance(raw, list):  # v2.1
        return {x.get("key"): x.get("value") for x in raw if isinstance(x, dict)}
    return {}


def _apply_auth(auth: Any, ctx: _Ctx, headers: list[NameValue], query: list[QueryParam], where: str) -> None:
    if not isinstance(auth, dict):
        return
    kind = auth.get("type")
    if kind in (None, "noauth"):
        return
    if kind == "bearer":
        token = ctx.sub(_auth_map(auth, "bearer").get("token", ""))
        headers.append(NameValue("Authorization", f"Bearer {token}"))
    elif kind == "basic":
        m = _auth_map(auth, "basic")
        cred = f"{ctx.sub(m.get('username', ''))}:{ctx.sub(m.get('password', ''))}"
        if "${" in cred:
            expr = "'" + cred.replace("\\", "\\\\").replace("'", "\\'").replace(",", "\\,") + "'"
            headers.append(NameValue("Authorization", "Basic ${__groovy(" + expr + ".bytes.encodeBase64().toString(),)}"))
            ctx.issues.append(Issue("info", "postman-basic-auth-function",
                                    f"{where}: basic auth uses variables, so it is encoded at run time with the "
                                    "built-in __groovy function."))
        else:
            headers.append(NameValue("Authorization", "Basic " + base64.b64encode(cred.encode()).decode()))
    elif kind == "apikey":
        m = _auth_map(auth, "apikey")
        key, value = ctx.sub(m.get("key", "")), ctx.sub(m.get("value", ""))
        if m.get("in") == "query":
            query.append(QueryParam(key, value))
        else:
            headers.append(NameValue(key, value))
    else:
        ctx.issues.append(Issue("warning", "postman-auth-unsupported",
                                f"{where}: auth type '{str(kind)[:30]}' is not converted; add it manually."))


def _url_string(url: Any, ctx: _Ctx) -> str:
    if isinstance(url, str):
        return url
    if not isinstance(url, dict):
        return ""
    if isinstance(url.get("raw"), str) and url["raw"]:
        return url["raw"]
    protocol = url.get("protocol") or "https"
    host = url.get("host")
    host = ".".join(host) if isinstance(host, list) else str(host or "")
    path = url.get("path")
    path = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
    port = f":{url['port']}" if url.get("port") else ""
    query = "&".join(f"{q.get('key', '')}={q.get('value', '') or ''}" for q in _kv_list(url.get("query")))
    return f"{protocol}://{host}{port}/{path.lstrip('/')}" + (f"?{query}" if query else "")


def _parse_body(raw: Any, ctx: _Ctx, headers: list[NameValue], where: str) -> Body:
    if not isinstance(raw, dict) or raw.get("disabled"):
        return Body("none")
    mode = raw.get("mode")
    ctype = header_get(headers, "content-type")
    if mode == "raw":
        text = ctx.sub(raw.get("raw", ""))
        lang = (((raw.get("options") or {}).get("raw") or {}).get("language")) if isinstance(raw.get("options"), dict) else None
        if ctype is None and lang in _RAW_LANG_TYPES and text:
            ctype = _RAW_LANG_TYPES[lang]
            headers.append(NameValue("Content-Type", ctype))
        return build_body(text, ctype)
    if mode == "urlencoded":
        if ctype is None:
            ctype = "application/x-www-form-urlencoded"
            headers.append(NameValue("Content-Type", ctype))
        fields = [FormField(ctx.sub(f.get("key", "")), ctx.sub(f.get("value", ""))) for f in _kv_list(raw.get("urlencoded"))]
        return Body("form", content_type=ctype, fields=fields)
    if mode == "formdata":
        fields = []
        for f in _kv_list(raw.get("formdata")):
            if f.get("type") == "file":
                src = f.get("src")
                src = src[0] if isinstance(src, list) and src else src
                name = re.split(r"[\\/]", str(src or "upload.bin"))[-1] or "upload.bin"
                fields.append(FormField(ctx.sub(f.get("key", "")), "", name, f.get("contentType")))
                ctx.issues.append(Issue("warning", "postman-file", f"{where}: form file '{name[:60]}' must be "
                                        "supplied at run time (see the FILE_DIR variable)."))
            else:
                fields.append(FormField(ctx.sub(f.get("key", "")), ctx.sub(f.get("value", ""))))
        return Body("multipart", fields=fields)
    if mode == "graphql":
        gql = raw.get("graphql") or {}
        variables = gql.get("variables")
        if isinstance(variables, str) and variables.strip():
            try:
                variables = json.loads(ctx.sub(variables))
            except json.JSONDecodeError:
                ctx.issues.append(Issue("warning", "postman-graphql-vars", f"{where}: GraphQL variables are not valid JSON; omitted."))
                variables = None
        payload = {"query": ctx.sub(gql.get("query", ""))}
        if variables:
            payload["variables"] = variables
        if ctype is None:
            headers.append(NameValue("Content-Type", "application/json"))
        return Body("raw", text=json.dumps(payload, ensure_ascii=False), content_type="application/json")
    if mode == "file":
        ctx.issues.append(Issue("warning", "postman-binary-body", f"{where}: binary file bodies are not supported; body omitted."))
        return Body("none")
    if mode:
        ctx.issues.append(Issue("warning", "postman-body-mode", f"{where}: body mode '{str(mode)[:20]}' is not supported; body omitted."))
    return Body("none")


def _walk(items: Any, folders: list[str], auth: Any, ctx: _Ctx, collection_name: str, out: list) -> None:
    if not isinstance(items, list):
        return
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or f"item {idx + 1}")
        for ev in item.get("event") or []:
            if isinstance(ev, dict) and ev.get("listen") in ("prerequest", "test"):
                ctx.scripts += 1
        if "item" in item:
            _walk(item["item"], folders + [name], item.get("auth") or auth, ctx, collection_name, out)
            continue
        request = item.get("request")
        if request is None:
            continue
        where = "Postman item '" + "/".join(folders + [name])[:80] + "'"
        if isinstance(request, str):
            request = {"url": request, "method": "GET"}
        if not isinstance(request, dict):
            raise InputError(f"{where}: 'request' must be an object or URL string.")
        method = str(request.get("method") or "GET")
        url = ctx.sub(_url_string(request.get("url"), ctx)).strip()
        if not url:
            raise InputError(f"{where}: the request has no URL.")
        headers: list[NameValue] = []
        raw_headers = request.get("header")
        if isinstance(raw_headers, str):
            for line in raw_headers.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers.append(NameValue(k.strip(), ctx.sub(v.strip())))
        else:
            headers = [NameValue(ctx.sub(h.get("key", "")), ctx.sub(h.get("value", ""))) for h in _kv_list(raw_headers)]
        extra_query: list[QueryParam] = []
        _apply_auth(request.get("auth") or auth, ctx, headers, extra_query, where)
        body = _parse_body(request.get("body"), ctx, headers, where)

        unresolved_origin = None
        m = re.match(r"^(\$\{[^}]+\})(.*)$", url)
        if m:  # the origin itself is an unknown variable, e.g. {{baseUrl}}/users
            unresolved_origin, rest = m.group(1), m.group(2) or "/"
            parts = split_url("http://unresolved.invalid" + (rest if rest.startswith(("/", "?")) else "/" + rest))
            ctx.issues.append(Issue("warning", "postman-unresolved-origin",
                                    f"{where}: the server comes from undefined variable {unresolved_origin}; it is "
                                    "kept as a JMeter property and host parameterization is not applied."))
        else:
            if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
                url = "https://" + url
                ctx.issues.append(Issue("info", "postman-no-scheme", f"{where}: URL has no scheme; https:// was assumed."))
            try:
                parts = split_url(url)
            except ValueError as exc:
                raise InputError(f"{where}: {exc}.") from None
        req = new_request(method, parts, headers=headers, body=body,
                          group_hint=" / ".join(folders) if folders else collection_name,
                          source_ref=where, unresolved_origin=unresolved_origin)
        if unresolved_origin:
            req.scheme, req.host, req.port = "", "", None
        req.query.extend(extra_query)
        out.append(req)


def parse_postman(text: str, doc: Any) -> ParseResult:
    info = doc.get("info") if isinstance(doc, dict) else None
    schema = str((info or {}).get("schema", ""))
    if "v2.1" not in schema and "v2.0" not in schema:
        raise InputError("Postman: only Collection v2.0 and v2.1 are supported. Re-export the collection as v2.1.")
    collection_name = str(info.get("name") or "Collection")[:80]
    variables: dict[str, str] = {}
    for v in doc.get("variable") or []:
        if isinstance(v, dict) and isinstance(v.get("key"), str) and not v.get("disabled"):
            variables[v["key"]] = "" if v.get("value") is None else str(v.get("value"))
    ctx = _Ctx(variables)
    requests: list = []
    _walk(doc.get("item"), [], doc.get("auth"), ctx, collection_name, requests)
    if not requests:
        raise InputError("Postman: the collection contains no requests.")
    issues = list(ctx.issues)
    if variables:
        issues.append(Issue("info", "postman-vars-inlined",
                            f"Inlined {len(variables)} collection variable(s): " + ", ".join(sorted(variables)[:20])))
    if ctx.unknown:
        issues.append(Issue("warning", "postman-unknown-vars",
                            "Variables with no value in the collection (pass them with -Jname=value): "
                            + ", ".join(sorted(ctx.unknown)[:20])))
    if ctx.unmapped_dynamic:
        issues.append(Issue("warning", "postman-dynamic-vars",
                            "Postman dynamic variables with no JMeter equivalent were left as-is: "
                            + ", ".join(sorted(ctx.unmapped_dynamic)[:20])))
    if ctx.scripts:
        issues.append(Issue("warning", "postman-scripts",
                            f"{ctx.scripts} pre-request/test script(s) were not converted (and were never executed). "
                            "Re-create assertions and extractors in JMeter."))
    unknown_vars = {re.sub(r"[^\w.-]", "_", n): "" for n in ctx.unknown}
    return ParseResult(requests, issues, variables=unknown_vars, grouping_source="Postman folders",
                       metadata={"name": collection_name})
