"""Write a JMeter 5.x .jmx test plan from a PreparedPlan.

Structure::

    Test Plan
      User Defined Variables   (hosts, source variables, secrets, FILE_DIR)
      HTTP Cookie Manager
      Thread Group             (threads/rampup/loops from -J properties, default 1)
        TX_01_<flow>           (Transaction Controller)
          TX_01_A01_<path>     (HTTP Request)
            HTTP Header Manager    (all recorded headers of this request)
            Constant Timer / extractors

Output is deterministic for the same input and plan (no timestamps or random ids).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import quote

from .ir import Issue, NameValue, QueryParam, Recording, Request
from .naming import NamedFlow
from .plan import Plan
from .transform import PreparedPlan

JMETER_VERSION = "5.6.3"
_STANDARD_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
                     "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "MKCALENDAR", "SEARCH"}
_INVALID_XML_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][\w.-]*)\}")


@dataclass
class HostVars:
    protocol: str
    host: str
    port: str


class _Writer:
    def __init__(self) -> None:
        self.stripped_control_chars = 0

    def text(self, s: str) -> str:
        cleaned = _INVALID_XML_RE.sub("", s)
        if cleaned != s:
            self.stripped_control_chars += 1
        return cleaned

    def prop(self, parent: ET.Element, kind: str, name: str, value) -> ET.Element:
        el = ET.SubElement(parent, kind, name=name)
        if kind == "boolProp":
            el.text = "true" if value else "false"
        else:
            el.text = self.text(str(value)) if value not in (None, "") else None
        return el

    def element(self, parent: ET.Element, tag: str, guiclass: str, testclass: str, testname: str,
                enabled: bool = True) -> ET.Element:
        return ET.SubElement(parent, tag, guiclass=guiclass, testclass=testclass,
                             testname=self.text(testname), enabled="true" if enabled else "false")


def _encode_query(params: list[QueryParam]) -> str:
    """Percent-encode decoded query params, keeping ${...} expressions literal."""
    def enc(s: str) -> str:
        out, last = [], 0
        for m in re.finditer(r"\$\{[^}]*\}", s):
            out.append(quote(s[last:m.start()], safe="-._~"))
            out.append(m.group(0))
            last = m.end()
        out.append(quote(s[last:], safe="-._~"))
        return "".join(out)
    return "&".join(enc(q.name) + ("=" + enc(q.value) if q.has_equals or q.value else "") for q in params)


def _arguments(w: _Writer, parent: ET.Element, name: str = "HTTPsampler.Arguments") -> ET.Element:
    ep = ET.SubElement(parent, "elementProp", name=name, elementType="Arguments",
                       guiclass="HTTPArgumentsPanel", testclass="Arguments", testname="User Defined Variables")
    return ET.SubElement(ep, "collectionProp", name="Arguments.arguments")


def _http_arg(w: _Writer, coll: ET.Element, name: str, value: str, encode: bool, use_equals: bool = True) -> None:
    ep = ET.SubElement(coll, "elementProp", name=w.text(name), elementType="HTTPArgument")
    w.prop(ep, "boolProp", "HTTPArgument.always_encode", encode)
    w.prop(ep, "stringProp", "Argument.value", value)
    w.prop(ep, "stringProp", "Argument.metadata", "=")
    w.prop(ep, "boolProp", "HTTPArgument.use_equals", use_equals)
    if name:
        w.prop(ep, "stringProp", "Argument.name", name)


def _header_manager(w: _Writer, parent: ET.Element, headers: list[NameValue], testname: str) -> None:
    hm = w.element(parent, "HeaderManager", "HeaderPanel", "HeaderManager", testname)
    coll = ET.SubElement(hm, "collectionProp", name="HeaderManager.headers")
    for h in headers:
        ep = ET.SubElement(coll, "elementProp", name="", elementType="Header")
        w.prop(ep, "stringProp", "Header.name", h.name)
        w.prop(ep, "stringProp", "Header.value", h.value)
    ET.SubElement(parent, "hashTree")


def _udv(w: _Writer, parent: ET.Element, entries: list[tuple[str, str, str]]) -> None:
    args = w.element(parent, "Arguments", "ArgumentsPanel", "Arguments", "User Defined Variables")
    coll = ET.SubElement(args, "collectionProp", name="Arguments.arguments")
    for name, value, desc in entries:
        ep = ET.SubElement(coll, "elementProp", name=name, elementType="Argument")
        w.prop(ep, "stringProp", "Argument.name", name)
        w.prop(ep, "stringProp", "Argument.value", value)
        w.prop(ep, "stringProp", "Argument.metadata", "=")
        if desc:
            w.prop(ep, "stringProp", "Argument.desc", desc)
    ET.SubElement(parent, "hashTree")


def _prop_default(value: str) -> str:
    """Escape a default value for use inside ${__P(name,default)}."""
    return value.replace("\\", "\\\\").replace(",", "\\,").replace(")", "\\)")


def _extractor(w: _Writer, parent: ET.Element, ex: dict) -> None:
    var = ex["var"]
    default = f"NOT_FOUND_{var}"
    if ex["type"] == "json":
        el = w.element(parent, "JSONPostProcessor", "JSONPostProcessorGui", "JSONPostProcessor",
                       f"Extract {var} ({ex.get('suggestion', '')})")
        w.prop(el, "stringProp", "JSONPostProcessor.referenceNames", var)
        w.prop(el, "stringProp", "JSONPostProcessor.jsonPathExprs", ex["expression"])
        w.prop(el, "stringProp", "JSONPostProcessor.match_numbers", "1")
        w.prop(el, "stringProp", "JSONPostProcessor.defaultValues", default)
    else:
        el = w.element(parent, "BoundaryExtractor", "BoundaryExtractorGui", "BoundaryExtractor",
                       f"Extract {var} ({ex.get('suggestion', '')})")
        w.prop(el, "stringProp", "BoundaryExtractor.useHeaders", "true" if ex.get("scope") == "headers" else "false")
        w.prop(el, "stringProp", "BoundaryExtractor.refname", var)
        w.prop(el, "stringProp", "BoundaryExtractor.lboundary", ex.get("left", ""))
        w.prop(el, "stringProp", "BoundaryExtractor.rboundary", ex.get("right", ""))
        w.prop(el, "stringProp", "BoundaryExtractor.default", default)
        w.prop(el, "boolProp", "BoundaryExtractor.default_empty_value", False)
        w.prop(el, "stringProp", "BoundaryExtractor.match_number", "1")
    ET.SubElement(parent, "hashTree")


def _bind_host_header(req: Request, host_vars: dict[tuple, "HostVars"]) -> None:
    """Point a recorded Host header at the HOST_n/PORT_n variables so environment overrides stay consistent."""
    hv = host_vars.get((req.scheme, req.host, req.port))
    if hv is None:
        return
    for h in req.headers:
        if h.name.lower() != "host":
            continue
        value = h.value.strip().lower()
        if value == req.host:
            h.value = "${" + hv.host + "}"
        elif req.port is not None and value == f"{req.host}:{req.port}":
            h.value = "${" + hv.host + "}:${" + hv.port + "}"


def _server_fields(req: Request, host_vars: dict[tuple, HostVars], parameterize: bool) -> tuple[str, str, str, str]:
    """(protocol, domain, port, path prefix)"""
    if req.unresolved_origin:
        return "", "", "", req.unresolved_origin
    if "${" in req.host or "${" in req.scheme:
        return req.scheme, req.host, "" if req.port is None else str(req.port), ""
    if parameterize:
        hv = host_vars[(req.scheme, req.host, req.port)]
        return "${" + hv.protocol + "}", "${" + hv.host + "}", "${" + hv.port + "}", ""
    return req.scheme, req.host, "" if req.port is None else str(req.port), ""


def generate_jmx(rec: Recording, plan: Plan, prepared: PreparedPlan, names: list[NamedFlow]) -> tuple[str, list[Issue]]:
    w = _Writer()
    issues: list[Issue] = []
    items = prepared.items
    sampler_names = {s.request_id: s.name for nf in names for s in nf.samplers}

    # Hosts in order of first use.
    host_vars: dict[tuple, HostVars] = {}
    host_entries: list[tuple[str, str, str]] = []
    if plan.parameterize_hosts:
        for p in items:
            r = p.request
            if r.unresolved_origin or "${" in r.host or "${" in r.scheme:
                continue
            key = (r.scheme, r.host, r.port)
            if key not in host_vars:
                n = len(host_vars) + 1
                hv = HostVars(f"PROTOCOL_{n}", f"HOST_{n}", f"PORT_{n}")
                host_vars[key] = hv
                origin = r.origin
                host_entries += [
                    (hv.protocol, f"${{__P({hv.protocol},{r.scheme})}}", f"Recorded origin {origin}"),
                    (hv.host, f"${{__P({hv.host},{_prop_default(r.host)})}}", f"Recorded origin {origin}"),
                    (hv.port, f"${{__P({hv.port},{'' if r.port is None else r.port})}}",
                     "Empty means the protocol default port"),
                ]

    for p in items:
        _bind_host_header(p.request, host_vars)

    # Variables referenced by requests.
    referenced: set[str] = set()
    for p in items:
        r = p.request
        blob = "\n".join([r.path, r.host, r.unresolved_origin or ""] + [q.name + q.value for q in r.query]
                         + [h.value for h in r.headers] + [f.value for f in r.body.fields] + [r.body.text or ""])
        referenced.update(_VAR_REF_RE.findall(blob))
    needs_file_dir = any(f.is_file for p in items for f in p.request.body.fields)

    var_entries: list[tuple[str, str, str]] = list(host_entries)
    own = {e[0] for e in host_entries} | prepared.correlation_vars | set(prepared.secret_vars)
    secret_variable_names = {s.field: s.var_name for s in prepared.secret_values_parameterized if s.kind == "variable"}
    for name in sorted(referenced - own - {"FILE_DIR"}):
        if name in secret_variable_names:
            var_entries.append((name, f"${{__P({name},)}}", "Secret: supply with -J" + name + "=..."))
        elif name in rec.variables:
            value = rec.variables[name]
            expr = value if "${" in value else f"${{__P({name},{_prop_default(value)})}}"
            var_entries.append((name, expr, "From the source recording"))
        else:
            var_entries.append((name, f"${{__P({name},)}}", "Undefined in the source; supply with -J" + name + "=..."))
            issues.append(Issue("warning", "undefined-variable",
                                f"Variable '{name}' is referenced but has no value in the source; pass -J{name}=... "
                                "or define it (it may have come from an extractor that was not converted)."))
    for var in sorted(v for v in prepared.secret_vars if v in referenced):
        var_entries.append((var, f"${{__P({var},)}}", f"Secret ({prepared.secret_vars[var]}): supply with -J{var}=..."))
    if needs_file_dir:
        var_entries.append(("FILE_DIR", "${__P(FILE_DIR,.)}", "Folder containing files for multipart uploads"))

    root = ET.Element("jmeterTestPlan", version="1.2", properties="5.0", jmeter=JMETER_VERSION)
    top = ET.SubElement(root, "hashTree")
    tp = w.element(top, "TestPlan", "TestPlanGui", "TestPlan", plan.test_plan_name)
    w.prop(tp, "stringProp", "TestPlan.comments",
           f"Generated by rec2jmx from '{rec.source_name}' ({rec.source_format}). Runtime properties: "
           "-Jthreads, -Jrampup, -Jloops, and the variables listed under User Defined Variables.")
    w.prop(tp, "boolProp", "TestPlan.functional_mode", False)
    w.prop(tp, "boolProp", "TestPlan.serialize_threadgroups", False)
    tp_args = ET.SubElement(tp, "elementProp", name="TestPlan.user_defined_variables", elementType="Arguments",
                            guiclass="ArgumentsPanel", testclass="Arguments", testname="User Defined Variables")
    ET.SubElement(tp_args, "collectionProp", name="Arguments.arguments")
    tp_tree = ET.SubElement(top, "hashTree")

    if var_entries:
        _udv(w, tp_tree, var_entries)
    cm = w.element(tp_tree, "CookieManager", "CookiePanel", "CookieManager", "HTTP Cookie Manager")
    ET.SubElement(cm, "collectionProp", name="CookieManager.cookies")
    w.prop(cm, "boolProp", "CookieManager.clearEachIteration", True)
    w.prop(cm, "boolProp", "CookieManager.controlledByThreadGroup", False)
    ET.SubElement(tp_tree, "hashTree")

    tg = w.element(tp_tree, "ThreadGroup", "ThreadGroupGui", "ThreadGroup", "Thread Group")
    w.prop(tg, "stringProp", "ThreadGroup.on_sample_error", "continue")
    lc = ET.SubElement(tg, "elementProp", name="ThreadGroup.main_controller", elementType="LoopController",
                       guiclass="LoopControlPanel", testclass="LoopController", testname="Loop Controller")
    w.prop(lc, "stringProp", "LoopController.loops", "${__P(loops,1)}")
    w.prop(lc, "boolProp", "LoopController.continue_forever", False)
    w.prop(tg, "stringProp", "ThreadGroup.num_threads", "${__P(threads,1)}")
    w.prop(tg, "stringProp", "ThreadGroup.ramp_time", "${__P(rampup,1)}")
    w.prop(tg, "boolProp", "ThreadGroup.same_user_on_next_iteration", True)
    w.prop(tg, "boolProp", "ThreadGroup.scheduler", False)
    w.prop(tg, "stringProp", "ThreadGroup.duration", "")
    w.prop(tg, "stringProp", "ThreadGroup.delay", "")
    tg_tree = ET.SubElement(tp_tree, "hashTree")

    by_flow: dict[int, list] = {}
    for p in items:
        by_flow.setdefault(p.flow_index, []).append(p)
    unusual_methods: set[str] = set()
    for fi, nf in enumerate(names):
        tc = w.element(tg_tree, "TransactionController", "TransactionControllerGui", "TransactionController", nf.tx_name)
        w.prop(tc, "boolProp", "TransactionController.includeTimers", False)
        w.prop(tc, "boolProp", "TransactionController.parent", False)
        tc_tree = ET.SubElement(tg_tree, "hashTree")
        for p in by_flow.get(fi, []):
            r = p.request
            if r.method not in _STANDARD_METHODS:
                unusual_methods.add(r.method)
            protocol, domain, port, prefix = _server_fields(r, host_vars, plan.parameterize_hosts)
            sp = w.element(tc_tree, "HTTPSamplerProxy", "HttpTestSampleGui", "HTTPSamplerProxy", sampler_names[r.id])
            w.prop(sp, "stringProp", "HTTPSampler.domain", domain)
            w.prop(sp, "stringProp", "HTTPSampler.port", port)
            w.prop(sp, "stringProp", "HTTPSampler.protocol", protocol)
            w.prop(sp, "stringProp", "HTTPSampler.contentEncoding", "UTF-8")
            body = r.body
            has_body = body.kind != "none"
            path = prefix + r.path
            use_args_for_query = not has_body
            send_form_as_args = body.kind == "form" and r.method == "POST"
            if r.query and not use_args_for_query:
                path += "?" + _encode_query(r.query)
            w.prop(sp, "stringProp", "HTTPSampler.path", path)
            w.prop(sp, "stringProp", "HTTPSampler.method", r.method)
            w.prop(sp, "boolProp", "HTTPSampler.follow_redirects", True)
            w.prop(sp, "boolProp", "HTTPSampler.auto_redirects", False)
            w.prop(sp, "boolProp", "HTTPSampler.use_keepalive", True)
            w.prop(sp, "boolProp", "HTTPSampler.DO_MULTIPART_POST", body.kind == "multipart")
            if body.kind == "multipart":
                w.prop(sp, "boolProp", "HTTPSampler.BROWSER_COMPATIBLE_MULTIPART", True)
            raw = body.kind == "raw" or (body.kind == "form" and not send_form_as_args)
            w.prop(sp, "boolProp", "HTTPSampler.postBodyRaw", raw)
            coll = _arguments(w, sp)
            if use_args_for_query:
                for q in r.query:
                    _http_arg(w, coll, q.name, q.value, True, q.has_equals or bool(q.value))
            elif body.kind == "raw":
                _http_arg(w, coll, "", body.text, False)
            elif body.kind == "form" and send_form_as_args:
                for f in body.fields:
                    _http_arg(w, coll, f.name, f.value, True)
            elif body.kind == "form":
                _http_arg(w, coll, "", _encode_query([QueryParam(f.name, f.value) for f in body.fields]), False)
            elif body.kind == "multipart":
                for f in body.fields:
                    if not f.is_file:
                        _http_arg(w, coll, f.name, f.value, False)
                files = [f for f in body.fields if f.is_file]
                if files:
                    fep = ET.SubElement(sp, "elementProp", name="HTTPsampler.Files", elementType="HTTPFileArgs")
                    fcoll = ET.SubElement(fep, "collectionProp", name="HTTPFileArgs.files")
                    for f in files:
                        fpath = "${FILE_DIR}/" + re.sub(r"[^A-Za-z0-9._-]", "_", f.file_name or "upload.bin")
                        fe = ET.SubElement(fcoll, "elementProp", name=fpath, elementType="HTTPFileArg")
                        w.prop(fe, "stringProp", "File.mimetype", f.content_type or "application/octet-stream")
                        w.prop(fe, "stringProp", "File.path", fpath)
                        w.prop(fe, "stringProp", "File.paramname", f.name)
                    issues.append(Issue("warning", "file-upload", f"{sampler_names[r.id]}: upload file(s) "
                                        + ", ".join((f.file_name or "")[:40] for f in files)
                                        + " must exist in ${FILE_DIR} at run time.", r.id))
                if r.method != "POST":
                    issues.append(Issue("warning", "multipart-method", f"{sampler_names[r.id]}: multipart bodies with "
                                        f"{r.method} may not be sent by every JMeter HTTP implementation.", r.id))
            sp_tree = ET.SubElement(tc_tree, "hashTree")
            if r.headers:
                _header_manager(w, sp_tree, r.headers, "HTTP Header Manager")
            if p.think_ms:
                t = w.element(sp_tree, "ConstantTimer", "ConstantTimerGui", "ConstantTimer", "Think Time")
                w.prop(t, "stringProp", "ConstantTimer.delay", str(p.think_ms))
                ET.SubElement(sp_tree, "hashTree")
            for ex in p.extractors:
                _extractor(w, sp_tree, ex)

    if unusual_methods:
        issues.append(Issue("warning", "unusual-method", "Non-standard HTTP methods may not be supported by JMeter: "
                            + ", ".join(sorted(m[:20] for m in unusual_methods))))
    if w.stripped_control_chars:
        issues.append(Issue("warning", "control-chars", f"Removed control characters that XML cannot represent from "
                            f"{w.stripped_control_chars} value(s)."))
    ET.indent(root, space="  ")
    xml = ET.tostring(root, encoding="unicode", short_empty_elements=True)
    # XML parsers normalize raw CR characters; keep CRLF bodies intact with a character reference.
    xml = xml.replace("\r", "&#13;")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml + "\n", issues
