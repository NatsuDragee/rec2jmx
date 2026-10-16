"""JMeter .jmx importer (re-standardize existing plans).

Converted: HTTP Request samplers, HTTP Header Managers (with JMeter scoping and
nearest-wins merging), HTTP Request Defaults (server fields), User Defined Variables,
and Transaction Controllers (as flow names). Everything else is reported.

Security: documents containing a DOCTYPE or ENTITY declaration are rejected before
parsing (JMeter never writes them), which rules out XXE and entity-expansion attacks.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from ..errors import InputError
from ..ir import Body, FormField, Issue, NameValue, QueryParam
from .common import ParseResult, SplitUrl, build_body, header_get, new_request, split_url

_SAMPLER_TAGS = {"HTTPSamplerProxy", "HTTPSampler", "HTTPSampler2"}
_THREAD_GROUP_TAGS = {"ThreadGroup", "SetupThreadGroup", "PostThreadGroup",
                      "kg.apc.jmeter.threads.UltimateThreadGroup", "com.blazemeter.jmeter.threads.concurrency.ConcurrencyThreadGroup",
                      "com.blazemeter.jmeter.threads.arrivals.ArrivalsThreadGroup"}
_PASS_THROUGH = {"GenericController", "RecordingController", "CriticalSectionController", "TestFragmentController"}
_LOGIC_CONTROLLERS = {"IfController", "WhileController", "LoopController", "ForeachController", "OnlyOnceController",
                      "RandomOrderController", "RandomController", "InterleaveControl", "ThroughputController",
                      "RunTime", "SwitchController"}
_NOT_FOLLOWED = {"ModuleController", "IncludeController"}
_BODY_METHODS = {"POST", "PUT", "PATCH"}
_VAR_RE = re.compile(r"\$\{([A-Za-z_][\w.-]*)\}")
_PROP_FN_RE = re.compile(r"^\$\{__(?:P|property)\(\s*([^,()]+?)\s*(?:,\s*([^()]*?)\s*)?(?:,\s*)?\)\}$")


@dataclass
class _Scope:
    headers: list[NameValue] = field(default_factory=list)
    defaults: dict[str, str] = field(default_factory=dict)


@dataclass
class _State:
    variables: dict[str, str] = field(default_factory=dict)
    unconverted: Counter = field(default_factory=Counter)
    flattened: Counter = field(default_factory=Counter)
    disabled: int = 0
    issues: list[Issue] = field(default_factory=list)
    requests: list = field(default_factory=list)


def _reject_dtd(text: str) -> None:
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise InputError("JMX: documents with DOCTYPE or ENTITY declarations are rejected for safety "
                         "(JMeter does not write them).")


def _props(el: ET.Element) -> dict[str, str]:
    out = {}
    for child in el:
        if child.tag in ("stringProp", "boolProp", "intProp", "longProp", "doubleProp", "floatProp"):
            name = child.get("name")
            if name:
                out[name] = child.text or ""
    return out


def _element_prop(el: ET.Element, name: str) -> ET.Element | None:
    for child in el:
        if child.tag == "elementProp" and child.get("name") == name:
            return child
    return None


def _collection_items(el: ET.Element | None, name: str) -> list[dict[str, str]]:
    if el is None:
        return []
    for child in el:
        if child.tag == "collectionProp" and child.get("name") == name:
            return [_props(item) for item in child if item.tag == "elementProp"]
    return []


def _pairs(tree: ET.Element | None):
    if tree is None:
        return []
    children = list(tree)
    out, i = [], 0
    while i < len(children):
        el = children[i]
        if el.tag == "hashTree":
            i += 1
            continue
        sub = children[i + 1] if i + 1 < len(children) and children[i + 1].tag == "hashTree" else None
        out.append((el, sub))
        i += 2 if sub is not None else 1
    return out


def _enabled(el: ET.Element) -> bool:
    return el.get("enabled", "true").lower() != "false"


def _merge_headers(base: list[NameValue], extra: list[NameValue]) -> list[NameValue]:
    names = {h.name.lower() for h in extra}
    return [h for h in base if h.name.lower() not in names] + extra


def _header_manager(el: ET.Element) -> list[NameValue]:
    return [NameValue(p.get("Header.name", ""), p.get("Header.value", ""))
            for p in _collection_items(el, "HeaderManager.headers") if p.get("Header.name")]


def _collect_variables(el: ET.Element, state: _State) -> None:
    for p in _collection_items(el, "Arguments.arguments"):
        name = p.get("Argument.name")
        if name:
            state.variables[name] = p.get("Argument.value", "")


def _resolve(value: str, state: _State, depth: int = 0) -> str:
    """Resolve ${VAR} and ${__P(name,default)} using User Defined Variables (for server fields)."""
    if depth > 5 or "${" not in value:
        return value
    m = _PROP_FN_RE.match(value.strip())
    if m:
        return _resolve(m.group(2) or "", state, depth + 1)

    def repl(mm: re.Match) -> str:
        name = mm.group(1)
        if name in state.variables:
            return _resolve(state.variables[name], state, depth + 1)
        return mm.group(0)

    return _VAR_RE.sub(repl, value)


def _scope_config(pairs, scope: _Scope, state: _State) -> _Scope:
    """JMeter applies config elements to every sampler in their parent's subtree."""
    headers, defaults = list(scope.headers), dict(scope.defaults)
    for el, _sub in pairs:
        if not _enabled(el):
            continue
        if el.tag == "HeaderManager":
            headers = _merge_headers(headers, _header_manager(el))
        elif el.tag == "ConfigTestElement" and el.get("guiclass") == "HttpDefaultsGui":
            p = _props(el)
            for key in ("HTTPSampler.domain", "HTTPSampler.port", "HTTPSampler.protocol"):
                if p.get(key):
                    defaults[key] = p[key]
    return _Scope(headers, defaults)


def _sampler(el: ET.Element, sub: ET.Element | None, scope: _Scope, hint: str | None, state: _State) -> None:
    name = (el.get("testname") or "HTTP Request")[:80]
    where = f"JMX sampler '{name}'"
    p = _props(el)
    local_headers = scope.headers
    for child, child_sub in _pairs(sub):
        if not _enabled(child):
            state.disabled += 1
        elif child.tag == "HeaderManager":
            local_headers = _merge_headers(local_headers, _header_manager(child))
        else:
            state.unconverted[child.tag] += 1

    def field_value(key: str) -> str:
        return p.get(key) or scope.defaults.get(key, "")

    method = (p.get("HTTPSampler.method") or "GET").upper()
    raw_path = p.get("HTTPSampler.path", "") or "/"
    protocol = _resolve(field_value("HTTPSampler.protocol"), state) or "http"
    domain = _resolve(field_value("HTTPSampler.domain"), state)
    port_s = _resolve(field_value("HTTPSampler.port"), state)
    try:
        if re.match(r"^https?://", raw_path, re.IGNORECASE):
            parts = split_url(raw_path)
        else:
            if not domain:
                state.issues.append(Issue("warning", "jmx-no-server", f"{where}: no server name (and no HTTP Request "
                                          "Defaults); sampler skipped."))
                return
            path, _, query = raw_path.partition("?")
            port = None
            if port_s and "${" not in port_s:
                if not port_s.isdigit():
                    raise ValueError("invalid port")
                port = int(port_s)
            if "${" in domain or "${" in protocol or (port_s and "${" in port_s):
                state.issues.append(Issue("warning", "jmx-unresolved-server",
                                          f"{where}: server fields use variables that could not be resolved; they "
                                          "are kept verbatim and host parameterization is not applied."))
            parts = SplitUrl(protocol.lower() if "${" not in protocol else protocol, domain if "${" in domain else domain.lower(),
                             port, path if path.startswith(("/", "$")) else "/" + path, query, False)
    except ValueError as exc:
        state.issues.append(Issue("warning", "jmx-bad-url", f"{where}: {exc}; sampler skipped."))
        return
    if parts.scheme not in ("http", "https") and "${" not in parts.scheme:
        state.issues.append(Issue("warning", "jmx-bad-url", f"{where}: unsupported protocol; sampler skipped."))
        return

    args = []
    for a in _collection_items(_element_prop(el, "HTTPsampler.Arguments"), "Arguments.arguments"):
        value = a.get("Argument.value", "")
        aname = a.get("Argument.name", "")
        encoded = a.get("HTTPArgument.always_encode", "false").lower() == "true"
        if not encoded and "%" in value + aname:
            value, aname = unquote_plus(value), unquote_plus(aname)
        args.append((aname, value, a.get("HTTPArgument.use_equals", "true").lower() != "false"))
    files = [fp for fp in _collection_items(_element_prop(el, "HTTPsampler.Files"), "HTTPFileArgs.files")]
    raw_body = p.get("HTTPSampler.postBodyRaw", "false").lower() == "true"
    multipart = p.get("HTTPSampler.DO_MULTIPART_POST", "false").lower() == "true" or bool(files)

    req = new_request(method, parts, headers=list(local_headers), group_hint=hint, source_ref=where)
    ctype = header_get(local_headers, "content-type")
    if raw_body:
        req.body = build_body("".join(a[1] for a in args), ctype)
        if req.body.kind == "none":
            req.body = Body("none")
    elif multipart:
        fields = [FormField(n, v) for n, v, _ in args]
        for fp in files:
            path = fp.get("File.path", "")
            fields.append(FormField(fp.get("File.paramname", "file"), "", re.split(r"[\\/]", path)[-1] or "upload.bin",
                                    fp.get("File.mimetype") or None))
        req.body = Body("multipart", fields=fields)
        if files:
            state.issues.append(Issue("warning", "jmx-file-upload", f"{where}: file upload paths are replaced with "
                                      "${FILE_DIR}/<name>; place the files there before running."))
    elif method in _BODY_METHODS and args:
        req.body = Body("form", content_type=ctype or "application/x-www-form-urlencoded",
                        fields=[FormField(n, v) for n, v, _ in args])
    else:
        req.query.extend(QueryParam(n, v, eq) for n, v, eq in args)
    state.requests.append(req)


def _walk(tree: ET.Element | None, scope: _Scope, hint: str | None, state: _State) -> None:
    pairs = _pairs(tree)
    scope = _scope_config(pairs, scope, state)
    for el, sub in pairs:
        tag = el.tag
        if not _enabled(el):
            state.disabled += 1
            continue
        if tag in _SAMPLER_TAGS:
            _sampler(el, sub, scope, hint, state)
        elif tag == "TransactionController":
            _walk(sub, scope, el.get("testname") or "Transaction", state)
        elif tag in _THREAD_GROUP_TAGS:
            _walk(sub, scope, el.get("testname") or "Thread Group", state)
        elif tag == "TestPlan":  # its variables were collected up front in parse_jmx
            _walk(sub, scope, hint, state)
        elif tag in _PASS_THROUGH:
            _walk(sub, scope, hint, state)
        elif tag in _LOGIC_CONTROLLERS:
            state.flattened[tag] += 1
            _walk(sub, scope, hint, state)
        elif tag in ("HeaderManager",) or (tag == "ConfigTestElement" and el.get("guiclass") == "HttpDefaultsGui"):
            continue  # applied by _scope_config
        elif tag == "Arguments":
            continue  # collected up front
        elif tag in _NOT_FOLLOWED:
            state.issues.append(Issue("warning", "jmx-module", f"JMX: {tag} '{(el.get('testname') or '')[:60]}' "
                                      "references other elements/files and was not followed."))
        else:
            state.unconverted[tag] += 1


def _collect_all_udvs(root: ET.Element, state: _State) -> None:
    # UDVs are evaluated before any thread starts, wherever they sit in the tree.
    for el in root.iter("Arguments"):
        if el.get("testclass") == "Arguments" and _enabled(el):
            _collect_variables(el, state)


def parse_jmx(text: str, doc=None) -> ParseResult:
    _reject_dtd(text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise InputError(f"JMX: the XML is not well-formed ({exc}).") from None
    if root.tag != "jmeterTestPlan":
        raise InputError("JMX: the root element is not <jmeterTestPlan>.")
    state = _State()
    for tp in root.iter("TestPlan"):
        ep = _element_prop(tp, "TestPlan.user_defined_variables")
        if ep is not None:
            _collect_variables(ep, state)
    _collect_all_udvs(root, state)
    _walk(root.find("hashTree"), _Scope(), None, state)
    if not state.requests:
        raise InputError("JMX: no enabled HTTP Request samplers were found.")
    issues = list(state.issues)
    if state.unconverted:
        listing = ", ".join(f"{tag} x{n}" for tag, n in sorted(state.unconverted.items()))
        issues.append(Issue("warning", "jmx-unconverted",
                            f"Not converted from the JMX: {listing}. Extractors, assertions, timers and scripts must be "
                            "re-added (or use rec2jmx correlation suggestions where recordings allow)."))
    if state.flattened:
        listing = ", ".join(f"{tag} x{n}" for tag, n in sorted(state.flattened.items()))
        issues.append(Issue("warning", "jmx-logic-flattened",
                            f"Logic controllers were flattened (children imported once, in order): {listing}."))
    if state.disabled:
        issues.append(Issue("info", "jmx-disabled", f"Skipped {state.disabled} disabled element(s)."))
    variables = {k: v for k, v in state.variables.items()}
    return ParseResult(state.requests, issues, variables=variables, grouping_source="JMX Transaction Controllers / Thread Groups")
