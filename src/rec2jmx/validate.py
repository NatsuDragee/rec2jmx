"""Validation of generated plans.

Levels:
1. ``structural_check`` - always run: XML well-formedness, hashTree pairing, required
   elements, unique controller/sampler names.
2. ``leak_check`` - always run when secrets are parameterized: no detected secret value
   may remain in the output.
3. ``jmeter_load_check`` - optional: JMeter loads and starts the plan with 0 threads.
4. ``jmeter_mock_run`` - optional: JMeter runs 1 thread x 1 loop against a local mock
   HTTP server on 127.0.0.1 and the received request sequence is compared.

JMeter is only invoked for plans that pass ``jmeter_safety_check``: every sampler server
must be a HOST_n/PORT_n/PROTOCOL_n property (which is overridden to 127.0.0.1), thread
counts must be property-driven, and no scripting/other samplers may be present. No
request is ever sent to a host from a recording.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

from .analysis.secrets import SecretFinding
from .errors import GenerationError, ValidationError
from .ir import Issue

JMETER_TIMEOUT_S = 300
_HOST_VAR = re.compile(r"^\$\{(HOST|PORT|PROTOCOL)_(\d+)\}$")


@dataclass
class ValidationReport:
    name: str
    ran: bool
    passed: bool
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "ran": self.ran, "passed": self.passed, "details": self.details}


def _pairs(tree: ET.Element):
    children = list(tree)
    i = 0
    while i < len(children):
        el = children[i]
        if el.tag == "hashTree":
            raise ValidationError("hashTree without a preceding element")
        if i + 1 >= len(children) or children[i + 1].tag != "hashTree":
            raise ValidationError(f"element <{el.tag}> '{el.get('testname', '')}' is not followed by a hashTree")
        yield el, children[i + 1]
        i += 2


def structural_check(xml_text: str) -> ValidationReport:
    rep = ValidationReport("structure", True, False)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        rep.details.append(f"XML is not well-formed: {exc}")
        return rep
    try:
        if root.tag != "jmeterTestPlan":
            raise ValidationError("root element is not jmeterTestPlan")
        top = root.find("hashTree")
        if top is None:
            raise ValidationError("missing top-level hashTree")
        counts: dict[str, int] = {}
        names: dict[str, int] = {}

        def walk(tree: ET.Element) -> None:
            for el, sub in _pairs(tree):
                counts[el.tag] = counts.get(el.tag, 0) + 1
                if el.tag in ("TransactionController", "HTTPSamplerProxy"):
                    n = el.get("testname", "")
                    names[n] = names.get(n, 0) + 1
                walk(sub)

        walk(top)
        for required in ("TestPlan", "ThreadGroup", "TransactionController", "HTTPSamplerProxy"):
            if not counts.get(required):
                raise ValidationError(f"no {required} element")
        dups = sorted(n for n, c in names.items() if c > 1)
        if dups:
            raise ValidationError("duplicate element names: " + ", ".join(dups[:5]))
        rep.passed = True
        rep.details.append(f"{counts['TransactionController']} transaction controller(s), "
                           f"{counts['HTTPSamplerProxy']} HTTP sampler(s); hashTree structure is consistent.")
    except ValidationError as exc:
        rep.details.append(str(exc))
    return rep


def leak_check(xml_text: str, findings: list[SecretFinding]) -> list[Issue]:
    """Raise if a parameterized secret (8+ chars) is still present; warn for shorter values."""
    issues = []
    for s in findings:
        forms = {s.value, escape(s.value), escape(s.value, {'"': "&quot;"})}
        if not any(f and f in xml_text for f in forms):
            continue
        if len(s.value) >= 8:
            raise GenerationError(f"Safety stop: secret {s.id} ({s.location()}) would still appear in the generated "
                                  "plan. Nothing was written. Please report this as a bug.")
        issues.append(Issue("warning", "short-secret-elsewhere",
                            f"A short value equal to secret {s.id} ({s.location()}) also appears elsewhere in the "
                            "plan; review it.", s.request_id))
    return issues


def find_jmeter(explicit: str | None = None) -> str | None:
    """Locate the JMeter launcher: explicit path, then $JMETER_HOME/bin, then PATH."""
    names = ["jmeter.bat", "jmeter.cmd", "jmeter"] if os.name == "nt" else ["jmeter", "jmeter.sh"]
    candidates = []
    if explicit:
        if os.path.isdir(explicit):
            candidates += [os.path.join(explicit, "bin", n) for n in names] + [os.path.join(explicit, n) for n in names]
        else:
            candidates.append(explicit)
    home = os.environ.get("JMETER_HOME")
    if home:
        candidates += [os.path.join(home, "bin", n) for n in names]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    return None


def jmeter_safety_check(xml_text: str) -> list[str]:
    """Return the host-variable indices to override. Raises ValidationError if running JMeter could be unsafe."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValidationError(f"not well-formed XML: {exc}") from None
    indices: set[str] = set()
    for el in root.iter():
        tag = el.tag
        if el.get("testclass") is None or el.get("enabled") == "false":
            continue
        if re.search(r"JSR223|BeanShell|OSProcess|JDBC|SystemSampler|Sampler", tag) and tag != "HTTPSamplerProxy":
            raise ValidationError(f"the plan contains <{tag}>; only HTTP samplers are allowed for JMeter validation")
        if tag.endswith("ThreadGroup") and tag != "ThreadGroup":
            raise ValidationError(f"the plan contains <{tag}>; only standard Thread Groups can be run safely")
        if tag == "ThreadGroup":
            props = {p.get("name"): (p.text or "") for p in el if p.tag == "stringProp"}
            if props.get("ThreadGroup.num_threads") != "${__P(threads,1)}":
                raise ValidationError("thread count is not property-driven (${__P(threads,1)}); refusing to run it")
        if tag == "HTTPSamplerProxy":
            props = {p.get("name"): (p.text or "") for p in el if p.tag == "stringProp"}
            name = el.get("testname", "")
            for key, kind in (("HTTPSampler.domain", "HOST"), ("HTTPSampler.port", "PORT"), ("HTTPSampler.protocol", "PROTOCOL")):
                m = _HOST_VAR.match(props.get(key, ""))
                if not m or m.group(1) != kind:
                    raise ValidationError(f"sampler '{name}' does not use a {kind}_n property for {key}; JMeter "
                                          "validation needs host parameterization so requests stay on 127.0.0.1")
                indices.add(m.group(2))
            if "://" in props.get("HTTPSampler.path", ""):
                raise ValidationError(f"sampler '{name}' has an absolute URL in its path")
            if props.get("HTTPSampler.embedded_url_re") or any(
                    p.get("name") == "HTTPSampler.image_parser" and (p.text or "") == "true" for p in el):
                raise ValidationError(f"sampler '{name}' retrieves embedded resources")
    return sorted(indices, key=int)


def _run_jmeter(jmeter: str, jmx_path: str, props: dict[str, str], workdir: str) -> tuple[int, str]:
    log = os.path.join(workdir, "jmeter.log")
    jtl = os.path.join(workdir, "results.jtl")
    cmd = [jmeter, "-n", "-t", jmx_path, "-l", jtl, "-j", log] + [f"-J{k}={v}" for k, v in props.items()]
    try:
        proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=JMETER_TIMEOUT_S,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise ValidationError(f"JMeter did not finish within {JMETER_TIMEOUT_S}s") from None
    except OSError as exc:
        raise ValidationError(f"could not start JMeter: {exc}") from None
    log_text = ""
    if os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as fh:
            log_text = fh.read()
    return proc.returncode, (proc.stdout or "") + "\n" + (proc.stderr or "") + "\n" + log_text


_LOAD_ERRORS = re.compile(r"Error in NonGUIDriver|CannotResolveClassException|ConversionException|"
                          r"Problem loading XML|Error loading|IllegalUserActionException|NoClassDefFoundError")


def jmeter_load_check(xml_text: str, jmeter: str) -> ValidationReport:
    rep = ValidationReport("jmeter-load", True, False)
    indices = jmeter_safety_check(xml_text)
    with tempfile.TemporaryDirectory(prefix="rec2jmx-") as tmp:
        path = os.path.join(tmp, "plan.jmx")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml_text)
        props = {"threads": "0", "loops": "1", "rampup": "0"}
        for i in indices:  # defence in depth: even if a thread started, it could only reach a closed local port
            props.update({f"HOST_{i}": "127.0.0.1", f"PORT_{i}": "9", f"PROTOCOL_{i}": "http"})
        code, output = _run_jmeter(jmeter, path, props, tmp)
    errors = [ln.strip()[:200] for ln in output.splitlines() if _LOAD_ERRORS.search(ln)]
    if code != 0 or errors:
        rep.details.append(f"JMeter exit code {code}")
        rep.details += errors[:5]
    else:
        rep.passed = True
        rep.details.append("JMeter loaded and started the plan with 0 threads (no requests sent).")
    return rep


class MockServer:
    """Local HTTP server on 127.0.0.1 that records requests. ``responder(method, path, headers, body)``
    returns (status, headers dict, body bytes)."""

    def __init__(self, responder=None):
        self.requests: list[dict] = []
        self._responder = responder or (lambda m, p, h, b: (200, {"Content-Type": "application/json"}, b"{}"))
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                rec = {"method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": body}
                outer.requests.append(rec)
                status, headers, payload = outer._responder(self.command, self.path, rec["headers"], body)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

            def log_message(self, *args) -> None:  # keep test output quiet; never log request contents
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "MockServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def expected_requests(xml_text: str) -> list[tuple[str, str]]:
    """(method, path-without-query) per HTTP sampler in document order."""
    root = ET.fromstring(xml_text)
    out = []
    for el in root.iter("HTTPSamplerProxy"):
        if el.get("enabled") == "false":
            continue
        props = {p.get("name"): (p.text or "") for p in el if p.tag == "stringProp"}
        out.append((props.get("HTTPSampler.method", "GET"), props.get("HTTPSampler.path", "/").split("?", 1)[0]))
    return out


def _path_matches(expected: str, actual: str) -> bool:
    pattern = "".join(".+?" if re.fullmatch(r"\$\{[^}]*\}", part) else re.escape(part)
                      for part in re.split(r"(\$\{[^}]*\})", expected))
    return re.fullmatch(pattern, actual) is not None


def jmeter_mock_run(xml_text: str, jmeter: str, responder=None, extra_props: dict[str, str] | None = None
                    ) -> tuple[ValidationReport, list[dict]]:
    rep = ValidationReport("jmeter-mock-run", True, False)
    indices = jmeter_safety_check(xml_text)
    expected = expected_requests(xml_text)
    with MockServer(responder) as server, tempfile.TemporaryDirectory(prefix="rec2jmx-") as tmp:
        path = os.path.join(tmp, "plan.jmx")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml_text)
        props = {"threads": "1", "loops": "1", "rampup": "0"}
        for i in indices:
            props.update({f"HOST_{i}": "127.0.0.1", f"PORT_{i}": str(server.port), f"PROTOCOL_{i}": "http"})
        props.update(extra_props or {})
        code, output = _run_jmeter(jmeter, path, props, tmp)
        received = list(server.requests)
    errors = [ln.strip()[:200] for ln in output.splitlines() if _LOAD_ERRORS.search(ln)]
    actual = [(r["method"], r["path"].split("?", 1)[0]) for r in received]
    if code != 0 or errors:
        rep.details.append(f"JMeter exit code {code}")
        rep.details += errors[:5]
    elif len(actual) != len(expected):
        rep.details.append(f"expected {len(expected)} request(s), the mock server received {len(actual)}")
    else:
        bad = [i for i, (e, a) in enumerate(zip(expected, actual)) if e[0] != a[0] or not _path_matches(e[1], a[1])]
        if bad:
            i = bad[0]
            rep.details.append(f"request {i + 1}: expected {expected[i][0]} {expected[i][1]}, got {actual[i][0]} {actual[i][1]}")
        else:
            rep.passed = True
            rep.details.append(f"JMeter sent all {len(actual)} request(s) to the local mock server in the expected "
                               "order with the expected methods and paths.")
    return rep, received
