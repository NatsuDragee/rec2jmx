"""Local web UI (stdlib only).

* Binds to 127.0.0.1 only. Requests whose Host/Origin is not this local server are
  rejected (DNS-rebinding / CSRF protection); POSTs must be application/json.
* Stateless: the browser keeps the uploaded file and resends it with each call. The
  server stores nothing on disk and does not log request contents.
* /api/request returns recorded values (including secrets) for the request detail view,
  because the user is inspecting their own local file; the UI masks sensitive values
  until the user reveals them. Reports from /api/inspect never contain secret values.
* The page uses no inline script, a strict Content-Security-Policy, and renders all
  recording-derived text with textContent.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .. import service
from ..analysis.grouping import GroupingSettings
from ..detect import DEFAULT_MAX_BYTES
from ..errors import PlanError, Rec2JmxError
from ..loader import load_bytes
from ..plan import plan_from_dict
from ..validate import find_jmeter, jmeter_load_check, jmeter_mock_run

_STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
           "/app.js": ("app.js", "text/javascript; charset=utf-8"),
           "/style.css": ("style.css", "text/css; charset=utf-8")}
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _settings(raw) -> GroupingSettings:
    raw = raw if isinstance(raw, dict) else {}

    def str_list(v):
        if isinstance(v, str):
            v = [x.strip() for x in v.split(",")]
        return [x for x in v if isinstance(x, str) and x] if isinstance(v, list) else []

    group_by = raw.get("groupBy", "auto")
    if group_by not in ("auto", "recorded", "gap", "single"):
        raise PlanError("groupBy must be auto, recorded, gap, or single.")
    try:
        gap = float(raw.get("gapSeconds", 5.0))
    except (TypeError, ValueError):
        raise PlanError("gapSeconds must be a number.") from None
    return GroupingSettings(group_by, gap, bool(raw.get("includeStatic", False)),
                            str_list(raw.get("includeHosts", [])), str_list(raw.get("excludeHosts", [])))


def make_handler(max_bytes: int):
    max_body = int(max_bytes * 1.4) + 1_000_000  # base64 overhead + JSON envelope

    class Handler(BaseHTTPRequestHandler):
        server_version = "rec2jmx"
        sys_version = ""

        def _allowed_hosts(self) -> set[str]:
            port = self.server.server_address[1]
            return {f"127.0.0.1:{port}", f"localhost:{port}"}

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            if self.headers.get("Host", "") not in self._allowed_hosts():
                self._json(403, {"error": "Requests must use http://127.0.0.1 or http://localhost on this port."})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin.split("://", 1)[-1] not in self._allowed_hosts():
                self._json(403, {"error": "Cross-origin requests are not allowed."})
                return False
            return True

        def do_GET(self) -> None:
            if not self._host_ok():
                return
            path = self.path.split("?", 1)[0]
            if path not in _STATIC:
                self._json(404, {"error": "Not found"})
                return
            name, ctype = _STATIC[path]
            data = resources.files("rec2jmx.web").joinpath("static", name).read_bytes()
            self._send(200, data, ctype)

        def do_POST(self) -> None:
            if not self._host_ok():
                return
            if not (self.headers.get("Content-Type", "").split(";")[0].strip() == "application/json"):
                self._json(415, {"error": "Content-Type must be application/json."})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length <= 0 or length > max_body:
                self._json(413, {"error": f"Request body missing or larger than the {max_bytes:,}-byte input limit."})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise PlanError("Request must be a JSON object.")
                if self.path == "/api/inspect":
                    self._json(200, self._inspect(payload))
                elif self.path == "/api/generate":
                    self._json(200, self._generate(payload))
                elif self.path == "/api/request":
                    self._json(200, self._request_detail(payload))
                else:
                    self._json(404, {"error": "Not found"})
            except json.JSONDecodeError:
                self._json(400, {"error": "Request body is not valid JSON."})
            except Rec2JmxError as exc:
                self._json(400, {"error": str(exc)})
            except Exception:  # report without echoing request data
                traceback.print_exc(file=sys.stderr)
                self._json(500, {"error": "Internal error while processing the recording (details are in the server console)."})

        def _analysis(self, payload):
            content = payload.get("content")
            if not isinstance(content, str):
                raise PlanError("Missing file content.")
            try:
                data = base64.b64decode(content, validate=True)
            except (binascii.Error, ValueError):
                raise PlanError("File content is not valid base64.") from None
            filename = payload.get("filename") if isinstance(payload.get("filename"), str) else ""
            forced = payload.get("format") or None
            rec = load_bytes(data, filename, forced, max_bytes)
            analysis = service.analyze(rec, _settings(payload.get("settings")))
            plan = plan_from_dict(payload["plan"]) if payload.get("plan") else service.default_plan(analysis)
            return analysis, plan

        def _inspect(self, payload):
            analysis, plan = self._analysis(payload)
            return service.preview(analysis, plan)

        def _request_detail(self, payload):
            analysis, plan = self._analysis(payload)
            rid = payload.get("requestId")
            if not isinstance(rid, str):
                raise PlanError("Missing requestId.")
            return service.request_detail(analysis, plan, rid)

        def _generate(self, payload):
            analysis, plan = self._analysis(payload)
            result = service.generate(analysis, plan)
            reports = list(result.validations)
            notes = []
            if payload.get("validateJmeter") or payload.get("validateMock"):
                jmeter = find_jmeter()
                if not jmeter:
                    notes.append("JMeter validation was requested but JMeter was not found (set JMETER_HOME).")
                else:
                    try:
                        if payload.get("validateJmeter"):
                            reports.append(jmeter_load_check(result.jmx, jmeter))
                        if payload.get("validateMock"):
                            reports.append(jmeter_mock_run(result.jmx, jmeter)[0])
                    except Rec2JmxError as exc:
                        notes.append(f"JMeter validation did not run: {exc}")
            result.report["generation"]["validations"] = [r.to_dict() for r in reports]
            result.report["generation"]["notes"] = notes
            base = (analysis.recording.source_name.rsplit(".", 1)[0] or "plan")
            return {"jmx": result.jmx, "filename": base + ".jmx", "report": result.report,
                    "summary": service.jmx_summary(result.jmx)}

        def log_message(self, fmt, *args) -> None:  # method + path only; never bodies
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?", 1)[0]))

    return Handler


def serve(port: int = 8765, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(max_bytes))
    print(f"rec2jmx web UI on http://127.0.0.1:{httpd.server_address[1]}/  (Ctrl+C to stop)")
    print("Uploaded recordings stay in your browser and in memory only; nothing is written to disk.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
