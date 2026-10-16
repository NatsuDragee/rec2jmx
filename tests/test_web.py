import base64
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest
from conftest import FIXTURE_SECRETS, fixture

from rec2jmx.web.server import make_handler


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(5 * 1024 * 1024))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    hdrs = {"Content-Type": "application/json"} if data is not None else {}
    hdrs.update(headers or {})
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), payload


def upload(path):
    with open(fixture(path), "rb") as fh:
        return {"filename": path.split("/")[-1], "content": base64.b64encode(fh.read()).decode()}


def test_static_page_has_security_headers_and_mobile_notice(server):
    status, headers, body = request(server, "GET", "/")
    assert status == 200 and "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert b"does not replay Android/iOS" in body and b"<script src=\"/app.js\">" in body
    assert request(server, "GET", "/app.js")[0] == 200
    assert request(server, "GET", "/../pyproject.toml")[0] == 404


def test_inspect_then_generate_with_edited_plan(server):
    status, _, body = request(server, "POST", "/api/inspect", upload("har/shop_flows.har"))
    report = json.loads(body)
    assert status == 200 and report["source"]["format"] == "har"
    assert [f["txName"] for f in report["flows"]] == ["TX_01_login", "TX_02_Checkout"]
    plan = report["plan"]
    plan["flows"].reverse()
    plan["acceptSuggestions"] = ["C02"]
    status, _, body = request(server, "POST", "/api/inspect", dict(upload("har/shop_flows.har"), plan=plan))
    assert [f["txName"] for f in json.loads(body)["flows"]] == ["TX_01_Checkout", "TX_02_login"]
    plan["flows"].reverse()
    status, _, body = request(server, "POST", "/api/generate", dict(upload("har/shop_flows.har"), plan=plan))
    out = json.loads(body)
    assert status == 200 and out["filename"] == "shop_flows.jmx"
    assert "Bearer ${C_token}" in out["jmx"]
    assert out["report"]["generation"]["validations"][0]["passed"] is True
    for secret in FIXTURE_SECRETS:
        assert secret not in body.decode()


def test_errors_are_user_facing(server):
    status, _, body = request(server, "POST", "/api/inspect", upload("har/malformed.har"))
    assert status == 400 and "malformed" in json.loads(body)["error"]
    status, _, body = request(server, "POST", "/api/inspect", {"filename": "a", "content": "%%%"})
    assert status == 400 and "base64" in json.loads(body)["error"]
    status, _, body = request(server, "POST", "/api/inspect", dict(upload("har/shop_flows.har"), plan={"rec2jmxPlan": 1, "flows": []}))
    assert status == 400 and "no flows" in json.loads(body)["error"]
    status, _, _ = request(server, "POST", "/api/inspect", b"not json")
    assert status == 400


def test_rejects_foreign_host_origin_and_content_type(server):
    assert request(server, "GET", "/", headers={"Host": "evil.test"})[0] == 403  # DNS rebinding
    assert request(server, "POST", "/api/inspect", upload("curl/cmd_style.txt"),
                   headers={"Origin": "http://evil.test"})[0] == 403
    status, _, _ = request(server, "POST", "/api/inspect", b"{}", headers={"Content-Type": "text/plain"})
    assert status == 415


def test_rejects_oversized_bodies_before_reading_them(server):
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=30)
    conn.putrequest("POST", "/api/inspect")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(500 * 1024 * 1024))
    conn.endheaders()  # no body is sent: the server must reject from the declared length alone
    assert conn.getresponse().status == 413
    conn.close()


def test_request_detail_shows_recorded_and_generated_headers(server):
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "POST", "url": "https://a.example.test/x", "body": {"text": "{\"password\":\"pw-123456789\"}", "contentType": "application/json"},
         "headers": [{"name": ":authority", "value": "a.example.test"}, {"name": ":method", "value": "POST"},
                     {"name": "Transfer-Encoding", "value": "chunked"}, {"name": "Authorization", "value": "Bearer tok-1234567890"},
                     {"name": "Accept", "value": "*/*"}]},
        {"method": "GET", "url": "https://a.example.test/y"}]}
    body = {"filename": "r.json", "content": base64.b64encode(json.dumps(doc).encode()).decode()}
    report = json.loads(request(server, "POST", "/api/inspect", body)[2])
    assert {r["id"]: r["host"] for r in report["requestIndex"]} == {"r0001": "a.example.test", "r0002": "a.example.test"}
    plan = dict(report["plan"], secretPolicy="include")
    status, _, raw = request(server, "POST", "/api/request", dict(body, plan=plan, requestId="r0001"))
    d = json.loads(raw)
    assert status == 200 and d["samplerName"] == "TX_01_A01_x" and d["sampler"]["method"] == "POST"
    rows = {h["name"]: (h["status"], h["jmx"], h["sensitive"]) for h in d["headers"]}
    assert rows[":authority"][0] == "mapped" and rows[":method"][0] == "mapped"
    assert rows["Transfer-Encoding"][0] == "dropped"
    assert rows["Authorization"] == ("kept", "Bearer tok-1234567890", True)
    assert rows["Accept"] == ("kept", "*/*", False)
    assert rows["Host"] == ("added", "${HOST_1}", False)  # created from :authority, bound to HOST_1
    assert d["body"]["sensitive"] is True
    # Parameterized: the header is still there, with the variable.
    plan["secretPolicy"] = "parameterize"
    d = json.loads(request(server, "POST", "/api/request", dict(body, plan=plan, requestId="r0001"))[2])
    assert {h["name"]: h["jmx"] for h in d["headers"]}["Authorization"] == "Bearer ${SECRET_Authorization}"
    # A request left out of the plan has no sampler.
    plan["flows"][0]["requests"] = ["r0001"]
    d = json.loads(request(server, "POST", "/api/request", dict(body, plan=plan, requestId="r0002"))[2])
    assert d["samplerName"] is None and d["sampler"] is None
    status, _, raw = request(server, "POST", "/api/request", dict(body, plan=plan, requestId="r9999"))
    assert status == 400 and "Unknown request id" in json.loads(raw)["error"]


def test_generate_returns_summary_and_host_categories(server):
    status, _, raw = request(server, "POST", "/api/generate", upload("har/shop_flows.har"))
    out = json.loads(raw)
    s = out["summary"]
    assert status == 200 and s["samplers"] == 6 and [t["name"] for t in s["transactions"]] == ["TX_01_login", "TX_02_Checkout"]
    assert s["extractors"] == 0 and "HOST_1" in s["variables"] and s["bytes"] == len(out["jmx"].encode())
    from rec2jmx.analysis.hosts import classify_host
    assert classify_host("www.google-analytics.com") == "analytics" and classify_host("bam.nr-data.net") == "monitoring"
    assert classify_host("api-cdn.mec1.pure.cloud") == "chat/support" and classify_host("api.example.test") is None
    assert classify_host("evilgoogle-analytics.com") is None
