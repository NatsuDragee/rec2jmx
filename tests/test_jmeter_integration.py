"""Validation with a real Apache JMeter install. Skipped when JMeter is not found.

Requests only ever go to a mock server on 127.0.0.1: every sampler's host, port and
protocol are JMeter properties that the validator overrides.
"""

import json

import pytest
from conftest import build

from rec2jmx import service
from rec2jmx.errors import ValidationError
from rec2jmx.validate import jmeter_load_check, jmeter_mock_run, jmeter_safety_check

pytestmark = pytest.mark.jmeter

LOADABLE = ["har/shop_flows.har", "har/mobile_no_pages.har", "curl/commands.sh", "curl/cmd_style.txt",
            "jmx/legacy_plan.jmx", "native/recording.json"]


@pytest.mark.parametrize("path", LOADABLE)
def test_jmeter_loads_generated_plans(jmeter, path):
    analysis, plan = build(path)
    plan.accepted = [s.id for s in analysis.suggestions if s.acceptable]
    plan.think_time = "recorded"
    report = jmeter_load_check(service.generate(analysis, plan).jmx, jmeter)
    assert report.passed, report.details


def test_jmeter_load_check_detects_broken_plans(jmeter):
    analysis, plan = build("curl/cmd_style.txt")
    jmx = service.generate(analysis, plan).jmx
    broken = jmx.replace('testclass="CookieManager"', 'testclass="NoSuchElement"').replace(
        "<CookieManager ", "<NoSuchElement ").replace("</CookieManager>", "</NoSuchElement>")
    report = jmeter_load_check(broken, jmeter)
    assert not report.passed and any("NoSuchElement" in d or "NonGUIDriver" in d for d in report.details)


def test_mock_run_exercises_every_correlation_with_fresh_values(jmeter):
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = [s.id for s in analysis.suggestions if s.acceptable]
    jmx = service.generate(analysis, plan).jmx

    def responder(method, path, headers, body):
        if path == "/":
            return 200, {"Content-Type": "text/html"}, b'<input type="hidden" name="csrf" value="FRESH-CSRF-1">'
        if path.startswith("/api/v1/login"):
            return 200, {"Content-Type": "application/json", "X-Session-Token": "FRESH-SESSION-2"}, \
                json.dumps({"token": "FRESH-JWT-3", "user": {"id": 42}}).encode()
        if path.startswith("/api/v1/users"):
            return 200, {"Content-Type": "application/json"}, b'{"cartId": "FRESH-CART-4"}'
        if path.startswith("/api/v1/orders") and method == "POST":
            return 201, {"Content-Type": "application/json"}, b'{"orderId": "FRESH-ORDER-5"}'
        return 200, {"Content-Type": "application/json"}, b"{}"

    report, received = jmeter_mock_run(jmx, jmeter, responder, {"SECRET_password": "pw-cli", "SECRET_api_key": "key-cli",
                                                                 "SECRET_Cookie": "sid=from-cli"})
    assert report.passed, report.details
    login, user, order, order_get, feedback = received[1:]
    assert json.loads(login["body"]) == {"username": "test.user", "password": "pw-cli", "csrf": "FRESH-CSRF-1"}
    assert user["headers"]["Authorization"] == "Bearer FRESH-JWT-3"
    assert order["headers"]["X-Session-Token"] == "FRESH-SESSION-2"
    assert json.loads(order["body"])["cartId"] == "FRESH-CART-4"
    assert order["path"].startswith("/api/v1/orders?_=") and order["path"] != "/api/v1/orders?_=1768471211000"
    assert order_get["path"] == "/api/v1/orders/FRESH-ORDER-5"
    assert feedback["body"] == b"rating=5&comment=great+service%21&api_key=key-cli"
    assert login["headers"]["Cookie"] == "sid=from-cli"  # recorded Cookie header kept (parameterized)


def test_mock_run_multipart_and_basic_auth(jmeter, tmp_path):
    (tmp_path / "me.png").write_bytes(b"\x89PNG fake")
    analysis, plan = build("curl/commands.sh")
    jmx = service.generate(analysis, plan).jmx
    report, received = jmeter_mock_run(jmx, jmeter, extra_props={
        "FILE_DIR": str(tmp_path).replace("\\", "/"), "SECRET_Authorization_2": "dTpw"})
    assert report.passed, report.details
    upload = received[3]
    assert upload["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="me.png"' in upload["body"] and b"\x89PNG fake" in upload["body"]
    assert received[4]["headers"]["Authorization"] == "Basic dTpw"
    assert received[2]["method"] == "DELETE"


def test_safety_check_refuses_plans_that_could_reach_real_hosts():
    analysis, plan = build("curl/commands.sh")
    plan.parameterize_hosts = False
    with pytest.raises(ValidationError, match="HOST_n"):
        jmeter_safety_check(service.generate(analysis, plan).jmx)
    analysis, plan = build("postman/collection_v21.json")  # {{gatewayUrl}} origin cannot be forced to localhost
    with pytest.raises(ValidationError, match="TX_03_A01_health"):
        jmeter_safety_check(service.generate(analysis, plan).jmx)
    with open(__file__.replace("test_jmeter_integration.py", "fixtures/jmx/legacy_plan.jmx"), encoding="utf-8") as fh:
        with pytest.raises(ValidationError):
            jmeter_safety_check(fh.read())


HEADER_FIXTURES = ["har/shop_flows.har", "har/mobile_no_pages.har", "curl/commands.sh", "curl/cmd_style.txt",
                   "jmx/legacy_plan.jmx", "native/recording.json"]


@pytest.mark.parametrize("path", HEADER_FIXTURES)
def test_every_recorded_header_reaches_the_server(jmeter, path, tmp_path):
    """With recorded values included, every sendable recorded header arrives with its recorded value."""
    (tmp_path / "me.png").write_bytes(b"png")
    analysis, plan = build(path)
    plan.secret_policy = "include"
    jmx = service.generate(analysis, plan).jmx
    report, received = jmeter_mock_run(jmx, jmeter, extra_props={"FILE_DIR": str(tmp_path).replace("\\", "/")})
    assert report.passed, report.details
    by_id = analysis.recording.by_id()
    order = plan.execution_order()
    assert len(received) == len(order)
    for rid, got in zip(order, received):
        req = by_id[rid]
        sent = {k.lower(): v for k, v in got["headers"].items()}
        for h in req.headers:
            name = h.name.lower()
            if name.startswith(":") or name == "transfer-encoding":
                continue  # the two tested exceptions
            assert name in sent, f"{rid}: header {h.name} was not sent"
            if name == "host":
                continue  # validation points every host at 127.0.0.1
            if name == "content-length" or (name == "content-type" and req.body.kind == "multipart"):
                continue  # JMeter computes these for the body it actually sends
            assert sent[name] == h.value, f"{rid}: header {h.name} changed"
