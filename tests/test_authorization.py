"""Regression tests: the Authorization request header is never removed, in any import mode."""

import json

import pytest
from conftest import build, from_text
from test_generator import sampler_header_list

from rec2jmx import service
from rec2jmx.validate import jmeter_mock_run

TOKEN = "Bearer test-auth-token-0123456789"
JMX = """<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree>
<TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="t"/><hashTree>
<ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="tg"/><hashTree>
<HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="s">
<stringProp name="HTTPSampler.domain">api.example.test</stringProp><stringProp name="HTTPSampler.protocol">https</stringProp>
<stringProp name="HTTPSampler.path">/me</stringProp><stringProp name="HTTPSampler.method">GET</stringProp>
</HTTPSamplerProxy><hashTree>
<HeaderManager guiclass="HeaderPanel" testclass="HeaderManager" testname="h"><collectionProp name="HeaderManager.headers">
<elementProp name="" elementType="Header"><stringProp name="Header.name">Authorization</stringProp>
<stringProp name="Header.value">%s</stringProp></elementProp></collectionProp></HeaderManager><hashTree/>
</hashTree></hashTree></hashTree></hashTree></jmeterTestPlan>""" % TOKEN

INPUTS = {
    "har": (json.dumps({"log": {"version": "1.2", "entries": [{"request": {
        "method": "GET", "url": "https://api.example.test/me", "headers": [{"name": "Authorization", "value": TOKEN}]}}]}}),
        "a.har", TOKEN),
    "curl -H": (f"curl https://api.example.test/me -H 'Authorization: {TOKEN}'", "a.sh", TOKEN),
    "curl -u": ("curl -u user:pass https://api.example.test/me", "a.sh", "Basic dXNlcjpwYXNz"),
    "curl --oauth2-bearer": ("curl --oauth2-bearer test-auth-token-0123456789 https://api.example.test/me", "a.sh", TOKEN),
    "jmx": (JMX, "a.jmx", TOKEN),
    "postman bearer": (json.dumps({"info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                                   "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "test-auth-token-0123456789"}]},
                                   "item": [{"name": "me", "request": {"method": "GET", "url": "https://api.example.test/me"}}]}),
                       "c.json", TOKEN),
    "postman header": (json.dumps({"info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                                   "item": [{"name": "me", "request": {"method": "GET", "url": "https://api.example.test/me",
                                                                       "header": [{"key": "Authorization", "value": TOKEN}]}}]}),
                       "c.json", TOKEN),
    "rec2jmx json": (json.dumps({"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "GET", "url": "https://api.example.test/me", "headers": {"Authorization": TOKEN}}]}), "r.json", TOKEN),
}


def _generate(text, filename, policy):
    analysis = service.analyze(from_text(text, filename))
    plan = service.default_plan(analysis)
    plan.secret_policy = policy
    result = service.generate(analysis, plan)
    return result, result.names[0].samplers[0].name


@pytest.mark.parametrize("mode", list(INPUTS))
def test_authorization_kept_as_recorded(mode):
    text, filename, expected = INPUTS[mode]
    result, sampler = _generate(text, filename, "include")
    assert ("Authorization", expected) in sampler_header_list(result.jmx, sampler)


@pytest.mark.parametrize("mode", list(INPUTS))
def test_authorization_still_sent_when_parameterized(mode):
    text, filename, expected = INPUTS[mode]
    result, sampler = _generate(text, filename, "parameterize")
    headers = dict(sampler_header_list(result.jmx, sampler))
    scheme = expected.split(" ", 1)[0]
    assert headers["Authorization"].startswith(scheme + " ${SECRET_Authorization")


def test_authorization_kept_when_its_token_is_correlated():
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = [s.id for s in analysis.suggestions if s.var_name == "C_token"]
    jmx = service.generate(analysis, plan).jmx
    assert ("Authorization", "Bearer ${C_token}") in sampler_header_list(jmx, "TX_01_A03_api_v1_users_id")


def test_sanitized_har_export_is_reported():
    entries = [{"request": {"method": "GET", "url": f"https://a.example.test/{i}", "headers": [{"name": "Accept", "value": "*/*"}]}}
               for i in range(3)]
    rec = from_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), "x.har")
    msg = next(i.message for i in rec.issues if i.code == "har-sanitized")
    assert "Export HAR (with sensitive data)" in msg
    assert not any(i.code == "har-sanitized" for i in build("har/shop_flows.har")[0].recording.issues)


@pytest.mark.jmeter
@pytest.mark.parametrize("mode", list(INPUTS))
def test_authorization_reaches_the_server(jmeter, mode):
    text, filename, expected = INPUTS[mode]
    result, _ = _generate(text, filename, "include")
    report, received = jmeter_mock_run(result.jmx, jmeter)
    assert report.passed, report.details
    assert received[0]["headers"]["Authorization"] == expected
