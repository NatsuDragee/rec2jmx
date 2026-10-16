import json
import xml.etree.ElementTree as ET

import pytest
from conftest import build, from_text

from rec2jmx import service
from rec2jmx.validate import structural_check

ALL_FIXTURES = ["har/shop_flows.har", "har/mobile_no_pages.har", "curl/commands.sh", "curl/cmd_style.txt",
                "jmx/legacy_plan.jmx", "postman/collection_v21.json", "native/recording.json"]


def gen(path, **plan_changes):
    analysis, plan = build(path)
    for k, v in plan_changes.items():
        setattr(plan, k, v)
    return service.generate(analysis, plan)


def samplers(jmx):
    root = ET.fromstring(jmx)
    out = []
    for el in root.iter("HTTPSamplerProxy"):
        props = {p.get("name"): p.text or "" for p in el if p.tag in ("stringProp", "boolProp")}
        args = []
        for ep in el.iter("elementProp"):
            if ep.get("elementType") == "HTTPArgument":
                ap = {p.get("name"): p.text or "" for p in ep}
                args.append((ap.get("Argument.name", ""), ap.get("Argument.value", ""), ap.get("HTTPArgument.always_encode")))
        out.append((el.get("testname"), props, args))
    return out


def sampler_headers(jmx, name):
    root = ET.fromstring(jmx)
    tree = list(root.iter("hashTree"))
    for parent in tree:
        kids = list(parent)
        for i, el in enumerate(kids):
            if el.tag == "HTTPSamplerProxy" and el.get("testname") == name:
                sub = kids[i + 1]
                return {h.find("stringProp[@name='Header.name']").text: h.find("stringProp[@name='Header.value']").text
                        for hm in sub.iter("HeaderManager") for h in hm.iter("elementProp")}
    raise AssertionError(name)


@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_every_fixture_generates_a_structurally_valid_plan(path):
    result = gen(path)
    assert structural_check(result.jmx).passed
    assert result.jmx.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<jmeterTestPlan')


@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_generation_is_deterministic(path):
    assert gen(path).jmx == gen(path).jmx


def test_request_order_and_fields_preserved():
    s = samplers(gen("har/shop_flows.har").jmx)
    assert [(n, p["HTTPSampler.method"], p["HTTPSampler.path"]) for n, p, _ in s] == [
        ("TX_01_A01_root", "GET", "/"),
        ("TX_01_A02_api_v1_login", "POST", "/api/v1/login"),
        ("TX_01_A03_api_v1_users_id", "GET", "/api/v1/users/42"),
        ("TX_02_A01_api_v1_orders", "POST", "/api/v1/orders?_=" + s[3][1]["HTTPSampler.path"].split("=")[1]),
        ("TX_02_A02_api_v1_orders_id", "GET", "/api/v1/orders/ord-20260115-0001"),
        ("TX_02_A03_api_v1_feedback", "POST", "/api/v1/feedback"),
    ]
    name, props, args = s[2]
    assert props["HTTPSampler.domain"] == "${HOST_2}" and args == [("include", "profile", "true")]
    _, props, args = s[1]
    assert props["HTTPSampler.postBodyRaw"] == "true"
    assert json.loads(args[0][1].replace("${SECRET_password}", "x"))["username"] == "test.user"
    _, props, args = s[5]  # form POST -> encoded arguments
    assert [(a[0], a[1]) for a in args] == [("rating", "5"), ("comment", "great service!"), ("api_key", "${SECRET_api_key}")]


def test_transaction_controllers_wrap_their_flows():
    root = ET.fromstring(gen("har/shop_flows.har").jmx)
    tg_tree = None
    for tree in root.iter("hashTree"):
        kids = list(tree)
        if any(k.tag == "TransactionController" for k in kids):
            tg_tree = kids
    tcs = [(k.get("testname"), [s.get("testname") for s in tg_tree[i + 1] if s.tag == "HTTPSamplerProxy"])
           for i, k in enumerate(tg_tree) if k.tag == "TransactionController"]
    assert tcs == [("TX_01_login", ["TX_01_A01_root", "TX_01_A02_api_v1_login", "TX_01_A03_api_v1_users_id"]),
                   ("TX_02_Checkout", ["TX_02_A01_api_v1_orders", "TX_02_A02_api_v1_orders_id", "TX_02_A03_api_v1_feedback"])]


def test_hosts_are_parameterized_with_recorded_defaults():
    jmx = gen("curl/commands.sh").jmx
    assert "${__P(HOST_1,api.example.test)}" in jmx and "${__P(PORT_2,8443)}" in jmx
    assert "${__P(threads,1)}" in jmx and "${__P(loops,1)}" in jmx
    hard = gen("curl/commands.sh", parameterize_hosts=False).jmx
    assert "HOST_1" not in hard and ">api.example.test<" in hard and ">8443<" in hard


def sampler_header_list(jmx, name):
    root = ET.fromstring(jmx)
    for parent in root.iter("hashTree"):
        kids = list(parent)
        for i, el in enumerate(kids):
            if el.tag == "HTTPSamplerProxy" and el.get("testname") == name:
                return [(h.find("stringProp[@name='Header.name']").text or "",
                         h.find("stringProp[@name='Header.value']").text or "")
                        for hm in kids[i + 1].iter("HeaderManager") for h in hm.iter("elementProp")]
    raise AssertionError(name)


def _sendable(headers):
    return [(h.name, h.value) for h in headers if not h.name.startswith(":") and h.name.lower() != "transfer-encoding"]


@pytest.mark.parametrize("policy", ["include", "parameterize"])
@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_every_recorded_header_is_kept_in_its_sampler(path, policy):
    analysis, plan = build(path)
    plan.secret_policy = policy
    result = service.generate(analysis, plan)
    by_id = analysis.recording.by_id()
    assert "HTTP Header Manager (common)" not in result.jmx
    checked = 0
    for nf in result.names:
        for s in nf.samplers:
            req = by_id[s.request_id]
            got = sampler_header_list(result.jmx, s.name)
            expected = _sendable(req.headers)
            if any(h.name.lower() == ":authority" for h in req.headers) and not any(n.lower() == "host" for n, _ in expected):
                expected = [("Host", "")] + expected
            assert [n for n, _ in got] == [n for n, _ in expected], s.name
            if policy == "include":
                for (n, v), (_, ev) in zip(got, expected):
                    if n.lower() == "host":
                        assert v.startswith("${HOST_") or v == ev, s.name
                    else:
                        assert v == ev, f"{s.name}: {n}"
            checked += 1
    assert checked == sum(len(f.request_ids) for f in plan.flows)


def test_tested_header_exceptions():
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "POST", "url": "https://a.example.test:8443/x", "body": {"text": "hi", "contentType": "text/plain"},
         "headers": [{"name": ":method", "value": "POST"}, {"name": ":authority", "value": "a.example.test:8443"},
                     {"name": ":path", "value": "/x"}, {"name": ":scheme", "value": "https"},
                     {"name": "Transfer-Encoding", "value": "chunked"}, {"name": "Content-Length", "value": "2"},
                     {"name": "Connection", "value": "keep-alive"}, {"name": "Accept-Encoding", "value": "gzip, br, zstd"},
                     {"name": "Cookie", "value": "a=1"}, {"name": "Expect", "value": "100-continue"},
                     {"name": "X-Empty", "value": None}]}]}
    analysis = service.analyze(from_text(json.dumps(doc), "r.json"))
    plan = service.default_plan(analysis)
    plan.secret_policy = "include"
    result = service.generate(analysis, plan)
    got = sampler_header_list(result.jmx, result.names[0].samplers[0].name)
    assert got == [("Host", "${HOST_1}:${PORT_1}"), ("Content-Length", "2"), ("Connection", "keep-alive"),
                   ("Accept-Encoding", "gzip, br, zstd"), ("Cookie", "a=1"), ("Expect", "100-continue"), ("X-Empty", "")]
    codes = {i.code for i in result.issues}
    assert {"http2-pseudo-headers", "transfer-encoding", "accept-encoding", "cookie-header"} <= codes
    hard = service.default_plan(analysis)
    hard.secret_policy, hard.parameterize_hosts = "include", False
    assert sampler_header_list(service.generate(analysis, hard).jmx, "TX_01_A01_x")[0] == ("Host", "a.example.test:8443")


def test_cookie_headers_are_secrets_when_parameterizing():
    analysis, plan = build("har/shop_flows.har")
    jmx = service.generate(analysis, plan).jmx
    assert ("Cookie", "${SECRET_Cookie}") in sampler_header_list(jmx, "TX_01_A02_api_v1_login")
    assert "old-session-cookie" not in jmx
    plan.secret_policy = "include"
    assert ("Cookie", "sid=old-session-cookie") in sampler_header_list(service.generate(analysis, plan).jmx,
                                                                       "TX_01_A02_api_v1_login")


def test_event_stream_requests_are_flagged():
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "GET", "url": "https://a.example.test/events", "headers": {"Accept": "text/event-stream"}}]}
    analysis = service.analyze(from_text(json.dumps(doc), "r.json"))
    assert [i.request_id for i in analysis.issues if i.code == "event-stream"] == ["r0001"]


def test_multipart_upload_and_file_dir():
    result = gen("curl/commands.sh")
    jmx = result.jmx
    assert "<boolProp name=\"HTTPSampler.DO_MULTIPART_POST\">true</boolProp>" in jmx
    assert "${FILE_DIR}/me.png" in jmx and "${__P(FILE_DIR,.)}" in jmx
    assert any(i.code == "file-upload" for i in result.issues)


def test_query_kept_in_path_when_body_present_and_encoded():
    rec = from_text("curl -X POST 'https://a.test/p?q=a%20b&flag' -H 'Content-Type: text/plain' --data-raw 'hello'")
    analysis = service.analyze(rec)
    s = samplers(service.generate(analysis, service.default_plan(analysis)).jmx)
    assert s[0][1]["HTTPSampler.path"] == "/p?q=a%20b&flag"


def test_non_post_form_bodies_are_sent_raw():
    rec = from_text("curl -X PUT https://a.test/p -d 'a=1&b=x y'")
    analysis = service.analyze(rec)
    _, props, args = samplers(service.generate(analysis, service.default_plan(analysis)).jmx)[0]
    assert props["HTTPSampler.postBodyRaw"] == "true" and args[0][1] == "a=1&b=x%20y"


def test_crlf_and_control_characters_survive_xml():
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "POST", "url": "https://a.test/x", "body": {"text": "line1\r\nline2\u0001end", "contentType": "text/plain"}}]}
    analysis = service.analyze(from_text(json.dumps(doc), "r.json"))
    result = service.generate(analysis, service.default_plan(analysis))
    body = samplers(result.jmx)[0][2][0][1]
    assert body == "line1\r\nline2end"
    assert any(i.code == "control-chars" for i in result.issues)


def test_think_time_modes():
    recorded = gen("har/shop_flows.har", think_time="recorded").jmx
    root = ET.fromstring(recorded)
    delays = [int(t.find("stringProp").text) for t in root.iter("ConstantTimer")]
    assert delays == [950, 950, 1450, 450]  # gaps within flows only; not before a flow's first request
    constant = ET.fromstring(gen("har/shop_flows.har", think_time="750").jmx)
    assert [t.find("stringProp").text for t in constant.iter("ConstantTimer")] == ["750"] * 5
    assert "ConstantTimer" not in gen("har/shop_flows.har").jmx


def test_imported_and_unknown_variables_are_declared():
    result = gen("jmx/legacy_plan.jmx")
    jmx = result.jmx
    assert "${__P(apiVersion,v2)}" in jmx
    assert "${__P(authToken,)}" in jmx and any(i.code == "undefined-variable" for i in result.issues)
    postman = gen("postman/collection_v21.json").jmx
    assert "${__P(gatewayUrl,)}" in postman and "${__P(clientId,)}" in postman
    assert ">${gatewayUrl}/health<" in postman  # unresolved origin kept in the path


def test_correlation_extractors_attach_to_source_sampler():
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = [s.id for s in analysis.suggestions if s.acceptable]
    result = service.generate(analysis, plan)
    jmx = result.jmx
    assert jmx.count("<JSONPostProcessor") == 3 and jmx.count("<BoundaryExtractor") == 2
    assert '"cartId": "${C_cartId}"' in jmx and "/api/v1/orders/${C_orderId}" in jmx
    assert set(result.report["generation"]["appliedSuggestions"]) == {s.id for s in analysis.suggestions if s.acceptable}
