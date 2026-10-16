import json

from conftest import build, from_text

from rec2jmx import service
from rec2jmx.analysis.grouping import GroupingSettings, flow_name_from_hint


def by_var(analysis):
    return {s.var_name: s for s in analysis.suggestions if s.kind == "correlation"}


def test_correlations_found_with_sources_and_extractors():
    analysis, _ = build("har/shop_flows.har")
    c = by_var(analysis)
    assert set(c) == {"C_csrf", "C_token", "C_X_Session_Token", "C_cartId", "C_orderId"}
    assert c["C_token"].source_request_id == "r0003" and c["C_token"].extractor == {"type": "json", "expression": "$.token"}
    assert [u.request_id for u in c["C_token"].usages] == ["r0004", "r0005", "r0006"]
    assert c["C_csrf"].extractor["type"] == "boundary" and c["C_csrf"].extractor["scope"] == "body"
    assert c["C_X_Session_Token"].extractor == {"type": "boundary", "scope": "headers", "left": "X-Session-Token: ", "right": "\n"}
    assert c["C_orderId"].usages[0].location == "path"


def test_suggestions_are_not_applied_by_default():
    analysis, plan = build("har/shop_flows.har")
    jmx = service.generate(analysis, plan).jmx
    assert "JSONPostProcessor" not in jmx and "BoundaryExtractor" not in jmx and "__time" not in jmx
    assert "cart-5521-aa90" in jmx  # recorded value kept until the user accepts the suggestion


def test_timestamp_suggestion():
    analysis, plan = build("har/shop_flows.har")
    ts = [s for s in analysis.suggestions if s.kind == "timestamp"]
    assert len(ts) == 1 and ts[0].replacement == "${__time()}" and ts[0].usages[0].location == "query '_'"
    plan.accepted = [ts[0].id]
    assert "/api/v1/orders?_=${__time()}" in service.generate(analysis, plan).jmx


def test_unresolved_dynamic_values_are_reported_but_not_acceptable():
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "POST", "url": "https://a.test/form", "body": {"form": [{"name": "csrf_token", "value": "zz9988776655"}]}}]}
    analysis = service.analyze(from_text(json.dumps(doc), "r.json"))
    s = analysis.suggestions[0]
    assert s.kind == "unresolved" and not s.acceptable


def test_values_from_earlier_requests_are_not_correlated():
    # The value is sent by the client before the server ever returns it: not a correlation.
    doc = {"format": "rec2jmx-recording", "version": 1, "requests": [
        {"method": "POST", "url": "https://a.test/a", "body": {"json": {"ref": "client-ref-123456"}},
         "response": {"status": 200, "body": "{\"ref\": \"client-ref-123456\"}"}},
        {"method": "GET", "url": "https://a.test/b?ref=client-ref-123456"}]}
    analysis = service.analyze(from_text(json.dumps(doc), "r.json"))
    assert not [s for s in analysis.suggestions if s.kind == "correlation"]


def test_recorded_grouping_from_pages():
    analysis, _ = build("har/shop_flows.har")
    assert [(f.name, f.basis, f.request_ids) for f in analysis.flows] == [
        ("login", "recorded", ["r0001", "r0003", "r0004"]),
        ("Checkout", "recorded", ["r0005", "r0006", "r0007"]),
    ]
    assert analysis.excluded == {"r0002": "static resource (type 'image')"}


def test_time_gap_grouping_is_flagged_heuristic():
    analysis, _ = build("har/mobile_no_pages.har")
    assert [(f.basis, f.request_ids) for f in analysis.flows] == [("time-gap", ["r0001", "r0002"]), ("time-gap", ["r0003", "r0004"])]
    assert any(i.code == "heuristic-grouping" for i in analysis.issues)
    single, _ = build("har/mobile_no_pages.har", GroupingSettings(group_by="single"))
    assert len(single.flows) == 1


def test_static_and_host_filters():
    analysis, _ = build("har/shop_flows.har", GroupingSettings(include_static=True))
    assert not analysis.excluded
    analysis, _ = build("har/shop_flows.har", GroupingSettings(exclude_hosts=["shop.*"]))
    assert set(analysis.excluded) == {"r0001", "r0002"}
    analysis, _ = build("har/shop_flows.har", GroupingSettings(include_hosts=["shop.example.test"], include_static=True))
    assert [r.id for r in analysis.included] == ["r0001", "r0002"]


def test_everything_filtered_out_is_an_error_issue():
    analysis, _ = build("har/shop_flows.har", GroupingSettings(include_hosts=["nothing.test"]))
    assert not analysis.flows and analysis.issues[0].code == "no-requests"


def test_flow_names_from_hints():
    assert flow_name_from_hint("https://shop.test/") == "Home"
    assert flow_name_from_hint("https://shop.test/en-gb/product/macbook") == "product_macbook"
    assert flow_name_from_hint("https://shop.test/index.php?route=checkout/cart") == "index.php_checkout_cart"
    assert flow_name_from_hint("Checkout") == "Checkout"


def test_formats_without_responses_say_so():
    analysis, _ = build("curl/commands.sh")
    assert any(i.code == "no-responses" for i in analysis.issues)
