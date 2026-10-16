import json

import pytest
from conftest import build

from rec2jmx import service
from rec2jmx.errors import PlanError
from rec2jmx.plan import Plan, PlanFlow, parse_think_time, plan_from_dict, reorder_flows


def test_plan_round_trip_through_json():
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = ["C02"]
    data = json.loads(json.dumps(service.preview(analysis, plan)["plan"]))
    assert "_requestIndex" in data
    again = plan_from_dict(data)
    assert again.to_dict() == plan.to_dict()


def test_user_edits_rename_split_and_exclude():
    analysis, plan = build("har/shop_flows.har")
    plan.flows = [PlanFlow("Open home", ["r0001"]), PlanFlow("Sign in", ["r0003", "r0004"]), PlanFlow("Buy", ["r0005", "r0006"])]
    report = service.preview(analysis, plan)
    assert [(f["txName"], [r["samplerName"] for r in f["requests"]]) for f in report["flows"]] == [
        ("TX_01_Open_home", ["TX_01_A01_root"]),
        ("TX_02_Sign_in", ["TX_02_A01_api_v1_login", "TX_02_A02_api_v1_users_id"]),
        ("TX_03_Buy", ["TX_03_A01_api_v1_orders", "TX_03_A02_api_v1_orders_id"]),
    ]
    assert "feedback" not in service.generate(analysis, plan).jmx


@pytest.mark.parametrize("mutate,msg", [
    (lambda p: setattr(p, "flows", []), "no flows"),
    (lambda p: p.flows[0].request_ids.append("r9999"), "unknown request id"),
    (lambda p: p.flows[1].request_ids.append("r0001"), "more than once"),
    (lambda p: setattr(p.flows[0], "name", " "), "has no name"),
    (lambda p: setattr(p.flows[0], "request_ids", []), "has no requests"),
    (lambda p: setattr(p, "accepted", ["C99"]), "Unknown suggestion"),
    (lambda p: setattr(p, "secret_policy", "print"), "secretPolicy"),
    (lambda p: setattr(p, "fingerprint", "sha256:other"), "different recording"),
])
def test_invalid_plans_are_rejected(mutate, msg):
    analysis, plan = build("har/shop_flows.har")
    mutate(plan)
    with pytest.raises(PlanError, match=msg):
        service.generate(analysis, plan)


def test_unresolved_suggestions_cannot_be_accepted():
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = ["C01"]
    analysis.suggestions[0].kind = "unresolved"
    with pytest.raises(PlanError, match="cannot be accepted"):
        service.generate(analysis, plan)


@pytest.mark.parametrize("data,msg", [
    ({}, "Not a rec2jmx plan"),
    ({"rec2jmxPlan": 1, "flows": {}}, "must be an array"),
    ({"rec2jmxPlan": 1, "flows": [{"name": 1, "requests": []}]}, "must be an object"),
    ({"rec2jmxPlan": 1, "flows": [], "acceptSuggestions": "C01"}, "acceptSuggestions"),
    ({"rec2jmxPlan": 1, "flows": [], "thinkTime": "soon"}, "Invalid think time"),
    ({"rec2jmxPlan": 1, "flows": [], "parameterizeHosts": "yes"}, "parameterizeHosts"),
])
def test_plan_json_validation(data, msg):
    with pytest.raises(PlanError, match=msg):
        plan_from_dict(data)


def test_reorder_requires_permutation():
    plan = Plan([PlanFlow("a", ["r1"]), PlanFlow("b", ["r2"])])
    with pytest.raises(PlanError, match="exactly once"):
        reorder_flows(plan, [1, 1])
    reorder_flows(plan, [2, 1])
    assert [f.name for f in plan.flows] == ["b", "a"]


def test_think_time_parsing():
    assert parse_think_time("Recorded") == "recorded" and parse_think_time(250) == "250"
    with pytest.raises(PlanError):
        parse_think_time("-5")


def test_correlation_skipped_when_flow_order_breaks_dependency():
    analysis, plan = build("har/shop_flows.har")
    token = next(s.id for s in analysis.suggestions if s.var_name == "C_token")
    plan.accepted = [token]
    reorder_flows(plan, [2, 1])  # checkout now runs before login
    result = service.generate(analysis, plan)
    skipped = [i for i in result.issues if i.code == "correlation-skipped"]
    assert skipped and "before its source" in skipped[0].message
    assert "C_token" not in result.jmx and "Bearer ${SECRET_Authorization}" in result.jmx


def test_correlation_skipped_when_source_excluded():
    analysis, plan = build("har/shop_flows.har")
    plan.accepted = [next(s.id for s in analysis.suggestions if s.var_name == "C_token")]
    plan.flows[0].request_ids.remove("r0003")
    result = service.generate(analysis, plan)
    assert any("not in the plan" in i.message for i in result.issues if i.code == "correlation-skipped")
