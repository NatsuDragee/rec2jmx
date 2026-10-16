import pytest
from conftest import build

from rec2jmx import service
from rec2jmx.naming import assign_names, path_label, sanitize_flow_name
from rec2jmx.plan import reorder_flows


def names(flows, secrets=frozenset()):
    return [(nf.tx_name, [s.name for s in nf.samplers]) for nf in assign_names(flows, secrets)]


def test_spec_examples():
    flows = [("Login", [("r1", "/users"), ("r2", "/users/{id}")]), ("Checkout", [("r3", "/orders")])]
    assert names(flows) == [
        ("TX_01_Login", ["TX_01_A01_users", "TX_01_A02_users_id"]),
        ("TX_02_Checkout", ["TX_02_A01_orders"]),
    ]


def test_transaction_numbers_increment_and_api_numbers_reset_per_flow():
    flows = [(f"F{t}", [(f"r{t}{a}", f"/p{a}") for a in range(1, 4)]) for t in range(1, 4)]
    result = names(flows)
    assert [tx for tx, _ in result] == ["TX_01_F1", "TX_02_F2", "TX_03_F3"]
    for t, (_, samplers) in enumerate(result, start=1):
        assert samplers == [f"TX_{t:02d}_A{a:02d}_p{a}" for a in range(1, 4)]


def test_numbering_widens_for_100_plus_items():
    flows = [("Big", [(f"r{i}", "/x") for i in range(120)])]
    _, samplers = names(flows)[0]
    assert samplers[0] == "TX_01_A001_x" and samplers[-1] == "TX_01_A120_x"


def test_names_are_stable_for_same_order():
    flows = [("Login", [("r1", "/a/b"), ("r2", "/c")]), ("Pay", [("r3", "/d")])]
    assert names(flows) == names(list(flows))


@pytest.mark.parametrize("path,label", [
    ("/", "root"),
    ("", "root"),
    ("/users/{id}", "users_id"),
    ("/users/:userId/orders", "users_userId_orders"),
    ("/api/${apiVersion}/session", "api_apiVersion_session"),
    ("/users/12345", "users_id"),
    ("/orders/0b9f1a3e-2c4d-4e5f-8a9b-1c2d3e4f5a6b/items", "orders_id_items"),
    ("/files/5f2b8c9d0e1f2a3b4c5d", "files_id"),
    ("/en-gb/product/macbook", "en_gb_product_macbook"),
    ("/index.php", "index_php"),
    ("/search?q=secret-token&page=2", "search"),  # query strings are never part of names
    ("/a%20b/c%2Fd", "a_b_c_d"),
    ("/reports/2026-01-15", "reports_id"),
    ("/t/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "t_id"),
    ("${baseUrl}/health", "health"),
])
def test_path_normalization(path, label):
    assert path_label(path) == label


def test_known_secret_values_never_appear_in_names():
    assert path_label("/reset/hunter2pass/confirm", {"hunter2pass"}) == "reset_id_confirm"


def test_long_paths_are_truncated_at_segment_boundary():
    label = path_label("/" + "/".join(f"segment{c}" for c in "abcdefghijkl"))
    assert len(label) <= 60 and label.endswith("segmentl") and not label.startswith("_")


def test_flow_name_sanitizing():
    assert sanitize_flow_name("Add to Cart / Step 2!") == "Add_to_Cart_Step_2"
    assert sanitize_flow_name("   ") == "Flow"
    assert len(sanitize_flow_name("x" * 100)) == 40


def test_duplicate_flow_names_and_paths_stay_distinct():
    flows = [("Login", [("r1", "/users"), ("r2", "/users"), ("r3", "/users/1")]), ("Login", [("r4", "/users")])]
    result = names(flows)
    all_names = [result[0][0], result[1][0]] + result[0][1] + result[1][1]
    assert len(all_names) == len(set(all_names))
    assert result[0][1] == ["TX_01_A01_users", "TX_01_A02_users", "TX_01_A03_users_id"]
    assert result[1][0] == "TX_02_Login"


def test_flow_order_controls_transaction_numbers_in_preview():
    analysis, plan = build("har/shop_flows.har")
    before = [f["txName"] for f in service.preview(analysis, plan)["flows"]]
    assert before == ["TX_01_login", "TX_02_Checkout"]
    reorder_flows(plan, [2, 1])
    after = service.preview(analysis, plan)["flows"]
    assert [f["txName"] for f in after] == ["TX_01_Checkout", "TX_02_login"]
    assert [r["samplerName"] for r in after[0]["requests"]] == [
        "TX_01_A01_api_v1_orders", "TX_01_A02_api_v1_orders_id", "TX_01_A03_api_v1_feedback"]


def test_generated_plan_uses_preview_names_exactly():
    analysis, plan = build("har/shop_flows.har")
    preview_names = [r["samplerName"] for f in service.preview(analysis, plan)["flows"] for r in f["requests"]]
    jmx = service.generate(analysis, plan).jmx
    positions = [jmx.index(f'testname="{n}"') for n in preview_names]
    assert positions == sorted(positions)  # same names, same order
