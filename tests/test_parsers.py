import json

import pytest
from conftest import from_text, load

from rec2jmx.errors import InputError
from rec2jmx.parsers.common import parse_pairs, split_url

# ---------------------------------------------------------------- common


def test_split_url_keeps_variables_and_ports():
    u = split_url("https://User:Pw@API.Example.test:8443/a/b?x=1#frag")
    assert (u.scheme, u.host, u.port, u.path, u.raw_query, u.had_userinfo) == ("https", "api.example.test", 8443, "/a/b", "x=1", True)
    assert split_url("http://${Server}/x").host == "${Server}"
    assert split_url("http://[::1]:8080").host == "[::1]"
    for bad in ("ftp://x.test/", "https://", "https://h.test:99999/", "no-scheme.test/x"):
        with pytest.raises(ValueError):
            split_url(bad)


def test_parse_pairs_preserves_order_flags_and_decoding():
    params = parse_pairs("b=2&a=hello+world&flag&e=%26")
    assert [(p.name, p.value, p.has_equals) for p in params] == [
        ("b", "2", True), ("a", "hello world", True), ("flag", "", False), ("e", "&", True)]

# ---------------------------------------------------------------- HAR


def test_har_parses_into_ir_preserving_order_and_fields():
    rec = load("har/shop_flows.har")
    assert [r.method for r in rec.requests] == ["GET", "GET", "POST", "GET", "POST", "GET", "POST"]
    assert [r.id for r in rec.requests] == [f"r{i:04d}" for i in range(1, 8)]
    login = rec.requests[2]
    assert (login.scheme, login.host, login.path) == ("https", "api.example.test", "/api/v1/login")
    assert login.body.kind == "raw" and json.loads(login.body.text)["username"] == "test.user"
    assert login.response.status == 200 and "token" in login.response.body_text
    assert login.group_hint == "https://shop.example.test/login"
    assert login.duration_ms == 50 and login.started_at is not None
    user = rec.requests[3]
    assert [(q.name, q.value) for q in user.query] == [("include", "profile")]
    feedback = rec.requests[6]
    assert feedback.body.kind == "form"
    assert [(f.name, f.value) for f in feedback.body.fields][:2] == [("rating", "5"), ("comment", "great service!")]
    assert rec.grouping_source == "HAR pages (pageref)"


def test_har_reports_skipped_entries():
    codes = {i.code for i in load("har/shop_flows.har").issues}
    assert {"websocket-skipped", "non-http-skipped"} <= codes


@pytest.mark.parametrize("path,msg", [
    ("har/malformed.har", "malformed"),
    ("har/empty_entries.har", "empty"),
])
def test_har_malformed(path, msg):
    with pytest.raises(InputError, match=msg):
        load(path)


def test_har_entry_level_problems_are_warnings_not_crashes():
    doc = {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": "https://ok.test/a", "headers": []}},
        {"request": {"url": "https://ok.test/b"}},
        "not an object",
        {"request": {"method": "GET", "url": "https://ok.test/c", "headers": "bad"}},
    ]}}
    rec = from_text(json.dumps(doc), "x.har")
    assert [r.path for r in rec.requests] == ["/a"]
    assert sum(1 for i in rec.issues if i.code == "entry-skipped") == 3


def test_har_with_only_unusable_entries_fails():
    doc = {"log": {"version": "1.2", "entries": [{"request": {"method": "GET", "url": "data:text/plain,hi"}}]}}
    with pytest.raises(InputError, match="no usable"):
        from_text(json.dumps(doc), "x.har")


def test_har_multipart_params_and_base64_response():
    doc = {"log": {"version": "1.2", "entries": [{
        "request": {"method": "POST", "url": "https://u.test/up", "headers": [],
                    "postData": {"mimeType": "multipart/form-data; boundary=xyz",
                                 "params": [{"name": "title", "value": "t"}, {"name": "f", "fileName": "a.png", "contentType": "image/png"}]}},
        "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "encoding": "base64",
                                                                "text": "eyJpZCI6ICJhYmMxMjM0NTY3OCJ9"}}}]}}
    r = from_text(json.dumps(doc), "x.har").requests[0]
    assert r.body.kind == "multipart"
    assert [(f.name, f.is_file) for f in r.body.fields] == [("title", False), ("f", True)]
    assert r.response.body_text == '{"id": "abc12345678"}'

# ---------------------------------------------------------------- cURL


def test_curl_bash_commands_into_ir():
    rec = load("curl/commands.sh")
    reqs = rec.requests
    assert [r.method for r in reqs] == ["POST", "GET", "DELETE", "POST", "POST"]
    assert [r.group_hint for r in reqs] == ["Login", "Browse catalog", "Browse catalog", "Upload avatar", "Upload avatar"]
    assert json.loads(reqs[0].body.text)["password"] == "Sup3rS3cret!"
    assert reqs[1].header("Authorization") == "Bearer tok_live_ABCDEF1234567890"
    assert [(q.name, q.value) for q in reqs[1].query] == [("category", "books"), ("page", "2")]
    assert reqs[2].header("X-Note") == "line\tone"  # $'...' ANSI-C quoting
    assert reqs[3].body.kind == "multipart"
    assert reqs[3].body.fields[1].file_name == "me.png" and reqs[3].body.fields[1].content_type == "image/png"
    legacy = reqs[4]
    assert (legacy.port, legacy.path) == (8443, "/form.php")
    assert legacy.header("Authorization").startswith("Basic ")
    assert [(f.name, f.value) for f in legacy.body.fields] == [("a", "1"), ("b", "two words")]


def test_curl_windows_cmd_syntax():
    r = load("curl/cmd_style.txt").requests[0]
    assert r.method == "POST"
    assert [(q.name, q.value) for q in r.query] == [("q", "red"), ("size", "10")]
    assert json.loads(r.body.text) == {"term": "red shoes"}
    assert r.header("content-type") == "application/json"


@pytest.mark.parametrize("path,msg", [("curl/unterminated.sh", "unterminated"), ("curl/pipe.sh", "shell operator")])
def test_curl_malformed(path, msg):
    with pytest.raises(InputError, match=msg):
        load(path)


@pytest.mark.parametrize("text,msg", [
    ("curl -H 'A: b'", "no URL"),
    ("curl https://a.test -d x -F y=1", "cannot be combined"),
    ("curl https://a.test\nwget https://b.test", "expected a command starting with 'curl'"),
    ("curl https://a.test -X", "requires a value"),
])
def test_curl_invalid_commands(text, msg):
    with pytest.raises(InputError, match=msg):
        from_text(text)


def test_curl_options_and_warnings():
    rec = from_text("curl -G https://a.test/s -d q=1 --data-urlencode 'name=a b' -d @body.json --frobnicate -k -L")
    r = rec.requests[0]
    assert r.method == "GET" and [(q.name, q.value) for q in r.query] == [("q", "1"), ("name", "a b")]
    codes = [i.code for i in rec.issues]
    assert "curl-file-ref" in codes and "curl-unknown-option" in codes and "curl-ignored-options" in codes


def test_curl_url_without_scheme_and_combined_flags():
    rec = from_text("curl -sXPUT api.test/x --json '{\"a\":1}'")
    r = rec.requests[0]
    assert (r.method, r.scheme, r.host) == ("PUT", "http", "api.test")
    assert r.header("Content-Type") == "application/json"
    assert any(i.code == "curl-no-scheme" for i in rec.issues)

# ---------------------------------------------------------------- JMX


def test_jmx_import_into_ir():
    rec = load("jmx/legacy_plan.jmx")
    login, accounts, logout = rec.requests
    assert (login.host, login.scheme, login.path, login.method) == ("legacy.example.test", "https", "/${apiVersion}/session", "POST")
    assert login.body.kind == "raw" and "${password}" in login.body.text
    # Header Manager scoping: sampler-level Accept overrides the global one.
    assert login.header("Accept") == "application/vnd.legacy+json" and login.header("Content-Type") == "application/json"
    assert accounts.header("Accept") == "application/json"
    assert [(q.name, q.value) for q in accounts.query] == [("limit", "50"), ("auth", "${authToken}")]
    assert (logout.host, logout.port, logout.body.kind) == ("auth.example.test", 8443, "form")
    assert [r.group_hint for r in rec.requests] == ["Sign in", "Users", "Users"]
    assert rec.variables["apiVersion"] == "v2"


def test_jmx_reports_unconverted_and_flattened_elements():
    msgs = {i.code: i.message for i in load("jmx/legacy_plan.jmx").issues}
    assert "RegexExtractor x1" in msgs["jmx-unconverted"] and "JSR223Sampler x1" in msgs["jmx-unconverted"]
    assert "IfController x1" in msgs["jmx-logic-flattened"]
    assert "jmx-disabled" in msgs


def test_jmx_rejects_doctype_and_entities():
    with pytest.raises(InputError, match="DOCTYPE or ENTITY"):
        load("jmx/xxe.jmx")


def test_jmx_malformed_and_empty():
    with pytest.raises(InputError, match="not well-formed"):
        load("jmx/malformed.jmx")
    with pytest.raises(InputError, match="no enabled HTTP Request samplers"):
        from_text('<jmeterTestPlan version="1.2"><hashTree/></jmeterTestPlan>', "a.jmx")

# ---------------------------------------------------------------- Postman


def test_postman_into_ir():
    rec = load("postman/collection_v21.json")
    login, search, gql, upload, health = rec.requests
    assert (login.method, login.host, login.path) == ("POST", "api.example.test", "/v3/auth/login")
    assert login.header("Authorization") is None  # noauth overrides collection bearer
    assert login.header("X-Client") == "${clientId}" and login.header("X-Old") is None
    assert [(f.name, f.value) for f in login.body.fields] == [("username", "test.user"), ("password", "pw-Example-42")]
    assert search.header("Authorization") == "Bearer pm-token-0123456789abcdef"  # inherited collection auth
    assert dict((q.name, q.value) for q in search.query)["rid"] == "${__UUID()}"
    assert json.loads(gql.body.text) == {"query": "query { product(id: 1) { name } }", "variables": {"a": 1}}
    assert upload.header("X-Api-Key") == "ak-99887766554433"
    assert upload.body.kind == "multipart" and upload.body.fields[1].file_name == "lamp.jpg"
    assert health.unresolved_origin == "${gatewayUrl}" and health.path == "/health"
    assert [r.group_hint for r in rec.requests] == ["Auth", "Catalog", "Catalog", "Catalog", "Example Store API"]
    codes = {i.code for i in rec.issues}
    assert {"postman-scripts", "postman-unknown-vars", "postman-unresolved-origin", "postman-file"} <= codes


def test_postman_v1_and_empty_rejected():
    with pytest.raises(InputError, match="v2.0 and v2.1"):
        load("postman/collection_v1.json")
    empty = {"info": {"name": "x", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}
    with pytest.raises(InputError, match="no requests"):
        from_text(json.dumps(empty), "c.json")

# ---------------------------------------------------------------- rec2jmx JSON


def test_native_json_into_ir():
    rec = load("native/recording.json")
    boot, order, feedback = rec.requests
    assert boot.header("User-Agent").startswith("ExampleApp") and boot.response.status == 200
    assert '"nonce"' in boot.response.body_text  # object bodies are serialized for analysis
    assert json.loads(order.body.text) == {"sku": "SKU-9", "qty": 1}
    assert [(f.name, f.value) for f in feedback.body.fields] == [("stars", "4"), ("text", "fast & easy")]
    assert [r.group_hint for r in rec.requests] == ["Launch", "Place order", "Place order"]


@pytest.mark.parametrize("path,msg", [
    ("native/missing_url.json", r"requests\[0\]\.url: required"),
    ("native/wrong_version.json", "unsupported version 7"),
])
def test_native_json_invalid(path, msg):
    with pytest.raises(InputError, match=msg):
        load(path)


@pytest.mark.parametrize("doc,msg", [
    ({"flows": [], "requests": []}, "exactly one"),
    ({"requests": [{"method": "GET", "url": "https://a.test", "body": {"text": "a", "json": 1}}]}, "exactly one of 'text'"),
    ({"requests": [{"method": "GET", "url": "https://a.test", "durationMs": -1}]}, "non-negative"),
    ({"requests": [{"method": "GET", "url": "https://a.test", "startedAt": "yesterday"}]}, "ISO-8601"),
    ({"requests": [{"method": "GET", "url": "https://a.test", "headers": [{"value": "x"}]}]}, "headers"),
])
def test_native_json_field_validation(doc, msg):
    doc = {"format": "rec2jmx-recording", "version": 1, **doc}
    with pytest.raises(InputError, match=msg):
        from_text(json.dumps(doc), "r.json")
