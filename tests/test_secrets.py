import json

import pytest
from conftest import FIXTURE_SECRETS, build, from_text

from rec2jmx import service
from rec2jmx.analysis.secrets import detect_secrets, is_sensitive_name
from rec2jmx.errors import GenerationError
from rec2jmx.validate import leak_check

ALL_FIXTURES = ["har/shop_flows.har", "har/mobile_no_pages.har", "curl/commands.sh", "jmx/legacy_plan.jmx",
                "postman/collection_v21.json", "native/recording.json"]


@pytest.mark.parametrize("name,expected", [
    ("password", True), ("user_password", True), ("access_token", True), ("apiKey", True), ("X-Api-Key", True),
    ("client_secret", True), ("pin", True), ("sid", True),
    ("csrf_token", False), ("X-CSRF-Token", False), ("token_type", False), ("username", False), ("page", False),
])
def test_sensitive_names(name, expected):
    assert is_sensitive_name(name) is expected


@pytest.mark.parametrize("path", ALL_FIXTURES)
def test_no_fixture_secret_in_generated_plan_or_report(path):
    analysis, plan = build(path)
    result = service.generate(analysis, plan)
    blob = result.jmx + json.dumps(result.report)
    for secret in FIXTURE_SECRETS:
        assert secret not in blob, f"{secret[:6]}... leaked"


def test_secrets_become_runtime_properties():
    analysis, plan = build("har/shop_flows.har")
    jmx = service.generate(analysis, plan).jmx
    assert '"password": "${SECRET_password}"' in jmx
    assert "Bearer ${SECRET_Authorization}" in jmx
    assert "api_key=${SECRET_api_key}" in jmx or ">${SECRET_api_key}<" in jmx
    assert "${__P(SECRET_password,)}" in jmx  # empty default, value supplied with -J


def test_correlated_token_replaces_secret_variable():
    analysis, plan = build("har/shop_flows.har")
    token = next(s.id for s in analysis.suggestions if s.var_name == "C_token")
    plan.accepted = [token]
    jmx = service.generate(analysis, plan).jmx
    assert "Bearer ${C_token}" in jmx
    assert "SECRET_Authorization" not in jmx  # unused secret variables are not declared


def test_include_policy_keeps_values_and_warns():
    analysis, plan = build("curl/commands.sh")
    plan.secret_policy = "include"
    result = service.generate(analysis, plan)
    assert "Sup3rS3cret!" in result.jmx
    assert any(i.code == "secrets-included" for i in result.issues)


def test_source_variable_secret_has_empty_default():
    analysis, plan = build("jmx/legacy_plan.jmx")
    jmx = service.generate(analysis, plan).jmx
    assert "${__P(password,)}" in jmx and "legacyPassw0rd" not in jmx


def test_value_patterns_detected_anywhere():
    text = "curl https://a.test/p -H 'X-Custom: AKIAABCDEFGHIJKLMNOP' -d 'note=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.sig12'"
    rec = from_text(text)
    reasons = {(s.kind, s.reason) for s in detect_secrets(rec)}
    assert ("header", "value looks like a AWS access key") in reasons
    assert any(kind == "form" and "JWT" in reason for kind, reason in reasons)


def test_same_value_shares_one_variable():
    analysis, _ = build("har/shop_flows.har")
    auth = {s.var_name for s in analysis.secrets if s.field == "Authorization"}
    assert auth == {"SECRET_Authorization"}


def test_preview_masks_secret_query_values():
    rec = from_text("curl 'https://a.test/x?api_key=abcdef123456&page=1'")
    analysis = service.analyze(rec)
    report = service.preview(analysis, service.default_plan(analysis))
    url = report["flows"][0]["requests"][0]["url"]
    assert url == "https://a.test/x?api_key=***&page=1"
    assert "abcdef123456" not in json.dumps(report)


def test_leak_check_fails_closed():
    analysis, _ = build("curl/commands.sh")
    with pytest.raises(GenerationError, match="Safety stop"):
        leak_check("<x>Sup3rS3cret!</x>", analysis.secrets)
    short = [s for s in analysis.secrets if s.field == "Authorization"][:1]
    short[0].value = "abc"
    assert leak_check("<x>abc</x>", short)[0].code == "short-secret-elsewhere"


def test_error_messages_do_not_echo_secrets():
    text = "curl 'https://user:Sup3rS3cret!@a.test:99999/x'"
    with pytest.raises(Exception) as exc:
        from_text(text)
    assert "Sup3rS3cret" not in str(exc.value)


def test_url_credentials_are_dropped():
    rec = from_text("curl 'https://user:Sup3rS3cret!@a.test/x'")
    assert any(i.code == "url-credentials-dropped" for i in rec.issues)
    analysis = service.analyze(rec)
    assert "Sup3rS3cret" not in service.generate(analysis, service.default_plan(analysis)).jmx
