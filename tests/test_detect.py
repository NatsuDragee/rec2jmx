import pytest
from conftest import fixture, from_text, load

from rec2jmx.detect import decode_text, detect_format, safe_display_name
from rec2jmx.errors import InputError
from rec2jmx.loader import load_bytes, load_file


@pytest.mark.parametrize("path,fmt", [
    ("har/shop_flows.har", "har"),
    ("curl/commands.sh", "curl"),
    ("curl/cmd_style.txt", "curl"),
    ("jmx/legacy_plan.jmx", "jmx"),
    ("postman/collection_v21.json", "postman"),
    ("native/recording.json", "rec2jmx-json"),
])
def test_detects_each_supported_format_from_content(path, fmt):
    assert load(path).source_format == fmt


def test_content_wins_over_extension_with_warning():
    text = open(fixture("har/shop_flows.har"), encoding="utf-8").read()
    rec = from_text(text, "capture.jmx")
    assert rec.source_format == "har"
    assert any(i.code == "extension-mismatch" for i in rec.issues)


def test_forced_format_mismatch_is_rejected_not_reinterpreted():
    text = open(fixture("har/shop_flows.har"), encoding="utf-8").read()
    with pytest.raises(InputError, match="will not be reinterpreted"):
        from_text(text, "x.har", forced_format="postman")


@pytest.mark.parametrize("text,msg", [
    ('{"hello": "world"}', "does not match a supported schema"),
    ("[1, 2]", "top-level array"),
    ("<html><body>hi</body></html>", "not a JMeter test plan"),
    ("GET /index.html HTTP/1.1", "Unrecognized input"),
    ('{"log": {"entries": [', "malformed at line 1"),
])
def test_unknown_or_malformed_content_gets_actionable_error(text, msg):
    with pytest.raises(InputError, match=msg):
        from_text(text)


def test_empty_and_oversized_inputs_rejected(tmp_path):
    with pytest.raises(InputError, match="empty"):
        load_bytes(b"   \n", "a.har")
    with pytest.raises(InputError, match="limit"):
        load_bytes(b"x" * 101, "a.har", max_bytes=100)
    big = tmp_path / "big.har"
    big.write_bytes(b"{" + b" " * 200 + b"}")
    with pytest.raises(InputError, match="limit"):
        load_file(str(big), max_bytes=100)


def test_decoding_rules():
    assert decode_text("\ufeffcurl x".encode("utf-8")) == "curl x"
    assert decode_text("curl https://a.test".encode("utf-16")) == "curl https://a.test"
    with pytest.raises(InputError, match="not valid UTF-8"):
        decode_text(b"curl \xff\xfe\xfa")
    with pytest.raises(InputError, match="binary"):
        decode_text(b"curl\x00x")


def test_deeply_nested_json_is_rejected_safely():
    with pytest.raises(InputError):
        from_text("[" * 100000 + "]" * 100000)


def test_unknown_forced_format():
    with pytest.raises(InputError, match="Unknown format"):
        detect_format("curl x", forced="pcap")


def test_display_names_are_sanitized():
    assert safe_display_name("../../etc/passwd") == "passwd"
    assert safe_display_name("C:\\Users\\x\\rec<script>.har") == "rec_script_.har"
    assert safe_display_name("") == "recording"


def test_missing_file_message_has_no_directory():
    with pytest.raises(InputError, match="not found: nope.har"):
        load_file("/some/secret/dir/nope.har")
