import json

from conftest import FIXTURE_SECRETS, fixture

from rec2jmx.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_formats_lists_supported_formats(capsys):
    code, out, _ = run(capsys, "formats")
    assert code == 0
    for label in ("HAR", "cURL", "JMeter test plan", "Postman Collection", "rec2jmx JSON recording", "Android/iOS"):
        assert label in out


def test_inspect_shows_format_names_secrets_suggestions_and_limits(capsys):
    code, out, _ = run(capsys, "inspect", fixture("har/shop_flows.har"))
    assert code == 0
    assert "Format:  HAR (HTTP Archive) 1.1/1.2" in out
    assert "[1] TX_01_login" in out and "TX_02_A02_api_v1_orders_id" in out
    assert "S01" in out and "kept as recorded" in out
    assert "[ ] C02" in out and "extract C_token from r0003 (JSON $.token)" in out
    assert "WebSocket" in out and "Mobile (Android/iOS) and browser UI interactions are not replayed" in out
    for secret in FIXTURE_SECRETS:
        assert secret not in out


def test_inspect_json_is_machine_readable(capsys):
    code, out, _ = run(capsys, "inspect", fixture("curl/commands.sh"), "--json")
    report = json.loads(out)
    assert code == 0 and report["source"]["format"] == "curl"
    assert [f["txName"] for f in report["flows"]] == ["TX_01_Login", "TX_02_Browse_catalog", "TX_03_Upload_avatar"]


def test_write_plan_edit_and_generate(capsys, tmp_path):
    plan_path = tmp_path / "plan.json"
    code, _, _ = run(capsys, "inspect", fixture("har/shop_flows.har"), "--write-plan", str(plan_path))
    assert code == 0
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["flows"].reverse()
    plan["flows"][0]["name"] = "Place order"
    plan["acceptSuggestions"] = ["C05"]
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    out_path = tmp_path / "out.jmx"
    code, out, err = run(capsys, "generate", fixture("har/shop_flows.har"), "--plan", str(plan_path), "-o", str(out_path))
    assert code == 0, err
    jmx = out_path.read_text(encoding="utf-8")
    assert 'testname="TX_01_Place_order"' in jmx and 'testname="TX_02_login"' in jmx
    assert "JMeter-based validation was not run" in out
    assert "Validation structure: PASSED" in out


def test_generate_refuses_to_overwrite_without_force(capsys, tmp_path):
    out_path = tmp_path / "out.jmx"
    out_path.write_text("keep me", encoding="utf-8")
    code, _, err = run(capsys, "generate", fixture("curl/cmd_style.txt"), "-o", str(out_path))
    assert code == 1 and "already exists" in err and out_path.read_text(encoding="utf-8") == "keep me"
    code, _, _ = run(capsys, "generate", fixture("curl/cmd_style.txt"), "-o", str(out_path), "--force")
    assert code == 0 and out_path.read_text(encoding="utf-8").startswith("<?xml")


def test_cli_options_map_to_plan(capsys, tmp_path):
    out_path = tmp_path / "o.jmx"
    code, out, err = run(capsys, "generate", fixture("har/shop_flows.har"), "-o", str(out_path), "--accept", "all",
                         "--flow-order", "2,1", "--think-time", "500", "--name", "Shop smoke", "--no-parameterize-hosts")
    assert code == 0, err
    jmx = out_path.read_text(encoding="utf-8")
    assert 'testname="Shop smoke"' in jmx and "HOST_1" not in jmx and "<JSONPostProcessor" in jmx
    assert "correlation was not applied" not in out
    assert "C02 was not applied" in out  # token source (login) now runs after its usages


def test_user_errors_exit_1_without_traceback(capsys, tmp_path):
    code, _, err = run(capsys, "inspect", fixture("har/malformed.har"))
    assert code == 1 and err.startswith("error: ") and "Traceback" not in err
    code, _, err = run(capsys, "inspect", str(tmp_path / "missing.har"))
    assert code == 1 and "not found" in err
    code, _, err = run(capsys, "generate", fixture("har/shop_flows.har"), "-o", str(tmp_path / "x.jmx"), "--accept", "C77")
    assert code == 1 and "Unknown suggestion" in err
    code, _, err = run(capsys, "inspect", fixture("har/shop_flows.har"), "--flow-order", "1")
    assert code == 1 and "exactly once" in err


def test_validate_existing_plan_structure(capsys, tmp_path):
    out_path = tmp_path / "o.jmx"
    run(capsys, "generate", fixture("native/recording.json"), "-o", str(out_path))
    code, out, _ = run(capsys, "validate", str(out_path))
    assert code == 0 and "structure: PASSED" in out
    out_path.write_text("<jmeterTestPlan><hashTree><TestPlan/></hashTree></jmeterTestPlan>", encoding="utf-8")
    code, out, _ = run(capsys, "validate", str(out_path))
    assert code == 2 and "FAILED" in out


def test_jmeter_validation_reports_missing_jmeter(capsys, tmp_path, monkeypatch):
    monkeypatch.delenv("JMETER_HOME", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    code, _, err = run(capsys, "generate", fixture("curl/cmd_style.txt"), "-o", str(tmp_path / "x.jmx"), "--validate-jmeter")
    assert code == 2 and "JMeter was not found" in err
    assert not (tmp_path / "x.jmx").exists()


def test_cli_survives_legacy_console_encoding(tmp_path):
    import os
    import subprocess
    import sys
    rec = tmp_path / "unicode.sh"
    rec.write_text("# flow: Zahlung \u2192 Bestätigung \u2713\ncurl 'https://api.example.test/caf\u00e9/\u6f22\u5b57'\n", encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=os.path.abspath("src"))
    proc = subprocess.run([sys.executable, "-m", "rec2jmx", "inspect", str(rec)], capture_output=True, env=env)
    assert proc.returncode == 0, proc.stderr.decode("cp1252", "replace")
    assert b"TX_01_Zahlung_Best_tigung" in proc.stdout


def test_cli_secret_policy_default_flag_and_plan(capsys, tmp_path):
    src = fixture("curl/commands.sh")
    default = tmp_path / "default.jmx"
    assert run(capsys, "generate", src, "-o", str(default))[0] == 0
    assert "Sup3rS3cret!" in default.read_text(encoding="utf-8")  # same default as the web UI: include
    param = tmp_path / "param.jmx"
    code, out, _ = run(capsys, "generate", src, "-o", str(param), "--secrets", "parameterize")
    text = param.read_text(encoding="utf-8")
    assert code == 0 and "Sup3rS3cret!" not in text and "${SECRET_password}" in text
    plan_path = tmp_path / "plan.json"
    run(capsys, "inspect", src, "--write-plan", str(plan_path))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["secretPolicy"] == "include"
    plan["secretPolicy"] = "parameterize"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    from_plan = tmp_path / "plan.jmx"
    assert run(capsys, "generate", src, "--plan", str(plan_path), "-o", str(from_plan))[0] == 0
    assert "Sup3rS3cret!" not in from_plan.read_text(encoding="utf-8")  # the plan file's choice is kept
