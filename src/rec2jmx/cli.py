"""Command-line interface: formats | inspect | generate | validate | serve."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, service
from .analysis.grouping import GroupingSettings
from .detect import DEFAULT_MAX_BYTES
from .errors import Rec2JmxError, ValidationError
from .formats import FORMATS, GENERAL_LIMITATIONS
from .loader import load_file
from .plan import parse_think_time, plan_from_dict, reorder_flows
from .validate import find_jmeter, jmeter_load_check, jmeter_mock_run, structural_check

EXIT_OK, EXIT_ERROR, EXIT_VALIDATION = 0, 1, 2
# Same default as the web UI: recorded values (tokens, passwords, cookies) are written into the .jmx.
DEFAULT_SECRET_POLICY = "include"


def _add_analysis_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="recording file (HAR, cURL, JMX, Postman v2.x, rec2jmx JSON)")
    p.add_argument("--format", choices=sorted(FORMATS), help="assert the input format (content is still checked)")
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_BYTES, help="maximum input size in bytes (default 50 MB)")
    p.add_argument("--group-by", choices=["auto", "recorded", "gap", "single"], default="auto",
                   help="how to group requests into flows (default: recorded groups, else time gaps)")
    p.add_argument("--gap", type=float, default=5.0, help="idle seconds that start a new flow with --group-by gap")
    p.add_argument("--include-static", action="store_true", help="keep static resources (HAR only)")
    p.add_argument("--include-host", action="append", default=[], metavar="GLOB", help="keep only matching hosts")
    p.add_argument("--exclude-host", action="append", default=[], metavar="GLOB", help="drop matching hosts")
    p.add_argument("--plan", help="reviewed plan JSON (from 'inspect --write-plan'); overrides grouping")
    p.add_argument("--flow-order", help="comma-separated flow numbers, e.g. 2,1,3 (sets transaction numbering)")
    p.add_argument("--accept", action="append", default=[], metavar="ID",
                   help="accept a correlation/timestamp suggestion by id (repeatable, or 'all')")
    p.add_argument("--secrets", choices=["parameterize", "include"],
                   help="include (default) keeps recorded values; parameterize replaces detected secrets with "
                        "${SECRET_*} properties supplied at run time with -J")
    p.add_argument("--think-time", help="none (default), recorded, or a constant in milliseconds")
    p.add_argument("--no-parameterize-hosts", action="store_true", help="hard-code recorded hosts instead of HOST_n")
    p.add_argument("--name", help="Test Plan name")
    p.add_argument("--json", action="store_true", help="print the machine-readable report")


def _build(args):
    rec = load_file(args.input, args.format, args.max_size)
    settings = GroupingSettings(args.group_by, args.gap, args.include_static, args.include_host, args.exclude_host)
    analysis = service.analyze(rec, settings)
    if args.plan:
        with open(args.plan, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise Rec2JmxError(f"The plan file is not valid JSON (line {exc.lineno}): {exc.msg}") from None
        plan = plan_from_dict(data)
    else:
        plan = service.default_plan(analysis)
    if args.flow_order:
        try:
            order = [int(x) for x in args.flow_order.split(",") if x.strip()]
        except ValueError:
            raise Rec2JmxError("--flow-order must be comma-separated numbers, e.g. 2,1,3") from None
        reorder_flows(plan, order)
    if args.accept:
        if "all" in args.accept:
            plan.accepted = [s.id for s in analysis.suggestions if s.acceptable]
        else:
            plan.accepted = list(dict.fromkeys(plan.accepted + args.accept))
    if args.secrets:
        plan.secret_policy = args.secrets
    elif not args.plan:  # a reviewed plan file keeps its own secretPolicy
        plan.secret_policy = DEFAULT_SECRET_POLICY
    if args.think_time:
        plan.think_time = parse_think_time(args.think_time)
    if args.no_parameterize_hosts:
        plan.parameterize_hosts = False
    if args.name:
        plan.test_plan_name = args.name[:120]
    return analysis, plan


_SEV = {"error": "ERROR", "warning": "WARN ", "info": "info "}


def _print_report(report: dict, out=None) -> None:
    out = out or sys.stdout
    src, summ = report["source"], report["summary"]
    print(f"Input:   {src['name']}", file=out)
    print(f"Format:  {src['formatLabel']}", file=out)
    print(f"Requests: {summ['parsed']} parsed, {summ['included']} included by default, "
          f"{len(summ['excluded'])} excluded, {summ['planned']} in plan", file=out)
    if report["hosts"]:
        print("Hosts:   " + ", ".join(f"{h['origin']} ({h['requests']})" for h in report["hosts"][:8]), file=out)
    print("\nProposed JMeter elements (transaction order = flow order):", file=out)
    for f in report["flows"]:
        print(f"  [{f['index']}] {f['txName']}    (flow '{f['name']}', grouping: {f['basis']})", file=out)
        for r in f["requests"]:
            print(f"        {r['samplerName']:<44} {r['method']:<6} {r['url']}   [{r['id']}]", file=out)
    if report["secrets"]:
        include = report["plan"]["secretPolicy"] == "include"
        print("\nPossible secrets " + ("(kept as recorded; --secrets parameterize replaces them with ${SECRET_*}):"
                                      if include else "(policy: parameterize):"), file=out)
        for s in report["secrets"]:
            target = "kept" if include else f"-> ${{{s['variable']}}}"
            print(f"  {s['id']} {s['requestId'] or 'variables'}: {s['location']} - {s['reason']} {target}", file=out)
    if report["suggestions"]:
        print("\nDynamic value suggestions (applied only when accepted with --accept ID):", file=out)
        for s in report["suggestions"]:
            mark = "[x]" if s["accepted"] else "[ ]" if s["acceptable"] else " - "
            uses = ", ".join(f"{u['requestId']} {u['location']}" for u in s["usages"][:3])
            more = f" (+{len(s['usages']) - 3} more)" if len(s["usages"]) > 3 else ""
            if s["kind"] == "correlation":
                ex = s["extractor"]
                how = f"JSON {ex['expression']}" if ex["type"] == "json" else f"boundary in response {ex['scope']}"
                desc = f"extract {s['variable']} from {s['sourceRequestId']} ({how}); used in {uses}{more}"
            elif s["kind"] == "timestamp":
                desc = f"replace with {s['replacement']} in {uses}"
            else:
                desc = f"{s['reason']}: {uses}"
            print(f"  {mark} {s['id']} {s['kind']:<11} [{s['confidence']}] {desc}", file=out)
    issues = report["issues"] + report.get("generation", {}).get("issues", [])
    shown = [i for i in issues if i["code"] != "detected-format"]
    if shown:
        print("\nMessages:", file=out)
        for i in shown:
            rid = f" [{i['requestId']}]" if i.get("requestId") else ""
            print(f"  {_SEV.get(i['severity'], i['severity'])} {i['message']}{rid}", file=out)
    print("\nLimitations:", file=out)
    for lim in report["limitations"]:
        print(f"  - {lim}", file=out)


def cmd_formats(args) -> int:
    for f in FORMATS.values():
        print(f"{f.key:<14} {f.label}")
        for lim in f.limitations:
            print(f"{'':<16}- {lim}")
    print("\nGeneral:")
    for lim in GENERAL_LIMITATIONS:
        print(f"  - {lim}")
    return EXIT_OK


def cmd_inspect(args) -> int:
    analysis, plan = _build(args)
    report = service.preview(analysis, plan)
    if args.write_plan:
        _write_new(args.write_plan, json.dumps(report["plan"], indent=2) + "\n", args.force)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
        if args.write_plan:
            print(f"\nPlan written to {args.write_plan}. Edit flow names/order/requests or acceptSuggestions, "
                  "then run: rec2jmx generate <input> --plan <plan.json> -o out.jmx")
    return EXIT_OK


def _write_new(path: str, text: str, force: bool) -> None:
    if os.path.exists(path) and not force:
        raise Rec2JmxError(f"{path} already exists; use --force to overwrite it.")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise Rec2JmxError(f"Output folder does not exist: {parent}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _jmeter_validations(jmx: str, args) -> list:
    reports = []
    if not (args.validate_jmeter or args.validate_mock):
        return reports
    jmeter = find_jmeter(args.jmeter)
    if not jmeter:
        raise ValidationError("JMeter was not found. Pass --jmeter <path to jmeter(.bat) or JMeter home> or set JMETER_HOME.")
    if args.validate_jmeter:
        reports.append(jmeter_load_check(jmx, jmeter))
    if args.validate_mock:
        reports.append(jmeter_mock_run(jmx, jmeter)[0])
    return reports


def _print_validations(reports, out=None) -> bool:
    out = out or sys.stdout
    ok = True
    for r in reports:
        status = "PASSED" if r.passed else "FAILED"
        ok &= r.passed
        print(f"Validation {r.name}: {status} - " + " | ".join(r.details), file=out)
    return ok


def cmd_generate(args) -> int:
    analysis, plan = _build(args)
    result = service.generate(analysis, plan)
    reports = list(result.validations) + _jmeter_validations(result.jmx, args)
    _write_new(args.output, result.jmx, args.force)
    result.report["generation"]["validations"] = [r.to_dict() for r in reports]
    result.report["generation"]["output"] = os.path.abspath(args.output)
    if args.json:
        print(json.dumps(result.report, indent=2))
        return EXIT_OK if all(r.passed for r in reports) else EXIT_VALIDATION
    _print_report(result.report)
    print(f"\nWrote {args.output}")
    ok = _print_validations(reports)
    if not (args.validate_jmeter or args.validate_mock):
        print("JMeter-based validation was not run (use --validate-jmeter and/or --validate-mock).")
    applied = result.report["generation"]["appliedSuggestions"]
    if applied:
        print("Applied suggestions: " + ", ".join(applied))
    return EXIT_OK if ok else EXIT_VALIDATION


def cmd_validate(args) -> int:
    with open(args.jmx, encoding="utf-8") as fh:
        jmx = fh.read()
    reports = [structural_check(jmx)] + _jmeter_validations(jmx, args)
    ok = _print_validations(reports)
    if not (args.validate_jmeter or args.validate_mock):
        print("JMeter-based validation was not run (use --validate-jmeter and/or --validate-mock).")
    return EXIT_OK if ok else EXIT_VALIDATION


def cmd_serve(args) -> int:
    from .web.server import serve
    serve(args.port, args.max_size)
    return EXIT_OK


def _add_validation_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--validate-jmeter", action="store_true",
                   help="load the plan in JMeter with 0 threads (hosts forced to 127.0.0.1)")
    p.add_argument("--validate-mock", action="store_true",
                   help="run 1 iteration in JMeter against a local 127.0.0.1 mock server and compare requests")
    p.add_argument("--jmeter", help="path to jmeter(.bat) or the JMeter home folder (default: JMETER_HOME or PATH)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rec2jmx", description="Convert recordings into Apache JMeter test plans. "
                                     "Recorded requests are never sent anywhere by this tool.")
    parser.add_argument("--version", action="version", version=f"rec2jmx {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("formats", help="list supported input formats and limitations").set_defaults(func=cmd_formats)

    p = sub.add_parser("inspect", help="show detected format, flows, proposed names, secrets, suggestions, warnings")
    _add_analysis_args(p)
    p.add_argument("--write-plan", metavar="PLAN.json", help="save an editable plan for review")
    p.add_argument("--force", action="store_true", help="overwrite --write-plan if it exists")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("generate", help="generate a .jmx test plan")
    _add_analysis_args(p)
    p.add_argument("-o", "--output", required=True, help="output .jmx path")
    p.add_argument("--force", action="store_true", help="overwrite the output if it exists")
    _add_validation_args(p)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("validate", help="validate an existing .jmx produced by rec2jmx")
    p.add_argument("jmx")
    _add_validation_args(p)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("serve", help="start the local web UI on 127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_BYTES)
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # legacy consoles (e.g. cp1252) must not crash on names/URLs
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Rec2JmxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_VALIDATION if isinstance(exc, ValidationError) else EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc.strerror or exc}: {os.path.basename(getattr(exc, 'filename', '') or '')}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
