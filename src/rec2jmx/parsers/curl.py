"""cURL command parser.

Accepts one or more ``curl`` commands as produced by "Copy as cURL" (bash or Windows
cmd syntax) or written by hand. The text is tokenized with a small POSIX-shell subset;
nothing is ever executed and no shell expansion is performed.

``# flow: <name>`` comment lines group the following commands into a named flow.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import quote_plus

from ..errors import InputError
from ..ir import Body, FormField, Issue, NameValue
from .common import ParseResult, build_body, header_get, new_request, split_url

# Short options that take an argument.
_SHORT_WITH_ARG = set("XHdFubAeoTxmwrEKcDyYzCQt")
_LONG_WITH_ARG = {
    "--request", "--header", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "--form", "--form-string", "--user", "--cookie", "--user-agent",
    "--referer", "--url", "--output", "--proxy", "--max-time", "--connect-timeout",
    "--write-out", "--cert", "--key", "--cacert", "--retry", "--resolve", "--oauth2-bearer",
    "--json", "--cookie-jar", "--limit-rate", "--max-redirs", "--interface", "--upload-file",
    "--range", "--retry-delay", "--retry-max-time", "--keepalive-time", "--trace",
    "--trace-ascii", "--stderr", "--config", "--netrc-file", "--aws-sigv4", "--proxy-user",
    "--connect-to", "--dns-servers", "--ciphers", "--tls-max", "--quote", "--telnet-option",
}
_IGNORED_NO_ARG = {
    "--compressed", "--silent", "--show-error", "--verbose", "--include", "--insecure",
    "--location", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
    "--fail", "--globoff", "--no-buffer", "--progress-bar", "--ipv4", "--ipv6", "--tlsv1.2",
    "--tlsv1.3", "--location-trusted", "--fail-with-body", "--no-keepalive", "--raw",
    "--path-as-is", "--ssl-no-revoke", "--no-progress-meter", "--remote-name", "--anyauth",
    "--basic", "--digest", "--ntlm", "--negotiate", "--no-sessionid", "--tcp-nodelay",
}
_IGNORED_SHORT = set("sSviLfgN0123456qjJOnRZ#k")
_IGNORED_WITH_ARG = {
    "--output", "--max-time", "--connect-timeout", "--write-out", "--retry", "--limit-rate",
    "--max-redirs", "--retry-delay", "--retry-max-time", "--keepalive-time", "--stderr",
    "--trace", "--trace-ascii", "--dns-servers", "--interface", "--ciphers", "--tls-max",
    "-o", "-m", "-w", "-r", "-y", "-Y", "-z", "-C", "-Q", "-t", "-c", "--cookie-jar",
}
_UNSUPPORTED_WITH_ARG = {
    "--cert": "client certificates", "--key": "client certificates", "--cacert": "CA bundles",
    "--resolve": "--resolve host overrides", "--connect-to": "--connect-to overrides",
    "--proxy": "proxies", "-x": "proxies", "--proxy-user": "proxy credentials",
    "--config": "curl config files", "-K": "curl config files", "--netrc-file": "netrc files",
    "--aws-sigv4": "AWS SigV4 signing", "--upload-file": "file uploads (-T)", "-T": "file uploads (-T)",
    "-E": "client certificates", "--range": "byte ranges", "-D": "header dump files",
    "--quote": "FTP quote commands", "--telnet-option": "telnet options",
}

_LONG_ALIASES = {"--data-ascii": "--data"}


@dataclass
class _Command:
    tokens: list[str]
    line: int
    flow: str | None


def _normalize_cmd_syntax(text: str) -> str:
    """Convert Windows cmd.exe "Copy as cURL (cmd)" escaping (``^"``, ``^`` continuations)."""
    if '^"' not in text and not re.search(r"\^\r?\n", text):
        return text
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "^" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "\r" and text[i + 2:i + 3] == "\n":
                out.append(" ")
                i += 3
                continue
            if nxt == "\n":
                out.append(" ")
                i += 2
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_ANSI_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a",
                   "b": "\b", "e": "\x1b", "f": "\f", "v": "\v", "?": "?"}


def _split_commands(text: str) -> list[_Command]:
    commands: list[_Command] = []
    tokens: list[str] = []
    buf: list[str] = []
    in_token = False
    line = 1
    cmd_line = 1
    flow: str | None = None
    i, n = 0, len(text)

    def end_token() -> None:
        nonlocal in_token
        if in_token:
            tokens.append("".join(buf))
            buf.clear()
            in_token = False

    def end_command() -> None:
        nonlocal tokens
        end_token()
        if tokens:
            commands.append(_Command(tokens, cmd_line, flow))
            tokens = []

    while i < n:
        c = text[i]
        if not tokens and not in_token and c not in " \t\r\n#":
            cmd_line = line
        if c == "\\" and text[i + 1:i + 2] == "\n":
            i += 2
            line += 1
            continue
        if c == "\\" and text[i + 1:i + 3] == "\r\n":
            i += 3
            line += 1
            continue
        if c in " \t\r":
            end_token()
            i += 1
            continue
        if c == "\n":
            end_command()
            line += 1
            i += 1
            continue
        if c == "#" and not in_token:
            j = text.find("\n", i)
            j = n if j == -1 else j
            comment = text[i + 1:j]
            m = re.match(r"\s*flow\s*:\s*(.+?)\s*$", comment, re.IGNORECASE)
            if m and not tokens:
                flow = m.group(1)
            i = j
            continue
        if c in ";|&<>`":
            raise InputError(
                f"cURL line {line}: shell operator '{c}' is not supported. Put each curl command on "
                "its own line and quote arguments that contain special characters."
            )
        if c == "'":
            j = text.find("'", i + 1)
            if j == -1:
                raise InputError(f"cURL line {line}: unterminated single quote.")
            seg = text[i + 1:j]
            buf.append(seg)
            line += seg.count("\n")
            in_token = True
            i = j + 1
            continue
        if c == "$" and text[i + 1:i + 2] == "'":
            i += 2
            while True:
                if i >= n:
                    raise InputError(f"cURL line {line}: unterminated $'...' string.")
                ch = text[i]
                if ch == "'":
                    i += 1
                    break
                if ch == "\\" and i + 1 < n:
                    esc = text[i + 1]
                    if esc in _ANSI_C_ESCAPES:
                        buf.append(_ANSI_C_ESCAPES[esc])
                        i += 2
                    elif esc == "x":
                        m = re.match(r"[0-9A-Fa-f]{1,2}", text[i + 2:i + 4])
                        if m:
                            buf.append(chr(int(m.group(0), 16)))
                            i += 2 + len(m.group(0))
                        else:
                            buf.append("\\x")
                            i += 2
                    elif esc in "uU":
                        width = 4 if esc == "u" else 8
                        m = re.match(r"[0-9A-Fa-f]{1,%d}" % width, text[i + 2:i + 2 + width])
                        if m:
                            buf.append(chr(int(m.group(0), 16)))
                            i += 2 + len(m.group(0))
                        else:
                            buf.append("\\" + esc)
                            i += 2
                    else:
                        buf.append("\\" + esc)
                        i += 2
                    continue
                if ch == "\n":
                    line += 1
                buf.append(ch)
                i += 1
            in_token = True
            continue
        if c == '"':
            i += 1
            while True:
                if i >= n:
                    raise InputError(f"cURL line {line}: unterminated double quote.")
                ch = text[i]
                if ch == '"':
                    i += 1
                    break
                if ch == "\\" and i + 1 < n and text[i + 1] in '"\\$`\n':
                    if text[i + 1] == "\n":
                        line += 1
                    else:
                        buf.append(text[i + 1])
                    i += 2
                    continue
                if ch == "\n":
                    line += 1
                buf.append(ch)
                i += 1
            in_token = True
            continue
        if c == "\\" and i + 1 < n:
            buf.append(text[i + 1])
            in_token = True
            i += 2
            continue
        buf.append(c)
        in_token = True
        i += 1
    end_command()
    return commands


def _parse_header(raw: str) -> NameValue | None:
    if ":" in raw:
        name, _, value = raw.partition(":")
        name, value = name.strip(), value.strip()
        if not name or not value:  # "Name:" removes a header in curl
            return None
        return NameValue(name, value)
    if raw.endswith(";"):  # "Name;" sends an empty header
        return NameValue(raw[:-1].strip(), "")
    return None


def _urlencode_data(arg: str) -> str:
    # --data-urlencode forms: "content", "=content", "name=content", "@file", "name@file"
    if "=" in arg:
        name, _, content = arg.partition("=")
        return f"{name}={quote_plus(content)}" if name else quote_plus(content)
    return quote_plus(arg)


def _parse_form(arg: str, literal: bool) -> tuple[FormField, bool]:
    """Returns (field, is_file_reference)."""
    name, _, value = arg.partition("=")
    if literal:
        return FormField(name, value), False
    if value.startswith("@") or value.startswith("<"):
        spec = value[1:]
        parts = spec.split(";")
        fpath = parts[0]
        ctype = None
        filename = re.split(r"[\\/]", fpath)[-1]
        for p in parts[1:]:
            k, _, v = p.partition("=")
            if k.strip() == "type":
                ctype = v.strip()
            elif k.strip() == "filename":
                filename = v.strip()
        if value.startswith("<"):
            return FormField(name, ""), True
        return FormField(name, "", filename or "upload.bin", ctype), True
    return FormField(name, value.split(";type=")[0]), False


def _parse_command(cmd: _Command, idx: int, issues: list[Issue], ignored: set[str]):
    tokens = cmd.tokens
    if tokens[0].lower() not in ("curl", "curl.exe"):
        raise InputError(f"cURL line {cmd.line}: expected a command starting with 'curl', found another command.")
    method = None
    headers: list[NameValue] = []
    data_parts: list[str] = []
    form_fields: list[FormField] = []
    urls: list[str] = []
    get_mode = head_mode = False
    i = 1

    def take_arg(opt: str) -> str:
        nonlocal i
        if i + 1 >= len(tokens):
            raise InputError(f"cURL line {cmd.line}: option {opt} requires a value.")
        i += 1
        return tokens[i]

    def handle(opt: str, val: str | None) -> None:
        nonlocal method, get_mode, head_mode
        opt = _LONG_ALIASES.get(opt, opt)
        if opt in ("-X", "--request"):
            method = val.upper()
        elif opt in ("-H", "--header"):
            h = _parse_header(val)
            if h is None:
                issues.append(Issue("warning", "curl-header", f"cURL line {cmd.line}: a header without a "
                                    "value was ignored (curl uses 'Name:' to remove headers)."))
            else:
                headers.append(h)
        elif opt in ("-d", "--data", "--data-binary"):
            if val.startswith("@"):
                issues.append(Issue("warning", "curl-file-ref", f"cURL line {cmd.line}: {opt} @file references "
                                    "are not read; the request body was left empty."))
            else:
                data_parts.append(val.replace("\r", "").replace("\n", "") if opt != "--data-binary" else val)
        elif opt == "--data-raw":
            data_parts.append(val)
        elif opt == "--data-urlencode":
            if val.startswith("@") or re.match(r"^[^=]*@", val) and "=" not in val:
                issues.append(Issue("warning", "curl-file-ref", f"cURL line {cmd.line}: --data-urlencode file "
                                    "references are not read; that value was left out."))
            else:
                data_parts.append(_urlencode_data(val))
        elif opt == "--json":
            data_parts.append(val)
            if header_get(headers, "content-type") is None:
                headers.append(NameValue("Content-Type", "application/json"))
            if header_get(headers, "accept") is None:
                headers.append(NameValue("Accept", "application/json"))
        elif opt in ("-F", "--form", "--form-string"):
            fld, is_ref = _parse_form(val, opt == "--form-string")
            if is_ref:
                issues.append(Issue("warning", "curl-file-ref", f"cURL line {cmd.line}: form file content is not "
                                    "read; supply the file at run time (see the FILE_DIR variable)."))
            form_fields.append(fld)
        elif opt in ("-u", "--user"):
            token = base64.b64encode(val.encode("utf-8")).decode("ascii")
            headers.append(NameValue("Authorization", f"Basic {token}"))
        elif opt == "--oauth2-bearer":
            headers.append(NameValue("Authorization", f"Bearer {val}"))
        elif opt in ("-b", "--cookie"):
            if "=" in val:
                headers.append(NameValue("Cookie", val))
            else:
                issues.append(Issue("warning", "curl-cookie-file", f"cURL line {cmd.line}: cookie files are not read."))
        elif opt in ("-A", "--user-agent"):
            headers.append(NameValue("User-Agent", val))
        elif opt in ("-e", "--referer"):
            headers.append(NameValue("Referer", val))
        elif opt == "--url":
            urls.append(val)
        elif opt in ("-G", "--get"):
            get_mode = True
        elif opt in ("-I", "--head"):
            head_mode = True
        elif opt in _UNSUPPORTED_WITH_ARG:
            issues.append(Issue("warning", "curl-unsupported-option",
                                f"cURL line {cmd.line}: {_UNSUPPORTED_WITH_ARG[opt]} ({opt}) are not converted."))
        elif opt in ("-k", "--insecure"):
            ignored.add(opt)
        else:
            ignored.add(opt)

    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            urls.extend(tokens[i + 1:])
            break
        if tok.startswith("--"):
            if tok in _LONG_WITH_ARG:
                handle(tok, take_arg(tok))
            elif tok in ("--get", "--head"):
                handle(tok, None)
            elif tok in _IGNORED_NO_ARG:
                ignored.add(tok)
            else:
                issues.append(Issue("warning", "curl-unknown-option",
                                    f"cURL line {cmd.line}: unknown option {tok[:40]} was ignored; if it takes a "
                                    "value, the next argument may have been misread as a URL."))
        elif tok.startswith("-") and len(tok) > 1:
            j = 1
            while j < len(tok):
                ch = tok[j]
                opt = "-" + ch
                if ch in _SHORT_WITH_ARG:
                    rest = tok[j + 1:]
                    handle(opt, rest if rest else take_arg(opt))
                    break
                if ch in "GI":
                    handle(opt, None)
                elif ch in _IGNORED_SHORT:
                    ignored.add(opt)
                else:
                    issues.append(Issue("warning", "curl-unknown-option",
                                        f"cURL line {cmd.line}: unknown option {opt} was ignored."))
                j += 1
        else:
            urls.append(tok)
        i += 1

    if not urls:
        raise InputError(f"cURL line {cmd.line}: no URL found in the curl command.")
    if data_parts and form_fields:
        raise InputError(f"cURL line {cmd.line}: -d/--data and -F/--form cannot be combined (curl rejects this too).")

    results = []
    for raw_url in urls:
        url = raw_url
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
            url = "http://" + url
            issues.append(Issue("warning", "curl-no-scheme",
                                f"cURL line {cmd.line}: URL has no scheme; http:// was assumed (as curl does)."))
        try:
            parts = split_url(url)
        except ValueError as exc:
            raise InputError(f"cURL line {cmd.line}: {exc}.") from None
        data = "&".join(data_parts)
        if get_mode and data:
            parts.raw_query = f"{parts.raw_query}&{data}" if parts.raw_query else data
            data = ""
        m = method or ("HEAD" if head_mode else "POST" if (data or form_fields) else "GET")
        hdrs = list(headers)
        if form_fields:
            body = Body("multipart", fields=list(form_fields))
        elif data:
            ctype = header_get(hdrs, "content-type")
            if ctype is None:
                ctype = "application/x-www-form-urlencoded"
                hdrs.append(NameValue("Content-Type", ctype))
            body = build_body(data, ctype)
        else:
            body = Body("none")
        req = new_request(m, parts, headers=hdrs, body=body, group_hint=cmd.flow,
                          source_ref=f"command {idx} (line {cmd.line})")
        if parts.had_userinfo:
            issues.append(Issue("warning", "url-credentials-dropped",
                                f"cURL line {cmd.line}: credentials embedded in the URL were removed; use -u instead."))
        results.append(req)
    return results


def parse_curl(text: str, doc=None) -> ParseResult:
    commands = _split_commands(_normalize_cmd_syntax(text))
    if not commands:
        raise InputError("No curl commands were found.")
    issues: list[Issue] = []
    if re.search(r"(?<![\\'])\$(?:\{|[A-Za-z_])", text) and "'$" not in text:
        issues.append(Issue("info", "curl-no-expansion",
                            "Shell variables ($NAME) were kept literally; no shell expansion is performed."))
    ignored: set[str] = set()
    requests = []
    for idx, cmd in enumerate(commands, start=1):
        requests.extend(_parse_command(cmd, idx, issues, ignored))
    if ignored:
        issues.append(Issue("info", "curl-ignored-options",
                            "Ignored curl options with no JMeter equivalent: " + ", ".join(sorted(ignored)) +
                            ". (JMeter follows redirects and accepts compressed responses by default.)"))
    has_flows = any(r.group_hint for r in requests)
    return ParseResult(requests, issues, grouping_source="'# flow:' comments" if has_flows else None)
