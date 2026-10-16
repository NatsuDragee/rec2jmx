"""Detect likely secrets (credentials, tokens, API keys) in requests and source variables.

Detection is deliberately broad: false positives only cost a JMeter property, while a
false negative could leak a credential into a shared .jmx file. Values are kept in
memory only and are never serialized into reports (only masked descriptions are).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..ir import Recording, Request

SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-amz-security-token", "x-goog-api-key", "ocp-apim-subscription-key",
    "x-functions-key", "x-session-token", "x-session-id", "x-refresh-token", "x-client-secret",
    "x-id-token", "x-user-token",
}
_NAME_FRAGMENTS = (
    "password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "privatekey",
    "sessionid", "signature", "credential", "authorization", "refreshtoken", "creditcard",
    "cardnumber", "cvv", "ssn",
)
_NAME_EXACT = {"pwd", "pass", "pin", "otp", "sid", "sig", "auth", "key", "jsessionid", "phpsessid"}
_NAME_NOT_SECRET = {"tokentype", "granttype", "responsetype", "tokentypehint", "csrftoken", "xsrftoken",
                    "csrfmiddlewaretoken", "xcsrftoken", "xxsrftoken", "passwordpolicy"}
_AUTH_SCHEMES = ("bearer", "basic", "token", "digest", "negotiate", "ntlm", "apikey", "sso-key", "jwt")

VALUE_PATTERNS = [
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("API key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
]


@dataclass
class SecretFinding:
    id: str
    request_id: str | None  # None for source variables
    kind: str  # header | query | form | json | body | path | variable
    field: str  # header/param/key/variable name, or pattern label
    value: str  # never serialized
    reason: str
    var_name: str = ""
    scheme_prefix: str = ""  # e.g. "Bearer " for Authorization headers

    def location(self) -> str:
        return f"{self.kind} '{self.field}'" if self.kind != "body" else f"body ({self.field})"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "requestId": self.request_id,
            "location": self.location(),
            "reason": self.reason,
            "variable": self.var_name,
            "masked": mask(self.value),
        }


def mask(value: str) -> str:
    return f"[redacted, {len(value)} chars]"


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def is_sensitive_name(name: str) -> bool:
    n = _norm(name)
    if not n or n in _NAME_NOT_SECRET or "csrf" in n or "xsrf" in n:
        return False
    return n in _NAME_EXACT or any(f in n for f in _NAME_FRAGMENTS)


def is_sensitive_header(name: str) -> bool:
    return name.lower() in SENSITIVE_HEADERS or (name.lower() not in ("cookie", "set-cookie") and is_sensitive_name(name))


def split_auth_scheme(value: str) -> tuple[str, str]:
    parts = value.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in _AUTH_SCHEMES and parts[1].strip():
        return parts[0] + " ", parts[1].strip()
    return "", value


def json_leaves(obj, path: str = "$"):
    """Yield (jsonpath, key, value) for scalar leaves."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            sub = f"{path}.{key}" if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) else f"{path}['{key}']"
            if isinstance(v, (dict, list)):
                yield from json_leaves(v, sub)
            else:
                yield sub, key, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            sub = f"{path}[{i}]"
            if isinstance(v, (dict, list)):
                yield from json_leaves(v, sub)
            else:
                yield sub, None, v


def try_json(text: str):
    s = text.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, RecursionError):
        return None


def _scalar_text(v) -> str | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float, str)):
        return str(v)
    return None


def _find_in_request(req: Request):
    """Yield (kind, field, value, reason, scheme_prefix)."""
    for h in req.headers:
        lname = h.name.lower()
        if lname in ("host", "content-length"):
            continue
        if lname == "cookie":
            if h.value and "${" not in h.value:
                yield "header", h.name, h.value, "cookie header (may carry session credentials)", ""
            continue
        if is_sensitive_header(h.name) and h.value:
            prefix, cred = split_auth_scheme(h.value) if lname in ("authorization", "proxy-authorization") else ("", h.value)
            if "${" not in cred:
                yield "header", h.name, cred, "sensitive header name", prefix
                continue
        for label, rx in VALUE_PATTERNS:
            for m in rx.finditer(h.value):
                yield "header", h.name, m.group(0), f"value looks like a {label}", ""
    for q in req.query:
        if q.value and "${" not in q.value and is_sensitive_name(q.name):
            yield "query", q.name, q.value, "sensitive parameter name", ""
        else:
            for label, rx in VALUE_PATTERNS:
                for m in rx.finditer(q.value):
                    yield "query", q.name, m.group(0), f"value looks like a {label}", ""
    for seg in req.path.split("/"):
        for label, rx in VALUE_PATTERNS:
            for m in rx.finditer(seg):
                yield "path", "segment", m.group(0), f"value looks like a {label}", ""
    body = req.body
    for f in body.fields:
        if f.is_file:
            continue
        if f.value and "${" not in f.value and is_sensitive_name(f.name):
            yield "form", f.name, f.value, "sensitive field name", ""
        else:
            for label, rx in VALUE_PATTERNS:
                for m in rx.finditer(f.value):
                    yield "form", f.name, m.group(0), f"value looks like a {label}", ""
    if body.kind == "raw" and body.text:
        doc = try_json(body.text)
        if doc is not None:
            for _path, key, v in json_leaves(doc):
                sv = _scalar_text(v)
                if key is not None and sv and "${" not in sv and is_sensitive_name(key):
                    yield "json", key, sv, "sensitive JSON key", ""
        for label, rx in VALUE_PATTERNS:
            for m in rx.finditer(body.text):
                yield "body", label, m.group(0), f"value looks like a {label}", ""
        for m in re.finditer(r"(?:^|[&?])([^=&\s]{1,64})=([^&\s]+)", body.text if doc is None else ""):
            if is_sensitive_name(m.group(1)) and "${" not in m.group(2) and len(body.text) < 10000:
                yield "body", m.group(1), m.group(2), "sensitive field name in raw body", ""


def _var_name(field: str, used: dict[str, str], value: str) -> str:
    base = "SECRET_" + (re.sub(r"[^A-Za-z0-9_]", "_", field).strip("_") or "value")
    base = re.sub(r"_+", "_", base)[:48]
    name, n = base, 2
    while name in used and used[name] != value:
        name = f"{base}_{n}"
        n += 1
    used[name] = value
    return name


def detect_secrets(rec: Recording, request_ids: set[str] | None = None) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    by_value: dict[str, str] = {}  # value -> var name (same value, same variable)
    used: dict[str, str] = {}
    seen: set[tuple] = set()

    def add(req_id, kind, field, value, reason, prefix=""):
        key = (req_id, kind, field, value)
        if key in seen or not value:
            return
        seen.add(key)
        pattern_hit = reason.startswith("value looks like")
        basis = "token" if pattern_hit and kind in ("body", "path") else field
        var = by_value.get(value) or _var_name(basis, used, value)
        by_value[value] = var
        findings.append(SecretFinding(f"S{len(findings) + 1:02d}", req_id, kind, field, value, reason, var, prefix))

    for req in rec.requests:
        if request_ids is not None and req.id not in request_ids:
            continue
        for kind, field, value, reason, prefix in _find_in_request(req):
            add(req.id, kind, field, value, reason, prefix)
    for name, value in rec.variables.items():
        if value and "${" not in value and (is_sensitive_name(name) or any(rx.search(value) for _, rx in VALUE_PATTERNS)):
            add(None, "variable", name, value, "sensitive source variable")
    return findings
