"""JMeter element naming and numbering.

* Transaction Controller: ``TX_<nn>_<flow-name>``, numbered across flows from 01 in the
  order the flows are presented (the plan order).
* Sampler: ``TX_<nn>_A<nn>_<api-path>``. API numbers restart at A01 for every flow and
  follow request order within the flow.
* Numbers are zero-padded to at least two digits (three if there are 100+ items).
* ``<api-path>`` comes from the URL path only. Query strings are never part of names.
  Segments that look like identifiers or secrets (numbers, UUIDs, long hex/base64
  tokens, JWTs, segments with 6+ digits, and known secret or dynamic values) become ``id``. ``{id}``/``:id``/``${id}``
  templates keep their parameter name. Other characters become ``_``.
* The numbers already make every name unique; a deterministic ``_2``, ``_3`` suffix is
  added only as a safety net if two final names ever collide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

MAX_FLOW_NAME = 40
MAX_PATH_LABEL = 60

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_TEMPLATE_RE = re.compile(r"^(?:\{([^{}]+)\}|:([A-Za-z_]\w*)|\$\{([^{}]+)\}|\{\{([^{}]+)\}\})$")


@dataclass
class NamedSampler:
    request_id: str
    name: str


@dataclass
class NamedFlow:
    flow_name: str  # as entered/derived (display)
    tx_name: str
    samplers: list[NamedSampler]


def _clean(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")


def sanitize_flow_name(name: str) -> str:
    cleaned = _clean(name or "")
    return cleaned[:MAX_FLOW_NAME].rstrip("_") or "Flow"


def _looks_like_id(seg: str) -> bool:
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg) or _HEX_RE.match(seg):
        return True
    if seg.startswith("eyJ") and seg.count(".") >= 2:
        return True
    if len(seg) >= 20 and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg):
        return True
    if re.fullmatch(r"\d+[-_.]\d+([-_.]\d+)*", seg):  # 2026-01-02, 1.2.3
        return True
    if sum(c.isdigit() for c in seg) >= 6:  # ord-20260115-0001
        return True
    return False


def path_label(path: str, secret_values: frozenset[str] | set[str] = frozenset()) -> str:
    raw = path.split("?", 1)[0].split("#", 1)[0]
    if re.match(r"^\$\{[^}]+\}", raw):  # unresolved origin variable prefix
        raw = re.sub(r"^\$\{[^}]+\}", "", raw)
    labels = []
    for seg in raw.split("/"):
        if not seg:
            continue
        seg = unquote(seg)
        m = _TEMPLATE_RE.match(seg)
        if m:
            name = next(g for g in m.groups() if g)
            labels.append(_clean(name) or "id")
            continue
        if seg in secret_values or any(s and len(s) >= 6 and s in seg for s in secret_values) or _looks_like_id(seg):
            labels.append("id")
            continue
        c = _clean(seg)
        if c:
            labels.append(c)
    label = "_".join(labels) or "root"
    if len(label) > MAX_PATH_LABEL:
        cut = label[-MAX_PATH_LABEL:]
        if "_" in cut[1:]:
            cut = cut[cut.index("_") + 1:]
        label = cut.strip("_") or label[:MAX_PATH_LABEL]
    return label


def _width(count: int) -> int:
    return max(2, len(str(count)))


def assign_names(flows: list[tuple[str, list[tuple[str, str]]]],
                 secret_values: frozenset[str] | set[str] = frozenset()) -> list[NamedFlow]:
    """flows: [(flow_name, [(request_id, path), ...]), ...] in presentation order."""
    tx_w = _width(len(flows))
    used: set[str] = set()

    def unique(name: str) -> str:
        if name not in used:
            used.add(name)
            return name
        n = 2
        while f"{name}_{n}" in used:
            n += 1
        used.add(f"{name}_{n}")
        return f"{name}_{n}"

    out = []
    for t, (flow_name, reqs) in enumerate(flows, start=1):
        tx_prefix = f"TX_{t:0{tx_w}d}"
        tx_name = unique(f"{tx_prefix}_{sanitize_flow_name(flow_name)}")
        a_w = _width(len(reqs))
        samplers = [
            NamedSampler(rid, unique(f"{tx_prefix}_A{a:0{a_w}d}_{path_label(path, secret_values)}"))
            for a, (rid, path) in enumerate(reqs, start=1)
        ]
        out.append(NamedFlow(flow_name, tx_name, samplers))
    return out
