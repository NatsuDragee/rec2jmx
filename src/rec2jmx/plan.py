"""The reviewable generation plan.

A plan fixes everything the user may review or edit before generation: flow order
(which determines transaction numbers), flow names, which requests are included,
accepted suggestions, secret policy, think time, and host parameterization.
It can be saved as JSON (``rec2jmx inspect --write-plan``), edited, and passed back
(``rec2jmx generate --plan``). The web UI exchanges the same structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import PlanError
from .ir import Recording

SECRET_POLICIES = ("parameterize", "include")
PLAN_VERSION = 1
MAX_THINK_MS = 600_000


@dataclass
class PlanFlow:
    name: str
    request_ids: list[str]


@dataclass
class Plan:
    flows: list[PlanFlow]
    test_plan_name: str = "Recorded scenario"
    secret_policy: str = "parameterize"
    accepted: list[str] = field(default_factory=list)
    think_time: str = "none"  # "none" | "recorded" | "<milliseconds>"
    parameterize_hosts: bool = True
    fingerprint: str = ""

    def execution_order(self) -> list[str]:
        return [rid for f in self.flows for rid in f.request_ids]

    def to_dict(self, request_index: dict[str, str] | None = None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rec2jmxPlan": PLAN_VERSION,
            "recordingFingerprint": self.fingerprint,
            "testPlanName": self.test_plan_name,
            "secretPolicy": self.secret_policy,
            "thinkTime": self.think_time,
            "parameterizeHosts": self.parameterize_hosts,
            "acceptSuggestions": list(self.accepted),
            "flows": [{"name": f.name, "requests": list(f.request_ids)} for f in self.flows],
        }
        if request_index:
            d["_requestIndex"] = dict(request_index)  # informational; ignored when loading
        return d


def parse_think_time(value: Any) -> str:
    s = str(value).strip().lower()
    if s in ("none", "recorded"):
        return s
    if s.isdigit() and 0 <= int(s) <= MAX_THINK_MS:
        return str(int(s))
    raise PlanError(f"Invalid think time {str(value)[:20]!r}: use 'none', 'recorded', or milliseconds (0-{MAX_THINK_MS}).")


def validate_plan(plan: Plan, rec: Recording, acceptable_ids: set[str], all_suggestion_ids: set[str]) -> None:
    if plan.fingerprint and rec.fingerprint and plan.fingerprint != rec.fingerprint:
        raise PlanError("The plan was created for a different recording (fingerprint mismatch). "
                        "Re-run 'inspect --write-plan' on this file.")
    if plan.secret_policy not in SECRET_POLICIES:
        raise PlanError(f"secretPolicy must be one of {', '.join(SECRET_POLICIES)}.")
    plan.think_time = parse_think_time(plan.think_time)
    if not plan.flows:
        raise PlanError("The plan has no flows.")
    known = {r.id for r in rec.requests}
    seen: set[str] = set()
    for i, f in enumerate(plan.flows, start=1):
        if not isinstance(f.name, str) or not f.name.strip():
            raise PlanError(f"Flow {i} has no name.")
        if not f.request_ids:
            raise PlanError(f"Flow {i} ('{f.name[:40]}') has no requests; remove it or add requests.")
        for rid in f.request_ids:
            if rid not in known:
                raise PlanError(f"Flow {i} references unknown request id '{str(rid)[:20]}'.")
            if rid in seen:
                raise PlanError(f"Request '{rid}' appears more than once in the plan.")
            seen.add(rid)
    for sid in plan.accepted:
        if sid not in all_suggestion_ids:
            raise PlanError(f"Unknown suggestion id '{str(sid)[:20]}'.")
        if sid not in acceptable_ids:
            raise PlanError(f"Suggestion '{sid}' is informational (no recorded source) and cannot be accepted.")


def plan_from_dict(data: Any) -> Plan:
    if not isinstance(data, dict) or data.get("rec2jmxPlan") != PLAN_VERSION:
        raise PlanError(f'Not a rec2jmx plan (expected "rec2jmxPlan": {PLAN_VERSION}).')
    flows_raw = data.get("flows")
    if not isinstance(flows_raw, list):
        raise PlanError("Plan 'flows' must be an array.")
    flows = []
    for i, f in enumerate(flows_raw, start=1):
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("requests"), list):
            raise PlanError(f"Plan flow {i} must be an object with 'name' (string) and 'requests' (array).")
        if not all(isinstance(r, str) for r in f["requests"]):
            raise PlanError(f"Plan flow {i}: request ids must be strings.")
        flows.append(PlanFlow(f["name"], list(f["requests"])))
    accepted = data.get("acceptSuggestions", [])
    if not isinstance(accepted, list) or not all(isinstance(a, str) for a in accepted):
        raise PlanError("Plan 'acceptSuggestions' must be an array of suggestion ids.")
    name = data.get("testPlanName", "Recorded scenario")
    if not isinstance(name, str):
        raise PlanError("Plan 'testPlanName' must be a string.")
    hosts = data.get("parameterizeHosts", True)
    if not isinstance(hosts, bool):
        raise PlanError("Plan 'parameterizeHosts' must be true or false.")
    return Plan(
        flows=flows,
        test_plan_name=name[:120] or "Recorded scenario",
        secret_policy=str(data.get("secretPolicy", "parameterize")),
        accepted=accepted,
        think_time=parse_think_time(data.get("thinkTime", "none")),
        parameterize_hosts=hosts,
        fingerprint=str(data.get("recordingFingerprint", "")),
    )


def reorder_flows(plan: Plan, order: list[int]) -> None:
    """Reorder flows by 1-based indices (must be a permutation)."""
    n = len(plan.flows)
    if sorted(order) != list(range(1, n + 1)):
        raise PlanError(f"--flow-order must list each flow number 1..{n} exactly once (got {order}).")
    plan.flows = [plan.flows[i - 1] for i in order]
