"""Produce a static beta readiness report; never opens gates or touches payment APIs."""
from __future__ import annotations

import json
from pathlib import Path

from finguard import gates
from finguard.gateway.service import action_config, validate_action_types, tool_entries


def collect(repo: Path) -> dict:
    cfg = json.loads((repo / "configs/action_types.json").read_text())
    gate_state = gates.load(repo / "configs/gates.json")
    problems = []
    try:
        validate_action_types(cfg)
    except (ValueError, TypeError) as exc:
        problems.append(f"action configuration invalid: {type(exc).__name__}")
    entries = {"_default": cfg.get("_default", {}), **tool_entries(cfg)}
    if any(v.get("enforce") is not True for v in entries.values()):
        problems.append("action config contains shadow/un-enforced tools")
    if any(v.get("fail_mode") == "open" for v in entries.values()):
        problems.append("action config contains fail-open tools")
    if any(not (v.get("open") and v.get("signed_by") and v.get("evidence"))
           for v in gate_state.values()):
        problems.append("one or more human approval gates are closed")
    if any(action_config(cfg, tool).get("fail_mode") != "escalate"
           for tool in ("get_invoice", "lookup_vendor")):
        problems.append("financial read-tool judge failure escalation is not configured")
    return {
        "mode": "static_repository_preflight",
        "production_beta_authorized": False,
        "automated_checks_only": True,
        "all_release_gates_open": not any("gate" in p for p in problems),
        "blockers": problems + [
            "Trained-model validation, client/tenant authorization, bank integration, external security review and actual mTLS handshake cannot be proven by this static report"
        ],
    }


def main() -> None:
    print(json.dumps(collect(Path(__file__).resolve().parents[1]), indent=2))


if __name__ == "__main__":
    main()
