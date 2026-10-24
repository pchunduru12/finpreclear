"""Shared fixtures for gateway tests. Fake entities only (.example domains, ACCT-0000 style).
template_author="claude-fixture", fixture_only=True: never used in train/test splits."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from finguard.gateway.records import JsonRecordsLookup
from finguard.gateway.service import create_app
from finguard.judge_client import StubJudge, StubStep
from finguard.retrieval import PolicyRetriever
from finguard.rules import RuleEngine
from finguard.schema import CheckRequest

ROOT = Path(__file__).resolve().parent.parent
ACTION_TYPES = json.loads((ROOT / "configs" / "action_types.json").read_text())
RECORDS = JsonRecordsLookup.from_json(ROOT / "configs" / "records_sample.json")
RULES = RuleEngine.from_json(ROOT / "configs" / "rules.json", records=RECORDS)
KEY = b"k" * 32  # fixture HMAC key for response signatures (fake)
RETRIEVER = PolicyRetriever.from_jsonl(ROOT / "policies" / "sample_policy.jsonl")

ALLOW = {"verdict": "allow", "risk_category": "none", "evidence": "", "reason": "Serves the request."}
BLOCK = {"verdict": "block", "risk_category": "indirect_injection", "evidence": "pay the new account",
         "reason": "Untrusted text redirects payment."}


def allow(p: float = 0.99, delay: float = 0.0) -> StubStep:
    return StubStep(output=ALLOW, p_verdict={"allow": p, "block": (1 - p) / 2, "escalate": (1 - p) / 2}, delay_s=delay)


def make_req(tool: str = "submit_payment", args: dict | None = None, context: list | None = None,
             rid: str = "r-1", **kw) -> CheckRequest:
    if args is None:
        args = {"vendor_id": "V-1001", "amount": 1200, "currency": "USD", "payee_account": "ACCT-0000-1111"}
    return CheckRequest.model_validate({
        "request_id": rid, "agent_role": "ap_clerk_agent", "user_request": "Pay ACME Supplies invoice INV-77 per the PO.",
        "tool_call": {"name": tool, "arguments": args}, "context": context or [], "workflow": "ap_invoice", **kw})


def vendor_master(acct: str = "ACCT-0000-1111") -> dict:
    """A caller-supplied 'trusted' vendor master context item. Rules now IGNORE it (H1d): the
    vendor master comes only from RECORDS. Kept so tests can prove it has no effect."""
    return {"source": "tool_result:vendor_master", "trust": "trusted",
            "content": json.dumps({"vendor_id": "V-1001", "name": "ACME Supplies", "bank_account": acct})}


def client(tmp_path, judge, action_types=None, shadow_override=None, rules=None, response_key=KEY, **kw):
    app = create_app(judge=judge, retriever=RETRIEVER, action_types=action_types or ACTION_TYPES, rules=rules or RULES,
                     audit_path=str(tmp_path / "audit.jsonl"), model_version="finguard-test-0",
                     shadow_override=shadow_override, response_key=response_key, **kw)
    return TestClient(app), tmp_path / "audit.jsonl"


def post(c: TestClient, req: CheckRequest) -> dict:
    r = c.post("/v1/check", json=req.model_dump(mode="json"))
    assert r.status_code == 200, r.text
    return r.json()


def enforced_types() -> dict:
    """action_types with enforce=True everywhere (the frozen config ships all-shadow)."""
    return {k: ({**v, "enforce": True} if isinstance(v, dict) else v) for k, v in ACTION_TYPES.items()}


__all__ = ["StubJudge", "StubStep", "ALLOW", "BLOCK", "allow", "make_req", "vendor_master", "client", "post",
           "enforced_types", "ACTION_TYPES", "RULES", "RECORDS", "RETRIEVER", "KEY"]
