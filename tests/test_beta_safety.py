"""Controlled beta preview and launch-security regressions; uses only fake fixture data."""
from __future__ import annotations

import json
import httpx
import pytest
from fastapi.testclient import TestClient

import gateway_fixtures as gf
from finguard.gateway.client import ActionStopped, GuardedToolClient, ToolRegistry
from finguard.gateway import serve
from finguard.rules import RuleEngine
from finguard.schema import Verdict


def _preview(http, ran):
    registry = ToolRegistry({
        "submit_payment": lambda **kw: ran.append(("payment", kw)),
        "get_invoice": lambda **kw: ran.append(("invoice", kw)),
    })
    return GuardedToolClient(registry, gateway_url="", action_types=gf.ACTION_TYPES,
                             response_key=gf.KEY, http=http, dry_run=True)


@pytest.mark.parametrize("account,expected", [
    ("ACCT-0000-1111", "allow"),
    ("ACCT-9999-0001", "block"),
])
def test_preview_never_executes_financial_write_even_if_allowed(tmp_path, account, expected):
    # Test the actual signed gateway response, not a fabricated local verdict.
    gateway, _ = gf.client(tmp_path, gf.StubJudge([gf.allow()]))
    ran = []
    client = _preview(gateway, ran)
    args = {"vendor_id": "V-1001", "amount": 1200, "currency": "USD", "payee_account": account}
    decision = client.call("submit_payment", args, request_id="beta-r1",
                           agent_role="test_fixture", user_request="Synthetic invoice")
    assert not decision.ran and decision.result is None and decision.shadow
    assert decision.decision is not None and decision.decision.verdict.value == expected
    assert ran == []


def test_preview_does_not_execute_read_tool_even_if_rules_fast_path(tmp_path):
    gateway, _ = gf.client(tmp_path, gf.StubJudge([gf.allow()]))
    ran = []
    result = _preview(gateway, ran).call("get_invoice", {"invoice_id": "INV-77"},
                                        request_id="r2", agent_role="fixture", user_request="Read test invoice")
    assert result.decision.verdict == Verdict.ALLOW and not result.ran and ran == []


def test_preview_gateway_outage_never_uses_fail_open():
    def offline(req):
        raise httpx.ConnectError("offline", request=req)
    http = httpx.Client(transport=httpx.MockTransport(offline), base_url="http://localhost")
    action_types = json.loads(json.dumps(gf.ACTION_TYPES))
    action_types["get_invoice"]["fail_mode"] = "open"  # malicious old fixture configuration
    ran = []
    registry = ToolRegistry({"get_invoice": lambda **kw: ran.append(kw)})
    client = GuardedToolClient(registry, gateway_url="", action_types=action_types,
                               http=http, response_key=gf.KEY, dry_run=True)
    with pytest.raises(ActionStopped) as exc:
        client.call("get_invoice", {"invoice_id": "INV-77"}, request_id="r3",
                    agent_role="fixture", user_request="Read fixture")
    assert exc.value.verdict == Verdict.ESCALATE and ran == []


def test_low_risk_model_allow_without_probabilities_escalates(tmp_path):
    rules = RuleEngine({**gf.RULES.config, "fast_path_low_tier": False})
    step = gf.StubStep(output={"verdict": "allow", "risk_category": "none",
                                "evidence": "", "reason": "all good"}, p_verdict={})
    from finguard.gateway.service import create_app
    app = create_app(gf.StubJudge([step]), gf.RETRIEVER, gf.ACTION_TYPES,
                     rules, str(tmp_path / "a.jsonl"), "fixture", response_key=gf.KEY)
    d = gf.post(TestClient(app), gf.make_req(tool="get_invoice", args={"invoice_id": "INV-77"}))
    assert d["verdict"] == "escalate" and d["decided_by"] == "threshold"


def test_production_launcher_disables_read_only_fast_path(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGUARD_RESPONSE_KEY", "k" * 40)
    args = serve.parse([
        "--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture",
        "--model-version", "fixture-v1", "--policies", "policies/sample_policy.jsonl",
        "--records", "configs/records_sample.json",
        "--audit-log", str(tmp_path / "audit.jsonl")])
    app = serve.build_app(args)  # direct fixture test; main() enforces production startup gates
    d = gf.post(TestClient(app), gf.make_req(tool="get_invoice", args={"invoice_id": "INV-77"}))
    assert d["verdict"] == "escalate" and d["decided_by"] == "fail_mode"


def test_production_sample_data_refused_at_transport_preflight():
    args = serve.parse([
        "--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture",
        "--model-version", "fixture", "--policies", "policies/sample_policy.jsonl",
        "--records", "configs/records_sample.json", "--audit-log", "audit.jsonl",
        "--redact", "--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem",
        "--ssl-ca-certs", "ca.pem"])
    assert "sample financial policy" in serve.transport_configuration_error(args)


def test_unapproved_production_gates_block_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGUARD_RESPONSE_KEY", "k" * 40)
    args = [
        "--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture",
        "--model-version", "fixture", "--policies", "/etc/finpreclear/policies.jsonl",
        "--records", "/etc/finpreclear/records.json", "--audit-log", str(tmp_path / "a.jsonl"),
        "--redact", "--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem",
        "--ssl-ca-certs", "ca.pem"]
    assert serve.main(args) == 3  # no gate or model run is opened by this test
