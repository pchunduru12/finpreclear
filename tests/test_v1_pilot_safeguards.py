"""v1 shadow-pilot safeguards: non-executing preview, fail-safe probabilities and the
pilot startup preflight. Fake fixture data only."""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway_fixtures as gf
from finguard import gates
from finguard.gateway import serve
from finguard.gateway.client import ActionStopped, GuardedToolClient, ToolRegistry
from finguard.gateway.service import create_app
from finguard.rules import RuleEngine
from finguard.schema import Verdict

PILOT = ["--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture", "--model-version", "fixture",
         "--policies", "/etc/finpreclear/policies.jsonl", "--records", "/etc/finpreclear/records.json",
         "--redact", "--host", "0.0.0.0", "--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem",
         "--ssl-ca-certs", "ca.pem"]


def _pilot(tmp_path, *extra):
    return serve.parse(PILOT + ["--audit-log", str(tmp_path / "a.jsonl"), *extra])


def _action_types(tmp_path, **override):
    types = {k: ({**v, **override} if isinstance(v, dict) else v) for k, v in gf.ACTION_TYPES.items()}
    path = tmp_path / "action_types.json"
    path.write_text(json.dumps(types))
    return str(path)


def _gates(tmp_path, *open_gates):
    data = {g: {"open": g in open_gates, "signed_by": "human:fixture" if g in open_gates else None,
                "date": None, "evidence": "fixture-evidence" if g in open_gates else None}
            for g in gates.GATE_ORDER}
    path = tmp_path / "gates.json"
    path.write_text(json.dumps(data))
    return path


# --- non-executing preview (demo, trace replay) ---------------------------------------

def _preview(http, ran):
    registry = ToolRegistry({"submit_payment": lambda **kw: ran.append(("payment", kw)),
                             "get_invoice": lambda **kw: ran.append(("invoice", kw))})
    return GuardedToolClient(registry, gateway_url="", action_types=gf.ACTION_TYPES,
                             response_key=gf.KEY, http=http, dry_run=True)


@pytest.mark.parametrize("account,expected", [("ACCT-0000-1111", "allow"), ("ACCT-9999-0001", "block")])
def test_preview_never_runs_a_payment_whatever_the_verdict(tmp_path, account, expected):
    gateway, _ = gf.client(tmp_path, gf.StubJudge([gf.allow()]))
    ran = []
    args = {"vendor_id": "V-1001", "amount": 1200, "currency": "USD", "payee_account": account}
    out = _preview(gateway, ran).call("submit_payment", args, request_id="r1",
                                      agent_role="fixture", user_request="Fixture invoice")
    assert not out.ran and out.result is None and out.decision.verdict.value == expected
    assert ran == []


def test_preview_gateway_outage_never_fails_open():
    def offline(req):
        raise httpx.ConnectError("offline", request=req)
    http = httpx.Client(transport=httpx.MockTransport(offline), base_url="http://localhost")
    types = json.loads(json.dumps(gf.ACTION_TYPES))
    types["get_invoice"]["fail_mode"] = "open"
    ran = []
    client = GuardedToolClient(ToolRegistry({"get_invoice": lambda **kw: ran.append(kw)}), gateway_url="",
                               action_types=types, http=http, response_key=gf.KEY, dry_run=True)
    with pytest.raises(ActionStopped) as exc:
        client.call("get_invoice", {"invoice_id": "INV-77"}, request_id="r2",
                    agent_role="fixture", user_request="Fixture read")
    assert exc.value.verdict == Verdict.ESCALATE and ran == []


# --- unscored allows ----------------------------------------------------------------------

def test_read_only_allow_without_probability_escalates(tmp_path):
    rules = RuleEngine({**gf.RULES.config, "fast_path_low_tier": False}, records=gf.RECORDS)
    step = gf.StubStep(output={"verdict": "allow", "risk_category": "none", "evidence": "", "reason": "ok"},
                       p_verdict={})
    app = create_app(gf.StubJudge([step]), gf.RETRIEVER, gf.ACTION_TYPES, rules,
                     str(tmp_path / "a.jsonl"), "fixture", response_key=gf.KEY)
    d = gf.post(TestClient(app), gf.make_req(tool="get_invoice", args={"invoice_id": "INV-77"}))
    assert d["verdict"] == "escalate" and d["decided_by"] == "threshold"


def test_pilot_launcher_sends_reads_to_the_judge(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGUARD_RESPONSE_KEY", "k" * 40)
    app = serve.build_app(serve.parse(["--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture",
                                       "--model-version", "fixture", "--policies", "policies/sample_policy.jsonl",
                                       "--records", "configs/records_sample.json",
                                       "--audit-log", str(tmp_path / "a.jsonl")]))
    d = gf.post(TestClient(app), gf.make_req(tool="get_invoice", args={"invoice_id": "INV-77"}))
    # No fast-path allow: the (unreachable) judge was consulted, so the fail mode decided.
    assert d["verdict"] == "escalate" and d["decided_by"] == "fail_mode"


# --- pilot startup preflight --------------------------------------------------------------

def test_shadow_pilot_config_passes_static_preflight(tmp_path):
    assert serve.pilot_configuration_error(_pilot(tmp_path)) is None


@pytest.mark.parametrize("drop,expect", [("--redact", "--redact")])
def test_pilot_requires_redaction(tmp_path, drop, expect):
    args = [x for x in PILOT if x != drop] + ["--audit-log", str(tmp_path / "a.jsonl")]
    assert expect in serve.pilot_configuration_error(serve.parse(args))


@pytest.mark.parametrize("flag,path,expect", [
    ("--policies", "policies/sample_policy.jsonl", "policies"),
    ("--policies", "fixtures/policies/alt_policy_v1.jsonl", "policies"),
    ("--records", "configs/records_sample.json", "records"),
])
def test_pilot_refuses_sample_data(tmp_path, flag, path, expect):
    args = _pilot(tmp_path)
    setattr(args, flag.lstrip("-"), str(serve.REPO_ROOT / path))
    assert expect in serve.pilot_configuration_error(args)


def test_pilot_requires_records(tmp_path):
    args = _pilot(tmp_path)
    args.records = None
    assert "records" in serve.pilot_configuration_error(args)


def test_pilot_refuses_model_enforcement(tmp_path):
    args = _pilot(tmp_path, "--action-types", _action_types(tmp_path, enforce=True))
    assert "shadow-only" in serve.pilot_configuration_error(args)


def test_force_shadow_is_the_allowed_emergency_switch(tmp_path):
    args = _pilot(tmp_path, "--action-types", _action_types(tmp_path, enforce=True), "--force-shadow")
    assert serve.pilot_configuration_error(args) is None


def test_pilot_refuses_fail_open(tmp_path):
    types = json.loads(json.dumps(gf.ACTION_TYPES))
    types["get_invoice"]["fail_mode"] = "open"
    path = tmp_path / "open.json"
    path.write_text(json.dumps(types))
    assert "fail-open" in serve.pilot_configuration_error(_pilot(tmp_path, "--action-types", str(path)))


def test_local_dev_is_exempt_from_pilot_checks(tmp_path):
    args = serve.parse(["--judge-url", "http://127.0.0.1:9", "--judge-model", "fixture", "--model-version", "fixture",
                        "--policies", "policies/sample_policy.jsonl", "--audit-log", str(tmp_path / "a.jsonl"),
                        "--insecure-dev"])
    assert serve.pilot_configuration_error(args) is None


def test_closed_gates_stop_pilot_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(gates, "GATES_FILE", _gates(tmp_path))
    monkeypatch.setattr(serve, "build_app", lambda _a: pytest.fail("app must not start with gates closed"))
    assert serve.main(PILOT + ["--audit-log", str(tmp_path / "a.jsonl")]) == 3


def test_pilot_needs_v1_targets_not_release_review(tmp_path, monkeypatch):
    # Gates 1-3 open, the public-release gate closed: the shadow pilot may start.
    monkeypatch.setattr(gates, "GATES_FILE",
                        _gates(tmp_path, "pilot_partner_signed", "teacher_selected", "v1_targets_met"))
    started = []
    monkeypatch.setattr(serve, "build_app", lambda a: started.append(a) or object())
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    assert serve.main(PILOT + ["--audit-log", str(tmp_path / "a.jsonl")]) == 0 and started


def test_targets_gate_alone_is_not_enough(tmp_path, monkeypatch):
    monkeypatch.setattr(gates, "GATES_FILE", _gates(tmp_path, "v1_targets_met"))
    monkeypatch.setattr(serve, "build_app", lambda _a: pytest.fail("earlier gates are closed"))
    assert serve.main(PILOT + ["--audit-log", str(tmp_path / "a.jsonl")]) == 3
