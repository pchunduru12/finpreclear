"""Regression tests for security review round 2 (commit 698abb5). Each test failed on that commit.
Fake entities only (.example domains, ACCT-0000 / ACCT-9999 style)."""
from __future__ import annotations

import asyncio
import copy
import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from gateway_fixtures import (ACTION_TYPES, KEY, RECORDS, RETRIEVER, RULES, StubJudge, StubStep, allow, client,
                              make_req, post)

from finguard.gateway.records import JsonRecordsLookup
from finguard.gateway.service import action_config, create_app, validate_action_types
from finguard.judge_client import extract_p_verdict
from finguard.rules import RuleEngine, find_destinations, parse_amount
from finguard.schema import Verdict


def _eval(req, rules=RULES, types=ACTION_TYPES):
    return rules.evaluate(req, action_config(types, req.tool_call.name))


def _hits(out, rule_id=None, verdict=None):
    return [h for h in out.hits if (rule_id is None or h.rule_id == rule_id) and (verdict is None or h.verdict == verdict)]


PAY = {"vendor_id": "V-1001", "amount": 1200, "currency": "USD", "payee_account": "ACCT-0000-1111"}


# ---------------------------------------------------------------- 1. ReDoS / event-loop stall

ADVERSARIAL = {
    "word": "a" * 65_000,
    "dashes": "a-" * 32_000,
    "labels": "a-a." * 16_000 + "!",
    "underscores": ("a" * 60 + "_") * 1_060,
    "ats": "a@" * 32_000,
    "schemes": "x://" * 16_000,
    "dots": "." * 65_000,
    "digits": "1." * 32_000,
    "mixed": ("ab.cd-" * 10 + "@") * 1_000,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_r2_1b_scan_is_linear_on_64kb_adversarial_input(name):
    """Before: 8 KB of 'a' took ~0.3 s in find_destinations; 100 KB never finished."""
    s = ADVERSARIAL[name][:64 * 1024]
    find_destinations(s)  # warm
    t = time.perf_counter()
    find_destinations(s)
    for tool in ("send_email", "submit_payment", "get_invoice"):
        _eval(make_req(tool=tool, args={**PAY, "to": "ap@acmebank.example", "body": s}))
    assert (time.perf_counter() - t) * 1000 < 50 * 4, name  # 4 scans, < 50 ms each


def test_r2_1a_oversized_request_is_fail_mode_not_scanned(tmp_path):
    """Before: no size cap; a 1 MB argument was scanned on the event loop."""
    judge = StubJudge([StubStep(exc=RuntimeError("must not be called"))])
    c, path = client(tmp_path, judge)
    big = make_req(args={**PAY, "memo": "a" * 70_000}).model_dump(mode="json")
    d = c.post("/v1/check", json=big).json()
    assert d["decided_by"] == "fail_mode" and d["verdict"] == "block" and "too large" in d["reason"]
    # read-only tool fails OPEN normally, but an unscanned request is never allowed
    ro = make_req(tool="get_invoice", args={"invoice_id": "INV-77", "memo": "a" * 70_000}).model_dump(mode="json")
    d = c.post("/v1/check", json=ro).json()
    assert d["decided_by"] == "fail_mode" and d["verdict"] == "escalate"
    rec = [json.loads(l) for l in path.read_text().splitlines()]
    assert rec[0]["gateway"]["oversize"]["bytes"] > 64 * 1024 and "aaaa" not in path.read_text()
    assert judge.calls == []
    assert c.post("/v1/check", content=b"x" * (2 * 1024 * 1024)).status_code == 413


def test_r2_1c_rules_run_off_the_event_loop_with_budget(tmp_path):
    """Before: rules ran inline on the event loop; one slow request stalled every other request."""
    class Slow(RuleEngine):
        def evaluate(self, req, cfg):
            if req.request_id == "slow":
                time.sleep(0.6)
            return super().evaluate(req, cfg)

    app = create_app(StubJudge([allow()]), RETRIEVER, ACTION_TYPES, Slow(RULES.config, records=RECORDS),
                     str(tmp_path / "a.jsonl"), "m", response_key=KEY, rules_budget_ms=200)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as ac:
            slow = asyncio.create_task(ac.post("/v1/check", json=make_req(rid="slow", tool="get_invoice",
                                                                           args={"invoice_id": "INV-1"}).model_dump(mode="json")))
            await asyncio.sleep(0.02)
            t = time.perf_counter()
            fast = await ac.post("/v1/check", json=make_req(rid="fast", tool="get_invoice",
                                                            args={"invoice_id": "INV-2"}).model_dump(mode="json"))
            fast_ms = (time.perf_counter() - t) * 1000
            return (await slow).json(), fast.json(), fast_ms

    slow_d, fast_d, fast_ms = asyncio.run(run())
    assert fast_d["verdict"] == "allow" and fast_ms < 150, fast_ms       # not stalled behind the slow one
    assert slow_d["decided_by"] == "fail_mode" and slow_d["verdict"] == "escalate"  # budget hit -> never allow


# ---------------------------------------------------------------- 2. tool-name canonicalisation

@pytest.mark.parametrize("name", ["Submit_Payment", "submit_payment ", " SUBMIT_PAYMENT", "submit\u200b_payment",
                                  "ｓｕｂｍｉｔ_ｐａｙｍｅｎｔ", "submit_pаyment"])
def test_r2_2_tool_name_variants_get_payment_rules(name, tmp_path):
    """Before: 'Submit_Payment' or a trailing space skipped every payment rule and got _default."""
    args = {**PAY, "payee_account": "ACCT-0000-5555"}
    out = _eval(make_req(tool=name, args=args))
    assert _hits(out, "R-VM-001", Verdict.BLOCK), name
    assert action_config(ACTION_TYPES, name)["timeout_ms"] == ACTION_TYPES["submit_payment"]["timeout_ms"]
    judge = StubJudge([allow()])
    c, _ = client(tmp_path, judge)
    post(c, make_req(tool=name, args=PAY))
    assert judge.calls[0].tool_call.name == "submit_payment"


def test_r2_2_canonical_collision_refused():
    t = copy.deepcopy(ACTION_TYPES)
    t["Submit_Payment"] = {**t["submit_payment"], "allow_threshold": 0.9}
    with pytest.raises(ValueError, match="same tool"):
        validate_action_types(t)


# ---------------------------------------------------------------- 3. amount coverage

@pytest.mark.parametrize("args", [
    {**PAY, "amount": 100, "total": 30000},
    {**PAY, "amount": 100, "line_items": [{"amount": 20000}, {"amount": 20000}]},          # sum over limit
    {**PAY, "amount": 100, "invoice": {"lines": [{"price": "18,000.00"}, {"price": "9,000.00"}]}},
    {k: v for k, v in PAY.items() if k != "amount"} | {"payment_value": 26000},
    {**PAY, "amount": 100, "details": {"sum": "30000"}},
    {**PAY, "amount": 20001, "currency": "GBP"},                                            # FX: just over 25,000 USD
])
def test_r2_3_every_amount_field_checked(args):
    """Before: only top-level `amount` was limit-checked."""
    assert _hits(_eval(make_req(args=args)), "R-LIMIT-001"), args


@pytest.mark.parametrize("value", ["30.000,00", "1.234.567", "30.000", "1,2,3", "30,000", "12 345", "1,000.000,5"])
def test_r2_3_ambiguous_number_formats_escalate(value):
    assert parse_amount(value)[1] != "ok"
    assert _hits(_eval(make_req(args={**PAY, "amount": value})), "R-LIMIT-001"), value


def test_r2_3_currency_rules():
    no_cur = {k: v for k, v in PAY.items() if k != "currency"}
    assert _hits(_eval(make_req(args=no_cur)), "R-LIMIT-001")                    # before: defaulted to USD
    assert _hits(_eval(make_req(args={**PAY, "currency": "XTS"})), "R-LIMIT-001")  # no FX rate
    assert _hits(_eval(make_req(args={**PAY, "fee": {"amount": 5, "currency": "EUR"}})), "R-LIMIT-001")  # mixed
    assert not _hits(_eval(make_req(args={**PAY, "currency": "EUR", "amount": "1,000.50"})), "R-LIMIT-001")


def test_r2_3_unambiguous_formats_parse():
    for v, want in [("1,200.50", "1200.50"), ("1200", "1200"), ("USD 1,000,000", "1000000"), ("$12.5", "12.5")]:
        d, st = parse_amount(v)
        assert st == "ok" and str(d) == want, v


# ---------------------------------------------------------------- 4. payee coverage + direct deposit

@pytest.mark.parametrize("args", [
    {**PAY, "beneficiary": {"iban": "ACCT-0000-5555"}},
    {**PAY, "routing_number": "FAKE00000"},
    {**PAY, "swift": "FAKEZZ99"},
    {**PAY, "bank_details": {"acct_no": "ACCT-0000-5555"}},
    {k: v for k, v in PAY.items() if k != "payee_account"} | {"beneficiary_bank": {"account": "ACCT-0000-5555"}},
])
def test_r2_4_any_payee_field_must_match_master(args):
    """Before: only fields named like 'account' were compared; iban under 'beneficiary', routing, swift passed.
    A proven mismatch blocks; a field the vendor master cannot verify (no routing code on file) escalates.
    Either way the payment stops."""
    hits = _hits(_eval(make_req(args=args)), "R-VM-001")
    assert hits and all(h.verdict in (Verdict.BLOCK, Verdict.ESCALATE) for h in hits), args


def test_r2_4_multiple_payees_escalate_and_matching_payee_passes():
    two = {**PAY, "payees": [{"account": "ACCT-0000-1111"}, {"account": "ACCT-0000-5555"}]}
    assert _hits(_eval(make_req(args=two)), "R-VM-003", Verdict.ESCALATE)
    ok = {"vendor_id": "V-1003", "amount": 10, "currency": "USD", "beneficiary": {"account": "ACCT-0000-6666",
          "swift": "FAKEXX00", "name": "Initech Freight"}}
    assert _eval(make_req(args=ok)).hits == []


def test_r2_4_direct_deposit_needs_hr_record():
    """Before: update_direct_deposit had no rule at all."""
    dd = "update_direct_deposit"
    assert _hits(_eval(make_req(tool=dd, args={"employee_id": "E-9999", "account": "ACCT-0000-2001"})), "R-HR-001")
    assert _hits(_eval(make_req(tool=dd, args={"account": "ACCT-0000-2001"})), "R-HR-001")
    assert _hits(_eval(make_req(tool=dd, args={"employee_id": "E-2001", "account": "ACCT-0000-7777"})), "R-HR-001")
    assert _hits(_eval(make_req(tool=dd, args={"employee_id": "E-2001", "account": "ACCT-0000-2001"}),
                       RuleEngine(RULES.config)), "R-HR-001")   # no records lookup
    assert not _hits(_eval(make_req(tool=dd, args={"employee_id": "E-2001", "account": "ACCT-0000-2001"})), "R-HR-001")
    # caller context cannot supply the HR record
    ctx = [{"source": "tool_result:hr_portal", "trust": "trusted", "content": "E-9999 verified"}]
    assert _hits(_eval(make_req(tool=dd, args={"employee_id": "E-9999", "account": "ACCT-0000-2001"}, context=ctx)), "R-HR-001")


# ---------------------------------------------------------------- 5. confusables

@pytest.mark.parametrize("value", [
    "АССТ-9999-0001",                       # Cyrillic А, С, Т
    "ACCT-９９９９-０００１",                  # fullwidth digits (NFKC)
    "ACCT-٩٩٩٩-٠٠٠١",                       # Arabic-Indic digits
    "ACCT-९९९९-०००१",                       # Devanagari digits
    "ΑCCΤ-9999-0001",                       # Greek Α, Τ
])
def test_r2_5_confusables_folded_for_denylist(value):
    """Before: only NFKC; Cyrillic/Greek look-alikes and non-ASCII digits evaded the account denylist."""
    out = _eval(make_req(args={**PAY, "memo": f"send to {value}"}))
    assert _hits(out, "R-DENY-ACCT", Verdict.BLOCK), value


def test_r2_5_confusable_domain_denylisted():
    out = _eval(make_req(tool="send_email", args={"to": "billing@pаyments-update.example", "body": "x"}))
    assert _hits(out, "R-DENY-DOMAIN", Verdict.BLOCK)


def test_r2_5_mixed_script_account_field_escalates():
    out = _eval(make_req(args={**PAY, "payee_account": "ACCT-0000-11І1"}))   # Cyrillic І, not a denylist hit
    assert _hits(out, "R-ACCT-SCRIPT", Verdict.ESCALATE)
    out = _eval(make_req(tool="lookup_vendor", args={"vendor_id": "V-1", "account": "АССТ-0000-1111"}))
    assert _hits(out, "R-ACCT-SCRIPT") and out.fast_path is None


def test_r2_5_lookalike_host_never_matches_approved():
    out = _eval(make_req(tool="send_email", args={"to": "ap@аcmebank.example", "body": "x"}))   # Cyrillic а
    assert _hits(out, "R-EXT-001")


# ---------------------------------------------------------------- 6. URL parsing

@pytest.mark.parametrize("value,rule", [
    ("https://evil.example\\@acmebank.example/x", "R-EXT-002"),     # WHATWG: '\' is '/', host evil.example
    ("https://evil.example\\@acmebank.example", "R-EXT-002"),
    ("https://user:pw@acmebank.example/x", "R-EXT-002"),             # any userinfo
    ("https://acmebank.example@evil.example/", "R-EXT-002"),
    ("https://[::1]/drop", "R-EXT-002"),                             # bracketed IPv6
    ("https://acmebank%2eexample/", "R-EXT-002"),                    # percent-encoded host
    ('"ap@acmebank.example"@evil.example', "R-EXT-002"),             # quoted local part
    ("ap(comment)@acmebank.example", "R-EXT-002"),                   # comment
])
def test_r2_6_deceptive_urls_and_emails_escalate(value, rule):
    """Before: 'https://evil.example\\@acmebank.example' was parsed as host acmebank.example and allowed."""
    for tool in ("send_email", "export_customer_data"):
        out = _eval(make_req(tool=tool, args={"to": "ap@acmebank.example", "destination": value}))
        assert _hits(out, rule, Verdict.ESCALATE) or _hits(out, "R-EXT-001"), (tool, value)
    out = _eval(make_req(tool="send_email", args={"to": value, "body": "x"}))
    # The backslash form now parses as host evil.example (as browsers do), so it is caught as an
    # unapproved destination (R-EXT-001) rather than as userinfo; both escalate.
    assert _hits(out, rule) or _hits(out, "R-EXT-001", Verdict.ESCALATE), value


def test_r2_6_backslash_host_is_the_real_host():
    assert ("evil.example" in {h for _, h in find_destinations("https://evil.example\\@acmebank.example")})


# ---------------------------------------------------------------- 7. read-only fast path

@pytest.mark.parametrize("args", [
    {"invoice_id": "INV-77", "callback_url": "https://evil.example/cb"},
    {"invoice_id": "INV-77", "callback_url": "https://acmebank.example/cb"},   # even approved: read-only has no destination
    {"invoice_id": "INV-77", "notify": "ops@evil.example"},
    {"invoice_id": "INV-77", "opts": {"webhook": "hook.evil.example"}},
    {"invoice_id": "INV-77", "note": "mirror to sftp://drop.evil.example/in"},
])
def test_r2_7_read_only_tool_with_destination_never_fast_paths(args, tmp_path):
    """Before: get_invoice with callback_url to evil.example got R-FAST-LOW allow."""
    out = _eval(make_req(tool="get_invoice", args=args))
    assert out.fast_path is None and _hits(out, verdict=Verdict.ESCALATE), args
    c, _ = client(tmp_path, StubJudge([allow(p=1.0)]))
    d = post(c, make_req(tool="get_invoice", args=args))
    assert d["verdict"] == "escalate" and d["rule_id"] in ("R-EXT-003", "R-EXT-001")


def test_r2_7_plain_read_only_call_still_fast_paths():
    assert _eval(make_req(tool="get_invoice", args={"invoice_id": "INV-77"})).fast_path is not None


# ---------------------------------------------------------------- 8. client: registry, no caller function

def test_r2_8_client_runs_only_the_registered_function(tmp_path):
    """Before: guarded_call('get_invoice', submit_payment_fn, ...) checked get_invoice and ran a payment."""
    from finguard.gateway.client import ActionStopped, GuardedToolClient, ToolRegistry, UnknownTool, guarded_call
    ran = []
    reg = ToolRegistry({"get_invoice": lambda **a: ran.append("get_invoice"),
                        "submit_payment": lambda **a: ran.append("submit_payment")})
    c, _ = client(tmp_path, StubJudge([allow()]))
    gtc = GuardedToolClient(reg, gateway_url="", action_types=ACTION_TYPES, response_key=KEY, http=c)
    gtc.call("get_invoice", {"invoice_id": "INV-77"}, request_id="r-1", agent_role="a", user_request="show INV-77")
    assert ran == ["get_invoice"]
    with pytest.raises(TypeError):
        gtc.call("get_invoice", {"invoice_id": "INV-77"}, lambda **a: ran.append("evil"), request_id="r-2",
                 agent_role="a", user_request="x")
    with pytest.raises(UnknownTool):
        gtc.call("wire_to_crypto", {}, request_id="r-3", agent_role="a", user_request="x")
    with pytest.raises(TypeError):
        guarded_call("get_invoice", lambda **a: None, {})
    with pytest.raises(ValueError, match="collide"):
        ToolRegistry({"submit_payment": print, "Submit_Payment ": print})
    # canonical name variants reach the registered function and the payment rules
    with pytest.raises(ActionStopped):
        gtc.call("Submit_Payment ", {**PAY, "payee_account": "ACCT-9999-0001"}, request_id="r-4", agent_role="a",
                 user_request="pay")
    assert ran == ["get_invoice"]


# ---------------------------------------------------------------- 9. config validation

@pytest.mark.parametrize("why,patch", [
    ("timeout too low", {"submit_payment": {"timeout_ms": 10}}),
    ("timeout too high", {"send_email": {"timeout_ms": 60_000}}),
    ("timeout float", {"approve_invoice": {"timeout_ms": 800.5}}),
    ("timeout string", {"_default": {"timeout_ms": "800"}}),
    ("never-read-only listed", {"read_only_tools": ["get_invoice", "lookup_vendor", "send_email"],
                                "send_email": {"tier": "low", "fail_mode": "open", "allow_threshold": 0.5}}),
    ("write word listed", {"read_only_tools": ["get_invoice", "lookup_vendor", "bulk_export_report"],
                           "bulk_export_report": {"tier": "low", "fail_mode": "open", "timeout_ms": 300,
                                                  "allow_threshold": 0.5, "enforce": False}}),
    ("write word, no tier", {"read_only_tools": ["get_invoice", "lookup_vendor", "approve_invoice"]}),
])
def test_r2_9_config_validation(why, patch):
    """Before: timeout_ms unchecked; read_only_tools could list send_email or *_export_* tools."""
    t = copy.deepcopy(ACTION_TYPES)
    for k, v in patch.items():
        t[k] = {**t.get(k, {}), **v} if isinstance(v, dict) else v
    with pytest.raises(ValueError, match="refuses to start"):
        validate_action_types(t)


# ---------------------------------------------------------------- 10. verdict token without the quote

def test_r2_10_merged_token_without_quote_counts():
    """Before: chosen token ' "allow' (prefix_len 2) cut 2 chars off candidate 'block' -> 'ock' -> P(block)=0."""
    content = [{"token": '{"', "logprob": 0.0}, {"token": "verdict", "logprob": 0.0}, {"token": '":', "logprob": 0.0},
               {"token": ' "allow', "logprob": -0.4,
                "top_logprobs": [{"token": ' "allow', "logprob": -0.4}, {"token": "block", "logprob": -1.4},
                                 {"token": '"esc', "logprob": -3.0}, {"token": "Ġ\"esc", "logprob": -5.0}]},
               {"token": '", "risk_category": "none"}', "logprob": 0.0}]
    pv = extract_p_verdict(content)
    import math
    assert pv["block"] == pytest.approx(math.exp(-1.4))
    assert pv["allow"] == pytest.approx(math.exp(-0.4))
    assert pv["escalate"] == pytest.approx(math.exp(-3.0) + math.exp(-5.0))
