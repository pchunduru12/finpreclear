"""Metrics: Wilson CIs, fail-closed accounting, slices, sample-size helpers."""
import pytest

from finguard.eval import metrics as M


def rec(i, gold="block", pred="block", split="test_iid", family="inj.a", workflow="ap_invoice",
        benign_kind=None, grounded=True, latency=10.0, cat=None, pred_cat=None):
    attack = gold != "allow"
    return M.EvalRecord(example_id=f"e{i}", split=split, gold_verdict=gold,
                        gold_category=cat or ("indirect_injection" if attack else "none"), is_attack=attack,
                        workflow=workflow, attack_family=family if attack else None,
                        benign_kind=None if attack else (benign_kind or "plain"), pred_verdict=pred,
                        pred_category=pred_cat or ("none" if pred == "allow" else "indirect_injection"),
                        grounded=grounded if pred in ("block", "escalate") else None,
                        latency_ms=latency if pred is not None else None)


def test_wilson_known_values():
    lo, hi = M.wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = M.wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)
    assert M.wilson(0, 0) == (0.0, 1.0)


def test_sample_size_helpers():
    n0 = M.sample_size_for_failures(0, 0.02)
    assert M.wilson(0, n0)[1] <= 0.02 < M.wilson(0, n0 - 1)[1]
    assert 185 <= n0 <= 195  # ~ z^2 / u  (estimate: 189)
    n2 = M.sample_size_for_failures(2, 0.02)
    assert M.wilson(2, n2)[1] <= 0.02 < M.wilson(2, n2 - 1)[1]
    n = M.sample_size_needed(0.01, 0.02)
    assert M.wilson(-(-0.01 * n // 1), n)[1] <= 0.02
    assert n > n2  # a real 1% rate needs far more rows than "2 failures"
    assert M.sample_size_needed(0.0, 0.02) == n0
    with pytest.raises(ValueError):
        M.sample_size_needed(0.03, 0.02)


def test_fail_closed_accounting():
    rs = [rec(1, "block", None), rec(2, "block", "allow"), rec(3, "block", "block"), rec(4, "escalate", "block"),
          rec(5, "allow", None), rec(6, "allow", "allow"), rec(7, "allow", "escalate")]
    s = M.compute(rs)
    assert (s.miss.k, s.miss.n) == (1, 4)              # invalid counted as stop
    assert (s.miss_strict.k, s.miss_strict.n) == (2, 4)  # invalid counted as miss
    assert (s.false_alarm.k, s.false_alarm.n) == (2, 3)  # invalid on benign = false alarm
    assert (s.invalid.k, s.invalid.n) == (2, 7)
    assert s.catch.k == 3
    assert s.confusion_2way["stop"]["stop"] == 3 and s.confusion_2way["allow"]["stop"] == 2
    assert s.confusion_3way["block"]["invalid"] == 1 and s.confusion_3way["escalate"]["block"] == 1
    assert (s.exact_verdict_acc.k, s.exact_verdict_acc.n) == (2, 7)


def test_category_grounding_latency():
    rs = [rec(1, pred_cat="payment_fraud"), rec(2), rec(3, grounded=False),
          rec(4, "allow", "allow", latency=500.0)] + [rec(10 + i, latency=float(i)) for i in range(96)]
    s = M.compute(rs)
    assert s.category_acc.n == 99 and s.category_acc.k == 98
    assert s.grounding.k == 98 and s.grounding.n == 99
    assert s.latency_ms["p99"] >= 95 and s.latency_ms["p50"] <= 50


def test_report_slices():
    rs = [rec(1, split="test_iid"), rec(2, "block", "allow", split="test_heldout_family", family="inj.b"),
          rec(3, "allow", "block", split="test_heldout_workflow", workflow="payroll", benign_kind="lookalike"),
          rec(4, "allow", "allow", split="test_heldout_policy", benign_kind="plain")]
    r = M.report(rs)
    assert set(r["by_split"]) == {"test_iid", "test_heldout_family", "test_heldout_workflow", "test_heldout_policy"}
    assert r["heldout_all"]["n"] == 3
    assert set(r["by_attack_family"]) == {"inj.a", "inj.b"}
    assert r["by_attack_family"]["inj.b"]["miss"]["k"] == 1
    assert set(r["by_workflow"]) == {"ap_invoice", "payroll"}
    assert r["lookalike_false_alarm"]["k"] == 1 and r["lookalike_false_alarm"]["n"] == 1
    assert r["benign_by_kind"]["plain"]["false_alarm"]["k"] == 0


def test_rate_fmt():
    assert M.Rate.of(0, 0).fmt() == "n/a (n=0)"
    assert "1/10" in M.Rate.of(1, 10).fmt()
