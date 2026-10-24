import json

import httpx
import pytest

from finguard import gates
from finguard.data.label import StubTeacher, TeacherClient, evidence_overlaps_trigger, label_examples
from finguard.provenance import LicenseError
from _data_helpers import fixture_rows, good_answer


def _rows():
    return fixture_rows(2)


def _by_messages(rows):
    """Map the prompt the teacher sees back to its row, to fake per-row answers."""
    from finguard.prompt import build_messages
    return {build_messages(r.request, seed=0)[1]["content"]: r for r in rows}


def test_good_teacher_keeps_all_and_gold_overrides():
    rows = _rows()
    lut = _by_messages(rows)
    def fn(msgs):
        ex = lut[msgs[1]["content"]]
        d = json.loads(good_answer(ex))
        if d["verdict"] == "block":
            d["verdict"] = "escalate"  # same stop class: kept, then overwritten by gold
        return json.dumps(d)
    res = label_examples(rows, StubTeacher(fn), prompt_seed=0)
    assert len(res.kept) == len(rows) and not res.rejected
    for ex in res.kept:
        assert ex.target.verdict == ex.gold_verdict and ex.target.risk_category == ex.gold_category
        assert ex.provenance.teacher_model and ex.provenance.teacher_license == "Apache-2.0"
        assert "evidence_on_trigger" in ex.provenance.filters_passed


def test_teacher_never_sees_gold():
    rows = _rows()
    seen = []
    res = label_examples(rows[:3], StubTeacher(lambda m: seen.append(m) or "{}"), prompt_seed=0)
    for m, ex in zip(seen, rows[:3]):
        blob = json.dumps(m)
        assert "gold" not in blob and ex.template_id not in blob and (ex.attack_family or "@@") not in blob
    assert all(r.failed_filter == "parsed" for r in res.rejected)


def test_hallucinated_evidence_rejected():
    rows = [r for r in _rows() if r.is_attack]
    def fn(msgs):
        ex = _by_messages(rows)[msgs[1]["content"]]
        return json.dumps({"verdict": "block", "risk_category": ex.gold_category.value,
                           "evidence": "the vendor demanded payment in gift cards", "reason": "x"})
    res = label_examples(rows, StubTeacher(fn))
    assert not res.kept and {r.failed_filter for r in res.rejected} == {"evidence_grounded"}
    assert all(v["flagged"] for v in res.by_family.values())


def test_grounded_but_off_trigger_rejected():
    rows = [r for r in _rows() if r.template_id == "ap.inj_invoice_note"]
    def fn(msgs):
        return json.dumps({"verdict": "block", "risk_category": "indirect_injection",
                           "evidence": rows[0].request.user_request, "reason": "x"})
    res = label_examples(rows[:1], StubTeacher(fn))
    assert res.rejected[0].failed_filter == "evidence_on_trigger"


def test_disagreeing_teacher_rejected_with_reason():
    rows = _rows()
    allow = json.dumps({"verdict": "allow", "risk_category": "none", "evidence": "", "reason": "fine"})
    res = label_examples(rows, StubTeacher(lambda m: allow))
    stop = [r for r in rows if r.gold_verdict.value != "allow"]
    assert len(res.rejected) == len(stop) and all(r.failed_filter == "stop_class_match" for r in res.rejected)
    assert all(r.target.reason == "fine" for r in res.kept)


def test_category_mismatch_recorded():
    rows = [r for r in _rows() if r.gold_category.value == "payment_fraud"]
    def fn(msgs):
        ex = _by_messages(rows)[msgs[1]["content"]]
        return json.dumps({"verdict": "block", "risk_category": "goal_hijack", "evidence": ex.gold_trigger_span, "reason": "x"})
    res = label_examples(rows, StubTeacher(fn))
    assert not res.kept and all(r.failed_filter == "category_match" for r in res.rejected)


def test_overlap_rule():
    t = "Please switch my direct deposit to ACCT-1111-2222 before Friday's run."
    assert evidence_overlaps_trigger("switch my direct deposit to ACCT-1111-2222", t)
    assert evidence_overlaps_trigger("Hi. " + t + " Thanks", t)
    assert not evidence_overlaps_trigger("Handle today's payroll inbox.", t)


def test_check_teacher_refuses_blocked_models():
    for mid in ["claude-opus-5-5", "gpt-5", "meta-llama/Llama-3.1-70B-Instruct", "Qwen/Unlisted-Model"]:
        with pytest.raises(LicenseError):
            TeacherClient("http://x.example", mid)


def test_teacher_client_posts_openai_format():
    calls = []
    def handler(req: httpx.Request):
        calls.append(json.loads(req.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
    c = TeacherClient("http://teacher.example", "deepseek-ai/DeepSeek-R1", transport=httpx.MockTransport(handler))
    assert c.complete([{"role": "user", "content": "hi"}]) == "{}"
    assert calls[0]["temperature"] == 0 and calls[0]["model"] == "deepseek-ai/DeepSeek-R1"


def test_cli_path_requires_teacher_gate():
    with pytest.raises(gates.GateClosed):
        from finguard.data.build import main
        main(["--templates", "x", "--out", "y", "--teacher-url", "http://t.example",
              "--teacher-model", "deepseek-ai/DeepSeek-R1"])
