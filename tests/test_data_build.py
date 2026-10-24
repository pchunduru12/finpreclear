import json

import pytest

from finguard.data.build import BuildError, build
from finguard.data.label import StubTeacher
from finguard.dataset import read_examples
from _data_helpers import FIXTURE, good_answer


def test_fixture_build_end_to_end(tmp_path):
    card = build(str(FIXTURE), tmp_path, fixtures=True, n_per_template=2, seed=3, created_at="t0")
    assert card["fixture_build"] and card["WARNING"]
    total = sum(c["rows"] for c in card["counts"].values())
    assert total == card["total_rows"] > 0
    rows = [r for s in card["counts"] for r in read_examples(tmp_path / f"{s}.jsonl")]
    benign = sum(r.gold_verdict.value == "allow" for r in rows) / len(rows)
    assert card["benign_share_overall"] == round(benign, 4)
    assert 0 < card["lookalike_share_of_benign"] < 1
    assert all(r.target and r.provenance.fixture_only for r in rows)
    assert card["prompt_version"] and card["retriever_versions"] and len(card["files"]["train"]["sha256"]) == 64
    # deterministic files for same seed + created_at
    card2 = build(str(FIXTURE), tmp_path / "b", fixtures=True, n_per_template=2, seed=3, created_at="t0")
    assert card["files"]["train"]["sha256"] == card2["files"]["train"]["sha256"]


def test_non_fixture_build_refuses_claude_fixture_templates(tmp_path):
    t = StubTeacher(lambda m: "{}")
    with pytest.raises(BuildError, match="refuses templates"):
        build(str(FIXTURE), tmp_path, fixtures=False, teacher=t)


def test_non_fixture_build_with_human_templates(tmp_path):
    src = tmp_path / "human.jsonl"
    lines = [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]
    src.write_text("\n".join(json.dumps({**d, "author": "human:jdoe", "reviewed_by": "human:rreviewer"}) for d in lines))
    from finguard.prompt import build_messages
    from finguard.data.generate import RetrieverPool, generate_all
    from finguard.data.templates import load_templates
    rows = generate_all(load_templates(src), 2, 0, RetrieverPool(), "t0")
    lut = {build_messages(r.request, seed=0)[1]["content"]: r for r in rows}
    allow = json.dumps({"verdict": "allow", "risk_category": "none", "evidence": "", "reason": "ok"})
    def fn(msgs):  # good on everything except one family -> it must be flagged, rows queued
        ex = lut[msgs[1]["content"]]
        return allow if ex.attack_family == "fraud.payee_swap" else good_answer(ex)
    card = build(str(src), tmp_path / "out", fixtures=False, teacher=StubTeacher(fn), n_per_template=2, seed=0, created_at="t0")
    assert card["provenance"]["fixture_only_rows"] == 0
    assert card["labeling"]["by_family"]["fraud.payee_swap"]["flagged"]
    assert any("fraud.payee_swap" in w for w in card["warnings"])
    q = (tmp_path / "out" / "review_queue.jsonl").read_text().splitlines()
    assert len(q) == card["review_queue_rows"] > 0
    assert all(json.loads(l)["failed_filter"] == "stop_class_match" for l in q)
