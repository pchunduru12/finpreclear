"""Harness: end-to-end on stub judges, fail-closed accounting, targets on CI bounds."""
import asyncio
import json
from pathlib import Path

import pytest

from fg_train_eval_fixtures import example
from finguard.dataset import write_jsonl
from finguard.eval import harness as H
from finguard.eval import metrics as M
from finguard.eval.stubs import ConstantStubJudge, OracleStubJudge
from finguard.schema import Verdict

REPO = Path(__file__).resolve().parents[1]
TARGETS = json.loads((REPO / "configs" / "targets.json").read_text())
SPLITS = ["test_iid", "test_heldout_family", "test_heldout_workflow", "test_heldout_policy"]


def make_rows(n_per_split=40, fixture=False):
    rows = []
    for s in SPLITS:
        for i in range(n_per_split):
            gold = [Verdict.ALLOW, Verdict.BLOCK, Verdict.ESCALATE, Verdict.ALLOW][i % 4]
            rows.append(example(f"{s}-{i}", gold=gold, split=s, fixture=fixture,
                                workflow="payroll" if s == "test_heldout_workflow" else "ap_invoice",
                                family="inj.new" if s == "test_heldout_family" else "inj.invoice_footer",
                                benign_kind="lookalike" if i % 8 == 0 else "plain"))
    return rows


def run(judge, rows, **kw):
    return asyncio.run(H.run_judge(judge, rows, concurrency=8, **kw))


def test_perfect_stub_records():
    rows = make_rows(8)
    recs = run(OracleStubJudge.from_examples(rows), rows)
    s = M.compute(recs)
    assert s.miss.k == 0 and s.false_alarm.k == 0 and s.invalid.k == 0
    assert s.grounding.k == s.grounding.n > 0


def test_stub_deterministic_and_imperfect():
    rows = make_rows(40)
    a = run(OracleStubJudge.from_examples(rows, accuracy=0.8, seed=1), rows)
    b = run(OracleStubJudge.from_examples(rows, accuracy=0.8, seed=1), rows)
    assert [r.pred_verdict for r in a] == [r.pred_verdict for r in b]
    s = M.compute(a)
    assert 0 < s.miss.k and 0 < s.false_alarm.k


def test_invalid_timeout_error_fail_closed():
    rows = make_rows(10)

    class Boom:
        model_version = "boom"
        async def judge(self, req, timeout_s):
            raise RuntimeError("server down")

    recs = run(Boom(), rows)
    s = M.compute(recs)
    assert s.invalid.k == len(rows) and s.miss.k == 0 and s.false_alarm.k == s.false_alarm.n
    assert s.miss_strict.k == s.miss_strict.n and recs[0].error == "RuntimeError"

    recs = run(OracleStubJudge.from_examples(rows, timeout_rate=1.0), rows)
    assert all(r.error == "timeout" for r in recs)
    recs = run(OracleStubJudge.from_examples(rows, invalid_rate=1.0), rows)
    assert all(r.pred_verdict is None and r.error is None for r in recs)


def test_slow_judge_hits_timeout():
    rows = make_rows(1)[:2]
    recs = run(OracleStubJudge.from_examples(rows, latency_ms=300, sleep=True), rows, timeout_ms=10)
    assert all(r.error == "timeout" and r.latency_ms == 10 for r in recs)


def test_targets_use_ci_bound_not_point():
    rows = make_rows(40)
    sc = H.build_scorecard(run(OracleStubJudge.from_examples(rows), rows), model_version="m", judge_kind="stub",
                           data_hashes={}, card_hashes={}, targets=TARGETS)
    t = {x["id"]: x for x in sc["targets"]}
    # Perfect on 120 held-out stop... rows: 0 misses but the Wilson lower bound is below 95%
    # with this few rows, so the target must FAIL (and say how many rows would be needed).
    assert t["heldout_catch"]["result"] == "FAIL"
    assert t["heldout_catch"]["observed"] < 0.95
    assert t["heldout_catch"]["rows_needed_with_zero_failures"] > 60
    assert t["latency_p95"]["result"] == "PASS"
    assert t["beats_open_baselines"]["result"] == "NOT_EVALUATED"
    # 0 misses on 30 held-out-family attacks still has a CI upper bound ~11% > 2 x 1% floor.
    assert t["unseen_family_transfer"]["result"] == "FAIL"


def test_targets_pass_with_enough_rows():
    rows = make_rows(400)
    sc = H.build_scorecard(run(OracleStubJudge.from_examples(rows), rows), model_version="m", judge_kind="stub",
                           data_hashes={}, card_hashes={}, targets=TARGETS)
    t = {x["id"]: x["result"] for x in sc["targets"]}
    assert t["heldout_catch"] == "PASS" and t["benign_false_alarm"] == "PASS"
    assert t["unseen_family_transfer"] == "PASS"


def test_baseline_comparison():
    rows = make_rows(100)
    ours = H.build_scorecard(run(OracleStubJudge.from_examples(rows), rows), model_version="m", judge_kind="stub",
                             data_hashes={}, card_hashes={}, targets=TARGETS)
    weak = H.build_scorecard(run(OracleStubJudge.from_examples(rows, accuracy=0.6), rows), model_version="b",
                             judge_kind="stub", data_hashes={}, card_hashes={}, targets=TARGETS)
    allow_all = H.build_scorecard(run(ConstantStubJudge(Verdict.ALLOW), rows), model_version="a",
                                  judge_kind="stub", data_hashes={}, card_hashes={}, targets=TARGETS)
    sc = H.build_scorecard(run(OracleStubJudge.from_examples(rows), rows), model_version="m", judge_kind="stub",
                           data_hashes={}, card_hashes={}, targets=TARGETS, baselines={"weak": weak, "allow": allow_all})
    t = {x["id"]: x for x in sc["targets"]}
    assert t["beats_open_baselines"]["result"] == "PASS"
    sc2 = H.build_scorecard(run(OracleStubJudge.from_examples(rows), rows), model_version="m", judge_kind="stub",
                            data_hashes={}, card_hashes={}, targets=TARGETS, baselines={"same": ours})
    assert {x["id"]: x for x in sc2["targets"]}["beats_open_baselines"]["result"] == "FAIL"


def test_cli_end_to_end(tmp_path):
    data = tmp_path / "data"
    write_jsonl(make_rows(12) + [example("tr", split="train")], data / "rows.jsonl")
    (data / "dataset_card.json").write_text('{"name": "fixture"}')
    out = tmp_path / "out"
    assert H.main(["--data", str(data), "--judge", "stub", "--out", str(out), "--stub-accuracy", "0.9"]) == 0
    sc = json.loads((out / "scorecard.json").read_text())
    assert sc["prompt_version"] and sc["model_version"] == "stub-oracle"
    assert "dataset_card.json" in sc["dataset_card_sha256"]
    assert sc["run"]["n_examples"] == 48   # train row excluded
    assert sc["banner"] is None
    md = (out / "scorecard.md").read_text()
    for s in SPLITS:
        assert s in md
    assert "Lookalike false-alarm rate" in md and ("**PASS**" in md or "**FAIL**" in md)
    assert len((out / "records.jsonl").read_text().splitlines()) == 48


def test_cli_refuses_fixtures_unless_flag(tmp_path):
    data = tmp_path / "d"
    write_jsonl(make_rows(2, fixture=True), data / "r.jsonl")
    with pytest.raises(SystemExit):
        H.main(["--data", str(data), "--judge", "stub", "--out", str(tmp_path / "o")])
    H.main(["--data", str(data), "--judge", "stub", "--out", str(tmp_path / "o"), "--allow-fixtures"])
    sc = json.loads((tmp_path / "o" / "scorecard.json").read_text())
    assert sc["banner"] == H.FIXTURE_BANNER
    assert H.FIXTURE_BANNER in (tmp_path / "o" / "scorecard.md").read_text()


def test_vllm_branch_needs_args(tmp_path):
    data = tmp_path / "d"
    write_jsonl(make_rows(1), data / "r.jsonl")
    with pytest.raises(SystemExit):
        H.main(["--data", str(data), "--judge", "vllm", "--out", str(tmp_path / "o")])


def test_policy_fill_uses_retriever(tmp_path):
    rows = make_rows(1)[:1]
    rows[0].request.policy_clauses = []
    H._fill_policies(rows, REPO / "policies" / "sample_policy.jsonl")
    assert rows[0].request.policy_clauses


def test_targets_file_marked_proposed():
    assert all(t["status"] == "proposed, confirm with pilot partner" for t in TARGETS["targets"])
