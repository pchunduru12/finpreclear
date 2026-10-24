"""SFT/RL exporters: format, determinism, and refusal of rows that must not train."""
import json

import pyarrow.parquet as pq
import pytest

from fg_train_eval_fixtures import example
from finguard.dataset import write_jsonl
from finguard.prompt import build_messages
from finguard.schema import RiskCategory, Verdict
from finguard.train import export_rl, export_sft
from finguard.train.common import admission_problem, prompt_seed
from finguard.train.reward import compute_score


def good_rows():
    return [example("a1", gold=Verdict.BLOCK), example("b1"), example("d1", split="dev"),
            example("d2", gold=Verdict.ESCALATE, split="dev", category=RiskCategory.POLICY_VIOLATION)]


def test_sft_export_format(tmp_path):
    m = export_sft.export(good_rows(), tmp_path)
    assert m["counts"] == {"train": 2, "dev": 2}
    recs = json.loads((tmp_path / "finguard_sft_train.json").read_text())
    r = recs[0]
    roles = [x["role"] for x in r["messages"]]
    assert roles == ["system", "user", "assistant"]
    ex = good_rows()[0]
    assert r["messages"][:2] == build_messages(ex.request, seed=prompt_seed(ex.example_id))
    tgt = json.loads(r["messages"][2]["content"])
    assert list(tgt) == ["verdict", "risk_category", "evidence", "reason"]
    assert tgt["verdict"] == "block"
    info = json.loads((tmp_path / "dataset_info.json").read_text())
    assert info["finguard_sft_train"]["formatting"] == "sharegpt"
    assert info["finguard_sft_dev"]["file_name"] == "finguard_sft_dev.json"
    assert info["finguard_sft_train"]["tags"]["system_tag"] == "system"


def test_prompt_seed_stable():
    assert prompt_seed("a1") == prompt_seed("a1") != prompt_seed("a2")
    ex = example("a1")
    assert build_messages(ex.request, seed=prompt_seed("a1")) == build_messages(ex.request, seed=prompt_seed("a1"))


@pytest.mark.parametrize("row,why", [
    (example("t", split="test_iid"), "split"),
    (example("t", split="test_heldout_family"), "split"),
    (example("f", fixture=True), "fixture_only"),
    (example("c", teacher="anthropic/claude-x"), "license"),
    (example("g", teacher="openai/gpt-4o"), "license"),
    (example("l", teacher="meta-llama/Llama-3.1-70B"), "license"),
    (example("u", teacher="some/unlisted-model"), "allowlist"),
    (example("n", teacher=None), "teacher_model"),
    (example("m", author="claude-fixture"), "license"),
    (example("s", source="agentdojo"), "license"),
    (example("x", target=False), "no target"),
])
def test_sft_refuses(row, why, tmp_path):
    with pytest.raises(SystemExit) as e:
        export_sft.export([row], tmp_path)
    assert why in str(e.value)


def test_sft_refuses_mismatched_and_ungrounded_targets(tmp_path):
    ex = example("mm", gold=Verdict.BLOCK)
    ex.target = ex.target.model_copy(update={"verdict": Verdict.ESCALATE})
    assert "disagrees" in admission_problem(ex, need_target=True, need_teacher=True, allow_fixtures=False)
    ex2 = example("ug", gold=Verdict.BLOCK)
    ex2.target = ex2.target.model_copy(update={"evidence": "text that is not in the input at all"})
    assert "does not quote the threat" in admission_problem(ex2, need_target=True, need_teacher=True, allow_fixtures=False)


def test_fixtures_allowed_with_flag_and_recorded(tmp_path):
    m = export_sft.export([example("f", fixture=True)], tmp_path, allow_fixtures=True)
    assert m["fixture_rows_included"] == 1 and m["counts"]["train"] == 1
    # A fixture with a blocked teacher is still refused.
    with pytest.raises(SystemExit):
        export_sft.export([example("f2", fixture=True, teacher="claude-3")], tmp_path, allow_fixtures=True)


def test_skip_rejected_lists_them(tmp_path):
    m = export_sft.export(good_rows() + [example("t", split="test_iid")], tmp_path, skip_rejected=True)
    assert [r["example_id"] for r in m["rejected"]] == ["t"]


def test_sft_cli(tmp_path):
    p = tmp_path / "in.jsonl"
    write_jsonl(good_rows(), p)
    assert export_sft.main(["--in", str(p), "--out", str(tmp_path / "o")]) == 0
    man = json.loads((tmp_path / "o" / "export_manifest.json").read_text())
    assert str(p) in man["inputs"]


def test_rl_export_columns_and_reward_roundtrip(tmp_path):
    m = export_rl.export(good_rows(), tmp_path)
    assert m["counts"] == {"train": 2, "dev": 2}
    t = pq.read_table(tmp_path / "train.parquet").to_pylist()
    r = t[0]
    assert set(r) == {"data_source", "prompt", "ability", "reward_model", "extra_info"}
    assert r["data_source"] == "finguard" and r["ability"] == "judge"
    assert [x["role"] for x in r["prompt"]] == ["system", "user"]
    assert r["reward_model"]["style"] == "rule"
    assert r["extra_info"] == {"example_id": "a1", "split": "train", "attack_family": "inj.invoice_footer",
                               "workflow": "ap_invoice"}
    gtj = json.loads(r["reward_model"]["ground_truth"])
    assert gtj["gold_verdict"] == "block" and "request" in gtj
    # The exported ground truth must drive the reward correctly end to end.
    ex = good_rows()[0]
    sol = ex.target.model_dump_json()
    assert compute_score(r["data_source"], sol, r["reward_model"]["ground_truth"], r["extra_info"]) == pytest.approx(1.2)
    # Same prompt as SFT for the same example (no train/RL skew).
    assert r["prompt"] == build_messages(ex.request, seed=prompt_seed(ex.example_id))


def test_rl_does_not_need_teacher_but_refuses_tests_and_fixtures(tmp_path):
    export_rl.export([example("n", teacher=None, target=False)], tmp_path)
    with pytest.raises(SystemExit):
        export_rl.export([example("t", split="test_iid")], tmp_path)
    with pytest.raises(SystemExit):
        export_rl.export([example("f", fixture=True)], tmp_path)


def test_rl_cli(tmp_path):
    p = tmp_path / "in.jsonl"
    write_jsonl(good_rows(), p)
    assert export_rl.main(["--in", str(p), "--out", str(tmp_path / "o")]) == 0
    assert (tmp_path / "o" / "dev.parquet").exists()
