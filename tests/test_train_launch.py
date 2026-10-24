"""Training configs and launchers: gate enforced first, provenance recorded, paper settings present."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from finguard.train.run_record import create_run

REPO = Path(__file__).resolve().parents[1]


def test_sft_yaml_paper_settings():
    for name, model in [("sft_qwen3_4b.yaml", "Qwen/Qwen3-4B"), ("sft_qwen3_8b.yaml", "Qwen/Qwen3-8B")]:
        txt = (REPO / "configs" / name).read_text()
        kv = dict(re.findall(r"^(\w+):\s*([^\s#]+)", txt, re.M))
        assert kv["model_name_or_path"] == model
        assert kv["stage"] == "sft" and kv["finetuning_type"] == "full" and kv["template"] == "qwen3"
        assert float(kv["learning_rate"]) == 1e-5 and float(kv["num_train_epochs"]) == 3
        assert kv["cutoff_len"] == "4096" and kv["bf16"] == "true"
        assert kv["eval_dataset"] == "finguard_sft_dev"
        assert (REPO / kv["deepspeed"]).is_file()
        json.loads((REPO / kv["deepspeed"]).read_text())
        # every setting line is labeled
        for line in txt.splitlines():
            if re.match(r"^(learning_rate|num_train_epochs|stage|finetuning_type|cutoff_len|model_name_or_path):", line):
                assert "[paper]" in line or "[guess]" in line or "[contract]" in line, line


def test_grpo_overrides():
    txt = (REPO / "configs" / "grpo_qwen3_4b.sh").read_text()
    for needle in ["algorithm.adv_estimator=grpo", "actor_rollout_ref.actor.optim.lr=1e-6",
                   "actor_rollout_ref.rollout.name=vllm", "actor_rollout_ref.rollout.n=16",
                   "trainer.total_training_steps=300", "custom_reward_function.path=finguard/train/reward.py",
                   "custom_reward_function.name=compute_score", "data.max_response_length=256",
                   "actor_rollout_ref.actor.use_kl_loss=True"]:
        assert needle in txt, needle
    assert "[paper]" in txt and "[guess]" in txt


def _env_without_gate(tmp_path):
    return dict(os.environ, PYTHONPATH=str(REPO))


@pytest.mark.parametrize("script", ["scripts/train_sft.sh", "scripts/train_grpo.sh"])
def test_launchers_refuse_when_gate_closed(script, tmp_path):
    # configs/gates.json ships with pilot_partner_signed closed.
    env = dict(os.environ, PYTHONPATH=str(REPO), SFT_CHECKPOINT="x", RUNS_DIR=str(tmp_path / "runs"))
    p = subprocess.run(["bash", str(REPO / script)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20)
    assert p.returncode == 3, p.stderr
    assert "REFUSED" in p.stderr
    assert not (tmp_path / "runs").exists()


def test_launchers_check_gate_before_anything():
    for s in ["scripts/train_sft.sh", "scripts/train_grpo.sh"]:
        lines = [l for l in (REPO / s).read_text().splitlines() if l.strip() and not l.startswith("#")]
        first_cmd = [l for l in lines if not l.startswith(("set ", "cd "))][0]
        assert first_cmd == "python3 -m finguard.gates pilot_partner_signed || exit 3"


def test_run_record_manifest(tmp_path):
    card = tmp_path / "dataset_card.json"; card.write_text('{"v": 1}')
    data = tmp_path / "sft"; data.mkdir(); (data / "a.json").write_text("[]")
    run = create_run("grpo", REPO / "configs" / "grpo_qwen3_4b.sh", card, data, tmp_path / "runs",
                     repo=tmp_path, allow_dirty=True)
    m = json.loads((run / "run_manifest.json").read_text())
    assert m["git"]["commit"] is None and m["allow_dirty"] is True
    assert len(m["dataset_card"]["sha256"]) == 64 and len(m["config"]["sha256"]) == 64
    assert str(data / "a.json") in m["data_files"]
    assert m["gates"]["pilot_partner_signed"]["open"] is False
    assert m["reward_config_defaults"]["invalid"] == -3.0
    assert (run / "grpo_qwen3_4b.sh").is_file()


def test_run_record_refuses_unpinned_code(tmp_path):
    card = tmp_path / "c.json"; card.write_text("{}")
    with pytest.raises(SystemExit) as e:
        create_run("sft", REPO / "configs" / "sft_qwen3_4b.yaml", card, card, tmp_path / "runs", repo=tmp_path)
    assert e.value.code == 4
