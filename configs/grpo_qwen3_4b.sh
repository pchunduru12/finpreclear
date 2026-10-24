#!/usr/bin/env bash
# FinGuard GRPO, stage 2 of 2 (after SFT). VeRL main_ppo hydra overrides.
# Launch ONLY via scripts/train_grpo.sh, which checks the gate, records provenance and
# sets the variables below. Running this file directly is refused.
#
# Legend:  [paper] = starting setting from arXiv 2610.31483 (Meta/CMU, transferable tool selection)
#          [guess] = our choice, tune on dev; record any change in the run dir
#          [contract] = forced by FinGuard contract / serving setup
# Key names follow VeRL's ppo_trainer.yaml (v0.4/v0.5 era). VERIFY against the installed
# VeRL version before the first run; hydra fails loudly on unknown keys, which is good.
set -euo pipefail

: "${FINGUARD_RUN_DIR:?launch via scripts/train_grpo.sh (gate check + provenance)}"
: "${SFT_CHECKPOINT:?path to the SFT checkpoint (HF format) to start RL from}"
RL_DATA_DIR="${RL_DATA_DIR:-build/rl}"       # from: python -m finguard.train.export_rl --out build/rl
N_GPUS="${N_GPUS:-8}"
NNODES="${NNODES:-1}"

python3 -m verl.trainer.main_ppo \
  algorithm.adv_estimator=grpo \
  algorithm.use_kl_in_reward=False \
  data.train_files="${RL_DATA_DIR}/train.parquet" \
  data.val_files="${RL_DATA_DIR}/dev.parquet" \
  data.prompt_key=prompt \
  data.train_batch_size=64 \
  data.max_prompt_length=3840 \
  data.max_response_length=256 \
  data.filter_overlong_prompts=True \
  data.truncation=error \
  +data.apply_chat_template_kwargs.enable_thinking=False \
  actor_rollout_ref.model.path="${SFT_CHECKPOINT}" \
  actor_rollout_ref.model.use_remove_padding=True \
  actor_rollout_ref.model.enable_gradient_checkpointing=True \
  actor_rollout_ref.actor.optim.lr=1e-6 \
  actor_rollout_ref.actor.ppo_mini_batch_size=32 \
  actor_rollout_ref.actor.ppo_micro_batch_size_per_gpu=4 \
  actor_rollout_ref.actor.use_kl_loss=True \
  actor_rollout_ref.actor.kl_loss_coef=0.001 \
  actor_rollout_ref.actor.kl_loss_type=low_var_kl \
  actor_rollout_ref.actor.entropy_coeff=0 \
  actor_rollout_ref.actor.fsdp_config.param_offload=False \
  actor_rollout_ref.actor.fsdp_config.optimizer_offload=False \
  actor_rollout_ref.rollout.name=vllm \
  actor_rollout_ref.rollout.n=16 \
  actor_rollout_ref.rollout.temperature=1.0 \
  actor_rollout_ref.rollout.tensor_model_parallel_size=1 \
  actor_rollout_ref.rollout.gpu_memory_utilization=0.6 \
  actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=8 \
  actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=8 \
  actor_rollout_ref.ref.fsdp_config.param_offload=True \
  reward_model.enable=False \
  reward_model.reward_manager=naive \
  custom_reward_function.path=finguard/train/reward.py \
  custom_reward_function.name=compute_score \
  trainer.total_training_steps=300 \
  trainer.total_epochs=100 \
  trainer.critic_warmup=0 \
  trainer.n_gpus_per_node="${N_GPUS}" \
  trainer.nnodes="${NNODES}" \
  trainer.save_freq=50 \
  trainer.test_freq=25 \
  trainer.val_before_train=True \
  trainer.project_name=finguard \
  trainer.experiment_name="$(basename "${FINGUARD_RUN_DIR}")" \
  trainer.default_local_dir="${FINGUARD_RUN_DIR}/checkpoints" \
  trainer.logger='[console]' \
  "$@"

# Value notes (one line per non-obvious setting):
#  adv_estimator=grpo ............ [paper] GRPO, no critic
#  actor.optim.lr=1e-6 ........... [paper]
#  rollout.name=vllm ............. [paper] vLLM rollouts
#  rollout.n=16 .................. [paper] 16 rollouts per prompt (group size)
#  total_training_steps=300 ...... [paper] "~300 steps"; total_epochs is only an upper bound
#  max_response_length=256 ....... [guess] output is one short JSON (~60-150 tokens); 256 leaves
#                                  room but truncated output parses as invalid -> -3, so watch
#                                  the truncation rate in logs
#  max_prompt_length=3840 ........ [guess] = SFT cutoff_len 4096 - 256; truncation=error so an
#                                  over-long prompt fails loudly instead of silently dropping policy text
#  enable_thinking=False ......... [contract] matches serving (judge_client) and SFT; key exists only
#                                  in newer VeRL - VERIFY, else bake into the tokenizer chat template
#  train_batch_size=64 ........... [guess] 64 prompts x 16 rollouts = 1024 samples/step
#  ppo_mini_batch_size=32 ........ [guess] 2 actor updates per step
#  use_kl_loss / 0.001 / low_var_kl [guess] standard VeRL GRPO example values; KL in loss, not reward
#  entropy_coeff=0 ............... [guess]
#  temperature=1.0 ............... [guess] rollout diversity; eval/serving uses temperature 0
#  gpu_memory_utilization=0.6 .... [guess]
#  save_freq / test_freq ......... [guess]
#  reward = finguard/train/reward.py:compute_score, RewardConfig defaults (invalid=-3, miss=-3,
#  false alarm=-1, block<->escalate=+0.5, category +0.2). Override with
#  custom_reward_function.reward_kwargs.<field>=<value>; scripts/train_grpo.sh records the
#  effective RewardConfig in the run dir.
