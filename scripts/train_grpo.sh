#!/usr/bin/env bash
# FinGuard GRPO launcher (VeRL + vLLM rollouts).
#   SFT_CHECKPOINT=runs/<sft run>/checkpoints scripts/train_grpo.sh [configs/grpo_qwen3_4b.sh] [--allow-dirty] [-- extra hydra overrides]
# Env: DATASET_CARD (default data/dataset_card.json), RL_DATA_DIR (default build/rl), RUNS_DIR (default runs)
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m finguard.gates pilot_partner_signed || exit 3

: "${SFT_CHECKPOINT:?set SFT_CHECKPOINT to the SFT checkpoint dir}"
CONFIG="${1:-configs/grpo_qwen3_4b.sh}"; shift || true
EXTRA=()
if [[ "${1:-}" == "--allow-dirty" ]]; then EXTRA+=(--allow-dirty); shift; fi
[[ "${1:-}" == "--" ]] && shift

export RL_DATA_DIR="${RL_DATA_DIR:-build/rl}"
FINGUARD_RUN_DIR="$(python3 -m finguard.train.run_record --kind grpo --config "${CONFIG}" \
  --dataset-card "${DATASET_CARD:-data/dataset_card.json}" --data "${RL_DATA_DIR}" \
  --runs-dir "${RUNS_DIR:-runs}" "${EXTRA[@]}")"
export FINGUARD_RUN_DIR SFT_CHECKPOINT
echo "run dir: ${FINGUARD_RUN_DIR}"
printf '%s\n' "SFT_CHECKPOINT=${SFT_CHECKPOINT}" "overrides=$*" > "${FINGUARD_RUN_DIR}/launch_args.txt"

bash "${CONFIG}" "$@" 2>&1 | tee "${FINGUARD_RUN_DIR}/train.log"
