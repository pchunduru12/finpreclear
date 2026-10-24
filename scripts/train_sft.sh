#!/usr/bin/env bash
# FinGuard SFT launcher (LLaMA-Factory, full fine-tune).
#   scripts/train_sft.sh [configs/sft_qwen3_4b.yaml] [--allow-dirty]
# Env: DATASET_CARD (default data/dataset_card.json), SFT_DATA (default build/sft), RUNS_DIR (default runs)
#
# Order matters: gate check first (no training before a pilot partner is signed), then the
# run dir + provenance manifest, then training. Nothing trains without a manifest.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m finguard.gates pilot_partner_signed || exit 3

CONFIG="${1:-configs/sft_qwen3_4b.yaml}"
EXTRA=()
[[ "${2:-}" == "--allow-dirty" ]] && EXTRA+=(--allow-dirty)

RUN_DIR="$(python3 -m finguard.train.run_record --kind sft --config "${CONFIG}" \
  --dataset-card "${DATASET_CARD:-data/dataset_card.json}" --data "${SFT_DATA:-build/sft}" \
  --runs-dir "${RUNS_DIR:-runs}" "${EXTRA[@]}")"
echo "run dir: ${RUN_DIR}"

# key=value overrides after the YAML are supported by llamafactory-cli (VERIFY on installed version).
llamafactory-cli train "${CONFIG}" \
  output_dir="${RUN_DIR}/checkpoints" \
  dataset_dir="${SFT_DATA:-build/sft}" \
  2>&1 | tee "${RUN_DIR}/train.log"
