# FinGuard v1 — action judge

Small open-weight model plus gateway that checks every tool call a bank's AI agent is about to make, and returns allow / block / escalate with risk category, exact-quote evidence, a one-line reason and a calibrated confidence.

Status: code and pipelines built and tested on CPU with fixture data. **No model trained.** Training is blocked by the `pilot_partner_signed` gate.

## Layout
| Path | What |
|---|---|
| `finguard/schema.py` | Input/output contract, evidence grounding, strict output parser |
| `finguard/prompt.py` | The one judge prompt (train = eval = serve), nonce-delimited untrusted content |
| `finguard/retrieval.py` | BM25 policy-clause retrieval, shared by data and serving |
| `finguard/provenance.py` | Teacher/source/author license guards, provenance record |
| `finguard/gates.py` | Plan gates enforced in code |
| `finguard/data/` | Templates → scenarios → teacher labels → gold filter → family/workflow/policy splits → dataset card |
| `finguard/train/` | Reward (GRPO), SFT/RL exporters, run records |
| `finguard/eval/` | Metrics with Wilson CIs, harness + scorecard, open-guard baselines |
| `finguard/rules.py`, `finguard/judge_client.py`, `finguard/gateway/` | Deterministic rules, vLLM judge client (logprob confidence), FastAPI gateway, hash-chained audit log |
| `configs/` | Action types and fail modes, rules, gates, splits, targets, LLaMA-Factory/VeRL configs, serving notes |
| `.claude/agents/` | The agent team that operates this repo (see CLAUDE.md for their hard rules) |
| `fixtures/` | Model-drafted test fixtures. Never training data. |

## Quick start (CPU, fixtures)
```bash
pip install pydantic fastapi uvicorn httpx pyarrow pytest
python -m pytest -q tests
python -m finguard.data.build --templates fixtures/templates_fixture.jsonl --out build/data --fixtures
python -m finguard.train.export_sft --in build/data/train.jsonl build/data/dev.jsonl --out build/sft --allow-fixtures
python -m finguard.train.export_rl  --in build/data/train.jsonl build/data/dev.jsonl --out build/rl  --allow-fixtures
python -m finguard.eval.harness --data build/data --judge stub --out build/eval --allow-fixtures
bash scripts/train_sft.sh   # refuses: pilot_partner_signed gate closed
```

## Real run (after gates open)
1. Security engineer writes templates (`author: human:<id>`); domain lead writes the bank's policy clauses.
2. Self-host the chosen teacher with vLLM; set `teacher_selected` gate; `python -m finguard.data.build --teacher-url ... --teacher-model ...`.
3. `scripts/train_sft.sh` → `scripts/train_grpo.sh` on one 8×A100/H100 node.
4. `python -m finguard.eval.harness --judge vllm --base-url ... --baseline-scorecard ...`.
5. Gateway in shadow mode (`enforce: false`) at the pilot partner; flip per tool only after targets hold on their traffic.

## Design decisions worth knowing
- **Labels come from construction, not the teacher.** The teacher writes evidence and reason only; rows where it disagrees go to a human review queue, never silently dropped.
- **Invalid output scores −3 in RL**, not 0 as first planned. At 0, emitting garbage would beat guessing when unsure (reward hacking).
- **Confidence is the verdict-token probability**, not a number the model writes.
- **Verdict is the first JSON key**, so the gateway knows the decision after ~10 output tokens.
- **Rules only tighten.** The model can never downgrade a rule's block or escalate. Unknown tools fail closed; only read-only tools may fail open.
- **Targets pass on the 95% CI bound, clustered by template.** Rows from one template are near-copies and count roughly as one sample. Showing false alarms ≤2% needs ~189 independent benign cases with zero false alarms, so that target is measured mainly on real shadow-pilot traffic; synthetic held-out sets prove catch rate.
- **Evidence must point at the threat.** Block/escalate evidence must quote untrusted content or tool arguments (and the planted trigger in synthetic data), never the policy text or the user's own request.
- **Every template needs two registered humans** (author + reviewer, `configs/authors.json`). Model-looking ids are refused.

The internal red-team generator is not in this repo and must never be.
