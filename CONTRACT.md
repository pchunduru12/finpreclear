# FinGuard build contract (for every builder agent)

Read before writing code. Do not edit files listed under "Frozen".

## Frozen shared files
- `finguard/schema.py` — CheckRequest (input), JudgeOutput (model output), Decision (gateway output), `evidence_is_grounded`, `parse_judge_output`, `STOP_VERDICTS`.
- `finguard/prompt.py` — `build_messages(req, seed)`. The ONLY way to build judge prompts (SFT, RL, eval, serving).
- `finguard/dataset.py` — `Example` row, `write_jsonl`, `read_examples`.
- `finguard/provenance.py` — teacher/source/author license checks, `Provenance`.
- `finguard/gates.py` — `require(gate)`. Training scripts call `require("pilot_partner_signed")`; teacher labeling calls `require("teacher_selected")`; release calls `require("independent_review_passed")`.
- `configs/action_types.json`, `configs/gates.json`, `policies/sample_policy.jsonl`.

## Hard rules
1. Python 3.11+, pydantic v2. Stdlib + pydantic + fastapi/httpx/pyarrow only. No GPU needed to import or test anything.
2. Every module has pytest tests under `tests/` that run on CPU in < 30 s. Use stub judges, never real models.
3. No Claude/GPT/Llama outputs in training data. Code must call `provenance.check_teacher` and `check_template_author` where relevant. Templates you write are fixtures: `template_author="claude-fixture"`, `fixture_only=True`.
4. Dual use: synthetic attack text stays at the level needed for labeling — plain-English planted instructions with fake entities (ACME-style names, account numbers like `ACCT-0000-1111`, domains under `.example`). No real banks, real account formats, obfuscation tricks, or working exploit payloads.
5. Splits are by `template_id`, `attack_family`, `workflow`, `policy_set` — never random rows.
6. Verdict semantics: gold attacks → block (or escalate when a legitimate path exists). "Missed attack" = model says allow when gold is block/escalate.
7. Keep code readable for a bank model-risk reviewer: docstrings say what and why.
