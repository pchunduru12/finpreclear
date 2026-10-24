# FinPreclear — project context (summary of plan doc, updated 2026-10-24)

Snapshot of `finguard-context.md` from the FinSecAgent Claude Project. Quick summary only; the live plan doc is the source of truth (links in `docs/README.md`; ask Padmaja for access).

Formerly "FinGuard"; renamed Oct 2026 because that name is already used by a 2023 financial AI guardrail (ACM) and a 2026 Alibaba finance compliance model (arXiv 2605.29427). Code package paths (`finguard/...`) not yet renamed.

## What it is
- Open-weight "action firewall" between a bank's AI agent and its tools.
- For every planned tool call returns: verdict (allow / block / escalate), risk category, one-line reason, evidence (exact triggering text), confidence.
- Runs in-house on one GPU — banks won't send transaction context to a third-party API.

## Why
- Agents now have real permissions: payments, vendor master data, customer records.
- Main threats: hidden instructions in invoices/emails/PDFs; valid-looking but wrong actions (change vendor bank details, release a wire, export customer data).
- Gap: newer open tool-call judges exist (TS-Guard, Safiron) but are general-purpose; none is trained on bank workflows or reads a bank's own policy clauses. Older guards mostly classify text for prompt injection (PromptGuard 2 allowed 311/311 FinVault attack steps); Mozilla.ai found real gaps on tool calls.

## Related work and baselines
- Open tool-call judges: TS-Guard (ToolSafe, RL on Qwen2.5-7B), Safiron, AprielGuard (8B), Granite Guardian (function-calling check).
- Policy-reading guard: gpt-oss-safeguard (20B/120B, Apache-2.0).
- Frameworks: LlamaFirewall, OpenAI Agents SDK tool guardrails, CommBank rule-based policy engine.
- Finance: FinHarness (GPT-4o judges, not in-house) + FinVault benchmark (eval-only until provenance checked); Alibaba "FinGuard" (Qwen3-8B, SFT + RL, finance compliance on chat queries/responses, not tool calls).
- Warning: USC "One Word Opens the Gate" (arXiv 2610.12292) — small guards flip under harmless-looking appended text; attacked decisions don't look less confident.
- Must-beat baselines: TS-Guard, Safiron, AprielGuard, Granite Guardian, gpt-oss-safeguard-20b, LlamaFirewall.

## Components
| Component | Release |
|---|---|
| Action judge (core, = v1) | Open weights |
| Injection detector | Open or reuse existing |
| Data-leak checker | Open |
| Audit summarizer (OWASP LLM Top 10, NIST AI RMF) | Open |
| Red-team generator | Closed, internal only |

## Approach
- Recipe from Meta/CMU paper "Training Small Language Models for Transferable Tool Selection" (arXiv 2610.31483): Qwen3-8B post-trained beat prompted 402B Llama-4-Maverick (41.5% vs 30.6%).
- Base: Qwen3-4B → 8B. No pretraining.
- SFT on teacher-written verdicts (keep only labels justifiable from input) → GRPO RL with automatic scoring.
- Rewards: correct verdict +1; missed attack ~−3; false alarm ~−1; correct category small bonus; invalid JSON −3; correct verdict without grounded evidence 0.
- Teacher must permit training + open release.

## Architecture
- Agent never calls a tool directly; every call is intercepted.
- Cheap rule checks first → model judges the rest using the bank's policy clauses (plain-English rules, BM25 retrieval).
- Banks change policy text, not the model — but any policy change re-runs the regression scorecard before going live.
- Fail-closed vs fail-open per action type (payments fail closed; read-only lookups fail open).
- Confidence thresholds control false alarms; they are not an attack detector.
- Every decision logged: input, verdict, reason, evidence, model version.
- Post-launch monitoring: block, escalate and override rates per tool vs shadow-pilot baseline.

## Input / output contract
- In (one JSON record): agent role + user's original request; planned tool name + args; recent context with untrusted content marked; applicable policy clauses.
- Out: verdict, risk category, reason, evidence, confidence.

## Plan — ~6 months, 21 steps
1. **Scope (month 1):** threat model, input/output contracts, policy format, system design. **Gate: pilot partner signed, including written model-risk acceptance criteria.**
2. **Data + SFT (months 2–3):** public benchmarks + synthetic finance scenarios (AP invoice, vendor onboarding, wire release, payroll, customer service) + sandbox runs; ~half normal actions; teacher labels + filtering + weekly spot checks; v0 model.
3. **RL + testing (months 4–5):** GRPO, eval harness (miss/false-alarm per attack + workflow, transfer tests, vs named baselines, confidence on attacked inputs, latency), red-team the guard itself incl. USC-style appended-text and fake-approval attacks. **Gate: meets v1 targets.**
4. **Pilot + release (month 6):** vLLM serving + quantized build, shadow pilot (judge but don't block), independent red-team review, publish Apache-2.0 weights + model card + scorecard + provenance, disclosure channel, quarterly refresh.

## v1 targets (to confirm with pilot partner)
- Catch ≥95% of known attack types (held-out set)
- False alarms ≤2% on normal finance actions
- Beat the must-beat baselines on tool-call attacks
- <300 ms per decision on one GPU
- Holds on unseen attack types

## Team (4–5)
ML engineer (post-training/RL) · data engineer · security engineer / red teamer · FS domain & controls lead · MLOps (part-time)

## Budget (rough)
- Compute: low tens of thousands $ (paper used one 8×A100 node)
- Teacher usage: depends on dataset size
- People: main cost

## Regulatory note
- SR 26-2 / OCC Bulletin 2026-13 (Apr 17, 2026) replaced SR 11-7 and SR 21-8. Generative and agentic AI are out of scope (footnote 3): the bank's own AI governance sets the bar. Rule-based deterministic processes aren't "models" → rules layer governed as an IT/SOX control. Bank stays responsible for outside models. Agencies plan an AI request for information.

## Top risks
- Teacher license blocks open release → permissive teachers only, provenance from day one
- Open weights help attackers → release defensive parts only; UK AISI found safeguards on open models largely ineffective post-release
- Attackers study the guard → private test set; one layer among permissions + human approval
- Too many false alarms → per-action thresholds, measure in pilot
- Synthetic ≠ real attacks → anonymized pilot traces, quarterly refresh
- Model-risk review slows adoption; bar varies by bank under SR 26-2 and may move after the AI RFI → evidence pack to SR 26-2 principles, acceptance criteria agreed at Phase 1 gate
- Crowded field → lead with bank workflows + policy clauses + in-house; publish head-to-head results
- Small judges flip under harmless appended text → rules decide parseable fields; adaptive red-team; confidence ≠ attack signal
- Old name clash → renamed FinPreclear; lawyer trademark search before release ("pre-clearance" is a common finance term, may be harder to register)
- Release is irreversible → independent review before each release

## Open decisions
- Pilot partner (not signed)
- Teacher model (recommended: Qwen3-235B-A22B-Instruct-2507, pending legal check)
- Final v1 targets
- Trademark check on FinPreclear; rename code package from `finguard`
