> Snapshot of the FinPreclear plan doc, Build plan tab, exported 2026-10-24. The live doc is the source of truth: https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v. Diagrams are not included in this export.

# Build plan: code, agent team, timeline and effort

Oct 24, 2026 · @Padmaja Chunduru

The v1 code is built and tested on CPU with fixture data; no model is trained yet. Everything up to the pilot-partner gate can proceed now; training waits for that gate.

## What's built

On this branch (PR #10), **305 automated CPU tests** pass on fixture data as of Oct 24 (main: 298; CI on each PR is the live count). PR #11 shows 317 because it adds future-enforcement tests that are out of v1 scope. None of this is trained-model validation. The fixture data was drafted by Claude and is marked never-for-training.

| Component | What it does | Status |
| --- | --- | --- |
| Shared contract (`schema.py`, `prompt.py`) | Input/output JSON; one prompt for train, eval and serving; exact-quote evidence check | Built |
| Policy retrieval (`retrieval.py`) | BM25 on plain-English clauses, same code for data and serving | Built |
| Licensing guards (`provenance.py`) | Blocks Claude, GPT, Llama and Llama-derived teachers; eval-only sources; author checks on every row | Built |
| Gates (`gates.py`) | Training, labeling and release scripts refuse to run while a gate is closed | Built; all gates closed |
| Data pipeline (`finguard/data`) | Templates → scenarios → teacher labels → gold filter → splits by family, workflow and policy set | Built; needs human-written templates |
| Training (`finguard/train`, `configs/`) | GRPO reward, SFT and RL exporters, LLaMA-Factory and VeRL configs, run records | Built; not run |
| Eval harness (`finguard/eval`) | Scorecard per slice with 95% confidence intervals, PASS/FAIL on the bound, open-guard baselines | Built |
| Gateway (`finguard/gateway`, `rules.py`) | Rules first, then model; fail modes per tool; shadow mode; hash-chained audit log | Built; about 4 ms p95 overhead excluding the model and records lookups |
| Agent team (`.claude/agents`) | Seven agent roles with hard limits | Defined |

Two independent code reviews found 2 critical and about 15 high issues. All are fixed, each with a regression test. The critical ones: the agent could supply its own policy text, and model confidence was inflated enough to pass the 0.95 bar. Rules now check payments against the bank's own vendor master and approval records, never the agent's context.

Residual risk: deterministic rules can never cover every field name or format. They are a backstop; the model and human approvals carry the main load. An outside red team must still test this before release.

## Agent team

The canonical team is seven `fg-*` agents plus the orchestrator. Their original Never limits are binding, especially the closed red-team generator's absolute prohibition on copying code or output to the open repository. Agents write code, run pipelines and read results. **Humans must write** all training and evaluation content from scratch; human review of agent-drafted content does not make it eligible. Humans sign gates and own the pilot. This split is a licensing requirement: anything an agent drafts would count as Claude output in the training data.

| Agent | Runs | Never |
| --- | --- | --- |
| Orchestrator (main session) | Tracks the plan, assigns work, reports status | Opens a gate |
| Data ops | Dataset builds, teacher labeling jobs, leakage and balance reports | Writes or edits templates, labels or reasons |
| Train ops | SFT and GRPO launches through the gated scripts; one change per run | Edits reward constants without review |
| Eval | Scorecards, regressions per family and workflow, ablations | Tunes on test splits |
| Gateway ops | vLLM serving, latency budget, fail-mode drills, audit-chain checks | Switches a tool from shadow to enforce |
| Model-risk docs | Model card, model-risk validation pack (SR 26-2 principles plus the bank's AI governance), control mapping | Marks a document approved |
| Reviewer (internal QA agent) | Cold review of changes and scorecards before a gate | Replaces the independent human/outside red-team review |
| Red-team ops (internal only) | The closed red-team generator in the sandbox, on an allowlisted open model | Copies generator code or output into the open repo |

Humans only: threat-model sign-off, attack and scenario templates, policy clauses, weekly label spot checks, gate decisions, the pilot relationship, and the external red-team review.

## Timeline

All timings are estimates, counted from T+0 = pilot agreement signed.

| Phase | When (estimate) | Gate that ends it |
| --- | --- | --- |
| 1 · Scope (pre-signature) | Now → T+0, about 4 weeks | 1 `pilot_partner_signed` |
| 2 · Data + SFT | T+0 → about T+10 weeks | 2 `teacher_selected` comes first, within about a week of T+0; no labeling before it |
| 3 · RL + testing | about T+10 → T+18 weeks | 3 `v1_targets_met`: shadow pilot may start |
| 4 · Shadow pilot + release | about T+18 → T+27 weeks | 4 `independent_review_passed`: public release of weights |

The signed pilot agreement is **T+0**. No training or teacher labeling occurs before the applicable signed gates; all data, model and shadow-pilot phases are relative to T+0. The pre-signature synthetic access-restricted demo is separate and capped at 2–4 weeks. It must not delay assigning the security engineer. Phase 4 runs about a month longer than the original plan, because a 4-week shadow pilot plus an outside review rarely fits in one month.

## Effort

These estimates are **human-only**, with agent hours separately shown; they must not be equated to engineering workstream estimates. With agents doing code, runs, evals and drafts, v1 needs about 65 human person-weeks (about 15 person-months). The original plan staffed 4–5 people for 6 months, roughly 24–30 person-months.

| Phase | Agent work (hours) | Human work (person-weeks) | Compute (USD) |
| --- | --- | --- | --- |
| Done now: code, tests, review | \~1.5 | 0 | 0 |
| 1 · Scope | \~20: baseline guards, latency test on base 4B, threat-model and model-risk drafts | \~7.5: security 3, domain/controls 3, ML 1, legal license review 0.5 | \~500 |
| 2 · Data + SFT | \~60: builds, labeling jobs, data reports, SFT runs | \~21: security 6, ML 6, data 4, domain 3, MLOps 2 | \~2k–5k: teacher on 1 node for 1–2 days, SFT runs |
| 3 · RL + testing | \~80: GRPO runs, eval sweeps, ablations, sandbox red-team ops | \~19: ML 8, security 6, MLOps 3, domain 2 | \~6k–12k: 8–12 node-days, 4B and 8B |
| 4 · Pilot + release | \~40: gateway ops, shadow-pilot analysis, model card and validation-pack drafts | \~18: domain 6, MLOps 6, ML 4, security 2 | \~1k + outside review fee (quote needed) |
| **Total** | **\~200** | **\~65** | **\~10k–20k + review fee** |

- The bottleneck is the security engineer. Templates must be human-written, roughly 300 at about 45 minutes each, which is about 6 weeks of work.
- Agents cut people-time, not calendar time. The pilot signature, a 4-week shadow pilot and the outside review set the calendar.
- Compute assumes one 8×A100 or H100 cloud node at about $25–35 per hour. The paper trained on one 8×A100 node.

## Changes this build makes to the plan

| Change | Why |
| --- | --- |
| Invalid output scores −3 in RL, not 0 | At 0, a model unsure about an attack scores better by emitting garbage than by guessing allow (−3) |
| Targets pass on the 95% confidence bound, not the point score | Model-risk teams will ask for intervals. Rows from one template count as roughly one sample, so intervals are clustered by template. Showing false alarms ≤ 2% needs about 189 independent benign cases with zero false alarms, or about 785 if the true rate is 1%. That is too many human templates, so the false-alarm target is measured mainly on real shadow-pilot traffic. Synthetic held-out sets prove catch rate: about 73 independent attack cases with zero misses for 95% |
| Confidence = probability of the verdict token; verdict is the first JSON key | A number the model writes about itself isn't calibrated. Verdict-first lets the gateway act after about 10 output tokens |
| An allow with no confidence escalates on every non-read-only tool; unknown tools need 0.95 to allow | Closes two fail-open paths found while building |
| Labels come from how the scenario was built; the teacher writes only evidence and reason | Teacher disagreements go to a human review queue. Silently dropping them would bias the data toward easy cases |
| Teacher candidates: Qwen3-235B-A22B-2507 (Apache-2.0), DeepSeek-V3-0324 and DeepSeek-R1 (MIT) | Original DeepSeek-V3 had a custom model license, so it is excluded. Kimi K3.1 Pro: recheck once its weights and license are published (due Nov 4) |
| TraceSafe benchmark is eval-only | Its agent turns came from ToolACE-8B, which is fine-tuned from Llama |
| Release gate adds a dual-use test of the release candidate; scorecards add ablations (rules on/off, each data source in/out) | Lesson from Kimi K3.1 Pro: removing risky data lowered exploit success only from 90.5% to 81.0%, so measure risk before releasing |
| Judge input length is capped | Very long inputs are an attack on the judge, so no long-context base model |
| Phase 4 runs about 2 months | A 4-week shadow pilot plus an outside review won't fit in one month |
| Confidence thresholds are a false-alarm control, not an attack detector; scorecard reports confidence on attacked inputs | USC guard paper (Oct 2026): a decision flipped by an attack is no less confident, so escalating the least-confident 10% of traffic cut attacked misses only from 60% to 54%. Tested on small encoders, so verify on our 4B judge |
| Rules layer governed as an IT/SOX control; the model judge goes through the bank's AI governance | SR 26-2 (Apr 2026) replaced SR 11-7: its model definition leaves out deterministic rule-based processes, and generative and agentic AI are out of scope |

Sources: [Meta/CMU tool-selection paper](https://arxiv.org/html/2610.31483) · [Qwen3-235B-A22B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-235B-A22B-Instruct-2507-FP8) · [DeepSeek-V3-0324 MIT license](https://huggingface.co/blog/open-r1/update-4) · [DeepSeek-R1 license](https://huggingface.co/deepseek-ai/DeepSeek-R1) · [TraceSafe dataset](https://huggingface.co/datasets/CyCraftAI/TraceSafe) · [ToolACE-8B](https://huggingface.co/Team-ACE/ToolACE-8B) · [Kimi K3.1 Pro blog](http://kimi.ai/blog/kimi-k3-1-pro) · [Kimi K3 model card](https://huggingface.co/moonshotai/Kimi-K3)

## Open decisions and risks

- [ ] **Pilot partner.** This is the critical path. Nothing trains until it's signed.
- [ ] **Teacher.** Recommended: self-host Qwen3-235B-A22B-Instruct-2507, which is Apache-2.0 and runs on one node. Legal confirms the license before the gate opens.
- [ ] **Security engineer.** Hire or assign now. Only humans can write templates, and template writing is the longest human task.
- [ ] **Test-set size.** Decide which slices are reported per bank. Each reported slice needs hundreds of benign rows, which drives how many templates are needed.
- [ ] **Not verified yet:**
  - the setting names for turning off Qwen3's thinking mode in LLaMA-Factory and VeRL;
  - the structured-output field name on the vLLM version we deploy;
  - latency on a real GPU. Every latency number so far is an estimate.
- [ ] **Shadow mode is on for every tool.** Nothing is blocked yet. Say this plainly to the pilot bank, and switch tools to enforce one at a time on evidence.
