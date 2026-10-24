> Snapshot of the FinPreclear plan doc, Project plan tab, exported 2026-10-24. The live doc is the source of truth: https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v. Diagrams are not included in this export.

# FinPreclear: Open-Weight Agent Action Firewall for Financial Services

can Oct 24, 2026 · @Padmaja Chunduru

Build a small, open-weight model that checks every action an AI agent is about to take in a bank, and blocks or escalates the risky ones before they run.

## Problem and opportunity

Banks are giving agents real permissions (payments, vendor master data, customer records), but no open model is built to check those actions against bank workflows and the bank's own policy text.

- **Hijacking through content.** Agents read invoices, emails and PDFs that can carry hidden instructions.
- **Valid-looking wrong actions.** An over-scoped agent can change vendor bank details, release a wire or export customer data, and each step looks normal on its own.
- **The gap.** Newer open tool-call judges exist (TS-Guard, Safiron), but they are general-purpose. Older guards mostly classify text for prompt injection: on FinVault's finance attacks, PromptGuard 2 allowed 311 of 311 attack steps. Mozilla's testing found real gaps in protecting function-calling (tool) operations.
- **Data can't leave.** Banks won't send transaction context to a third-party API, so they need a small model they run in-house.

Opportunity: an open-weight, finance-specific action guard that any bank, fintech or vendor can run, inspect and audit.

## Related work and baselines

Several open models already judge agent tool calls before they run. None is trained on bank workflows or reads a bank's own policy clauses; that is FinPreclear's gap.

| Work | What it is | How FinPreclear differs |
| --- | --- | --- |
| [TS-Guard (ToolSafe)](https://aclanthology.org/2026.findings-acl.1850/) | Open step-level tool-call judge, RL-trained on Qwen2.5-7B, weights public | General-purpose; no bank workflows or policy clauses |
| [Safiron](https://arxiv.org/abs/2510.09781) | Compact pre-execution guardian; outputs a risk flag, risk type and rationale | Closest output contract; not finance-specific |
| [AprielGuard](https://arxiv.org/abs/2512.20293) | 8B guard for safety and attacks, including agentic tool use | Broad taxonomy; not built around bank actions |
| [Granite Guardian](https://www.ibm.com/granite/docs/models/guardian) | IBM guard; its function-calling check flags malformed or hallucinated calls | Targets broken calls, not malicious ones |
| [gpt-oss-safeguard](https://openai.com/index/introducing-gpt-oss-safeguard/) | 20B/120B, Apache-2.0; reads a written policy at inference time | Same policy-text idea; slow for checking every call |
| [LlamaFirewall](https://arxiv.org/abs/2505.03574) | Meta framework; AlignmentCheck uses prompted Llama 4 Maverick | A framework with a large judge, not a small in-house model |
| [FinHarness](https://arxiv.org/abs/2605.27333) and [FinVault](https://arxiv.org/abs/2601.07853) | Finance-agent safety harness and benchmark | Uses GPT-4o judges, so a bank can't run it in-house |
| [One Word Opens the Gate (USC)](https://arxiv.org/abs/2610.12292) | Small guards flip under harmless-looking appended text; attacked decisions don't look less confident | Shapes our red-team tests and escalation design |

Must-beat baselines for v1: TS-Guard, Safiron, AprielGuard, Granite Guardian, gpt-oss-safeguard-20b and LlamaFirewall, scored on our held-out sets plus FinVault (eval-only).

## What we build

FinPreclear sits between an agent and its tools. For every planned tool call it returns: **allow / block / escalate**, a one-line reason, and a risk category (e.g. payment fraud, data leak, injection, privilege misuse).

| Component | What it does | Release |
| --- | --- | --- |
| Action judge (core) | Reads the planned tool call, recent context and the firm's policy; returns the verdict | Open weights |
| Injection detector | Flags hidden instructions in invoices, emails, PDFs and API responses the agent reads | Open (or reuse existing) |
| Data-leak checker | Catches account numbers and customer data in agent outputs | Open |
| Audit summarizer | Turns agent logs into findings mapped to OWASP LLM Top 10 and NIST AI RMF | Open |
| Red-team generator | Creates attack scenarios to test agents in a sandbox | Closed, internal only |

Version 1 = the action judge only. The other components follow once it works.

## Approach

We follow the recipe from the Meta/CMU tool-selection paper (Oct 2026). There, a Qwen3-8B model trained this way beat a prompted 402B Llama-4-Maverick (41.5% vs 30.6% exact match) and worked on new domains without retraining.

- **Base model:** Qwen3-4B or 8B (Apache-2.0). Small enough to run on one GPU inside a bank. No pretraining from scratch.
- **Teacher model:** writes example verdicts and reasoning for training. It must have a license that allows training and open release. Avoid Claude, GPT and Llama outputs: their terms or licenses restrict this, and the paper did not release its model partly for this reason.
- **Step 1, SFT:** the small model learns the output format and reasoning from teacher examples. Only keep labels that can be justified from the input alone (the paper's gold filtering).
- **Step 2, RL (GRPO):** the model is scored automatically.
  - Correct verdict: reward.
  - Missed attack (allowed when it should block): large penalty.
  - False alarm: smaller penalty.
  - Correct risk category and valid format: small reward.
- **Transfer tests:** evaluate on attack types, policies and agent frameworks the model never saw in training.
- **Tooling:** LLaMA-Factory (SFT), VeRL + vLLM (RL), the same open stack the paper used.

## Plan and milestones

Version 1 uses four ordered approval gates. The post-signature program begins at T+0, defined as the date the pilot agreement is signed. No training or labeling starts before the relevant gates open. The diagram below is a historical two-gate snapshot.

&#91;embedded content: FinPreclear v1 roadmap · 4 phases, 2 gates\]

No training starts until a pilot bank is signed. Nothing is published until the model meets the version 1 targets and passes an independent review.

## Team and skills

A core team of 4–5 people is enough for version 1.

| Role | Responsible for |
| --- | --- |
| ML engineer (post-training, RL) | SFT and GRPO runs, reward design, evaluation |
| Data engineer | Synthetic scenario pipeline, label filtering, dataset versioning |
| Security engineer / red teamer | Realistic attacks, sandbox, testing the guard itself |
| Financial-services domain and controls lead | Payment flows, policies, SOX / model-risk mapping, pilot partners |
| MLOps engineer (can be part-time) | GPU training, serving, latency, monitoring |

## Budget and success metrics

Compute is the small cost; good attack data and people are the big ones. Figures below are rough estimates, not quotes.

- **Compute:** the paper trained on one 8×A100 node. Expect low tens of thousands of dollars in cloud GPU time for several training runs.
- **Teacher model usage:** for generating training examples; depends on dataset size.
- **People:** the 4–5 person team for about 6 months is the main cost.

Proposed version 1 targets (to confirm with pilot partners):

- Catches at least 95% of known attack types in the held-out test set.
- False alarms on normal finance actions at 2% or less.
- Beats the must-beat baselines under Related work and baselines on tool-call attacks.
- Decision in under 300 ms on a single GPU.
- Holds up on attack types it never saw in training.

## Risks and mitigations

The biggest risks are a licensing mistake that blocks open release, and an offensive capability leaking out with the weights.

| Risk | Mitigation |
| --- | --- |
| Teacher-model license blocks open release | Use only permissively licensed teachers; record data provenance from day one |
| Open weights help attackers | Release only defensive components; keep the red-team generator closed and sandboxed. UK AISI found safeguards on open models were largely ineffective once released |
| Attackers study the open guard to evade it | Assume it will be probed; keep a private test set; ship it as one layer alongside permissions and human approvals |
| Too many false alarms, so teams switch it off | Tune the block/escalate threshold per action type; measure false alarms on real workflows in the pilot |
| Synthetic data doesn't match real attacks | Pilot partners supply anonymized agent traces; refresh attacks every quarter |
| Model-risk review slows bank adoption. SR 26-2 (Apr 2026) replaced SR 11-7 and excludes generative and agentic AI, so each bank's own AI governance sets the bar, and it may move after the agencies' planned AI request for information | Ship a model card, eval reports and an audit trail designed for model-risk teams. Package the evidence to SR 26-2 principles even though not required; agree the pilot bank's acceptance criteria at the Phase 1 gate; track the RFI |
| Release can't be taken back | Independent red-team review before each public release; responsible-disclosure channel |
| Crowded field: FinPreclear looks like one more guard model | Lead with what's new (bank workflows, bank policy clauses, in-house, evidence quotes); publish head-to-head results against the named baselines |
| Small judges flip under harmless-looking appended text, and attacked decisions don't look less confident | Rules decide fields that can be parsed; adaptive red-team before the v1 gate; use confidence to control false alarms, not to detect attacks |
| The old name "FinGuard" was already used by a 2023 financial AI guardrail and a 2026 Alibaba finance compliance model | Renamed to FinPreclear (Oct 2026). A lawyer runs a trademark search before release; "pre-clearance" is a common finance term, which can make the name harder to register |

Step-by-step design: Design plan

## Sources

- [Training Small Language Models for Transferable Tool Selection (Meta/CMU, arXiv 2610.31483)](https://arxiv.org/abs/2610.31483)
- [Mozilla.ai: Can open-source guardrails really protect AI agents?](https://blog.mozilla.ai/can-open-source-guardrails-really-protect-ai-agents/)
- [UK AISI: How far behind the frontier are open weight models on cyber?](https://www.aisi.gov.uk/work/how-far-behind-the-frontier-are-leading-open-weight-models-on-cyber)
- [Federal Reserve SR 26-2: Revised Guidance on Model Risk Management](https://www.federalreserve.gov/supervisionreg/srletters/sr2602.htm)
- [Orrick: Agencies overhaul model risk management guidance](https://www.orrick.com/en/Insights/2026/04/Agencies-Overhaul-Model-Risk-Management-Guidance-for-Banks-Heres-What-Changed)
- [Forvis Mazars: Implications of the updated MRM guidance](https://www.forvismazars.us/forsights/2026/06/implications-of-the-updated-interagency-mrm-guidance)
- [FinGuard: A Multimodal AIGC Guardrail in Financial Scenarios (ACM, 2023)](https://doi.org/10.1145/3595916.3626351)
- [FinGuard: Detecting Financial Regulatory Non-Compliance in LLM Interactions (Alibaba, 2026)](https://arxiv.org/abs/2605.29427)
