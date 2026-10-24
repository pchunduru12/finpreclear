# FinPreclear v1 — reconciled agent roster and scope

**Reviewed October 24, 2026.** This file supersedes the earlier eight-agent execution ledger.

## Roles

The Build plan specifies **seven operational agents plus the main-session orchestrator**. The original `.claude/agents/fg-*.md` files are canonical. GitHub Issues #2–#9 remain eight **review workstreams**, not eight additional autonomous agents. The QA agent is an internal code reviewer, never an independent model-risk signatory.

| Canonical role | Tracks | Binding NEVER constraint |
| --- | --- | --- |
| Orchestrator | #2–#9 | Never opens approval gates |
| fg-data-ops | #2, #8 | Never writes/edits training or test templates, labels or reasons; no labeling before teacher gate |
| fg-train-ops | #2, #8 | Never bypasses pilot signature or edits reward constants without human review |
| fg-eval | #2, #4 | Never tunes to test splits |
| fg-gateway-ops | #3, #4, #5 | Never switches a tool from shadow to enforce |
| fg-modelrisk-docs | #6 | Never marks governance documents approved |
| fg-reviewer (QA agent) | #9 | Never substitutes for the outside human reviewer |
| fg-redteam-ops (CLOSED INTERNAL ONLY) | #7 | Never copies generator code, prompts or outputs into the open repo, training/test corpus or release artifacts |

The redundant `fp-*.md` specialist overlays introduced in PR #10 have been removed. The seven original `fg-*.md` operating agents remain authoritative. All AI-authored material must remain fixture-only and must not enter human-written training/evaluation content, even after human edits.

## Scope and gates

**v1 = a single bank-hosted action judge in shadow mode**. No SaaS tenant isolation, public beta, or live financial enforcement. Keep mTLS, per-bank authentication, secrets, and read-only vendor-master/approvals systems-of-record adapters.

**T+0 = signed pilot partnership.** No labeling or training until relevant signed gates open. Pre-signature work can include an access-restricted, **human-scenario-only**, 2–4-week synthetic **demo**, visibly labeling every verdict `STUB / SIMULATION — NOT A TRAINED MODEL`. The demo may not delay hiring/assigning the security engineer responsible for approximately six human weeks of template writing.

Four ordered human gates, all currently closed:
1. `pilot_partner_signed` — before training.
2. `teacher_selected` — after legal license review, before teacher labeling.
3. `v1_targets_met` — validated model and bank-approved acceptance criteria.
4. `independent_review_passed` — outside human review before public model release.

The Build plan estimates about **65 human person-weeks**, with about 200 agent hours separately. Do not combine this with engineering workstream estimates.

## Governance and tests

Deterministic rules = bank **IT/SOX controls**. The generative action judge = bank **AI governance**. SR 26-2 superseded SR 11-7 in April 2026; it does not apply directly to generative or agentic AI; its principles can be informative.

At commit `a50f3003` on downstream draft PR #11, GitHub Actions run `40132231898` recorded **317 passing CPU fixture tests**, not trained-model accuracy. PR #10 earlier had 304 passing CPU tests. External security/model-risk sign-off remains outstanding.
