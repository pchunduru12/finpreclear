# FinPreclear design-partner deck

Text export of the Slides artifact (layout, diagrams and styling not preserved). Live deck: https://claude.ai/code/artifact/583cf8a6-e914-41c3-bc9b-7d8764cb0026

## Section: Summary: what FinPreclear is and what we ask

---

**Slide 1 (cover)**

Design-partner briefing · Draft for discussion
# FinPreclear
A pre-execution check for every action a bank’s AI agent takes, run inside the bank
Padmaja Chunduru · October 2026
Prepared for [Bank name]
© 2026 Padmaja Chunduru. Confidential and proprietary. Any use of this material without the specific permission of Padmaja Chunduru is strictly prohibited.

> Speaker notes: For banks and vendors considering a design partnership. No trained model or pilot yet; this is the plan and the evidence behind it.

---

**Slide 2 (exec)**

Executive summary
### FinPreclear checks every action a bank’s AI agent takes, before it runs, inside the bank
Situation
Banks are adopting AI agents, mostly inside vendor software: 30% already deploy agentic AI, and 83% of those run it embedded in third-party applications.
Complication
Agents act on what they read. Text hidden in an invoice or email can become a vendor bank-detail change or a wire. Open guards check text, not bank actions, and US regulators left agentic-AI controls to each bank.
Resolution
FinPreclear is a small, open-weight model that judges every planned tool call against the bank’s own policy and returns allow, block or escalate, with a reason and evidence. It runs on one GPU inside the bank.
Our ask
One design partner for a shadow pilot on one workflow. Nothing is blocked during the pilot, and no data leaves the bank.
Sources: Bank Director 2026 Technology Survey; Federal Reserve SR 26-2
2

> Speaker notes: The one-slide version. Lead with the ask if time is short: a shadow pilot on one workflow, nothing blocked, no data leaving the bank.

## Section: Why now: agents, losses, today’s controls, regulation

---

**Slide 3 (adoption)**

Why now · Adoption
### Banks are moving AI from answering questions to taking actions, mostly through vendor software
72%
of banks use generative AI
30%
deploy agentic AI that carries out multistep tasks on its own
83%
of banks using agentic AI get it embedded in third-party applications
So what
Most agents a bank runs were built by someone else. The bank needs a control it owns, sitting between any agent and the bank’s own systems.
Source: Bank Director 2026 Technology Survey, reported by FinXTech (Sep 2026)
3

---

**Slide 4 (losses)**

Why now · Losses
### The fraud an agent could be steered into is already among the costliest cybercrimes
$3.05B
reported US business email compromise losses in 2025, up from $2.77B in 2024
74%
of US organizations were hit by business email compromise in 2025
No. 2
cause of reported cybercrime losses in 2025, after investment fraud
The same pattern, a new target
An invoice or email carries a hidden instruction
An agent with payment or vendor-master rights reads it
A bank-detail change or wire goes out before anyone looks
Sources: FBI IC3 2025 Internet Crime Report; AFP 2026 Payments Fraud and Control Survey
4

> Speaker notes: Business email compromise is the human version of the attack agents now face: a convincing message redirects a payment. IC3 figures are reported losses only, so the true number is higher.

---

**Slide 5 (gap)**

Why now · Today’s controls
### Today’s guards check what AI says, not what a bank agent is about to do

| Approach | Examples | Gap for bank actions |
| --- | --- | --- |
| Prompt-injection classifiers | PromptGuard 2 (in LlamaFirewall) | Look for trigger words. On FinVault finance attacks, it allowed 311 of 311 attack steps |
| Open tool-call judges | TS-Guard, Safiron, AprielGuard, Granite Guardian | General-purpose; not trained on bank workflows or a bank’s policy clauses |
| Large prompted judges | LlamaFirewall AlignmentCheck, FinHarness | Rely on very large or external models, so transaction data leaves the bank |
| Rule engines | Bank-built policy engines | Exact on known fields, but cannot read intent hidden in documents |

Sources: FinHarness (arXiv 2605.27333); ToolSafe (ACL 2026); Safiron (ICLR 2026); Meta LlamaFirewall
5

> Speaker notes: The FinVault result comes from the FinHarness paper’s run of LlamaFirewall. Finance attacks are semantic (authority, fake documents), so trigger-word classifiers miss them.

---

**Slide 6 (regulation)**

Why now · Regulation
### US regulators have left agentic-AI controls to each bank’s own governance
SR 26-2 replaced SR 11-7 on April 17, 2026
New model-risk guidance from the Fed, OCC and FDIC.
Generative and agentic AI are out of its scope
Footnote 3 sends banks to their own risk management and governance. The agencies plan a request for information on AI.
Tool misuse is a named agentic risk
OWASP Top 10 for Agentic Applications (Dec 2025), item ASI02.
What it means for a bank
The control for agent actions, and the evidence behind it, is the bank’s to design now.
FinPreclear ships with an evidence pack built to SR 26-2 principles, ready for the bank’s own model-risk review.
Sources: Federal Reserve SR 26-2 (Apr 2026); Orrick (Apr 2026); OWASP GenAI Security Project
6

## Section: The solution: how it works and how it compares

---

**Slide 7 (statement)**

The solution
### FinPreclear clears every agent action before it runs.
Fast rules first. Then a small judge that reads the bank’s own policy. Then allow, block or escalate, with a reason and evidence.
7

---

**Slide 8 (how)**

How it works
### Every tool call passes fast rules first, then a small judge that reads the bank’s policy
**Bank policy clauses**
plain English, per action
**AI agent**
plans a tool call
**Tool gateway**
intercepts every call
**Fast rules**
exact checks on known fields
**FinPreclear judge**
small open model, one GPU
block
escalate
allow
In the pilot, every verdict is logged and nothing is blocked (shadow mode).
**Back to agent**
action stopped
**Human reviewer**
approves or rejects
**Tool runs**
action executes
Audit log: every input, verdict, reason, evidence quote and model version, hash-chained
Source: FinPreclear plan doc, Design plan (architecture)
8

> Speaker notes: Rules handle what can be parsed exactly (amounts, vendor master, approvals) and are checked against the bank’s own records, never the agent’s context. The judge handles intent the rules can’t read.

---

**Slide 9 (example)**

What a bank sees
### Each decision comes with a reason and the exact evidence a reviewer needs
What the agent proposed
Workflow: accounts payable
Agent read: a vendor invoice (PDF, untrusted)
update_vendor_bank_details( vendor: V-1042, account: ****8831)
Illustrative, synthetic example. No trained model yet.
What FinPreclear returns

| Verdict | ESCALATE to a human reviewer |
| --- | --- |
| Risk | Payment fraud, via an instruction inside a document |
| Reason | Bank-detail change requested by text in an untrusted invoice; no call-back on record |
| Policy | “New vendor bank details need a call-back check before any payment.” |
| Evidence | “…please update our remittance account to the one below…” (quoted from the invoice) |

Built from the FinPreclear output contract (plan doc, Design plan step 3). Every verdict is also logged.
9

> Speaker notes: The evidence field must be an exact quote from the input; the system checks that. This is what lets a reviewer or model-risk team see why a decision was made.

---

**Slide 10 (landscape)**

Landscape
### Open tool-call judges exist, but none is small, bank-specific and built for actions
General-purpose
Finance- or bank-specific
Small
can run inside the bank
TS-Guard
Safiron
AprielGuard
Granite Guardian
Judge tool calls before they run; not trained on bank workflows or policy clauses
FinPreclear
Alibaba FinGuard
FinPreclear judges bank tool calls against bank policy. FinGuard (2026) checks chat answers for compliance, not tool calls.
Large
or an external model
LlamaFirewall AlignmentCheck
gpt-oss-safeguard
Large prompted or reasoning judges; slow or costly to run on every call
FinHarness
Finance-agent research harness using GPT-4o judges, so transaction data leaves the bank
Sources: papers and model cards listed under Related work in the FinPreclear plan doc
10

> Speaker notes: Positions are by category, not measured scores. Head-to-head results against these baselines are part of the v1 gate.

---

**Slide 11 (modelrisk)**

Built to be validated
### One evidence pack answers the questions a bank’s model-risk team will ask

| Model-risk question | What FinPreclear provides |
| --- | --- |
| What happens if it is wrong? | Use statement per tool: payments fail closed, lookups fail open |
| Does it work? | Misses and false alarms per attack family, with 95% intervals |
| Can we reproduce it? | Open weights, eval code and frozen test sets the bank can re-run |
| Does it hold up under attack? | Outside red-team review, including attacks aimed at the judge |
| Why did it block this? | Reason and exact evidence quote in a hash-chained audit log |
| Is it still working? | Override and escalation rates tracked; full re-test on policy change |

Mapped to
SR 26-2 principles
NIST AI RMF
OWASP Agentic Top 10 (ASI02)
SOX change and access controls
Source: FinPreclear plan doc (Design and Build plans)
11

> Speaker notes: The rules layer is not a “model” under SR 26-2, so it can be governed as an ordinary IT/SOX control. Only the judge goes through the bank’s AI governance.

## Section: Status, plan and the design partnership

---

**Slide 12 (status)**

Where we are
### The system is built and tested; training waits for a design partner
**Built**
- Gateway: rules first, fail modes per tool, shadow mode, audit log
- Evaluation harness with 95% intervals and open-guard baselines
- Data pipeline with licensing and provenance guards
- 295 automated tests passing (CPU, test data)
**Not yet**
- No trained model
- Latency not yet measured on a GPU
- No pilot or real bank traffic
- Trademark check on the name pending
**Gates**
- Design partner signed, then training starts
- v1 targets met, then the pilot starts
- Outside red-team review passed, then public release
Source: FinPreclear plan doc, Build plan (status as of Oct 24, 2026)
12

> Speaker notes: Be plain about status: code and tests exist; no model has been trained, and no number on these slides comes from a trained model.

---

**Slide 13 (roadmap)**

Plan · estimated dates
### Version 1 takes about seven months, gated on a signed design partner
**1 · Scope**
Oct 26 – Nov 20
- Threat model sign-off
- Bank policy clauses
- Baseline open guards
- Latency test, base model
Gate: design partner signed
**2 · Data + training**
Nov 23 – Jan 29
- Human-written scenario templates
- Teacher labels, then filtering
- Weekly label spot checks
- First model and scorecard
**3 · RL + testing**
Feb 1 – Mar 26
- Reinforcement learning, 4B then 8B
- Tests on unseen attack types
- Red team attacks the judge
- Dual-use test of the model
Gate: v1 targets met
**4 · Pilot + release**
Mar 29 – May 28
- Shadow pilot, 4+ weeks
- Enforce tool by tool, on evidence
- Outside red-team review
- Publish open weights
Gate: outside review passed
Estimates. Assumes a design partner signs by Nov 20, 2026. Each week of delay moves every later date.
13

---

**Slide 14 (partnership)**

The design partnership
### Shadow mode first: nothing is blocked, and no data leaves the bank
**What we ask**
- One workflow to start, such as AP invoices and vendor bank-detail changes
- Agent traces and tool logs, read inside your environment
- Your payment and data policies in plain English
- A model-risk contact to agree acceptance criteria in writing
**What you get**
- Runs on one GPU in your environment; no data leaves
- A shadow pilot of 4+ weeks: it judges, but blocks nothing
- A scorecard on your workflows: misses, false alarms, latency
- An evidence pack for your model-risk review
v1 targets to agree together:
≥95% of held-out attacks caught · ≤2% false alarms · under 300 ms per decision · beats named open guards
Targets are proposals, to be confirmed with the design partner
14

> Speaker notes: The false-alarm target is measured mainly on real shadow-pilot traffic; synthetic tests can’t prove it alone. That is why the partner’s traffic matters.

## Section: Business model, risks, team and next steps

---

**Slide 15 (business)**

Business model · not decided
### Three ways to fund an open model; we will choose with design partners
**A · Open-core**
Free open weights. Paid tier: support, tuning on the bank’s policies, validation pack, managed updates.
Fits if
many banks adopt the open model
Watch-out
large banks may find the free tier enough
**B · Licensed bank edition**
Open base model. Paid, tuned version for each bank and workflow, with updates.
Fits if
tuning on bank data drives most of the value
Watch-out
less open; harder to share attack data across banks
**C · Consortium**
Banks and vendors co-fund it as shared infrastructure, with pooled attack data.
Fits if
banks see agent safety as pre-competitive
Watch-out
slow to form; governance overhead
Options for discussion; no pricing set
15

---

**Slide 16 (risks)**

Risks
### We are managing the main risks openly, starting with attacks on the judge itself

| Risk | How we manage it |
| --- | --- |
| Judge fooled by harmless-looking text | Rules decide parseable fields; adaptive red-team before release |
| Open weights help attackers | Defensive parts only; private test set; one layer of several |
| Too many false alarms | Shadow mode first; per-tool thresholds tuned on pilot traffic |
| License blocks open release | Permissive teacher models only; provenance recorded per example |
| Regulatory bar moves after the AI RFI | Criteria agreed in writing; evidence built to SR 26-2 principles |
| Name may be hard to trademark | Legal check before any public release |

Source: FinPreclear plan doc, risk register; USC “One Word Opens the Gate” (arXiv 2610.12292)
16

> Speaker notes: Lead with the first row. Recent research shows small guard models can be flipped by harmless-looking text, which is why rules decide anything that can be parsed exactly.

---

**Slide 17 (team)**

Team · names to come
### A small team that pairs bank controls with model training
Lead · bank technology and controls
**[Name]**
[Background in one or two lines]
ML engineer · post-training and RL
**[Name]**
[Background in one or two lines]
Security engineer · red team
**[Name]**
[Background in one or two lines]
Data engineer · scenarios and provenance
**[Name]**
[Background in one or two lines]
MLOps · serving and monitoring
**[Name]**
[Background in one or two lines]
Advisors · model risk, payments
**[Names]**
[Roles and firms]
Placeholders: names and bios to be added
17

---

**Slide 18 (next)**

Next steps
### Three steps to a shadow pilot
1
A 45-minute working session with your payments operations and model-risk leads
2
Pick one workflow and agree acceptance criteria in writing
3
Sign the design-partner agreement by [date]; training starts after signing
Our ask
[Design-partner terms or investment amount: $__]
Padmaja Chunduru · [email]
18
