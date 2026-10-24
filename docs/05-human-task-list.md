> Snapshot of the FinGuard human task list, exported 2026-10-24. The live doc is the source of truth: https://claude.ai/artifact/FMthR5n6gkpe8ezXK85eqz. Diagrams are not included in this export.

# FinGuard human task list

Oct 24, 2026 · @Padmaja Chunduru

The tasks only people can do, in order, with what "done" means for each. Agents handle code, runs, evals and drafts. These tasks need a human because they involve judgment, sign-off, a relationship, or content that must not be model-written.

## Who does what

| Role | Owns | Load (estimate) |
| --- | --- | --- |
| Project lead (you) | Pilot partner, gate sign-offs, budget, hiring, outside reviewer | Ongoing |
| Security engineer | Threat model, attack templates, label spot checks, red-teaming the guard | \~17 person-weeks, the bottleneck |
| FS domain and controls lead | Policy clauses, benign templates, SOX / SR 11-7 mapping, pilot reviewers | \~14 person-weeks |
| ML engineer | Approves training runs and reward changes, reads scorecards | \~19 person-weeks |
| Data engineer (part-time) | Owns dataset versions and the review queue | \~4 person-weeks |
| MLOps (part-time) | GPUs, vLLM, gateway deployment, monitoring | \~11 person-weeks |
| Legal | Teacher and dataset licenses, pilot contract, release license | \~1 person-week |

Why agents can't do these tasks:

- **Licensing:** anything an agent writes into training data would be Claude output.
- **Accountability:** gates and enforce switches need a named person who signs.
- **Relationships and judgment:** the pilot bank, the outside review, and deciding what counts as an attack in that bank.

## Phase 1, now to Nov 20: sign the pilot, lock the scope

The pilot signature is the critical path. Every week it slips moves everything after it by a week.

- [ ] **Staff the bottleneck first** (you, by Oct 30). Hire or assign the security engineer and the domain/controls lead. Done when both have start dates.
- [ ] **Shortlist 3–5 pilot candidates** (you, by Oct 31). Mid-size banks or fintechs already running agents on AP, vendor onboarding or wires. Done when each has a named sponsor and a first meeting.
- [ ] **Sign the pilot partner** (you plus legal, target Nov 20). Agree on:
  - The workflows in scope.
  - Read-only access to vendor master, approvals and HR records.
  - Anonymized agent traces for testing.
  - Their model-risk team's sign-off on the v1 targets.
  - A 4-week shadow pilot.
  - Who reviews FinGuard's verdicts each week. Done when the contract is signed. Then open the `pilot_partner_signed` gate in `configs/gates.json` with your name, the date and a link to the contract.
- [ ] **Write the threat model** (security engineer, by Nov 13). One page covering:
  - Actions in scope and attack types.
  - 3–5 example scenarios per type.
  - What counts as block versus escalate at this bank. Done when the pilot bank's security team has signed it.
- [ ] **Collect the bank's policy clauses** (domain lead, by Nov 20). Turn their payment, vendor, data and IAM rules into short plain-English clauses, one per line. Done when their controls owner confirms each clause.
- [ ] **Fill the rules config** (domain lead with the bank). Agent approval limit, FX source, approved recipient domains, and the fraud team's denylist. Done when committed to `configs/rules.json`.
- [ ] **Review the teacher license** (legal, by Nov 20). Recommended teacher: Qwen3-235B-A22B-Instruct-2507, Apache-2.0. Confirm the license allows training and open release, and record the license link. Then open the `teacher_selected` gate.

## Phase 2, Nov 23 – Jan 29: write templates, check labels

- [ ] **Register template authors** (security engineer). Add each author and reviewer to `configs/authors.json` in a reviewed commit. Done when the commit is merged.
- [ ] **Write about 300 templates** (security engineer for attacks, domain lead for benign cases). About 45 minutes each, roughly 6 weeks for the security engineer.
  - Cover all 5 workflows: AP invoice, vendor onboarding, wire release, payroll, customer service.
  - About half benign. Many benign cases should look suspicious but be fine, e.g. a bank-detail change with a completed call-back on record.
  - Use fake names, `ACCT-0000-1111` style accounts and `.example` domains. No working exploits.
  - Never paste in text drafted by Claude, GPT or any other model.
- [ ] **Second-review every template** (a different registered human). Set `reviewed_by` to the reviewer's id. Done when every template has a reviewer.
- [ ] **Choose the held-out sets** (security engineer plus ML engineer). Pick which attack families, which workflow and which policy wording are kept out of training. Done when committed to `configs/splits.json`, before any model sees data.
- [ ] **Clear the review queue** (security engineer, weekly). Read each row the teacher disagreed with. Fix the template, or confirm the construction label is right. Done when the queue is empty before each training run.
- [ ] **Spot-check labels** (security engineer, weekly). A random 2% per attack family, at least 20 rows, logged with pass or fail. Done when every family's fail rate is under 5%.
- [ ] **Approve the first SFT run** (ML engineer). Read the dataset card and approve the launch, then read the v0 scorecard.

## Phase 3, Feb 1 – Mar 26: train, attack the guard, sign the targets

- [ ] **Approve each GRPO run** (ML engineer). One change per run, written down. Stop any run whose invalid-output rate rises, or whose dev false alarms rise while reward rises. Done when each run has an approve or stop note.
- [ ] **Approve any reward change** (ML engineer plus security engineer). Reward constants change only in a reviewed commit. Garbage output must never score better than a real answer.
- [ ] **Red-team the guard** (security engineer, about 4 weeks). Try to fool FinGuard itself:
  - Instructions aimed at the judge.
  - Very long inputs.
  - Attacks split across several harmless-looking steps.
  - Odd field names and look-alike characters. Log every bypass as a new attack family for the next data round. Done when the findings list is reviewed and triaged.
- [ ] **Read the scorecard against the targets** (ML engineer plus domain lead). Every target passes on the confidence bound, not the point estimate. Write down every slice that misses. Done when the pilot bank's model-risk team has seen the scorecard.
- [ ] **Decide 4B or 8B** (ML engineer). Pick the smaller model that clears the targets within the latency budget on the bank's GPU.
- [ ] **Sign the v1 targets gate** (you, plus the pilot's model-risk lead). Open `v1_targets_met` with both names, the date and a link to the scorecard. Done when the gate is open.

## Phase 4, Mar 29 – May 28: shadow pilot, enforce, review, release

- [ ] **Book the outside red team now, not in March** (you, by Jan 15). Good firms book months ahead. Get a fixed scope and a quote. Done when the contract is signed with dates.
- [ ] **Set up the bank side** (MLOps with the bank's IT). Certificates for mTLS, the signing key in their secret manager, read-only records access, audit anchoring to their WORM store or SIEM. Done when the gateway starts in their network and the outage test passes.
- [ ] **Run the weekly pilot review** (domain lead plus the bank's reviewers, at least 4 weeks). Compare FinGuard's verdicts with the reviewers' decisions on the same actions, and record misses and false alarms per tool.
- [ ] **Switch tools to enforce, one at a time** (the bank's controls lead signs; you approve). Only for tools whose false-alarm upper bound is 2% or less with no unexplained misses. Done when each switch has a written reason in a reviewed commit.
- [ ] **Fix or document every outside finding** (security engineer). Each finding is fixed and retested, or written into the model card as a known limitation.
- [ ] **Run the dual-use test** (security engineer). Check whether the release candidate can be prompted, or lightly fine-tuned, to write attacks. Done when the result is recorded and reviewed.
- [ ] **Sign the release gate** (you, plus the outside reviewer's report). Open `independent_review_passed`, then work through the release checklist in the deployment guide.
- [ ] **Open the disclosure channel** (you). A public address for bypass reports, with a named owner and a response time. Done before the weights go public.

## Every week, for the whole project

- [ ] Read the agents' status report: data, runs, eval, gateway. Approve or stop anything waiting on a human. (You, 30 minutes)
- [ ] Spot-check labels and clear the review queue. (Security engineer, about half a day)
- [ ] Check that no gate was opened, and no tool switched to enforce, without a signed commit. (You, 5 minutes)
- [ ] Re-check the licenses of the teacher and any new data source before they are used. Agents flag new sources but may not add them. (Legal or you, as needed)
- [ ] Update the plan doc's open decisions and dates. (You, 15 minutes)
