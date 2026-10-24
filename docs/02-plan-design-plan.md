> Snapshot of the FinPreclear plan doc, Design plan tab, exported 2026-10-24. The live doc is the source of truth: https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v. Diagrams are not included in this export.

# FinPreclear design plan, step by step

Oct 24, 2026 · @Padmaja Chunduru

The design takes 21 steps across the four phases on the Project plan tab. The core idea: the agent never calls a tool directly; every call is checked first.

## Architecture

&#91;embedded content: FinPreclear architecture · interception, judgment, three outcomes\]

Cheap rule checks run first; the model judges what's left, using the bank's policy clauses. Every outcome is logged for audit and model-risk review.

## Phase 1: Scope (month 1)

Goal: lock what the model judges, what it sees and what it returns, before any data is built.

1. **Write the threat model.**
   - Actions in scope: payments and wires, vendor bank-detail changes, customer data access and export, credential or permission changes.
   - Attack types: hidden instructions in documents (indirect injection), goal hijacking, privilege misuse, data exfiltration, wrong tool or wrong arguments.
   - Output: a one-page threat list with 3–5 example scenarios per attack type.
2. **Define the input contract.** Each check sends one JSON record:
   - Agent role and the user's original request.
   - The planned tool call: tool name and arguments.
   - Recent context, with untrusted content (emails, PDFs, API replies) clearly marked.
   - The policy clauses that apply.
3. **Define the output contract.**
   - Verdict: allow / block / escalate.
   - Risk category, one-line reason, and the evidence (the exact text that triggered it).
   - Confidence score, so each bank can set its own thresholds. Thresholds control false alarms; they are not an attack detector, because attacks that flip a decision leave confidence unchanged.
4. **Design the policy format.**
   - Policies are plain-English rules, e.g. "New vendor bank details need a call-back check before any payment."
   - A retriever (BM25 to start) pulls the relevant clauses for each action, as in the paper's Retrieve step.
   - Result: banks change policy text, not the model.
5. **Design the system.** See the architecture diagram above.
   - Decide fail-closed vs fail-open per action type. Example: a payment fails closed if the guard is down; a read-only lookup fails open.
6. **Gate: pilot partner signed.** Agree on the workflows, data access and success targets with one bank or fintech. Also agree, in writing, the bank's model-risk acceptance criteria: the evidence its model-risk team needs to approve the pilot.

## Phase 2: Data and SFT (months 2–3)

Goal: a clean, labeled dataset and a first model (v0) that outputs the right format.

7. **Collect data from three sources.**
   - Public agent-attack benchmarks, re-framed into our input format. FinVault, TS-Bench and Pre-Exec Bench are eval-only until their provenance is checked; their traces may come from GPT or Llama models.
   - Synthetic finance scenarios: workflow templates (AP invoice, vendor onboarding, wire release, payroll, customer service) × attack templates × normal look-alikes.
   - Sandbox runs: real agents doing finance tasks, with attacks planted in their documents and tool replies.
8. **Balance the data.**
   - Roughly half normal actions, many of them suspicious-looking but fine (to keep false alarms low).
   - Hold out entire attack families and workflows for testing, never just random rows.
9. **Pick the models.**
   - Base: Qwen3-4B and 8B (Apache-2.0). Train 4B first; it is faster to iterate.
   - Teacher: a large model whose license allows training and open release. Record its name, version and license for every example.
10. **Label with the teacher, then filter.**
    - Teacher writes the verdict, category, reason and evidence for each example.
    - Keep a label only if it can be justified from the input alone (the paper's gold filtering).
    - A security reviewer spot-checks a sample of labels each week.
11. **Run SFT.**
    - Train on (input → short reasoning + JSON verdict) pairs with LLaMA-Factory.
    - Starting settings from the paper: learning rate 1e-5, 3 epochs, full fine-tune.
    - Output: v0 model and a first scorecard on the test set.

## Phase 3: RL and testing (months 4–5)

Goal: push the model past v0 and prove it holds up on attacks it has never seen.

12. **Design the rewards.** Scored automatically, no human labeling:

| Outcome | Reward |
| --- | --- |
| Correct verdict | +1 |
| Missed attack (allowed, should block) | large penalty, e.g. −3 |
| False alarm (blocked, should allow) | smaller penalty, e.g. −1 |
| Correct risk category | small bonus |
| Invalid JSON or no evidence quoted | −3 for invalid JSON (so garbage never beats a guess); 0 for a correct verdict without grounded evidence |

13. **Run GRPO** with VeRL + vLLM, starting from the SFT model. Starting settings from the paper: learning rate 1e-6, 16 rollouts per prompt, about 300 steps. Then scale to 8B.
14. **Build the evaluation harness.** One command produces a scorecard:
    - Miss rate and false-alarm rate, per attack type and per workflow.
    - Results on held-out attack families, unseen policies and a different agent framework (the transfer tests).
    - Comparison against TS-Guard, Safiron, AprielGuard, Granite Guardian, gpt-oss-safeguard-20b, LlamaFirewall and a large prompted model.
    - Latency per decision.
    - Confidence on attacked inputs, to show whether low confidence flags attacks.
15. **Attack the guard itself.** The red team tries to fool FinPreclear: instructions aimed at the judge, very long contexts, split-up attacks across several harmless-looking steps. Add the attacks from the USC guard paper: harmless-looking text appended to tool output, and fake "pre-approved" notes. Report misses and false alarms separately.
16. **Gate: meets v1 targets.** Only a model that clears the targets on the Project plan tab moves to the pilot.

## Phase 4: Pilot and release (month 6)

Goal: prove it on real bank workflows, then publish it safely.

17. **Package for serving.**
    - vLLM on a single GPU inside the bank's network; a quantized version for lower cost.
    - Every decision written to an audit log: input, verdict, reason, evidence, model version.
    - Monitoring after launch: block, escalate and reviewer-override rates per tool, compared with the shadow-pilot baseline.
    - Any change to a bank's policy clauses re-runs the regression scorecard before it goes live.
18. **Run a shadow pilot.**
    - FinPreclear judges live agent actions but blocks nothing yet.
    - Compare its verdicts with what the bank's reviewers decided; tune thresholds per action type.
    - Switch to enforcing mode only for action types where misses and false alarms meet the targets.
19. **Independent review.** An outside red team tests the release candidate. Fix or document what they find. Before it, run a dual-use test: can the release candidate be prompted or lightly fine-tuned to write attacks?
20. **Publish the open weights.**
    - Apache-2.0 license, model card listing known failure modes, full eval scorecard, data provenance.
    - Release only the defensive models; the red-team generator stays internal.
    - Open a responsible-disclosure channel for bypasses.
21. **Set a refresh cycle.** Add new attack types each quarter and re-run the full scorecard before every new version.
