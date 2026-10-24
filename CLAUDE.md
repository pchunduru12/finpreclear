# FinGuard — rules for every agent working in this repo

FinGuard v1 = the action judge only: a small open-weight model (Qwen3-4B, then 8B) that checks each planned tool call of a bank's AI agent and returns allow / block / escalate with category, evidence, reason and confidence. Source of truth: the FinGuard plan doc (Project plan + Design plan tabs).

## Never
- Author, edit or paraphrase training or test CONTENT (templates, scenarios, labels, reasons, evidence). Agents write code, run pipelines, read results. Content comes from named humans (`human:<id>`) or an allowlisted open teacher (`finguard/provenance.py`). Anything an agent drafts is `claude-fixture`, `fixture_only=True`.
- Open a gate (`configs/gates.json`) or bypass `gates.require`. Gates are opened by a human in a reviewed commit with sign-off and evidence.
- Use Claude, GPT, Llama (or Llama-derived) outputs as teacher data. Never add a teacher to the allowlist without a human-checked license link.
- Send pilot or bank data to any external API.
- Upload weights, datasets or the red-team generator anywhere public.
- Write working exploits or payloads aimed at real systems. Attack text stays plain-English, fake entities (`ACCT-0000-1111`, `*.example`).
- Split by random rows. Splits are by template, attack family, workflow and policy set.

## Always
- Use `finguard.prompt.build_messages` for every judge prompt (train, eval, serve).
- Record provenance for every row and a run record for every training run.
- Report PASS/FAIL on the confidence-interval bound, not the point estimate.
- Map findings to SR 11-7, SOX, OWASP LLM Top 10 and NIST AI RMF when writing for model risk.
- Stop and ask a human when a change touches schema.py, prompt.py, provenance.py, gates.py or rewards.
