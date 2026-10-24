> Snapshot of the FinGuard deployment guide, exported 2026-10-24. The live doc is the source of truth: https://claude.ai/artifact/Nc1ZVRTpeTF4B5qBjAxq54. Diagrams are not included in this export.

# FinGuard deployment guide

Oct 24, 2026 · @Padmaja Chunduru

How to take FinGuard from the repo to a gateway that checks every agent tool call inside a bank. Steps 2–4 need the pilot-partner and teacher gates open; step 8 needs the v1-targets gate.

## At a glance

&#91;embedded content: FinGuard deployment · what runs where inside the bank\]

All links use mTLS. The agent can reach the gateway only; the gateway alone talks to the judge and the systems of record.

## Before you start

**Hardware** (estimates; confirm with the pilot bank's infrastructure team)

| Use | What | Where |
| --- | --- | --- |
| Tests, data builds | Any laptop or VM, Python 3.11+ | Anywhere |
| Teacher labeling | One 8×H100 node (Qwen3-235B-A22B in FP8 is about 240 GB of weights) | Your cloud, for synthetic data only |
| Training | One 8×A100 or 8×H100 node, 80 GB GPUs | Your cloud |
| Serving the judge | One GPU (L4, L40S or H100 class) | Inside the bank's network |
| Gateway | 2 vCPU, 4 GB RAM per process, local disk for the audit log | Inside the bank, next to the judge |

**Software:** Python 3.11+, vLLM, LLaMA-Factory and VeRL. Pin all three versions in the build image and record them with every model version. Several config key names are marked VERIFY in the repo; check them against the pinned versions before the first run.

**Access you need from the bank**

- A secret manager for the response-signing key (`FINGUARD_RESPONSE_KEY`, at least 32 bytes).
- Internal PKI to issue mTLS certificates for the gateway, the judge server and each agent runtime.
- Read-only service accounts for the vendor master, payment approvals and HR verification systems.
- A WORM store or SIEM to anchor the audit log's head hash daily.

**Gates that must be open first.** Scripts refuse to run otherwise. A human opens a gate in `configs/gates.json` through a reviewed commit, with sign-off and evidence.

| Gate | Needed before |
| --- | --- |
| `pilot_partner_signed` | Any training run (Steps 3–4) |
| `teacher_selected` | Teacher labeling (Step 2) |
| `v1_targets_met` | Shadow pilot on the bank's traffic (Step 8) |
| `independent_review_passed` | Publishing weights |

## Step 1: Set up and test the repo

Goal: every test passes on a laptop before anything touches a GPU. Takes about 10 minutes.

1. Unzip `finguard-v1-scaffold.zip` and enter the folder.
2. Install the CPU dependencies:

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install pydantic fastapi uvicorn httpx pyarrow pytest
   ```
3. Run the tests. Expect 298 passed:

   ```bash
   python -m pytest -q tests
   ```
4. Run the pipeline end to end on the sample data. Every output is marked fixture-only and must never be used for real training:

   ```bash
   python -m finguard.data.build --templates fixtures/templates_fixture.jsonl --out build/data --fixtures
   python -m finguard.eval.harness --data build/data --judge stub --out build/eval --allow-fixtures
   ```
5. Confirm the gates hold. This must print `REFUSED` and exit with code 3:

   ```bash
   bash scripts/train_sft.sh
   ```

## Step 2: Build the dataset

Goal: a labeled dataset with held-out splits and a dataset card. Needs the `teacher_selected` gate, human-written templates and the bank's policy clauses.

1. Add each template author and reviewer to `configs/authors.json`, keeping `"environment": "production"`. Only the security lead edits this file, in a reviewed commit.
2. Put the human-written templates in `data/templates.jsonl`. Each template needs `"author": "human:<id>"` and a different `"reviewed_by"`.
3. Put the bank's policy clauses in `policies/<policy_set>.jsonl`, one clause per line, in the same format as `policies/sample_policy.jsonl`.
4. Set held-out families, the held-out workflow and the held-out policy set in `configs/splits.json`.
5. Serve the teacher on the teacher node:

   ```bash
   vllm serve Qwen/Qwen3-235B-A22B-Instruct-2507-FP8 --tensor-parallel-size 8 --port 8000
   ```
6. Build the dataset:

   ```bash
   python -m finguard.data.build --templates data/templates.jsonl --out data/v1 \
     --teacher-url http://teacher:8000 --teacher-model Qwen/Qwen3-235B-A22B-Instruct-2507 \
     --n-per-template 100 --seed 0
   ```
7. Read `data/v1/dataset_card.json`:
   - Benign share about 50% in each split.
   - No family flagged for more than 30% rejection.
   - Any test templates dropped as clones of train templates.
   - Near-duplicates removed.
8. Send `data/v1/review_queue.jsonl` to the security engineer. The teacher disagreed with the construction label on those rows.

The build refuses templates from unregistered authors, Claude-drafted fixtures, and teachers not on the license allowlist.

## Step 3: Train (SFT, then GRPO)

Goal: a v0 model from SFT, then the RL-tuned model. Needs the `pilot_partner_signed` gate. Each launcher writes a run record with the git commit, dataset-card hash and config, which is the SR 11-7 trail. Commit everything first; scripts refuse a dirty repo unless given `--allow-dirty`.

1. Export the training data (train and dev splits only; test splits are refused):

   ```bash
   python -m finguard.train.export_sft --in data/v1/train.jsonl data/v1/dev.jsonl --out build/sft
   python -m finguard.train.export_rl  --in data/v1/train.jsonl data/v1/dev.jsonl --out build/rl
   ```
2. Run SFT on Qwen3-4B. Paper settings: learning rate 1e-5, 3 epochs, full fine-tune.

   ```bash
   DATASET_CARD=data/v1/dataset_card.json SFT_DATA=build/sft bash scripts/train_sft.sh configs/sft_qwen3_4b.yaml
   ```
3. Score the SFT checkpoint (Step 4) before starting RL. This is the v0 scorecard.
4. Run GRPO from the SFT checkpoint. Paper settings: learning rate 1e-6, 16 rollouts per prompt, about 300 steps.

   ```bash
   DATASET_CARD=data/v1/dataset_card.json SFT_CHECKPOINT=runs/<sft-run>/checkpoints \
     bash scripts/train_grpo.sh configs/grpo_qwen3_4b.sh
   ```
5. Watch during GRPO, and stop the run if either happens:
   - The invalid-output rate rises.
   - Reward rises while dev false alarms also rise. That pattern is reward hacking.
6. When 4B clears the targets, repeat with `configs/sft_qwen3_8b.yaml` and compare.

## Step 4: Evaluate

Goal: a scorecard that passes every v1 target on its 95% confidence bound. Intervals are clustered by template.

1. Serve the checkpoint you are scoring with vLLM (as in Step 5), then run the harness on every test split:

   ```bash
   python -m finguard.eval.harness --data data/v1 --judge vllm --base-url http://judge:8000 \
     --model finguard-4b --model-version finguard-4b-grpo-<date>-<sha> \
     --policies policies/<policy_set>.jsonl --out runs/<run>/eval
   ```
2. Score the open guard baselines (Qwen3Guard-Gen, IBM Granite Guardian) the same way. Pass their scorecards with `--baseline-scorecard`. The prompt and output mappings are in `finguard/eval/baselines.py`. The harness has no CLI switch for them yet; the eval agent adds one before the first comparison.
3. Read `scorecard.md`. Check:
   - Held-out catch rate (strict: invalid output counts as a miss).
   - Unseen-family transfer.
   - Latency p95.
   - Every slice that got worse than the previous version.
4. Run the dual-use test on the release candidate. Can it be prompted, or lightly fine-tuned, to write finance-workflow attacks? Record the result in the run folder.
5. Never tune on test splits. If a test split was used for any decision, mark it burned and build a new one.

The false-alarm target (≤ 2%) cannot be proven on synthetic data without hundreds of independent benign templates. Treat the synthetic false-alarm figure as a screen; prove the target on shadow-pilot traffic (Step 8).

## Step 5: Serve the judge

Goal: the trained model answering on one GPU inside the bank, behind mTLS.

1. Copy the approved checkpoint into the bank's model store. Its name must carry the version, e.g. `finguard-4b-grpo-2026-03-20-ab12cd`.
2. Start vLLM, pinned to the version you evaluated with:

   ```bash
   vllm serve /models/finguard-4b-grpo-<date>-<sha> --served-model-name finguard-4b \
     --max-model-len 8192 --enable-prefix-caching --max-logprobs 5 --gpu-memory-utilization 0.85
   ```

   Logprobs are required; the gateway's confidence comes from the verdict-token probability.
3. A quantized build (FP8 or AWQ) is a different model for model-risk purposes. Re-run the full Step 4 scorecard on it before it serves traffic.
4. Put the judge behind TLS that accepts only the gateway's client certificate. The judge is never reachable from agent runtimes.
5. Measure latency on this GPU at the pilot's expected concurrency: p50, p95 and p99. The repo's latency budget table is all estimates until this runs.

## Step 6: Deploy the gateway

Goal: the gateway running in shadow mode, signed and logged, reading the bank's own records.

1. Prepare four config files and review each one with the bank's controls lead:
   - `action_types.json`:
     - Tier, fail mode, timeout and allow threshold per tool.
     - Every tool starts with `"enforce": false`.
     - Only true read-only tools go in `read_only_tools`.
   - `rules.json`:
     - The agent's approval limit, the FX rates and approved recipient domains.
     - The denylist from the bank's fraud team.
   - The bank's policy clauses (`policies.jsonl`).
   - The records adapter. In the pilot, a JSON export in `configs/records_sample.json` format. In production, a read-only adapter to the vendor master, approvals and HR systems.
2. Put the signing key in the secret manager and expose it to the gateway as `FINGUARD_RESPONSE_KEY` (at least 32 bytes).
3. Start one gateway process per audit file:

   ```bash
   python -m finguard.gateway.serve \
     --judge-url https://judge:8000 --judge-model finguard-4b --model-version finguard-4b-grpo-<date>-<sha> \
     --policies /etc/finguard/policies.jsonl --action-types /etc/finguard/action_types.json \
     --rules /etc/finguard/rules.json --records /etc/finguard/records.json \
     --audit-log /var/log/finguard/audit-$(hostname)-1.jsonl --redact \
     --host 0.0.0.0 --port 8443 \
     --ssl-certfile gw.crt --ssl-keyfile gw.key --ssl-ca-certs agents-ca.crt
   ```
4. The gateway refuses to start if:
   - The signing key is missing or too short.
   - A tool is wrongly marked read-only.
   - A threshold is below the minimum (0.9 high, 0.8 medium).
   - A non-read-only tool is set to fail open.
   - TLS is not configured. Fix the config; don't work around it.
   - Pilot checks (any non-loopback start): `--redact` is missing; the policies or records are the repo's samples or fixtures; no records are given; any tool fails open; any tool has `"enforce": true` without `--force-shadow`; or the `v1_targets_met` gate (with the two gates before it) is closed. The read-only fast path is off, so the judge sees every call.
5. Check it's up: `curl --cert agent.crt --key agent.key https://gateway:8443/healthz`.
6. Anchor the audit log's head hash to the WORM store or SIEM every day. Truncation of the end of the log can only be detected against that anchor.

## Step 7: Wire the agent to the gateway

Goal: the agent can no longer call any tool directly. Every call goes through the gateway client.

1. In the agent runtime, register the real tool functions once. The agent itself never holds them:

   ```python
   from finguard.gateway.client import GuardedToolClient, ToolRegistry, ActionStopped
   
   registry = ToolRegistry({"submit_payment": erp.submit_payment, "lookup_vendor": erp.lookup_vendor})
   guard = GuardedToolClient(registry, gateway_url="https://gateway:8443",
                             action_types=json.load(open("/etc/finguard/action_types.json")))
   ```
2. Replace every direct tool call with `guard.call`. Mark each piece of context as trusted or untrusted:

   ```python
   try:
       out = guard.call("submit_payment", args, request_id=uuid4().hex, agent_role="ap_agent",
                        user_request=task.text, workflow="ap_invoice",
                        context=[{"source": "invoice_pdf", "trust": "untrusted", "content": pdf_text}])
   except ActionStopped as stop:
       route_to_human_queue(stop)   # block or escalate
   ```
3. Mark as trusted only what the bank's own code produced: the authenticated user, system messages and internal records. Emails, PDFs, invoices, web pages and third-party API replies are always untrusted.
4. Use a unique `request_id` per call. The client rejects replayed or mismatched responses.
5. Ship the client its own copy of `action_types.json` with the agent runtime; don't fetch it from the gateway. The client also needs `FINGUARD_RESPONSE_KEY` and an mTLS client certificate.
6. Test the outage path before go-live. Stop the gateway and confirm:
   - Payments, wires and exports stop.
   - Read-only lookups still run, and each one logs a warning.

## Step 8: Shadow pilot

Goal: prove misses and false alarms on the bank's real traffic. Needs the `v1_targets_met` gate. v1 ends here: model verdicts never block in v1.

1. Run at least 4 weeks with `"enforce": false` on every tool.
   - FinGuard records a verdict on every action but doesn't stop the model-judged ones.
   - Deterministic rule blocks, like a denylisted account or a payee that doesn't match the master, are enforced from day one. Agree this with the bank's controls lead before go-live; it changes their payment flow.
   - A gateway outage still stops high-risk tools (local fail-closed), even in shadow mode. Agree this with the bank too, and test it (Step 7.6).
2. Each week, compare FinGuard's verdicts with what the bank's reviewers decided on the same actions. Count misses and false alarms per tool, with confidence intervals.
3. Tune per tool only: allow thresholds in `action_types.json`, and policy wording in `policies.jsonl`. Never edit the model during the pilot.
4. The pilot is where the false-alarm target (≤ 2%) is proven; the `v1_targets_met` gate covers what synthetic held-out sets can prove (catch rate, unseen families, baselines, latency).
5. After v1 (not in the v1 launcher): per-tool enforcement of model verdicts. A tool qualifies only when its false-alarm upper bound is at or below 2% and no misses are unexplained. It needs a separate reviewed change to the launcher (see draft PR #11), one tool per commit, signed off by the bank's controls lead, with a written reason the bank's model-risk team can read.

## Run it day to day

| When | Do | Alert if |
| --- | --- | --- |
| Continuously | Track verdict mix per tool, fail-mode count, invalid-output rate, judge p95 latency | Fail modes or invalid output above 0.5% of calls; p95 above the tool's timeout; sudden jump in allow share |
| Daily | `python -c "from finguard.gateway.audit import verify_chain; print(verify_chain('<audit file>'))"` on every audit file, then anchor each head hash to the WORM store | Any chain error |
| Weekly | Review a sample of escalations and blocks with the bank's reviewers | A reviewer disagrees with more than 1 in 20 |
| Monthly | Fail-mode drill: stop the judge, then the gateway, and confirm payments stop and lookups run | Any high-risk tool runs during the drill |
| Quarterly | Add new attack families, rebuild the data, re-run the full scorecard before any new version | Any slice worse than the version in production |

**Rollback**

- Bad model version: restart the gateway with the previous `--model-version` and its vLLM checkpoint. Every decision records which version made it.
- Bad config change: revert the commit and redeploy to both the gateway and the client copy.
- Emergency: restart with `--force-shadow`. Model verdicts stop blocking; deterministic rule blocks stay on. Tell the bank's controls lead the same day.

## Release the open weights

Release can't be taken back. Do it only when every box is ticked and the `independent_review_passed` gate is open.

- [ ] Outside red team has tested the release candidate; every finding is fixed or documented in the model card.
- [ ] Dual-use test result recorded: the checkpoint doesn't meaningfully help write attacks.
- [ ] Model card lists known failure modes, every slice that missed a target, and the latency hardware.
- [ ] Full scorecard published, including ablations (rules on/off, each data source in/out).
- [ ] Provenance report: every training row's source, license, author, reviewer and teacher, with dataset-card hashes.
- [ ] Teacher license re-checked on release day.
- [ ] Only defensive parts in the release. The red-team generator, its prompts and its outputs are not in the package.
- [ ] Private test set kept back, so attackers can't tune against it.
- [ ] Responsible-disclosure channel live before the weights go public.
- [ ] Apache-2.0 license file and NOTICE included.
