# Serving the FinGuard judge (vLLM)

The gateway (`finguard/gateway/service.py`) talks to the judge only over HTTP
(`finguard/judge_client.VLLMJudge` -> `POST /v1/chat/completions`). Nothing in this repo imports vLLM.

## Run it (one GPU)

```bash
# full precision (BF16) - reference for eval parity
vllm serve /models/finguard-qwen3-4b-sft-<date>-<sha> \
  --served-model-name finguard-4b \
  --max-model-len 8192 \
  --enable-prefix-caching \
  --max-logprobs 5 \
  --gpu-memory-utilization 0.85

# quantised variant for latency/cost: FP8 (Hopper/Ada) or a pre-quantised AWQ checkpoint
vllm serve /models/finguard-qwen3-4b-sft-<date>-<sha>-fp8  --quantization fp8 ...
vllm serve /models/finguard-qwen3-4b-sft-<date>-<sha>-awq  --quantization awq ...
```

- Pin the vLLM version in the deployment image and record it with the model version; the
  structured-output request fields changed across versions (see below).
- A quantised checkpoint is a **different model** for SR 11-7: re-run the full eval (incl.
  held-out families) and the p_verdict calibration on it before it serves traffic. Don't
  assume BF16 results transfer.
- Qwen3 hybrid thinking: the client sends `chat_template_kwargs.enable_thinking=false` so the
  first generated tokens are the JSON (and the verdict).

## Structured output: config flag

`VLLMJudgeConfig.structured_mode`:

| mode | sends |
|---|---|
| `both_new` (default) | `response_format={"type":"json_schema",...}` + `structured_outputs={"json": schema}` |
| `both_legacy` | `response_format` + `guided_json` (older vLLM) |
| `response_format` / `structured_outputs` / `guided_json` / `none` | just that one |

vLLM has deprecated the `guided_*` fields in favour of `structured_outputs`
(mapping `guided_json -> structured_outputs.json`), per
[Anyscale structured output docs](https://docs.anyscale.com/llm/serving/structured-output);
see also [vLLM structured outputs docs](https://docs.vllm.ai/en/v0.20.2/features/structured_outputs/).
Check against the pinned version: some versions reject unknown/duplicate fields.

Even with constrained decoding the gateway re-parses with `schema.parse_judge_output` and
treats any failure as the tool's fail mode (constraint can still be cut off by `max_tokens`).

## Why prefix caching matters

Every request starts with the same system prompt, and requests for the same tool share most
of the retrieved policy clauses. With prefix caching, those KV blocks are computed once and
reused, so prefill cost is mostly the per-request part (context items + tool call).

Caveat: `prompt.render_user_message` puts AGENT ROLE / WORKFLOW / USER REQUEST **before** the
policy clauses, and the random nonce appears in the context block. So today only the system
prompt is reliably shared; policy clauses are cached only when role, workflow and user
request also match. See "recommended frozen-file change" below.

## Latency budget for the < 300 ms target (ALL ESTIMATES - to be measured on the target GPU)

Assumes Qwen3-4B, FP8 on one L4/L40S/H100-class GPU, ~1.5-3k prompt tokens, low concurrency.

| stage | estimate | notes |
|---|---|---|
| gateway overhead (validate, rules, records lookup, BM25, audit flock + fsync, HMAC) | **measured 2026-10-24: p95 0.94 ms pipeline, 4.3 ms incl. HTTP + fsync** (500 req, stub judge, in-memory JSON records, CPU sandbox; was 0.37 / 4.1 ms before the security fixes) | fsync dominates; local disk, not network storage. A real RecordsLookup adds its own network round trip (est. 2-20 ms) on payment tools |
| network gateway <-> vLLM | 1-5 ms (est.) | same host / same rack |
| prefill, system prompt cached | 20-80 ms (est.) | only uncached suffix; grows with context length |
| decode to verdict (~5-10 tokens: `{"verdict": "allow`) | 10-40 ms (est.) | ~3-8 ms/token for 4B FP8 (est.) |
| decode remaining (~40-150 tokens: category, evidence, reason) | 60-250 ms (est.) | the part that blows the budget |
| **total, wait for full JSON** | ~100-380 ms (est.) | |
| **total, act at verdict token** | ~35-130 ms (est.) | see design option |

Measure p50/p95/p99 under the pilot's expected concurrency, with realistic context lengths,
before claiming the target. `timeout_ms` in `configs/action_types.json` (300 ms for low tier)
is tighter than the full-JSON estimate: expect low-tier tools to hit fail-open on the model
path if the fast-path rule is disabled.

## Design option: act on the verdict token, finish evidence/reason asynchronously

The schema puts `verdict` first so the gateway can decide after ~10 tokens (stream=True,
read logprobs at the verdict token).

- **Allow only.** Return allow as soon as the verdict token is known and P(allow) clears the
  threshold; keep the stream open and write evidence/reason to the audit record when done.
- **Block / escalate wait for the full JSON** - the human reviewer and the agent need the
  reason, and they are not latency-critical.
- Risks to handle before enabling: (1) the rest of the JSON may end up malformed or
  inconsistent (e.g. allow with a non-`none` category) after the action ran - log it as a
  post-hoc anomaly and alert, it cannot be undone; (2) audit record is written in two parts -
  needs a "pending" record plus a completion record chained after it, so no decision is
  ever unlogged; (3) model-risk sign-off, because the model's own consistency check
  (schema validator) no longer gates the action.
- Not implemented in v1 code. Do it only if measured latency misses the target.

## Transport security (production requirements)

- **mTLS is required** between the agent runtime and the gateway, and between the gateway and
  vLLM / the systems-of-record adapters. The gateway trusts only client certificates issued to
  registered agent runtimes; the agent pins the gateway's certificate. Plain HTTP is for tests.
- **Signed responses (defence in depth).** The gateway signs every `/v1/check` response with
  HMAC-SHA256 over (domain tag, SHA-256 of the canonical request JSON, tool name, response
  body), sent as `X-FinGuard-Signature: v1=<hex>`, plus `X-FinGuard-Tool` and
  `X-FinGuard-Request-Sha256`. Key: env `FINGUARD_RESPONSE_KEY` (>= 32 bytes, from the bank's
  secret manager, rotated on a schedule). The gateway refuses to start without it.
  `finguard.gateway.client.guarded_call` rejects a missing/invalid signature, a different
  tool, request digest or request_id, and applies the tool's LOCAL fail mode.
- Limits of the HMAC (state these to model risk): it is a shared symmetric key, so any holder
  can forge responses; it does not stop replay of the same response for an identical request
  (same request_id + args); request_ids must be unique per call. mTLS + unique request_ids
  cover these.
- The client keeps its **own copy** of `configs/action_types.json` (deployed with the agent
  runtime, not fetched from the gateway). A tool runs on a non-allow verdict only when the
  local copy AND the gateway both say shadow (`enforce=false`) and the decision is not a
  deterministic rule block.

## Systems of record (rules)

`finguard/gateway/records.py` defines `RecordsLookup` (vendor_master, approval). Payment and
vendor-bank-detail rules read ONLY from it; caller context and trust labels can never loosen
a rule. `configs/records_sample.json` (fake values) backs tests and pilot config. A
production adapter must be read-only, authenticate as the gateway service identity, use
short timeouts (any error escalates) and expose a `version` (recorded in every audit record
as `gateway.records_version`).

## Audit log with several workers

`AuditLog` takes an exclusive `fcntl.flock` around read-tail + append, verifies records other
writers added, and refuses to append on a chain fork (service returns 503). flock is advisory
and local-filesystem only (not NFS/SMB). **At scale, run one log file per worker process**
(`audit-<host>-<pid>.jsonl`, each head anchored to the SIEM/WORM store) **or a single
audit-writer service**; a shared file serialises every decision on one lock and fsync.

## Startup refusals

The gateway raises at startup (does not serve) when: tier `low` is set on a tool not in
`read_only_tools`; `allow_threshold` < 0.9 (high) or < 0.8 (medium); fail-open on a non-low
tier; unknown tier/fail mode; no PolicyRetriever; no or short `FINGUARD_RESPONSE_KEY`.
Caller-sent `policy_clauses` are always discarded (ids + hash logged).
