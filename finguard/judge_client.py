"""Judge implementations used by the gateway.

VLLMJudge   - talks to the trained FinGuard model on an OpenAI-compatible vLLM server
              over HTTP (POST /v1/chat/completions). No GPU or vLLM import needed here.
StubJudge   - scripted outputs, delays and exceptions for tests. Never used in production.

Why confidence comes from logprobs, not the model's text: a model can be talked into
writing "confidence: 0.99" by injected content. The probability mass the model puts on
the verdict token is a property of the forward pass, so the gateway's allow threshold
(configs/action_types.json: allow_threshold) is computed only from that. The reported
p_verdict values are RAW token probabilities, never renormalised over the three verdicts.

Model-risk notes (SR 11-7): every call is temperature 0 with structured output, the prompt
is built only by finguard.prompt.build_messages, and the per-request prompt seed (which
fixes the random delimiter nonce) is returned so the exact prompt can be rebuilt from the
audit log.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional, Sequence, Union

import httpx

from .judge_api import JudgeResult
from .prompt import PROMPT_VERSION, build_messages
from .schema import CheckRequest, JudgeOutput, Verdict, parse_judge_output

VERDICTS = tuple(v.value for v in Verdict)  # ("allow", "block", "escalate")

# How to ask vLLM for schema-constrained JSON. vLLM deprecated the `guided_*` request
# fields in favour of `structured_outputs` (see configs/serving.md for sources), so the
# default sends the OpenAI-standard response_format plus the new field. "guided_json"
# keeps compatibility with older servers.
StructuredMode = Literal["response_format", "structured_outputs", "guided_json", "both_new", "both_legacy", "none"]


class JudgeError(RuntimeError):
    """Judge server answered with an error or an unusable payload."""


class VLLMJudgeResult(JudgeResult):
    """Kept as an alias; the audit fields now live on judge_api.JudgeResult."""


# ---------------------------------------------------------------- p_verdict extraction

_VERDICT_KEY_RE = re.compile(r'"verdict"\s*:\s*"')


_STRIP = ' "\'\t\n\r\u0120\u2581'  # quotes, whitespace, BPE space markers (Ġ, ▁)


def _candidate_verdict(token_text: str, prefix_len: int) -> Optional[str]:
    """Map one candidate token at the verdict position to a verdict, or None.

    Every candidate is an alternative for the SAME position, so it is matched on its own
    text: leading quotes / whitespace / BPE space markers stripped, lower-cased, then
    prefix-matched in both directions ("esc" -> escalate, "allow" -> allow, '"block' -> block,
    ' "block' -> block). The three verdicts have distinct first letters, so this is
    unambiguous. If that gives nothing, the chosen token's prefix_len (characters before the
    value, e.g. the quote in ' "allow') is cut off and matched again.
    Before (security review round 2 #10): prefix_len was always cut first, so a candidate
    'block' (no quote) next to a chosen ' "allow' lost its first two letters and P(block) read 0.
    """
    for t in (token_text, token_text[prefix_len:] if 0 < prefix_len < len(token_text) else None):
        if t is None:
            continue
        t = t.lstrip(_STRIP).lower()
        if not t:
            continue
        for v in VERDICTS:
            if v.startswith(t) or t.startswith(v):
                return v
    return None


# Minimum summed raw probability of allow/block/escalate at the verdict position. Below it,
# the forward pass put real mass on something else (or top_logprobs is too short to see it),
# so the numbers are not a usable confidence and the gateway treats them as unavailable.
MIN_VERDICT_MASS = 0.9


def extract_p_verdict(logprobs_content: Optional[Sequence[dict]], min_mass: float = MIN_VERDICT_MASS) -> dict[str, float]:
    """RAW probability per verdict at the first token of the verdict value. No renormalisation.

    Walks the generated tokens, concatenating their text, until the text contains
    `"verdict": "`. The token covering the next character is the verdict token. Each of its
    top_logprobs candidates is mapped to a verdict by prefix ("all", "esc", "block"...) and
    exp(logprob) is summed per verdict. The values are reported as-is (security review C2:
    renormalising over three tokens turned a raw P(allow)=0.55 into 0.966).

    Returns {} (gateway: confidence unavailable -> escalate on every non-low tool) if
    logprobs are missing, the key is never found, or the summed raw mass of the three
    verdicts is below `min_mass`. It never falls back to anything the model wrote.
    """
    if not logprobs_content:
        return {}
    text = ""
    starts: list[int] = []
    for tok in logprobs_content:
        starts.append(len(text))
        text += tok.get("token", "")
    m = _VERDICT_KEY_RE.search(text)
    if not m:
        return {}
    value_pos = m.end()
    idx = next((i for i in range(len(starts)) if starts[i] <= value_pos < starts[i] + len(logprobs_content[i].get("token", ""))), None)
    if idx is None:
        return {}
    tok = logprobs_content[idx]
    prefix_len = value_pos - starts[idx]
    cands = list(tok.get("top_logprobs") or [])
    if not any(c.get("token") == tok.get("token") for c in cands) and "logprob" in tok:
        cands.append({"token": tok.get("token", ""), "logprob": tok["logprob"]})
    mass = {v: 0.0 for v in VERDICTS}
    seen_tokens: set[str] = set()
    for c in cands:
        t = c.get("token", "")
        if t in seen_tokens:  # a duplicated candidate must not be counted twice
            continue
        seen_tokens.add(t)
        v = _candidate_verdict(t, prefix_len)
        lp = c.get("logprob")
        if v is None or lp is None or not math.isfinite(lp):
            continue
        mass[v] += math.exp(min(lp, 0.0))
    total = sum(mass.values())
    if total < min_mass:
        return {}
    return {v: min(mass[v], 1.0) for v in VERDICTS}


def _messages_sha256(messages: list[dict]) -> str:
    return hashlib.sha256(json.dumps(messages, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


# ---------------------------------------------------------------- vLLM judge

@dataclass
class VLLMJudgeConfig:
    base_url: str                      # e.g. http://judge:8000
    model: str                         # served model name passed to `vllm serve --served-model-name`
    model_version: str                 # checkpoint id recorded in Decision + audit (e.g. finguard-4b-sft-2026-10-24-ab12cd)
    api_key: Optional[str] = None
    max_tokens: int = 200
    top_logprobs: int = 5
    structured_mode: StructuredMode = "both_new"
    disable_thinking: bool = True      # Qwen3 hybrid models: chat_template_kwargs.enable_thinking=False
    extra_body: dict = field(default_factory=dict)


class VLLMJudge:
    """judge_api.Judge against vLLM's OpenAI-compatible chat completions endpoint."""

    def __init__(self, config: VLLMJudgeConfig, client: Optional[httpx.AsyncClient] = None):
        self.config = config
        self.model_version = config.model_version
        headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
        self._client = client or httpx.AsyncClient(base_url=config.base_url, headers=headers)
        self._schema = JudgeOutput.model_json_schema()

    async def aclose(self) -> None:
        await self._client.aclose()

    def build_payload(self, req: CheckRequest, seed: int) -> dict:
        messages = build_messages(req, seed=seed)
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.config.max_tokens,
            "logprobs": True,
            "top_logprobs": self.config.top_logprobs,
        }
        mode = self.config.structured_mode
        rf = {"type": "json_schema", "json_schema": {"name": "JudgeOutput", "schema": self._schema, "strict": True}}
        if mode in ("response_format", "both_new", "both_legacy"):
            body["response_format"] = rf
        if mode in ("structured_outputs", "both_new"):
            body["structured_outputs"] = {"json": self._schema}
        if mode in ("guided_json", "both_legacy"):
            body["guided_json"] = self._schema
        if self.config.disable_thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        body.update(self.config.extra_body)
        return body

    async def judge(self, req: CheckRequest, timeout_s: float) -> VLLMJudgeResult:
        # Random per-request seed -> random delimiter nonce, but recorded so the prompt can be rebuilt.
        seed = secrets.randbits(32)
        payload = self.build_payload(req, seed)
        t0 = time.perf_counter()
        try:
            r = await self._client.post("/v1/chat/completions", json=payload, timeout=timeout_s)
        except httpx.TimeoutException as e:
            raise asyncio.TimeoutError(str(e)) from e
        except httpx.HTTPError as e:
            raise JudgeError(f"judge transport error: {e!r}") from e
        latency_ms = (time.perf_counter() - t0) * 1000
        if r.status_code != 200:
            raise JudgeError(f"judge HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = r.json()
            choice = data["choices"][0]
            raw = choice["message"].get("content") or ""
        except Exception as e:  # noqa: BLE001 - any shape problem is a judge error
            raise JudgeError(f"judge response shape: {e!r}") from e
        lp = (choice.get("logprobs") or {}).get("content")
        return VLLMJudgeResult(
            output=parse_judge_output(raw),
            p_verdict=extract_p_verdict(lp),
            raw_text=raw,
            latency_ms=latency_ms,
            model_version=self.model_version,
            prompt_seed=seed,
            prompt_sha256=_messages_sha256(payload["messages"]),
            finish_reason=choice.get("finish_reason"),
        )


# ---------------------------------------------------------------- stub judge (tests only)

@dataclass
class StubStep:
    """One scripted judge response. Set exactly one of output/text/exc."""
    output: Optional[Union[JudgeOutput, dict]] = None
    text: Optional[str] = None
    exc: Optional[BaseException] = None
    p_verdict: Optional[dict[str, float]] = None  # None -> 1.0 on the scripted verdict
    delay_s: float = 0.0


class StubJudge:
    """Scripted judge for tests. `script` is a list of StubStep (consumed in order, last one
    repeats) or a callable(req) -> StubStep. Honours delays so gateway timeouts can be tested."""

    def __init__(self, script: Union[Sequence[StubStep], Callable[[CheckRequest], StubStep]],
                 model_version: str = "stub-0"):
        self.script = script
        self.model_version = model_version
        self.calls: list[CheckRequest] = []

    def _next(self, req: CheckRequest) -> StubStep:
        if callable(self.script):
            return self.script(req)
        i = min(len(self.calls) - 1, len(self.script) - 1)
        return self.script[i]

    async def judge(self, req: CheckRequest, timeout_s: float) -> JudgeResult:
        self.calls.append(req)
        step = self._next(req)
        if step.delay_s:
            await asyncio.sleep(step.delay_s)
        if step.exc is not None:
            raise step.exc
        if step.text is not None:
            raw = step.text
        else:
            out = step.output if isinstance(step.output, JudgeOutput) else JudgeOutput.model_validate(step.output)
            raw = out.model_dump_json()
        parsed = parse_judge_output(raw)
        if step.p_verdict is not None:
            pv = step.p_verdict
        elif parsed is not None:
            pv = {v: (1.0 if v == parsed.verdict.value else 0.0) for v in VERDICTS}
        else:
            pv = {}
        return JudgeResult(output=parsed, p_verdict=pv, raw_text=raw,
                           latency_ms=step.delay_s * 1000, model_version=self.model_version)


__all__ = ["VLLMJudge", "VLLMJudgeConfig", "VLLMJudgeResult", "StubJudge", "StubStep",
           "JudgeError", "extract_p_verdict", "MIN_VERDICT_MASS", "PROMPT_VERSION"]
