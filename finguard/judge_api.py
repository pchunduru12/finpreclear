"""Interface every judge implements: the trained model via vLLM, baseline guard models,
and stubs for tests. The eval harness and the gateway depend only on this."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from .schema import CheckRequest, JudgeOutput


@dataclass
class JudgeResult:
    output: Optional[JudgeOutput]   # None = malformed / unparseable
    p_verdict: dict[str, float]     # probability per verdict from the verdict token; {} if unavailable
    raw_text: str
    latency_ms: float
    model_version: str
    prompt_seed: Optional[int] = None      # with prompt_sha256, lets audit rebuild the exact prompt
    prompt_sha256: Optional[str] = None
    finish_reason: Optional[str] = None
    error: Optional[str] = None            # set when the judge failed; output is then None


class Judge(Protocol):
    model_version: str

    async def judge(self, req: CheckRequest, timeout_s: float) -> JudgeResult:
        """Raise asyncio.TimeoutError on timeout; any other exception = judge error."""
        ...
