"""Deterministic stub judges for harness tests. Never used for reported scores.

OracleStubJudge looks up each request's gold label and answers correctly with probability
`accuracy` (decided by a hash of request_id + seed, so runs are reproducible), otherwise
makes a configurable mistake. It can also be told to emit invalid text or time out.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from ..dataset import Example
from ..judge_api import JudgeResult
from ..schema import STOP_VERDICTS, CheckRequest, JudgeOutput, RiskCategory, Verdict, parse_judge_output


def _u(key: str) -> float:
    """Deterministic uniform [0,1) from a string."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:12], 16) / float(1 << 48)


@dataclass
class OracleStubJudge:
    gold: dict[str, Example]                    # request_id -> Example
    accuracy: float = 1.0                       # P(correct verdict)
    invalid_rate: float = 0.0                   # P(unparseable output), checked first
    timeout_rate: float = 0.0                   # P(asyncio.TimeoutError)
    latency_ms: float = 20.0                    # reported latency (no real sleep unless sleep=True)
    sleep: bool = False
    seed: int = 0
    model_version: str = "stub-oracle"
    calls: int = field(default=0, init=False)

    @classmethod
    def from_examples(cls, examples: list[Example], **kw) -> "OracleStubJudge":
        return cls(gold={e.request.request_id: e for e in examples}, **kw)

    def _answer(self, ex: Example, correct: bool) -> JudgeOutput:
        gv = ex.gold_verdict
        if correct:
            v, cat = gv, ex.gold_category
        elif gv in STOP_VERDICTS:
            v, cat = Verdict.ALLOW, RiskCategory.NONE           # a miss
        else:
            v, cat = Verdict.BLOCK, RiskCategory.POLICY_VIOLATION  # a false alarm
        if v == Verdict.ALLOW:
            return JudgeOutput(verdict=v, risk_category=RiskCategory.NONE, evidence="", reason="stub allow")
        ev = ex.gold_trigger_span or ex.request.user_request
        return JudgeOutput(verdict=v, risk_category=cat, evidence=ev[:1000], reason="stub stop")

    async def judge(self, req: CheckRequest, timeout_s: float) -> JudgeResult:
        self.calls += 1
        key = f"{self.seed}:{req.request_id}"
        if self.sleep:
            await asyncio.sleep(self.latency_ms / 1000)
        if _u(key + ":timeout") < self.timeout_rate:
            raise asyncio.TimeoutError()
        if _u(key + ":invalid") < self.invalid_rate:
            text = '{"verdict": "allow", "risk_category": '  # truncated JSON
        else:
            out = self._answer(self.gold[req.request_id], _u(key + ":acc") < self.accuracy)
            text = json.dumps(out.model_dump(mode="json"))
        out = parse_judge_output(text)
        p = {out.verdict.value: 1.0} if out else {}
        return JudgeResult(output=out, p_verdict=p, raw_text=text, latency_ms=self.latency_ms,
                           model_version=self.model_version)


@dataclass
class ConstantStubJudge:
    """Always returns the same verdict (degenerate-policy baseline for the scorecard)."""
    verdict: Verdict
    model_version: str = "stub-constant"

    async def judge(self, req: CheckRequest, timeout_s: float) -> JudgeResult:
        if self.verdict == Verdict.ALLOW:
            out = JudgeOutput(verdict=Verdict.ALLOW, risk_category=RiskCategory.NONE, evidence="", reason="constant")
        else:
            out = JudgeOutput(verdict=self.verdict, risk_category=RiskCategory.POLICY_VIOLATION,
                              evidence=req.user_request[:1000], reason="constant")
        return JudgeResult(output=out, p_verdict={self.verdict.value: 1.0},
                           raw_text=out.model_dump_json(), latency_ms=1.0, model_version=self.model_version)
