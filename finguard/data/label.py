"""Teacher labeling and the gold filter.

The teacher writes evidence + reason text only. Gold verdict/category come from the
template, by construction, and overwrite whatever the teacher said. The teacher is shown
exactly what the judge will see at serving time (prompt.build_messages) and never the
gold label, so its rationale cannot be "reasoning backwards" from the answer.

Gold filter (an example is kept only if ALL pass):
  parsed            teacher text parses via schema.parse_judge_output
  stop_class_match  teacher stop/allow class equals gold (block+escalate are one class)
  category_match    teacher risk_category equals gold
  evidence_grounded teacher evidence is a verbatim quote from the input (allow: may be empty)
  evidence_on_trigger  for attacks/violations, evidence overlaps the planted trigger span

Rejected rows are written to a review queue with the reason, never silently dropped.
Rejection rates are reported per attack_family: if the teacher fails the hard families,
filtering silently biases the dataset toward easy cases, so families above 30% are flagged.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Optional, Protocol

import httpx
from pydantic import BaseModel

from .. import gates
from ..dataset import Example
from ..prompt import build_messages
from ..provenance import check_teacher
from ..schema import STOP_VERDICTS, JudgeOutput, evidence_is_grounded, parse_judge_output

FILTERS = ["parsed", "stop_class_match", "category_match", "evidence_grounded", "evidence_on_trigger"]
REJECTION_FLAG_THRESHOLD = 0.30
_WS = re.compile(r"\s+")
_TOK = re.compile(r"[a-z0-9]+")


class Teacher(Protocol):
    model_id: str
    license: str

    def complete(self, messages: list[dict]) -> str: ...


class TeacherClient:
    """OpenAI-compatible chat client (vLLM / SGLang / hosted). temperature=0 for reproducibility.
    Refuses to construct for any teacher that fails the licensing allowlist."""

    def __init__(self, base_url: str, model_id: str, api_key: Optional[str] = None,
                 timeout_s: float = 120.0, max_tokens: int = 400,
                 transport: Optional[httpx.BaseTransport] = None):
        self.license = check_teacher(model_id)["license"]  # raises LicenseError
        self.model_id = model_id
        self.max_tokens = max_tokens
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout_s, headers=headers, transport=transport)

    def complete(self, messages: list[dict]) -> str:
        r = self._http.post("/v1/chat/completions", json={
            "model": self.model_id, "messages": messages, "temperature": 0, "max_tokens": self.max_tokens})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class StubTeacher:
    """Test double. `fn(example_request_messages) -> str`; never a real model.
    Uses an allowlisted id so provenance fields look like a real run."""

    def __init__(self, fn, model_id: str = "Qwen/Qwen3-235B-A22B-Instruct-2507"):
        self.license = check_teacher(model_id)["license"]
        self.model_id = model_id
        self._fn = fn

    def complete(self, messages: list[dict]) -> str:
        return self._fn(messages)


class Rejection(BaseModel):
    example_id: str
    template_id: str
    attack_family: Optional[str]
    workflow: str
    failed_filter: str
    detail: str
    teacher_model: str
    teacher_raw: str


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip().lower()


def evidence_overlaps_trigger(evidence: str, trigger: str, min_token_overlap: float = 0.5) -> bool:
    """Normalised substring either direction, or >= 50% of the trigger's tokens covered."""
    e, t = _norm(evidence), _norm(trigger)
    if not e or not t:
        return False
    if e in t or t in e:
        return True
    tt, et = set(_TOK.findall(t)), set(_TOK.findall(e))
    return bool(tt) and len(tt & et) / len(tt) >= min_token_overlap


def check_teacher_output(ex: Example, raw: str) -> tuple[Optional[JudgeOutput], Optional[str], str]:
    """Apply the gold filter. Returns (parsed_output, failed_filter_or_None, detail)."""
    out = parse_judge_output(raw)
    if out is None:
        return None, "parsed", "teacher output did not parse as JudgeOutput"
    gold_stop = ex.gold_verdict in STOP_VERDICTS
    if (out.verdict in STOP_VERDICTS) != gold_stop:
        return out, "stop_class_match", f"teacher {out.verdict.value} vs gold {ex.gold_verdict.value}"
    if out.risk_category != ex.gold_category:
        return out, "category_match", f"teacher {out.risk_category.value} vs gold {ex.gold_category.value}"
    if gold_stop or out.evidence:
        if not evidence_is_grounded(out.evidence, ex.request):
            return out, "evidence_grounded", f"evidence not a verbatim quote: {out.evidence[:120]!r}"
    if gold_stop and ex.gold_trigger_span and not evidence_overlaps_trigger(out.evidence, ex.gold_trigger_span):
        return out, "evidence_on_trigger", f"evidence {out.evidence[:80]!r} does not overlap trigger"
    return out, None, "ok"


class LabelResult(BaseModel):
    kept: list[Example]
    rejected: list[Rejection]
    by_family: dict[str, dict]          # family -> {n, rejected, rate, flagged}
    by_filter: dict[str, int]


def label_examples(examples: Iterable[Example], teacher: Teacher, prompt_seed: int = 0) -> LabelResult:
    """Label rows with the teacher and apply the gold filter. Target = teacher text with
    verdict and category overwritten by gold (the teacher only contributes evidence/reason)."""
    kept: list[Example] = []
    rejected: list[Rejection] = []
    fam = defaultdict(lambda: {"n": 0, "rejected": 0})
    by_filter: dict[str, int] = defaultdict(int)
    for ex in examples:
        key = ex.attack_family or ("benign" if ex.benign_kind else "policy_violation")
        fam[key]["n"] += 1
        msgs = build_messages(ex.request, seed=prompt_seed)  # gold is never in here
        raw = teacher.complete(msgs)
        out, failed, detail = check_teacher_output(ex, raw)
        if failed:
            fam[key]["rejected"] += 1
            by_filter[failed] += 1
            rejected.append(Rejection(example_id=ex.example_id, template_id=ex.template_id,
                                      attack_family=ex.attack_family, workflow=ex.workflow,
                                      failed_filter=failed, detail=detail,
                                      teacher_model=teacher.model_id, teacher_raw=raw[:2000]))
            continue
        evidence = out.evidence if ex.gold_verdict in STOP_VERDICTS else ""
        target = JudgeOutput(verdict=ex.gold_verdict, risk_category=ex.gold_category,
                             evidence=evidence, reason=out.reason)
        prov = ex.provenance.model_copy(update={
            "teacher_model": teacher.model_id,
            "teacher_license": teacher.license,
            "filters_passed": ex.provenance.filters_passed + FILTERS,
        })
        kept.append(ex.model_copy(update={"target": target, "provenance": prov}))
    by_family = {k: {**v, "rate": round(v["rejected"] / v["n"], 4) if v["n"] else 0.0,
                     "flagged": v["n"] > 0 and v["rejected"] / v["n"] > REJECTION_FLAG_THRESHOLD}
                 for k, v in sorted(fam.items())}
    return LabelResult(kept=kept, rejected=rejected, by_family=by_family, by_filter=dict(by_filter))


def fixture_targets(examples: Iterable[Example], reasons: dict[str, str]) -> list[Example]:
    """--fixtures path (no teacher): target = gold verdict/category, evidence = trigger span,
    reason = template fixture_reason. Only valid for fixture builds."""
    out = []
    for ex in examples:
        stop = ex.gold_verdict in STOP_VERDICTS
        target = JudgeOutput(verdict=ex.gold_verdict, risk_category=ex.gold_category,
                             evidence=(ex.gold_trigger_span or "") if stop else "",
                             reason=reasons[ex.template_id][:300])
        prov = ex.provenance.model_copy(update={"filters_passed": ex.provenance.filters_passed + ["fixture_target"]})
        out.append(ex.model_copy(update={"target": target, "provenance": prov}))
    return out


def require_teacher_gate() -> None:
    """CLI path only: labeling for real data needs the 'teacher_selected' gate (and its predecessors)."""
    gates.require("teacher_selected")


__all__ = ["TeacherClient", "StubTeacher", "label_examples", "fixture_targets", "check_teacher_output",
           "evidence_overlaps_trigger", "require_teacher_gate", "LabelResult", "Rejection"]
