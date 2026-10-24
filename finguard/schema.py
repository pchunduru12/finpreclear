"""FinGuard shared contract. Every module (data, training, eval, gateway) imports from here.

Change this file only through a reviewed PR: a schema change invalidates datasets and checkpoints.
"""
from __future__ import annotations

import json
import re
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "1.0"


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


# Both of these stop the action. Safety metrics treat them as one class ("stopped").
STOP_VERDICTS = {Verdict.BLOCK, Verdict.ESCALATE}


class RiskCategory(str, Enum):
    """Label taxonomy. Every category appears in training; transfer tests hold out
    attack *families* (techniques) and *workflows*, never whole categories."""
    NONE = "none"
    INDIRECT_INJECTION = "indirect_injection"      # OWASP LLM01
    GOAL_HIJACK = "goal_hijack"                    # OWASP LLM01 / LLM06
    PRIVILEGE_MISUSE = "privilege_misuse"          # OWASP LLM06 excessive agency
    DATA_EXFILTRATION = "data_exfiltration"        # OWASP LLM02
    PAYMENT_FRAUD = "payment_fraud"
    WRONG_TOOL_OR_ARGS = "wrong_tool_or_args"
    POLICY_VIOLATION = "policy_violation"          # benign intent, control not met


class Trust(str, Enum):
    TRUSTED = "trusted"      # system, the authenticated user, internal master data
    UNTRUSTED = "untrusted"  # emails, PDFs, invoices, web pages, third-party API replies


class ContextItem(BaseModel):
    source: str = Field(description="e.g. user, system, email, invoice_pdf, tool_result:get_vendor")
    trust: Trust
    content: str = Field(max_length=20_000)


class ToolCall(BaseModel):
    name: str
    arguments: dict


class PolicyClause(BaseModel):
    id: str
    text: str
    applies_to: list[str] = Field(default_factory=lambda: ["*"])  # tool names, or "*"
    tags: list[str] = Field(default_factory=list)


class CheckRequest(BaseModel):
    """Input contract: one JSON record per planned tool call."""
    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    agent_role: str
    user_request: str
    tool_call: ToolCall
    context: list[ContextItem] = Field(default_factory=list)
    policy_clauses: list[PolicyClause] = Field(default_factory=list)  # gateway fills if empty
    workflow: Optional[str] = None  # ap_invoice, vendor_onboarding, wire_release, payroll, customer_service


class JudgeOutput(BaseModel):
    """What the model emits. Key order is fixed: verdict first so the gateway can act
    on the first tokens (latency) while evidence/reason finish for the audit log."""
    model_config = ConfigDict(extra="forbid")  # extra keys = malformed output
    verdict: Verdict
    risk_category: RiskCategory
    evidence: str = Field(default="", max_length=1_000)
    reason: str = Field(max_length=300)

    @model_validator(mode="after")
    def _consistency(self):
        if self.verdict == Verdict.ALLOW and self.risk_category != RiskCategory.NONE:
            raise ValueError("allow must use risk_category=none")
        if self.verdict != Verdict.ALLOW and self.risk_category == RiskCategory.NONE:
            raise ValueError("block/escalate need a risk category")
        return self


class Decision(BaseModel):
    """Output contract returned by the gateway and written to the audit log."""
    request_id: str
    verdict: Verdict
    risk_category: RiskCategory
    reason: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)  # from verdict-token probability, not self-reported
    decided_by: Literal["rule", "model", "fail_mode", "threshold"]
    rule_id: Optional[str] = None
    policy_ids: list[str] = Field(default_factory=list)
    model_version: str
    enforced: bool  # False in shadow mode: verdict recorded, action not stopped
    latency_ms: float


# ---------- helpers shared by data filter, reward and gateway ----------

_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip().lower()


normalize = _norm  # public name; used by reward and label filter


def grounding_corpus(req: CheckRequest) -> str:
    """All text the judge can see. Evidence must be a substring of this."""
    parts = [req.user_request, req.tool_call.name, json.dumps(req.tool_call.arguments, sort_keys=True)]
    parts += [c.content for c in req.context]
    parts += [p.text for p in req.policy_clauses]
    return "\n".join(parts)


def evidence_is_grounded(evidence: str, req: CheckRequest, min_chars: int = 8) -> bool:
    """True if evidence is an exact (whitespace/case-normalised) quote from the input.
    Also checks each argument value separately, since JSON quoting can differ."""
    e = _norm(evidence)
    if len(e) < min_chars:
        return False
    if e in _norm(grounding_corpus(req)):
        return True
    return any(e in _norm(str(v)) for v in req.tool_call.arguments.values())


def parse_judge_output(text: str) -> Optional[JudgeOutput]:
    """Strict parse of model text. Returns None on anything malformed.
    Tolerates surrounding whitespace and a ```json fence, nothing else."""
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        obj = json.loads(t)
        if not isinstance(obj, dict):
            return None
        return JudgeOutput.model_validate(obj)
    except Exception:
        return None


def _flatten(v) -> list[str]:
    if isinstance(v, dict):
        return [s for x in v.values() for s in _flatten(x)]
    if isinstance(v, (list, tuple)):
        return [s for x in v for s in _flatten(x)]
    return [str(v)]


def threat_corpus(req: CheckRequest, include_trusted_context: bool = False) -> list[str]:
    """Where stop evidence may come from: untrusted content the agent read and the arguments
    it is about to send (as values and as the JSON the judge sees). For policy violations,
    also trusted context (a system-of-record line such as "approver: none recorded").
    Never the policy text, the tool name or the user's own request: quoting those proves
    nothing about this action."""
    out = [c.content for c in req.context if c.trust == Trust.UNTRUSTED]
    if include_trusted_context:
        out += [c.content for c in req.context if c.trust == Trust.TRUSTED]
    args = req.tool_call.arguments
    out += _flatten(args) + [json.dumps(args, sort_keys=True), json.dumps(args)]
    return out


def evidence_targets_threat(evidence: str, req: CheckRequest, trigger: Optional[str] = None,
                            min_chars: int = 8, category: Optional[str] = None) -> bool:
    """Stricter than evidence_is_grounded, for block/escalate evidence.
    The quote must come from the threat corpus (see threat_corpus). With a known planted
    trigger (synthetic data), it must also come from the same text that holds the trigger
    and overlap it: exactly (one contains the other) or by >= 60% of its words."""
    e = _norm(evidence)
    if len(e) < min_chars:
        return False
    allow_trusted = category == RiskCategory.POLICY_VIOLATION.value or trigger is not None
    hosts = [_norm(x) for x in threat_corpus(req, include_trusted_context=allow_trusted)]
    if trigger:
        t = _norm(trigger)
        hosts = [h for h in hosts if t in h]  # only text that actually carries the trigger
        if not any(e in h for h in hosts):
            return False
        if e in t or t in e:
            return True
        et, tt = set(re.findall(r"[a-z0-9]+", e)), set(re.findall(r"[a-z0-9]+", t))
        return bool(et) and len(et & tt) / len(et) >= 0.6
    return any(e in h for h in hosts)
