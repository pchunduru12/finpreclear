"""Scenario template format.

A template is one scenario pattern (e.g. "invoice note asks the agent to pay a different
account"). generate.py expands it into many Example rows by filling {slot} placeholders
with fake, seeded values. Templates - not rows - are the split unit, so two rows from the
same template can never land on both sides of a train/test boundary.

Gold labels are set here, by construction. The teacher model later writes evidence and
reason text but never decides the gold verdict or category.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from ..schema import RiskCategory, Trust, Verdict

Workflow = Literal["ap_invoice", "vendor_onboarding", "wire_release", "payroll", "customer_service"]
WORKFLOWS: tuple[str, ...] = ("ap_invoice", "vendor_onboarding", "wire_release", "payroll", "customer_service")

SLOT_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_FAMILY_RE = re.compile(r"^[a-z]+\.[a-z0-9_]+$")


class TemplateError(ValueError):
    pass


class ContextPattern(BaseModel):
    source: str
    trust: Trust
    content: str


class Template(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9_.\-]+$")
    author: str                                   # human:<id> | model:<allowlisted id> | claude-fixture
    reviewed_by: Optional[str] = None             # second registered human; required for non-fixture builds
    workflow: Workflow
    is_attack: bool
    attack_family: Optional[str] = None           # technique id, e.g. "inj.invoice_note"
    benign_kind: Optional[Literal["plain", "lookalike"]] = None
    gold_verdict: Verdict
    gold_category: RiskCategory
    agent_role: str
    user_request: str                              # pattern with {slots}
    tool_name: str
    arguments: dict[str, Any]                      # values may contain {slots}
    context: list[ContextPattern] = Field(default_factory=list)
    trigger_span: Optional[str] = None             # planted text; required unless gold is allow
    policy_set: str                                # policies/<policy_set>.jsonl
    fixture_reason: Optional[str] = Field(default=None, max_length=300)  # reason used for --fixtures targets
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _consistency(self):
        allow = self.gold_verdict == Verdict.ALLOW
        if allow != (self.gold_category == RiskCategory.NONE):
            raise ValueError("allow <=> gold_category=none")
        if self.is_attack:
            if allow:
                raise ValueError("attack templates cannot be gold allow")
            if not self.attack_family or not _FAMILY_RE.match(self.attack_family):
                raise ValueError("attack templates need attack_family like 'inj.invoice_note'")
            if self.benign_kind is not None:
                raise ValueError("attack templates cannot set benign_kind")
        else:
            if self.attack_family is not None:
                raise ValueError("non-attack templates must have attack_family=None")
            if allow and self.benign_kind is None:
                raise ValueError("benign (allow) templates need benign_kind plain|lookalike")
            if not allow and self.benign_kind is not None:
                raise ValueError("policy-violation templates are not benign; leave benign_kind unset")
        if not allow and not self.trigger_span:
            raise ValueError("block/escalate templates need trigger_span (the planted text)")
        return self

    def slot_names(self) -> set[str]:
        """Every {slot} used anywhere in the template (validated against the slot filler)."""
        texts = [self.user_request, json.dumps(self.arguments), self.trigger_span or ""]
        texts += [c.content for c in self.context]
        return {m for t in texts for m in SLOT_RE.findall(t)}


def template_skeleton(t: "Template") -> str:
    """Template text with {slots} unfilled: the unit for template-level near-duplicate checks
    (filled rows differ by slot values, which hides a cloned template from row-level checks)."""
    parts = [t.user_request, t.tool_name, json.dumps(t.arguments, sort_keys=True), t.trigger_span or ""]
    parts += [c.content for c in t.context]
    return "\n".join(parts)


def load_templates(path: str | Path) -> list[Template]:
    """Load a JSONL file of templates. Fails loudly on duplicates or bad rows."""
    out: list[Template] = []
    seen: set[str] = set()
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            t = Template.model_validate(json.loads(line))
        except Exception as e:  # noqa: BLE001 - re-raised with location for the reviewer
            raise TemplateError(f"{path}:{n}: {e}") from e
        if t.id in seen:
            raise TemplateError(f"{path}:{n}: duplicate template id {t.id}")
        seen.add(t.id)
        out.append(t)
    return out
