"""Dataset row format shared by the data pipeline, training exporters and eval harness."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator, Literal, Optional

from pydantic import BaseModel

from .provenance import Provenance
from .schema import CheckRequest, JudgeOutput, RiskCategory, Verdict

Split = Literal["train", "dev", "test_iid", "test_heldout_family", "test_heldout_workflow", "test_heldout_policy"]


class Example(BaseModel):
    example_id: str
    request: CheckRequest
    gold_verdict: Verdict            # set by construction (template), not by the teacher
    gold_category: RiskCategory
    gold_trigger_span: Optional[str] = None  # planted text that makes it an attack/violation
    target: Optional[JudgeOutput] = None     # full training target (teacher-written evidence/reason)
    is_attack: bool
    attack_family: Optional[str] = None      # technique id, e.g. "inj.invoice_footer"; None if benign
    benign_kind: Optional[str] = None        # "plain" | "lookalike" for benign rows
    workflow: str
    policy_set: str
    template_id: str                          # split unit: a template never spans splits
    split: Optional[Split] = None
    provenance: Provenance


def write_jsonl(rows: Iterable[BaseModel], path: str | Path) -> int:
    n = 0
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for r in rows:
            f.write(r.model_dump_json() + "\n")
            n += 1
    return n


def read_examples(path: str | Path) -> Iterator[Example]:
    with Path(path).open() as f:
        for line in f:
            if line.strip():
                yield Example.model_validate(json.loads(line))
