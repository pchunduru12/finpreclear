"""Helpers shared by the SFT and RL exporters (and reused by eval).

Why this exists: the SFT exporter, the RL exporter and the reward must agree exactly on
(a) the prompt seed for an example, (b) the target JSON text and (c) which rows are
admissible for training. Disagreement here is train/serve skew or a provenance leak.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ..dataset import Example
from ..provenance import LicenseError, check_human, check_source, check_teacher, check_template_author
from ..schema import STOP_VERDICTS, JudgeOutput, evidence_targets_threat

TRAINING_SPLITS = ("train", "dev")
TARGET_KEY_ORDER = ("verdict", "risk_category", "evidence", "reason")


def prompt_seed(example_id: str) -> int:
    """Stable 32-bit seed from the example id (fixes the delimiter nonce in the prompt).
    sha256 rather than hash(): Python's hash() is salted per process."""
    return int(hashlib.sha256(example_id.encode("utf-8")).hexdigest()[:8], 16)


def target_text(out: JudgeOutput) -> str:
    """Assistant target as the model must emit it: one JSON object, fixed key order
    (verdict first so the gateway can act on the first tokens)."""
    d = out.model_dump(mode="json")
    return json.dumps({k: d[k] for k in TARGET_KEY_ORDER}, ensure_ascii=False)


def ground_truth_json(ex: Example) -> str:
    """What the RL reward needs per prompt: gold labels + the request (for evidence grounding)."""
    return json.dumps(
        {
            "gold_verdict": ex.gold_verdict.value,
            "gold_category": ex.gold_category.value,
            "gold_trigger_span": ex.gold_trigger_span,
            "request": ex.request.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Rejection:
    example_id: str
    reason: str


def admission_problem(ex: Example, *, need_target: bool, need_teacher: bool, allow_fixtures: bool) -> Optional[str]:
    """Return why a row may NOT enter a training set, or None if it may.

    Checks, in order (first failure wins, so the reason is specific):
      1. split is train/dev (a test row in training data invalidates every held-out score)
      2. fixture_only rows only with explicit allow_fixtures (model-drafted templates)
      3. source license verified (provenance.check_source)
      4. template author allowed (human or allowlisted model), skipped for allowed fixtures
      5. teacher on allowlist and not a blocked provider (only when teacher text is used: SFT)
      6. SFT target present and consistent with the construction-time gold label
    """
    if ex.split not in TRAINING_SPLITS:
        return f"split={ex.split!r} not allowed in training (only {TRAINING_SPLITS})"
    p = ex.provenance
    if p.fixture_only and not allow_fixtures:
        return "fixture_only row (use --allow-fixtures for smoke runs only)"
    try:
        check_source(p.source, for_training=True)
        if p.template_author.startswith("external:") and p.template_author != f"external:{p.source}":
            return f"author {p.template_author} does not match source {p.source}"
        if not p.fixture_only:
            check_template_author(p.template_author)
            check_human(p.reviewed_by)
        if need_teacher:
            if not p.teacher_model and not (p.fixture_only and allow_fixtures):  # smoke runs have no teacher
                return "no provenance.teacher_model for teacher-written target"
            if p.teacher_model:  # a named teacher is always license-checked, fixtures included
                check_teacher(p.teacher_model)
    except LicenseError as e:
        return f"license: {e}"
    if need_target:
        t = ex.target
        if t is None:
            return "no target"
        if t.verdict != ex.gold_verdict or t.risk_category != ex.gold_category:
            return (f"target ({t.verdict.value}/{t.risk_category.value}) disagrees with gold "
                    f"({ex.gold_verdict.value}/{ex.gold_category.value})")
        # Teaching the model to cite text that is not in the input would train it to
        # fabricate audit evidence; the RL reward refuses that, so SFT must too.
        if t.verdict in STOP_VERDICTS and not evidence_targets_threat(t.evidence, ex.request, ex.gold_trigger_span,
                                                                        category=t.risk_category.value):
            return "target evidence for block/escalate does not quote the threat (untrusted content, tool args or planted trigger)"
    return None


def partition(rows: Iterable[Example], **kw) -> tuple[list[Example], list[Rejection]]:
    ok, bad = [], []
    for ex in rows:
        why = admission_problem(ex, **kw)
        (bad.append(Rejection(ex.example_id, why)) if why else ok.append(ex))
    return ok, bad
