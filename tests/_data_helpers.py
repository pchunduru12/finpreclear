"""Shared helpers for data-pipeline tests (stub teachers only, never real models)."""
from __future__ import annotations

import json
from pathlib import Path

from finguard.data.generate import RetrieverPool, generate_all
from finguard.data.templates import load_templates

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "fixtures" / "templates_fixture.jsonl"


def fixture_templates():
    return load_templates(FIXTURE)


def fixture_rows(n=2, seed=0):
    return generate_all(fixture_templates(), n, seed, RetrieverPool(), created_at="t0")


def good_answer(ex) -> str:
    """What an ideal teacher would say: right class, right category, quote the trigger."""
    return json.dumps({"verdict": ex.gold_verdict.value, "risk_category": ex.gold_category.value,
                       "evidence": ex.gold_trigger_span or "", "reason": "test reason"})
