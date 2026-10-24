"""Licensing and provenance guardrails. These run in code, not just in a policy doc,
because a single bad teacher or source contaminates every checkpoint trained after it.

Every entry below records where the license was checked. Re-verify before each release.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

# Teachers allowed to write rationales/evidence for training data.
# Teacher is still an OPEN DECISION in the plan; this list is the candidate set.
TEACHER_ALLOWLIST: dict[str, dict] = {
    "Qwen/Qwen3-235B-A22B-Instruct-2507": {
        "license": "Apache-2.0",
        "checked": "2026-10-24",
        "source": "https://huggingface.co/Qwen/Qwen3-235B-A22B-Instruct-2507-FP8",
    },
    "Qwen/Qwen3-235B-A22B-Thinking-2507": {
        "license": "Apache-2.0",
        "checked": "2026-10-24",
        "source": "https://huggingface.co/Qwen/Qwen3-235B-A22B-Thinking-2507-FP8",
    },
    "deepseek-ai/DeepSeek-V3-0324": {
        "license": "MIT",  # original DeepSeek-V3 had a custom model license: NOT allowed
        "checked": "2026-10-24",
        "source": "https://huggingface.co/blog/open-r1/update-4",
    },
    "deepseek-ai/DeepSeek-R1": {
        "license": "MIT (explicitly allows distillation)",
        "checked": "2026-10-24",
        "source": "https://huggingface.co/deepseek-ai/DeepSeek-R1",
    },
}

# Hard stop regardless of allowlist edits: providers whose terms or licenses restrict
# training other models on outputs (project rule), plus Llama-derived distills.
BLOCKED_TEACHER_PATTERNS = [r"claude", r"anthropic", r"\bgpt-(?!oss)", r"openai", r"\bo[134]-", r"llama", r"maverick", r"gemini"]

# Public sources. "VERIFY" = license not yet checked by a human; cannot enter train/test.
SOURCE_LICENSES: dict[str, str] = {
    "synthetic_v1": "internal (owned)",
    "tracesafe": "Apache-2.0 (HF card CyCraftAI/TraceSafe, checked 2026-10-24)",
    "agentdojo": "VERIFY",
    "injecagent": "VERIFY",
    "asb": "VERIFY",
}

# Sources usable for evaluation only, never training. TraceSafe agent turns come from
# ToolACE-8B, which is fine-tuned from Llama-3.1-8B-Instruct (project rule: no Llama outputs).
EVAL_ONLY_SOURCES = {"tracesafe"}

# Authors allowed to write scenario/attack templates used in train/test splits.
# Model-drafted templates (including anything Claude drafted in this repo) are fixtures only.
HUMAN_AUTHOR_RE = re.compile(r"^human:[a-z0-9._-]+$")
# A human id must also be in the registry (configs/authors.json, maintained by the security
# lead in reviewed commits). Ids that look like models are refused even if registered.
_MODELISH = re.compile(r"claude|gpt|llama|gemini|model|bot|agent", re.I)
AUTHORS_FILE = Path(os.environ.get("FINGUARD_AUTHORS_FILE",
                                   Path(__file__).resolve().parent.parent / "configs" / "authors.json"))


FINGUARD_ENV = os.environ.get("FINGUARD_ENV", "production")


def registered_humans() -> set[str]:
    """Registry file must declare the same environment as FINGUARD_ENV (default production),
    so a stray FINGUARD_AUTHORS_FILE cannot silently swap in the test registry."""
    try:
        reg = json.loads(Path(AUTHORS_FILE).read_text())
    except FileNotFoundError:
        return set()
    if reg.get("environment", "production") != FINGUARD_ENV:
        raise LicenseError(f"author registry {AUTHORS_FILE} is for environment "
                           f"'{reg.get('environment')}', not '{FINGUARD_ENV}'.")
    return set(reg.get("humans", {}))


def registry_info() -> dict:
    """Recorded in dataset cards so reviewers can see which registry approved the authors."""
    return {"authors_file": str(AUTHORS_FILE), "environment": FINGUARD_ENV}


def check_human(person: Optional[str]) -> None:
    if not HUMAN_AUTHOR_RE.match(person or ""):
        raise LicenseError(f"'{person}' is not a human:<id> identity.")
    pid = person.removeprefix("human:")
    if _MODELISH.search(pid):
        raise LicenseError(f"'{person}' looks like a model identity; refused.")
    if pid not in registered_humans():
        raise LicenseError(f"'{person}' is not in the approved author registry ({AUTHORS_FILE}).")


class LicenseError(RuntimeError):
    pass


def check_teacher(model_id: str) -> dict:
    mid = model_id.lower()
    for pat in BLOCKED_TEACHER_PATTERNS:
        if re.search(pat, mid):
            raise LicenseError(f"Teacher '{model_id}' is blocked by project licensing rule ({pat}).")
    if model_id not in TEACHER_ALLOWLIST:
        raise LicenseError(f"Teacher '{model_id}' is not on the verified allowlist.")
    return TEACHER_ALLOWLIST[model_id]


def check_source(source: str, for_training: bool = False) -> str:
    lic = SOURCE_LICENSES.get(source)
    if lic is None or lic == "VERIFY":
        raise LicenseError(f"Source '{source}' has no verified license; cannot be used in splits.")
    if for_training and source in EVAL_ONLY_SOURCES:
        raise LicenseError(f"Source '{source}' is eval-only; it cannot enter training data.")
    return lic


def check_template_author(author: str) -> None:
    if author.startswith("human:"):
        check_human(author)
        return
    if author.startswith("external:"):
        # Public benchmark item: allowed where its source license is verified. Training
        # exporters additionally call check_source(..., for_training=True).
        check_source(author.removeprefix("external:"))
        return
    if author.startswith("model:"):
        check_teacher(author.removeprefix("model:"))  # internal red-team generator on an allowed model
        return
    raise LicenseError(f"Template author '{author}' not allowed for train/test (fixture only).")


class Provenance(BaseModel):
    source_type: Literal["synthetic_template", "public_benchmark", "sandbox_run", "pilot_trace"]
    source: str                      # key in SOURCE_LICENSES
    source_item_id: str              # template id or benchmark item id
    source_license: str
    template_author: str             # human:<id> | model:<allowlisted id> | claude-fixture
    generator_version: str
    teacher_model: Optional[str] = None
    teacher_license: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    seed: Optional[int] = None
    filters_passed: list[str] = Field(default_factory=list)
    reviewed_by: Optional[str] = None       # second registered human who approved the template
    fixture_only: bool = False       # True => never in train/test splits or reported scores
