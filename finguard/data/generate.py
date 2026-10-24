"""Expand templates into Example rows.

Why it works this way:
- Slot filling is seeded from (seed, template_id, index) via sha256, so a rebuild with the
  same seed reproduces the same rows byte-for-byte (model-risk reproducibility).
- All entities are fake (ACME-style names, ACCT-0000-1111 accounts, *.example domains),
  per CONTRACT rule 4.
- Policy clauses come from finguard.retrieval.PolicyRetriever, the same retriever the
  gateway uses, so training sees exactly what serving will see.
- Every attack/violation row must contain its planted trigger text verbatim; we assert
  this with schema.evidence_is_grounded so the evidence filter and reward can rely on it.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from ..dataset import Example
from ..provenance import LicenseError, Provenance, check_source, check_template_author
from ..retrieval import PolicyRetriever
from ..schema import CheckRequest, ContextItem, ToolCall, evidence_is_grounded
from .templates import SLOT_RE, Template

GENERATOR_VERSION = "gen-1.0"
SOURCE = "synthetic_v1"

REPO = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_DIRS = [REPO / "policies", REPO / "fixtures" / "policies"]

# ---- fake entity pools (fictional names only; nothing resembles a real bank or account) ----
VENDORS = ["Acme Industrial Supply", "Globex Parts Co", "Initech Office Services", "Umbrella Logistics",
           "Vandelay Imports", "Soylent Foods", "Tyrell Components", "Wonka Packaging", "Cyberdyne Facilities",
           "Hooli Cloud Services", "Oscorp Lab Supply", "Gringotts Courier"]
PEOPLE = ["Jordan Avery", "Sam Patel", "Riley Chen", "Morgan Diaz", "Casey Okafor", "Taylor Novak",
          "Jamie Rossi", "Alex Kim", "Drew Haddad", "Quinn Larsen", "Robin Mbeki", "Avery Santos"]


class GenerationError(RuntimeError):
    pass


def stable_int(*parts: Any) -> int:
    """Process-independent hash (Python's hash() is salted per process)."""
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:8], "big")


def _slug(s: str) -> str:
    return "".join(ch for ch in s.lower().replace(" ", ".") if ch.isalnum() or ch == ".")


def _acct(rng: random.Random) -> str:
    return f"ACCT-{rng.randrange(10_000):04d}-{rng.randrange(10_000):04d}"


def _usd(x: float) -> str:
    return f"USD {x:,.2f}"


def fill_slots(rng: random.Random) -> dict[str, str]:
    """One coherent set of fake values. Accounts and ids are guaranteed distinct."""
    v1, v2 = rng.sample(VENDORS, 2)
    p = rng.sample(PEOPLE, 4)
    accts: set[str] = set()
    while len(accts) < 3:
        accts.add(_acct(rng))
    acct_list = sorted(accts)  # sort first: set order is not deterministic across processes
    rng.shuffle(acct_list)
    a_master, a_attacker, a_new = acct_list
    small = rng.randrange(500, 20_000) + rng.randrange(100) / 100
    large = rng.randrange(30_000, 72_000)  # above the 25k agent limit; a third stays below it
    wire = rng.randrange(100_000, 999_999)
    vendor_slug = _slug(v1).split(".")[0]
    return {
        "vendor_name": v1,
        "vendor_name_alt": v2,
        "vendor_domain": f"{vendor_slug}.example",
        "attacker_domain": f"{vendor_slug}-{rng.choice(['payments', 'billing-desk', 'remit', 'accounts-team'])}.example",
        "bank_domain": "bank.example",
        "contact_name": p[0],
        "approver_name": p[1],
        "employee_name": p[2],
        "employee_name_slug": _slug(p[2]),
        "customer_name": p[3],
        "customer_email": f"{_slug(p[3])}@mail.example",
        "attacker_email": f"records-{rng.randrange(100, 999)}@archive-drop.example",
        "employee_id": f"EMP-{rng.randrange(10_000, 99_999)}",
        "customer_id": f"CUST-{rng.randrange(100_000, 999_999)}",
        "invoice_id": f"INV-{rng.randrange(10_000, 99_999)}",
        "po_id": f"PO-{rng.randrange(10_000, 99_999)}",
        "wire_id": f"WIRE-{wire}",
        "wire_id_alt": f"WIRE-{wire + rng.randrange(1, 5_000)}",
        "case_id": f"CASE-{rng.randrange(1_000, 9_999)}",
        "acct_master": a_master,
        "acct_attacker": a_attacker,
        "acct_new": a_new,
        "amount_small": _usd(small),
        "amount_large": _usd(large),
        "amount_third": _usd(round(large / 3, 2)),
        "phone": f"+1-555-01{rng.randrange(100):02d}",
        "date": f"2026-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}",
        "record_count": str(rng.choice([5_000, 25_000, 120_000])),
    }


def _render(text: str, slots: dict[str, str], tid: str) -> str:
    def sub(m):
        k = m.group(1)
        if k not in slots:
            raise GenerationError(f"template {tid}: unknown slot {{{k}}}")
        return slots[k]
    return SLOT_RE.sub(sub, text)


def _render_obj(obj: Any, slots: dict[str, str], tid: str) -> Any:
    if isinstance(obj, str):
        return _render(obj, slots, tid)
    if isinstance(obj, dict):
        return {k: _render_obj(v, slots, tid) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render_obj(v, slots, tid) for v in obj]
    return obj


class RetrieverPool:
    """Loads one PolicyRetriever per policy_set from policies/<set>.jsonl (first match wins)."""

    def __init__(self, policy_dirs: Optional[Iterable[str | Path]] = None, k: int = 5):
        self.dirs = [Path(d) for d in (policy_dirs or DEFAULT_POLICY_DIRS)]
        self.k = k
        self._cache: dict[str, PolicyRetriever] = {}

    def get(self, policy_set: str) -> PolicyRetriever:
        if policy_set not in self._cache:
            for d in self.dirs:
                p = d / f"{policy_set}.jsonl"
                if p.exists():
                    self._cache[policy_set] = PolicyRetriever.from_jsonl(p, k=self.k)
                    break
            else:
                raise GenerationError(f"policy set '{policy_set}' not found in {[str(d) for d in self.dirs]}")
        return self._cache[policy_set]

    def versions(self) -> dict[str, str]:
        return {k: r.version for k, r in sorted(self._cache.items())}


def author_is_fixture(author: str) -> bool:
    """True when the author may NOT feed train/test (provenance.check_template_author fails)."""
    try:
        check_template_author(author)
        return False
    except LicenseError:
        return True


def generate_examples(t: Template, n: int, seed: int, retrievers: RetrieverPool,
                      created_at: Optional[str] = None) -> list[Example]:
    """Render n rows of one template. Deterministic for a given (seed, template id, n,
    created_at); pass a fixed created_at to get byte-identical rebuilds."""
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    source_license = check_source(SOURCE)
    fixture_only = author_is_fixture(t.author)
    retriever = retrievers.get(t.policy_set)
    rows: list[Example] = []
    for i in range(n):
        row_seed = stable_int(seed, t.id, i) % (2**31)
        slots = fill_slots(random.Random(row_seed))
        rid = f"{t.id}-s{seed}-{i:03d}"
        req = CheckRequest(
            request_id=rid,
            agent_role=t.agent_role,
            user_request=_render(t.user_request, slots, t.id),
            tool_call=ToolCall(name=t.tool_name, arguments=_render_obj(t.arguments, slots, t.id)),
            context=[ContextItem(source=c.source, trust=c.trust, content=_render(c.content, slots, t.id)) for c in t.context],
            workflow=t.workflow,
        )
        req.policy_clauses = retriever.retrieve(req)
        trigger = _render(t.trigger_span, slots, t.id) if t.trigger_span else None
        if trigger is not None and not evidence_is_grounded(trigger, req):
            raise GenerationError(f"template {t.id}: trigger span not found verbatim in rendered row {rid}")
        rows.append(Example(
            example_id=rid,
            request=req,
            gold_verdict=t.gold_verdict,
            gold_category=t.gold_category,
            gold_trigger_span=trigger,
            is_attack=t.is_attack,
            attack_family=t.attack_family,
            benign_kind=t.benign_kind,
            workflow=t.workflow,
            policy_set=t.policy_set,
            template_id=t.id,
            provenance=Provenance(
                source_type="synthetic_template",
                source=SOURCE,
                source_item_id=t.id,
                source_license=source_license,
                template_author=t.author,
                reviewed_by=t.reviewed_by,
                generator_version=GENERATOR_VERSION,
                seed=row_seed,
                created_at=created_at,
                fixture_only=fixture_only,
                filters_passed=["trigger_grounded"] if trigger else [],
            ),
        ))
    return rows


def generate_all(templates: list[Template], n_per_template: int, seed: int, retrievers: RetrieverPool,
                 created_at: Optional[str] = None) -> list[Example]:
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    out: list[Example] = []
    for t in templates:
        out += generate_examples(t, n_per_template, seed, retrievers, created_at)
    return out


def template_reason(t: Template) -> str:
    """Reason text for --fixtures targets (no teacher): the template's own fixture_reason."""
    return t.fixture_reason or ("Action serves the request and meets policy." if t.gold_verdict == "allow"
                                else f"Gold {t.gold_verdict.value}: {t.gold_category.value}.")
