"""Config-driven split assignment (configs/splits.json) and near-duplicate removal.

Rules (CONTRACT rule 5: never random rows):
  1. attack_family in heldout_families      -> test_heldout_family
  2. workflow in heldout_workflows          -> test_heldout_workflow
  3. policy_set in heldout_policy_sets      -> test_heldout_policy
  4. otherwise by stable hash of template_id -> train / dev / test_iid
A template therefore lives in exactly one split, and no row of a held-out family, workflow
or policy set can reach train/dev. assert_no_leakage() re-checks this after the fact.

Near-duplicates: a test row that is almost a copy of a train row (char 5-gram Jaccard
> 0.8) measures memorisation, not generalisation, so it is dropped and counted. Exact
Jaccard for small sets; MinHash-LSH candidates + exact verification for large ones.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from pydantic import BaseModel, Field

from ..dataset import Example

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SPLITS_CONFIG = REPO / "configs" / "splits.json"
TRAIN_SIDE = ("train", "dev")
TEST_SPLITS = ("test_iid", "test_heldout_family", "test_heldout_workflow", "test_heldout_policy")
EXACT_PAIR_LIMIT = 2_000_000


class SplitError(RuntimeError):
    pass


class NearDupConfig(BaseModel):
    shingle_chars: int = 5
    jaccard_max: float = 0.8


class SplitConfig(BaseModel):
    version: str
    heldout_families: list[str] = Field(default_factory=list)
    heldout_workflows: list[str] = Field(default_factory=list)
    heldout_policy_sets: list[str] = Field(default_factory=list)
    iid_ratios: dict[str, float] = Field(default_factory=lambda: {"train": 0.7, "dev": 0.1, "test_iid": 0.2})
    hash_salt: str = "finguard-splits-v1"
    near_dup: NearDupConfig = Field(default_factory=NearDupConfig)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_SPLITS_CONFIG) -> "SplitConfig":
        d = json.loads(Path(path).read_text())
        return cls.model_validate({k: v for k, v in d.items() if not k.startswith("_")})


def template_bucket(template_id: str, salt: str) -> float:
    """Stable value in [0,1) per template (sha256; independent of process and row order)."""
    h = hashlib.sha256(f"{salt}|{template_id}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64


def split_for(ex: Example, cfg: SplitConfig) -> str:
    if ex.attack_family and ex.attack_family in cfg.heldout_families:
        return "test_heldout_family"
    if ex.workflow in cfg.heldout_workflows:
        return "test_heldout_workflow"
    if ex.policy_set in cfg.heldout_policy_sets:
        return "test_heldout_policy"
    u = template_bucket(ex.template_id, cfg.hash_salt)
    r = cfg.iid_ratios
    if u < r["train"]:
        return "train"
    if u < r["train"] + r["dev"]:
        return "dev"
    return "test_iid"


def _ensure_categories_in_train(rows: list[Example], tmpl_split: dict[str, str], cfg: SplitConfig) -> list[str]:
    """schema.RiskCategory promises every category appears in train. If hashing left a
    category with no train template, move that category's lowest-hash dev/test_iid
    template into train (deterministic, still template-level). Held-out splits are never
    touched. Returns the moved template ids so the card can report them."""
    cat_tmpls: dict[str, set[str]] = defaultdict(set)
    for ex in rows:
        cat_tmpls[ex.gold_category.value].add(ex.template_id)
    moved = []
    for cat, tids in sorted(cat_tmpls.items()):
        if any(tmpl_split[t] == "train" for t in tids):
            continue
        movable = sorted((t for t in tids if tmpl_split[t] in ("dev", "test_iid")),
                         key=lambda t: template_bucket(t, cfg.hash_salt))
        if movable:
            tmpl_split[movable[0]] = "train"
            moved.append(movable[0])
    return moved


def assign_splits(rows: Iterable[Example], cfg: SplitConfig, allow_fixtures: bool = False,
                  report: Optional[dict] = None) -> list[Example]:
    rows = list(rows)
    for ex in rows:
        if ex.provenance.fixture_only and not allow_fixtures:
            raise SplitError(f"{ex.example_id}: fixture_only row in a non-fixture build")
    tmpl_split = {ex.template_id: split_for(ex, cfg) for ex in rows}
    moved = _ensure_categories_in_train(rows, tmpl_split, cfg)
    if report is not None:
        report["moved_to_train_for_category_coverage"] = moved
    out = [ex.model_copy(update={"split": tmpl_split[ex.template_id]}) for ex in rows]
    assert_no_leakage(out, cfg)
    return out


def assert_no_leakage(rows: list[Example], cfg: SplitConfig) -> None:
    """Hard checks a reviewer can rely on; raises SplitError on any violation."""
    tmpl_splits: dict[str, set[str]] = defaultdict(set)
    for ex in rows:
        tmpl_splits[ex.template_id].add(ex.split)
        if ex.split in TRAIN_SIDE:
            if ex.attack_family in cfg.heldout_families:
                raise SplitError(f"held-out family {ex.attack_family} in {ex.split}: {ex.example_id}")
            if ex.workflow in cfg.heldout_workflows:
                raise SplitError(f"held-out workflow {ex.workflow} in {ex.split}: {ex.example_id}")
            if ex.policy_set in cfg.heldout_policy_sets:
                raise SplitError(f"held-out policy set {ex.policy_set} in {ex.split}: {ex.example_id}")
    multi = {t: s for t, s in tmpl_splits.items() if len(s) > 1}
    if multi:
        raise SplitError(f"templates span splits: {sorted(multi)[:5]}")


# ---------------- near-duplicate removal ----------------

def dedup_text(ex: Example) -> str:
    """Scenario text only. Policy clauses are excluded: they repeat across many rows by
    design and would make unrelated scenarios look like duplicates."""
    r = ex.request
    parts = [r.user_request, r.tool_call.name, json.dumps(r.tool_call.arguments, sort_keys=True)]
    parts += [f"{c.source}|{c.content}" for c in r.context]
    return " ".join(" ".join(parts).lower().split())


def _h64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")


def shingles(text: str, k: int = 5) -> frozenset[int]:
    """Character k-gram set, hashed to 64-bit ints (stable across processes)."""
    if len(text) < k:
        return frozenset({_h64(text)})
    return frozenset(_h64(text[i:i + k]) for i in range(len(text) - k + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


_MERSENNE = (1 << 61) - 1


def _minhash(sh: frozenset[int], perms: list[tuple[int, int]]) -> list[int]:
    return [min(((a * x + b) % _MERSENNE) for x in sh) for a, b in perms]


def _lsh_candidates(test_sh: list[frozenset], train_sh: list[frozenset], bands: int = 16, rows: int = 4) -> list[set[int]]:
    """Candidate train indices per test row. With 16x4 bands, P(catch | J=0.8) ~ 0.9998."""
    import random
    rng = random.Random(1234)
    perms = [(rng.randrange(1, _MERSENNE), rng.randrange(_MERSENNE)) for _ in range(bands * rows)]
    buckets: dict[tuple, list[int]] = defaultdict(list)
    for j, s in enumerate(train_sh):
        sig = _minhash(s, perms)
        for b in range(bands):
            buckets[(b, tuple(sig[b * rows:(b + 1) * rows]))].append(j)
    out = []
    for s in test_sh:
        sig = _minhash(s, perms)
        cand: set[int] = set()
        for b in range(bands):
            cand.update(buckets.get((b, tuple(sig[b * rows:(b + 1) * rows])), ()))
        out.append(cand)
    return out


class NearDupReport(BaseModel):
    threshold: float
    method: str
    checked_test_rows: int
    dropped: int
    dropped_by_split: dict[str, int]
    dropped_ids: list[str]
    max_jaccard_kept: float


def remove_near_duplicates(rows: list[Example], cfg: SplitConfig, method: Optional[str] = None) -> tuple[list[Example], NearDupReport]:
    """Drop test rows whose Jaccard to ANY train row exceeds cfg.near_dup.jaccard_max."""
    k, thr = cfg.near_dup.shingle_chars, cfg.near_dup.jaccard_max
    train = [ex for ex in rows if ex.split == "train"]
    test_idx = [i for i, ex in enumerate(rows) if ex.split in TEST_SPLITS]
    train_sh = [shingles(dedup_text(ex), k) for ex in train]
    test_sh = [shingles(dedup_text(rows[i]), k) for i in test_idx]
    method = method or ("exact" if len(train_sh) * len(test_sh) <= EXACT_PAIR_LIMIT else "minhash_lsh")
    if method == "exact":
        cands = [range(len(train_sh))] * len(test_sh)
    else:
        cands = _lsh_candidates(test_sh, train_sh)
    drop: set[int] = set()
    max_kept = 0.0
    for pos, i in enumerate(test_idx):
        best = max((jaccard(test_sh[pos], train_sh[j]) for j in cands[pos]), default=0.0)
        if best > thr:
            drop.add(i)
        else:
            max_kept = max(max_kept, best)
    by_split: dict[str, int] = defaultdict(int)
    for i in drop:
        by_split[rows[i].split] += 1
    kept = [ex for i, ex in enumerate(rows) if i not in drop]
    return kept, NearDupReport(threshold=thr, method=method, checked_test_rows=len(test_idx), dropped=len(drop),
                               dropped_by_split=dict(by_split), dropped_ids=sorted(rows[i].example_id for i in drop),
                               max_jaccard_kept=round(max_kept, 4))


def drop_cloned_test_templates(rows: list[Example], templates, cfg: SplitConfig) -> tuple[list[Example], list[dict]]:
    """Template-level near-duplicates. A template copied under a new id has different slot
    values in every row, so row-level Jaccard can stay under the cutoff (review finding H5).
    Compare unfilled template text; drop every row of a test template that is a near-copy
    of any train/dev template, and report it."""
    from .templates import template_skeleton
    split_of = {ex.template_id: ex.split for ex in rows}
    k, thr = cfg.near_dup.shingle_chars, cfg.near_dup.jaccard_max
    sk = {t.id: shingles(template_skeleton(t), k) for t in templates if t.id in split_of}
    train_ids = [i for i in sk if split_of[i] in ("train", "dev")]
    dropped: list[dict] = []
    for tid in sk:
        if split_of[tid] in ("train", "dev"):
            continue
        best_id, best = None, 0.0
        for j in train_ids:
            s = jaccard(sk[tid], sk[j])
            if s > best:
                best_id, best = j, s
        if best > thr:
            dropped.append({"template_id": tid, "split": split_of[tid], "clone_of": best_id, "jaccard": round(best, 3)})
    gone = {d["template_id"] for d in dropped}
    return [ex for ex in rows if ex.template_id not in gone], dropped
