"""Dataset build CLI.

  python -m finguard.data.build --templates PATH --out DIR [--fixtures]
      [--teacher-url URL --teacher-model ID] [--n-per-template N] [--seed S]

Pipeline: load templates -> author check -> generate -> label -> split -> near-dup ->
write one JSONL per split + dataset_card.json + review_queue.jsonl.

--fixtures: test-only build. Allows claude-fixture templates, skips the teacher, and
writes targets straight from gold (evidence = trigger span). Every row is fixture_only
and the card says so; these files must never feed training or reported scores.
Non-fixture builds refuse any template whose author fails provenance.check_template_author
and require the 'teacher_selected' gate before any teacher call.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..dataset import Example, write_jsonl
from ..prompt import PROMPT_VERSION
from ..provenance import LicenseError, check_human, check_template_author, registry_info
from ..schema import SCHEMA_VERSION, STOP_VERDICTS
from .generate import GENERATOR_VERSION, RetrieverPool, generate_all, template_reason
from .label import REJECTION_FLAG_THRESHOLD, Teacher, TeacherClient, fixture_targets, label_examples, require_teacher_gate
from .splits import DEFAULT_SPLITS_CONFIG, SplitConfig, assign_splits, drop_cloned_test_templates, remove_near_duplicates
from .templates import Template, load_templates

ALL_SPLITS = ["train", "dev", "test_iid", "test_heldout_family", "test_heldout_workflow", "test_heldout_policy"]


class BuildError(RuntimeError):
    pass


def check_authors(templates: list[Template], fixtures: bool) -> None:
    if fixtures:
        return
    bad = []
    for t in templates:
        try:
            check_template_author(t.author)
            check_human(t.reviewed_by)  # a second registered human approved it
            if t.reviewed_by == t.author:
                raise LicenseError("reviewer must differ from author")
        except LicenseError as e:
            bad.append(f"{t.id}: {e}")
    if bad:
        raise BuildError("non-fixture build refuses templates:\n  " + "\n  ".join(bad))


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _benign(ex: Example) -> bool:
    return ex.gold_verdict not in STOP_VERDICTS


def dataset_card(rows: list[Example], files: dict[str, Path], *, fixtures: bool, seed: int, n_per_template: int,
                 retrievers: RetrieverPool, cfg: SplitConfig, near_dup: dict, label_report: Optional[dict],
                 n_review: int, templates_path: str, split_report: Optional[dict] = None) -> dict:
    """Counts and provenance a model-risk reviewer needs to sign off on a dataset."""
    by_split = defaultdict(list)
    for ex in rows:
        by_split[ex.split].append(ex)

    def share(xs, pred):
        return round(sum(map(pred, xs)) / len(xs), 4) if xs else None

    benign = [ex for ex in rows if _benign(ex)]
    counts = {}
    for s in ALL_SPLITS:
        xs = by_split.get(s, [])
        counts[s] = {
            "rows": len(xs),
            "templates": len({x.template_id for x in xs}),
            "by_family": dict(sorted(Counter(x.attack_family or ("benign" if _benign(x) else "policy_violation") for x in xs).items())),
            "by_workflow": dict(sorted(Counter(x.workflow for x in xs).items())),
            "by_verdict": dict(sorted(Counter(x.gold_verdict.value for x in xs).items())),
            "benign_share": share(xs, _benign),
        }
    warnings = []
    for s, c in counts.items():
        if s == "test_heldout_family":
            continue  # attacks-only by construction; its benign share is 0 on purpose
        if c["rows"] and c["benign_share"] is not None and not (0.35 <= c["benign_share"] <= 0.65):
            warnings.append(f"{s}: benign share {c['benign_share']} outside 0.35-0.65 (target ~0.50)")
    train_cats = {x.gold_category.value for x in by_split.get("train", [])}
    all_cats = {x.gold_category.value for x in rows}
    if missing := sorted(all_cats - train_cats):
        warnings.append(f"categories absent from train: {missing}")
    if label_report:
        for fam, v in label_report["by_family"].items():
            if v["flagged"]:
                warnings.append(f"teacher rejection {v['rate']:.0%} for family {fam} (> {REJECTION_FLAG_THRESHOLD:.0%}): filtered data is biased toward easy cases")
    prov = {
        "sources": dict(Counter(x.provenance.source for x in rows)),
        "source_licenses": sorted({x.provenance.source_license for x in rows}),
        "template_authors": dict(Counter(x.provenance.template_author for x in rows)),
        "teacher_models": dict(Counter(x.provenance.teacher_model or "none" for x in rows)),
        "teacher_licenses": sorted({x.provenance.teacher_license for x in rows if x.provenance.teacher_license}),
        "fixture_only_rows": sum(x.provenance.fixture_only for x in rows),
    }
    return {
        "fixture_build": fixtures,
        "WARNING": "FIXTURE BUILD: claude-fixture templates, gold-derived targets. Not training data; never report scores on it." if fixtures else None,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "templates_file": templates_path,
        "seed": seed,
        "n_per_template": n_per_template,
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "prompt_version": PROMPT_VERSION,
        "retriever_versions": retrievers.versions(),
        "splits_config": {"version": cfg.version, "heldout_families": cfg.heldout_families,
                          "heldout_workflows": cfg.heldout_workflows, "heldout_policy_sets": cfg.heldout_policy_sets,
                          **(split_report or {})},
        "total_rows": len(rows),
        "benign_share_overall": share(rows, _benign),
        "lookalike_share_of_benign": share(benign, lambda x: x.benign_kind == "lookalike"),
        "counts": counts,
        "near_duplicates": near_dup,
        "labeling": label_report,
        "review_queue_rows": n_review,
        "provenance": prov,
        "author_registry": registry_info(),
        "files": {k: {"path": p.name, "sha256": _sha256(p)} for k, p in files.items()},
        "warnings": warnings,
    }


def build(templates_path: str, out_dir: str, *, fixtures: bool = False, teacher: Optional[Teacher] = None,
          n_per_template: int = 4, seed: int = 0, splits_config: str | Path = DEFAULT_SPLITS_CONFIG,
          policy_dirs=None, created_at: Optional[str] = None) -> dict:
    """Library entry point (the CLI wraps this). Returns the dataset card."""
    templates = load_templates(templates_path)
    check_authors(templates, fixtures)
    retrievers = RetrieverPool(policy_dirs)
    rows = generate_all(templates, n_per_template, seed, retrievers, created_at)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    label_report, rejections = None, []
    if fixtures:
        rows = fixture_targets(rows, {t.id: template_reason(t) for t in templates})
    else:
        if teacher is None:
            raise BuildError("non-fixture build needs a teacher (--teacher-url and --teacher-model)")
        res = label_examples(rows, teacher, prompt_seed=seed)
        rows, rejections = res.kept, res.rejected
        label_report = {"teacher_model": teacher.model_id, "kept": len(res.kept), "rejected": len(res.rejected),
                        "by_filter": res.by_filter, "by_family": res.by_family}

    cfg = SplitConfig.load(splits_config)
    split_report: dict = {}
    rows = assign_splits(rows, cfg, allow_fixtures=fixtures, report=split_report)
    rows, dropped_tmpl = drop_cloned_test_templates(rows, templates, cfg)
    split_report["test_templates_dropped_as_clones_of_train"] = dropped_tmpl
    rows, nd = remove_near_duplicates(rows, cfg)

    files: dict[str, Path] = {}
    for s in ALL_SPLITS:
        p = out / f"{s}.jsonl"
        write_jsonl([x for x in rows if x.split == s], p)
        files[s] = p
    rq = out / "review_queue.jsonl"
    write_jsonl(rejections, rq)
    files["review_queue"] = rq

    card = dataset_card(rows, files, fixtures=fixtures, seed=seed, n_per_template=n_per_template,
                        retrievers=retrievers, cfg=cfg, near_dup=nd.model_dump(), label_report=label_report,
                        n_review=len(rejections), templates_path=str(templates_path),
                        split_report=split_report)
    (out / "dataset_card.json").write_text(json.dumps(card, indent=2) + "\n")
    return card


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m finguard.data.build", description=__doc__.split("\n\n")[0])
    ap.add_argument("--templates", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fixtures", action="store_true", help="test-only build: allow claude-fixture templates, no teacher")
    ap.add_argument("--teacher-url")
    ap.add_argument("--teacher-model")
    ap.add_argument("--n-per-template", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--splits-config", default=str(DEFAULT_SPLITS_CONFIG))
    a = ap.parse_args(argv)

    teacher = None
    if not a.fixtures:
        if not (a.teacher_url and a.teacher_model):
            ap.error("non-fixture builds need --teacher-url and --teacher-model")
        require_teacher_gate()  # raises GateClosed until the teacher decision is signed off
        teacher = TeacherClient(a.teacher_url, a.teacher_model)
    card = build(a.templates, a.out, fixtures=a.fixtures, teacher=teacher, n_per_template=a.n_per_template,
                 seed=a.seed, splits_config=a.splits_config)
    summary = {s: c["rows"] for s, c in card["counts"].items()}
    print(json.dumps({"rows": summary, "benign_share": card["benign_share_overall"],
                      "near_dup_dropped": card["near_duplicates"]["dropped"], "warnings": card["warnings"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
