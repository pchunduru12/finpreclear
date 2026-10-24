"""Example JSONL -> LLaMA-Factory SFT dataset (sharegpt-style "messages").

    python -m finguard.train.export_sft --in data/train.jsonl data/dev.jsonl --out build/sft \
        [--allow-fixtures] [--dataset-name finguard_sft]

Writes <out>/<name>_train.json, <out>/<name>_dev.json, <out>/dataset_info.json and
<out>/export_manifest.json (row counts, rejections, input sha256s - provenance for SR 11-7).

Refuses (does not silently drop) rows that would contaminate training: any split other
than train/dev, fixture_only rows (unless --allow-fixtures), unverified sources/authors,
teachers not on the allowlist or from blocked providers, targets that disagree with the
construction-time gold label, ungrounded stop evidence. Exit code 2 if any row is refused,
unless --skip-rejected, in which case refused rows are listed in the manifest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from ..dataset import Example, read_examples
from ..prompt import PROMPT_VERSION, build_messages
from .common import TRAINING_SPLITS, partition, prompt_seed, sha256_file, target_text


def to_sft_record(ex: Example) -> dict:
    """One training conversation. The prompt comes only from prompt.build_messages."""
    assert ex.target is not None
    msgs = build_messages(ex.request, seed=prompt_seed(ex.example_id))
    return {
        "messages": msgs + [{"role": "assistant", "content": target_text(ex.target)}],
        # Extra keys are ignored by LLaMA-Factory (columns map only "messages") but keep
        # every training row traceable back to its Example.
        "example_id": ex.example_id,
        "split": ex.split,
    }


def dataset_info_entry(file_name: str) -> dict:
    """LLaMA-Factory dataset_info.json entry for sharegpt format with OpenAI-style roles."""
    return {
        "file_name": file_name,
        "formatting": "sharegpt",
        "columns": {"messages": "messages"},
        "tags": {
            "role_tag": "role", "content_tag": "content",
            "user_tag": "user", "assistant_tag": "assistant", "system_tag": "system",
        },
    }


def export(rows: Iterable[Example], out_dir: str | Path, *, name: str = "finguard_sft",
           allow_fixtures: bool = False, skip_rejected: bool = False, inputs: list[str] = ()) -> dict:
    out = Path(out_dir)
    ok, bad = partition(rows, need_target=True, need_teacher=True, allow_fixtures=allow_fixtures)
    if bad and not skip_rejected:
        msg = "\n".join(f"  {r.example_id}: {r.reason}" for r in bad[:20])
        raise SystemExit(f"REFUSED {len(bad)} row(s):\n{msg}\n(fix the data or pass --skip-rejected)")
    out.mkdir(parents=True, exist_ok=True)
    info, counts = {}, {}
    for split in TRAINING_SPLITS:
        recs = [to_sft_record(e) for e in ok if e.split == split]
        counts[split] = len(recs)
        fname = f"{name}_{split}.json"
        (out / fname).write_text(json.dumps(recs, ensure_ascii=False, indent=1))
        info[f"{name}_{split}"] = dataset_info_entry(fname)
    (out / "dataset_info.json").write_text(json.dumps(info, indent=2))
    manifest = {
        "prompt_version": PROMPT_VERSION,
        "counts": counts,
        "fixture_rows_included": sum(e.provenance.fixture_only for e in ok),
        "rejected": [{"example_id": r.example_id, "reason": r.reason} for r in bad],
        "inputs": {p: sha256_file(p) for p in inputs},
        "outputs": {f"{name}_{s}.json": sha256_file(out / f"{name}_{s}.json") for s in TRAINING_SPLITS},
    }
    (out / "export_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def _read_all(paths: list[str]) -> Iterable[Example]:
    for p in paths:
        yield from read_examples(p)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--in", dest="inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dataset-name", default="finguard_sft")
    ap.add_argument("--allow-fixtures", action="store_true", help="smoke tests only; never for a real run")
    ap.add_argument("--skip-rejected", action="store_true")
    a = ap.parse_args(argv)
    m = export(_read_all(a.inputs), a.out, name=a.dataset_name, allow_fixtures=a.allow_fixtures,
               skip_rejected=a.skip_rejected, inputs=a.inputs)
    print(json.dumps({"counts": m["counts"], "rejected": len(m["rejected"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
