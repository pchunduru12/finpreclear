"""Example JSONL -> VeRL RL parquet (one file per split: train.parquet, dev.parquet).

    python -m finguard.train.export_rl --in data/train.jsonl data/dev.jsonl --out build/rl [--allow-fixtures]

Columns (VeRL RLHFDataset convention):
  data_source   "finguard"        - selects the reward; ours is a custom function anyway
  prompt        [{role, content}] - system + user from prompt.build_messages (same seed as SFT)
  ability       "judge"
  reward_model  {style: "rule", ground_truth: <json string: gold labels + CheckRequest>}
  extra_info    {example_id, split, attack_family, workflow}

RL needs no teacher text (the reward uses construction-time gold labels), so the teacher
check is skipped here; split, fixture, source and author checks still apply.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

import pyarrow as pa
import pyarrow.parquet as pq

from ..dataset import Example, read_examples
from ..prompt import PROMPT_VERSION, build_messages
from .common import TRAINING_SPLITS, ground_truth_json, partition, prompt_seed, sha256_file

DATA_SOURCE = "finguard"

SCHEMA = pa.schema([
    ("data_source", pa.string()),
    ("prompt", pa.list_(pa.struct([("role", pa.string()), ("content", pa.string())]))),
    ("ability", pa.string()),
    ("reward_model", pa.struct([("style", pa.string()), ("ground_truth", pa.string())])),
    ("extra_info", pa.struct([("example_id", pa.string()), ("split", pa.string()),
                              ("attack_family", pa.string()), ("workflow", pa.string())])),
])


def to_rl_record(ex: Example) -> dict:
    return {
        "data_source": DATA_SOURCE,
        "prompt": build_messages(ex.request, seed=prompt_seed(ex.example_id)),
        "ability": "judge",
        "reward_model": {"style": "rule", "ground_truth": ground_truth_json(ex)},
        "extra_info": {"example_id": ex.example_id, "split": ex.split,
                       "attack_family": ex.attack_family, "workflow": ex.workflow},
    }


def export(rows: Iterable[Example], out_dir: str | Path, *, allow_fixtures: bool = False,
           skip_rejected: bool = False, inputs: list[str] = ()) -> dict:
    out = Path(out_dir)
    ok, bad = partition(rows, need_target=False, need_teacher=False, allow_fixtures=allow_fixtures)
    if bad and not skip_rejected:
        msg = "\n".join(f"  {r.example_id}: {r.reason}" for r in bad[:20])
        raise SystemExit(f"REFUSED {len(bad)} row(s):\n{msg}\n(fix the data or pass --skip-rejected)")
    out.mkdir(parents=True, exist_ok=True)
    counts, outputs = {}, {}
    for split in TRAINING_SPLITS:
        recs = [to_rl_record(e) for e in ok if e.split == split]
        counts[split] = len(recs)
        path = out / f"{split}.parquet"
        pq.write_table(pa.Table.from_pylist(recs, schema=SCHEMA), path)
        outputs[path.name] = sha256_file(path)
    manifest = {
        "prompt_version": PROMPT_VERSION, "counts": counts,
        "fixture_rows_included": sum(e.provenance.fixture_only for e in ok),
        "rejected": [{"example_id": r.example_id, "reason": r.reason} for r in bad],
        "inputs": {p: sha256_file(p) for p in inputs}, "outputs": outputs,
    }
    (out / "export_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--in", dest="inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--allow-fixtures", action="store_true", help="smoke tests only; never for a real run")
    ap.add_argument("--skip-rejected", action="store_true")
    a = ap.parse_args(argv)
    rows = (e for p in a.inputs for e in read_examples(p))
    m = export(rows, a.out, allow_fixtures=a.allow_fixtures, skip_rejected=a.skip_rejected, inputs=a.inputs)
    print(json.dumps({"counts": m["counts"], "rejected": len(m["rejected"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
