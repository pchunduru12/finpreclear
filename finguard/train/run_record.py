"""Create a training run directory and record what produced it (SR 11-7 model provenance).

    python -m finguard.train.run_record --kind sft --config configs/sft_qwen3_4b.yaml \
        --dataset-card data/dataset_card.json --data build/sft [--runs-dir runs] [--allow-dirty]

Prints the run dir path on stdout. Writes <run_dir>/run_manifest.json with: git commit and
dirty flag, sha256 of the dataset card, config and every exported data file, a copy of the
config, the gate state, reward config (GRPO), prompt/schema versions, python + package
versions, host and UTC start time.

Refuses (exit 4) when the code cannot be pinned to a commit (not a git repo, or uncommitted
changes) unless --allow-dirty, which is recorded in the manifest. A checkpoint whose code
cannot be reproduced is not acceptable evidence for model validation.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from .. import gates
from ..prompt import PROMPT_VERSION
from ..schema import SCHEMA_VERSION
from .common import sha256_file

TRACKED_PACKAGES = ["torch", "transformers", "llamafactory", "verl", "vllm", "deepspeed", "pydantic", "pyarrow"]


def git_state(repo: Path) -> dict:
    def run(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    try:
        return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"commit": None, "dirty": True}


def package_versions() -> dict:
    out = {}
    for p in TRACKED_PACKAGES:
        try:
            out[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            out[p] = None
    return out


def create_run(kind: str, config: Path, dataset_card: Path, data: Path, runs_dir: Path,
               repo: Path, allow_dirty: bool = False, now: datetime | None = None) -> Path:
    git = git_state(repo)
    if (git["commit"] is None or git["dirty"]) and not allow_dirty:
        raise SystemExit(4)
    if not dataset_card.is_file():
        raise FileNotFoundError(f"dataset card not found: {dataset_card}")
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    run_dir = runs_dir / f"{kind}_{config.stem}_{stamp}_{(git['commit'] or 'nogit')[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(config, run_dir / config.name)
    data_files = sorted(p for p in data.rglob("*") if p.is_file()) if data.is_dir() else [data]
    manifest = {
        "kind": kind,
        "started_utc": now.isoformat(),
        "git": git,
        "allow_dirty": allow_dirty,
        "config": {"path": str(config), "sha256": sha256_file(config)},
        "dataset_card": {"path": str(dataset_card), "sha256": sha256_file(dataset_card)},
        "data_files": {str(p): sha256_file(p) for p in data_files},
        "gates": gates.load(),
        "prompt_version": PROMPT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "python": sys.version.split()[0],
        "packages": package_versions(),
        "host": platform.node(),
    }
    if kind == "grpo":
        from .reward import config_dict
        manifest["reward_config_defaults"] = config_dict()
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kind", choices=["sft", "grpo"], required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--dataset-card", type=Path, required=True)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--runs-dir", type=Path, default=Path("runs"))
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--allow-dirty", action="store_true")
    a = ap.parse_args(argv)
    try:
        run_dir = create_run(a.kind, a.config, a.dataset_card, a.data, a.runs_dir, a.repo, a.allow_dirty)
    except SystemExit as e:
        if e.code == 4:
            print("REFUSED: code is not at a clean git commit (use --allow-dirty for smoke runs only)", file=sys.stderr)
        raise
    print(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
