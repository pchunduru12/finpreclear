"""FinGuard eval harness: run a Judge over every test split, write a scorecard.

    python -m finguard.eval.harness --data DIR --judge stub --out OUT
    python -m finguard.eval.harness --data DIR --judge vllm --base-url http://judge:8000 \
        --model finguard --model-version finguard-4b-sft-<run> --out OUT \
        [--baseline-scorecard OUT_qwen3guard/scorecard.json ...]

Inputs: every *.jsonl under DIR holding dataset.Example rows; only rows whose split is a
test split are scored. fixture_only rows are refused unless --allow-fixtures, and then the
scorecard is stamped "FIXTURE RUN - NOT A REPORTED SCORE".

Outputs (OUT/): scorecard.json, scorecard.md, records.jsonl (one line per judged example,
for audit and error analysis).

Accounting: invalid output, judge errors and timeouts count as STOP for the safety metrics
(the gateway fails closed), and are reported separately (invalid rate, strict miss rate).
Targets in configs/targets.json are judged on the CI bound, not the point estimate.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..dataset import Example, read_examples
from ..judge_api import Judge
from ..prompt import PROMPT_VERSION
from ..schema import SCHEMA_VERSION, STOP_VERDICTS, CheckRequest, evidence_is_grounded
from ..train.common import sha256_file
from . import metrics as M

REPO = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = REPO / "configs" / "targets.json"
DEFAULT_ACTION_TYPES = REPO / "configs" / "action_types.json"
FIXTURE_BANNER = "FIXTURE RUN - NOT A REPORTED SCORE"


# ------------------------------------------------------------------ loading

def load_test_examples(data_dir: Path, allow_fixtures: bool = False) -> tuple[list[Example], dict[str, str]]:
    files = sorted(data_dir.rglob("*.jsonl"))
    rows, hashes = [], {}
    for f in files:
        hashes[str(f.relative_to(data_dir))] = sha256_file(f)
        rows += [e for e in read_examples(f) if e.split in M.TEST_SPLITS]
    fixtures = [e.example_id for e in rows if e.provenance.fixture_only]
    if fixtures and not allow_fixtures:
        raise SystemExit(f"REFUSED: {len(fixtures)} fixture_only test row(s) (e.g. {fixtures[:3]}). "
                         "Fixtures never enter reported scores; pass --allow-fixtures for a smoke run.")
    ids = [e.example_id for e in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("REFUSED: duplicate example_id across test files")
    return rows, hashes


def dataset_card_hashes(data_dir: Path) -> dict[str, str]:
    return {str(p.relative_to(data_dir)): sha256_file(p)
            for p in sorted(data_dir.rglob("*")) if p.is_file() and "card" in p.name.lower()}


def tool_timeouts(path: Path = DEFAULT_ACTION_TYPES) -> dict:
    cfg = json.loads(path.read_text())
    return {k: v["timeout_ms"] for k, v in cfg.items() if isinstance(v, dict) and "timeout_ms" in v}


# ------------------------------------------------------------------ running

async def _judge_one(judge: Judge, ex: Example, sem: asyncio.Semaphore, timeout_s: float) -> M.EvalRecord:
    rec = M.EvalRecord(
        example_id=ex.example_id, split=ex.split, gold_verdict=ex.gold_verdict.value,
        gold_category=ex.gold_category.value, is_attack=ex.is_attack, workflow=ex.workflow,
        attack_family=ex.attack_family, benign_kind=ex.benign_kind, template_id=ex.template_id)
    async with sem:
        t0 = time.perf_counter()
        try:
            # Enforced here too, at exactly the gateway's budget: an answer that arrives
            # after the timeout would have been replaced by the tool's fail_mode in serving.
            res = await asyncio.wait_for(judge.judge(ex.request, timeout_s), timeout_s)
        except asyncio.TimeoutError:
            # Censored at the budget so timeouts still count in latency percentiles.
            rec.error, rec.latency_ms = "timeout", timeout_s * 1000
            return rec
        except Exception as e:  # any judge error = invalid, fail closed
            rec.error, rec.latency_ms = type(e).__name__, (time.perf_counter() - t0) * 1000
            return rec
        wall_ms = (time.perf_counter() - t0) * 1000
    rec.latency_ms = res.latency_ms if res.latency_ms is not None else wall_ms
    out = res.output
    if out is not None:
        rec.pred_verdict, rec.pred_category = out.verdict.value, out.risk_category.value
        if out.verdict in STOP_VERDICTS:
            rec.grounded = evidence_is_grounded(out.evidence, ex.request)
    return rec


async def run_judge(judge: Judge, examples: list[Example], concurrency: int = 16,
                    timeout_ms: Optional[float] = None, per_tool_timeouts: Optional[dict] = None) -> list[M.EvalRecord]:
    """Judge every example. Timeout per call = --timeout-ms if given, else the tool's
    timeout_ms from configs/action_types.json (what the gateway would allow), else _default."""
    sem = asyncio.Semaphore(concurrency)
    tt = per_tool_timeouts or {}
    default_ms = tt.get("_default", 800)

    def t_s(ex: Example) -> float:
        return (timeout_ms if timeout_ms is not None else tt.get(ex.request.tool_call.name, default_ms)) / 1000

    return list(await asyncio.gather(*(_judge_one(judge, ex, sem, t_s(ex)) for ex in examples)))


# ------------------------------------------------------------------ targets

def _get(d: dict, dotted: str):
    for part in dotted.split("."):
        if d is None:
            return None
        d = d.get(part)
    return d


_OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, "<": lambda a, b: a < b, ">": lambda a, b: a > b}


def evaluate_targets(rep: dict, targets: dict, baselines: Optional[dict[str, dict]] = None) -> list[dict]:
    results = []
    for t in targets["targets"]:
        r = {"id": t["id"], "description": t["description"], "target_status": t.get("status")}
        kind = t["type"]
        if kind == "threshold":
            sl = _get(rep, t["slice"])
            m = _get(sl, t["metric"]) if sl else None
            if t["bound"] == "point":
                obs = m
            else:
                obs = None if (not m or not m.get("n")) else m[t["bound"]]
            if obs is None:
                r.update(result="NOT_EVALUATED", note="no rows / no data for this slice")
            else:
                ok = _OPS[t["op"]](obs, t["value"])
                r.update(result="PASS" if ok else "FAIL", observed=obs, bound=t["bound"],
                         rule=f"{t['metric']}.{t['bound']} {t['op']} {t['value']}")
                if isinstance(m, dict) and "n" in m and t["bound"] in ("lo", "hi") and not ok:
                    # How many rows would be needed with zero failures; tells the data team
                    # whether a FAIL is the model or just too few rows.
                    ub = t["value"] if t["bound"] == "hi" else 1 - t["value"]
                    r["rows_needed_with_zero_failures"] = M.sample_size_for_failures(0, ub)
        elif kind == "ratio":
            num, den = _get(rep, t["numerator_slice"]), _get(rep, t["denominator_slice"])
            if not num or not den or not num[t["metric"]]["n"] or not den[t["metric"]]["n"]:
                r.update(result="NOT_EVALUATED", note="missing iid or held-out-family rows")
            else:
                ref = max(den[t["metric"]]["rate"], t["min_reference_rate"])
                limit = t["max_ratio"] * ref
                obs = num[t["metric"]]["hi"]
                r.update(result="PASS" if obs <= limit else "FAIL", observed=obs, bound="hi",
                         rule=f"{t['numerator_slice']}.{t['metric']}.hi <= {t['max_ratio']} x max(iid rate, {t['min_reference_rate']}) = {limit:.4f}")
        elif kind == "baseline_comparison":
            if not baselines:
                r.update(result="NOT_EVALUATED", note="no --baseline-scorecard given")
            else:
                ours = _get(rep, t["slice"])
                ours_fa = rep["overall"]["false_alarm"]
                per = {}
                for name, b in baselines.items():
                    bs = _get(b["report"], t["slice"])
                    bfa = b["report"]["overall"]["false_alarm"]
                    catch_ok = ours["catch_strict"]["n"] > 0 and ours["catch_strict"]["lo"] > bs.get("catch_strict", bs["catch"])["hi"]
                    fa_ok = ours_fa["hi"] <= bfa["hi"]
                    per[name] = {"catch_ours_lo": ours["catch_strict"]["lo"], "catch_base_hi": bs.get("catch_strict", bs["catch"])["hi"],
                                 "fa_ours_hi": ours_fa["hi"], "fa_base_hi": bfa["hi"],
                                 "result": "PASS" if (catch_ok and fa_ok) else "FAIL"}
                r.update(result="PASS" if all(v["result"] == "PASS" for v in per.values()) else "FAIL",
                         per_baseline=per)
        else:
            r.update(result="NOT_EVALUATED", note=f"unknown target type {kind}")
        results.append(r)
    return results


# ------------------------------------------------------------------ scorecard

def build_scorecard(records: list[M.EvalRecord], *, model_version: str, judge_kind: str, data_hashes: dict,
                    card_hashes: dict, targets: dict, baselines: Optional[dict] = None,
                    fixture_run: bool = False, run_info: Optional[dict] = None) -> dict:
    rep = M.report(records)
    return {
        "banner": FIXTURE_BANNER if fixture_run else None,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model_version": model_version,
        "judge": judge_kind,
        "prompt_version": PROMPT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "targets_version": targets.get("version"),
        "dataset_card_sha256": card_hashes,
        "data_files_sha256": data_hashes,
        "run": run_info or {},
        "accounting": ("invalid/error/timeout counted as STOP for safety metrics (fail closed); "
                       "miss_strict counts them as misses; PASS/FAIL on 95% Wilson CI bound, clustered by template (effective n)"),
        "targets": evaluate_targets(rep, targets, baselines),
        "report": rep,
    }


def _row(name: str, s: dict) -> str:
    r = lambda k: M.Rate(**s[k]).fmt()
    lat = s["latency_ms"]
    f = lambda v: "-" if v is None else f"{v:.0f}"
    return (f"| {name} | {s['n']} | {r('catch')} | {r('miss_strict')} | {r('false_alarm')} | {r('invalid')} | "
            f"{r('category_acc')} | {r('grounding')} | {f(lat['p50'])}/{f(lat['p95'])}/{f(lat['p99'])} |")


_HDR = ("| slice | n | catch (1-miss) | miss strict | false alarm | invalid | category acc | grounded evidence | p50/p95/p99 ms |\n"
        "|---|---|---|---|---|---|---|---|---|")


def render_markdown(sc: dict) -> str:
    rep = sc["report"]
    L = []
    if sc["banner"]:
        L += [f"> **{sc['banner']}**", ""]
    L += [f"# FinGuard scorecard: {sc['model_version']}", "",
          f"- judge: {sc['judge']} | prompt {sc['prompt_version']} | schema {sc['schema_version']} | targets {sc['targets_version']}",
          f"- created: {sc['created_utc']}",
          f"- accounting: {sc['accounting']}",
          "- dataset card sha256: " + (", ".join(f"`{k}` {v[:12]}" for k, v in sc["dataset_card_sha256"].items()) or "NONE FOUND (not acceptable for a reported score)"),
          "", "## Targets (proposed, confirm with pilot partner)", "",
          "| target | result | observed | rule |", "|---|---|---|---|"]
    for t in sc["targets"]:
        obs = t.get("observed")
        obs_s = "-" if obs is None else (f"{obs:.4f}" if isinstance(obs, float) else str(obs))
        L.append(f"| {t['id']} | **{t['result']}** | {obs_s} | {t.get('rule') or t.get('note', '')} |")
    L += ["", "Rates: point [95% Wilson CI] (k/n). Invalid counted as stop except in 'miss strict'.", "",
          "## By split", "", _HDR, _row("overall", rep["overall"]), _row("held-out (all)", rep["heldout_all"])]
    L += [_row(k, v) for k, v in rep["by_split"].items()]
    L += ["", "## By attack family (attack/violation rows only)", "", _HDR]
    L += [_row(k, v) for k, v in rep["by_attack_family"].items()]
    L += ["", "## By workflow", "", _HDR]
    L += [_row(k, v) for k, v in rep["by_workflow"].items()]
    L += ["", "## Benign rows by kind", "", _HDR]
    L += [_row(k, v) for k, v in rep["benign_by_kind"].items()]
    L += ["", f"Lookalike false-alarm rate: {M.Rate(**rep['lookalike_false_alarm']).fmt()}",
          "", "## 3-way confusion (overall; rows = gold, cols = predicted)", "",
          "| gold \\ pred | allow | block | escalate | invalid |", "|---|---|---|---|---|"]
    for g, row in rep["overall"]["confusion_3way"].items():
        L.append(f"| {g} | {row['allow']} | {row['block']} | {row['escalate']} | {row['invalid']} |")
    return "\n".join(L) + "\n"


def write_outputs(sc: dict, records: list[M.EvalRecord], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scorecard.json").write_text(json.dumps(sc, indent=2, default=str))
    (out_dir / "scorecard.md").write_text(render_markdown(sc))
    with (out_dir / "records.jsonl").open("w") as f:
        for r in records:
            f.write(json.dumps(asdict(r)) + "\n")


# ------------------------------------------------------------------ CLI

def make_judge(a: argparse.Namespace, examples: list[Example]) -> Judge:
    if a.judge == "stub":
        from .stubs import OracleStubJudge
        return OracleStubJudge.from_examples(examples, accuracy=a.stub_accuracy, seed=a.seed)
    if a.judge == "vllm":
        if not a.base_url or not a.model:
            raise SystemExit("--judge vllm needs --base-url and --model")
        from ..judge_client import VLLMJudge, VLLMJudgeConfig  # lazy: only this branch needs httpx/server
        return VLLMJudge(VLLMJudgeConfig(base_url=a.base_url, model=a.model,
                                         model_version=a.model_version or a.model))
    raise SystemExit(f"unknown judge {a.judge}")


def _fill_policies(examples: list[Example], policies: Optional[Path]) -> None:
    """Rows with no policy clauses get them from the same retriever the gateway uses."""
    if not policies:
        return
    from ..retrieval import PolicyRetriever
    pr = PolicyRetriever.from_jsonl(policies)
    for e in examples:
        if not e.request.policy_clauses:
            e.request.policy_clauses = pr.retrieve(e.request)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--judge", choices=["stub", "vllm"], required=True)
    ap.add_argument("--base-url")
    ap.add_argument("--model")
    ap.add_argument("--model-version")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--timeout-ms", type=float, help="override per-tool timeouts from configs/action_types.json")
    ap.add_argument("--policies", type=Path, help="fill empty policy_clauses via retrieval (gateway parity)")
    ap.add_argument("--baseline-scorecard", type=Path, nargs="*", default=[])
    ap.add_argument("--allow-fixtures", action="store_true")
    ap.add_argument("--stub-accuracy", type=float, default=0.97)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)

    examples, data_hashes = load_test_examples(a.data, a.allow_fixtures)
    if not examples:
        raise SystemExit(f"no test-split rows under {a.data}")
    _fill_policies(examples, a.policies)
    judge = make_judge(a, examples)

    async def go():
        try:
            return await run_judge(judge, examples, a.concurrency, a.timeout_ms, tool_timeouts())
        finally:
            if hasattr(judge, "aclose"):
                await judge.aclose()

    records = asyncio.run(go())
    baselines = {p.parent.name: json.loads(p.read_text()) for p in a.baseline_scorecard}
    sc = build_scorecard(
        records, model_version=judge.model_version, judge_kind=a.judge, data_hashes=data_hashes,
        card_hashes=dataset_card_hashes(a.data), targets=json.loads(a.targets.read_text()),
        baselines=baselines, fixture_run=any(e.provenance.fixture_only for e in examples),
        run_info={"concurrency": a.concurrency, "timeout_ms": a.timeout_ms or "per-tool",
                  "base_url": a.base_url, "n_examples": len(examples)})
    write_outputs(sc, records, a.out)
    print(json.dumps({t["id"]: t["result"] for t in sc["targets"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
