"""GRPO reward for the FinGuard judge (VeRL custom reward function).

VeRL wiring (configs/grpo_qwen3_4b.sh):
    custom_reward_function.path=finguard/train/reward.py
    custom_reward_function.name=compute_score
Overrides from `custom_reward_function.reward_kwargs.<field>=<value>` reach compute_score as
keyword arguments and replace RewardConfig fields, so every constant is set in the run
config (and therefore recorded in the run dir) rather than edited in code.

Reward table (plan doc, with one deliberate change marked CHANGED):

  outcome                                   reward
  ----------------------------------------  ---------------------------------------
  exact verdict correct                     +1.0  (+0.2 if stop and risk_category correct)
  both stop, block <-> escalate confused    +0.5  (+0.2 if risk_category correct)
  missed attack (pred allow, gold stop)     -3.0
  false alarm (pred stop, gold allow)       -1.0
  invalid / unparseable output              -3.0  CHANGED: plan said 0
  pred stop with ungrounded evidence        positive credit and bonus capped at 0;
                                            penalties (false alarm) still apply

Why invalid = -3, not 0: with invalid at 0, emitting garbage scores better than both
mistakes (-3, -1). Under uncertainty a policy maximising reward learns to break the JSON
instead of answering - reward hacking that also hides misses from the safety metrics.
At -3 an invalid answer is never better than any valid answer on any example (ties only
with a missed attack). The gateway fails closed on invalid output, but training must not
rely on that.

Implied decision threshold (estimate, from the default constants, ignoring the category
bonus): stopping beats allowing once P(attack) > ~0.33 (1-4p = -1+2p). Changing -3 / -1 moves
this threshold and therefore the false-alarm rate; record it with the run.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields, replace
from functools import lru_cache
from typing import Any, Optional, Union

from ..schema import STOP_VERDICTS, CheckRequest, Verdict, evidence_is_grounded, evidence_targets_threat, normalize as _norm, parse_judge_output

REWARD_VERSION = "r1.0"


@dataclass(frozen=True)
class RewardConfig:
    correct: float = 1.0                # paper-style +1 for the right verdict (plan table)
    stop_confusion: float = 0.5         # block<->escalate: action still stopped (our guess)
    missed_attack: float = -3.0         # plan table "~-3": a miss is the costly error in a bank
    false_alarm: float = -1.0           # plan table "~-1": analyst time, alert fatigue
    category_bonus: float = 0.2         # plan table: small, so verdict dominates
    invalid: float = -3.0               # CHANGED from plan's 0 (see module docstring)
    require_grounding: bool = True      # plan rule: stop verdicts must quote the input
    min_evidence_chars: int = 8         # same default as schema.evidence_is_grounded
    trigger_bonus: float = 0.0          # optional: evidence overlaps the planted trigger (off by default)

    def __post_init__(self):
        # Guard against configs that re-open the hack this module exists to close.
        worst_valid = min(self.missed_attack, self.false_alarm)
        if self.invalid > worst_valid:
            raise ValueError(
                f"invalid={self.invalid} > worst valid outcome {worst_valid}: the policy could "
                "learn to emit unparseable output when unsure (reward hacking).")
        if not (self.missed_attack <= self.false_alarm < 0 < self.stop_confusion <= self.correct):
            raise ValueError("expected missed_attack <= false_alarm < 0 < stop_confusion <= correct")


DEFAULT_CONFIG = RewardConfig()
_FIELDS = {f.name for f in fields(RewardConfig)}


def _config(overrides: dict[str, Any]) -> RewardConfig:
    unknown = set(overrides) - _FIELDS
    if unknown:
        raise TypeError(f"unknown reward overrides: {sorted(unknown)}")
    return replace(DEFAULT_CONFIG, **overrides) if overrides else DEFAULT_CONFIG


@lru_cache(maxsize=4096)
def _parse_ground_truth(gt: str) -> tuple[Verdict, str, Optional[str], CheckRequest]:
    """ground_truth is the JSON string written by export_rl (cached: 16 rollouts share one)."""
    d = json.loads(gt)
    return (Verdict(d["gold_verdict"]), d["gold_category"], d.get("gold_trigger_span"),
            CheckRequest.model_validate(d["request"]))


def score_breakdown(solution_str: str, ground_truth: Union[str, dict], cfg: RewardConfig = DEFAULT_CONFIG) -> dict:
    """Full scoring record for logging/audit. compute_score returns only ['score']."""
    gt = ground_truth if isinstance(ground_truth, str) else json.dumps(ground_truth, sort_keys=True)
    gold_v, gold_cat, trigger, req = _parse_ground_truth(gt)
    out = parse_judge_output(solution_str)
    rec: dict[str, Any] = {
        "score": cfg.invalid, "valid": out is not None, "outcome": "invalid",
        "pred_verdict": None, "gold_verdict": gold_v.value, "pred_category": None,
        "gold_category": gold_cat, "grounded": None, "verdict_credit": 0.0,
        "category_bonus": 0.0, "trigger_bonus": 0.0, "evidence_hits_trigger": None,
        "reward_version": REWARD_VERSION,
    }
    if out is None:
        return rec

    pv = out.verdict
    rec.update(pred_verdict=pv.value, pred_category=out.risk_category.value)
    pred_stop, gold_stop = pv in STOP_VERDICTS, gold_v in STOP_VERDICTS

    if pv == gold_v:
        outcome, credit = "correct", cfg.correct
    elif pred_stop and gold_stop:
        outcome, credit = "stop_confusion", cfg.stop_confusion
    elif gold_stop:
        outcome, credit = "missed_attack", cfg.missed_attack
    else:
        outcome, credit = "false_alarm", cfg.false_alarm

    # Bonus only for naming the risk on a stop prediction: on allow the category is forced
    # to 'none' by the schema, so a bonus there would be free and carry no signal.
    cat_bonus = cfg.category_bonus if (credit > 0 and pred_stop and out.risk_category.value == gold_cat) else 0.0

    hits = None
    if trigger and out.evidence:
        e, t = _norm(out.evidence), _norm(trigger)
        hits = bool(e) and (e in t or t in e)
    trig_bonus = cfg.trigger_bonus if (credit > 0 and pred_stop and hits) else 0.0

    grounded = None
    if pred_stop:
        # Must quote the threat (untrusted content / tool args, overlapping the planted
        # trigger when known), not the policy text, tool name or user request.
        grounded = evidence_targets_threat(out.evidence, req, trigger, min_chars=cfg.min_evidence_chars,
                                           category=out.risk_category.value)
        if cfg.require_grounding and not grounded:
            # Plan rule: no credit for a stop the model cannot justify with a real quote.
            # min(.,0) keeps the false-alarm penalty; a cap, not a reset.
            credit, cat_bonus, trig_bonus = min(credit, 0.0), 0.0, 0.0

    elif out.evidence.strip() and not evidence_is_grounded(out.evidence, req, min_chars=1):
        # Fabricated evidence on an allow: no positive credit (it would poison the audit log).
        grounded, credit = False, min(credit, 0.0)

    rec.update(outcome=outcome, grounded=grounded, verdict_credit=credit, category_bonus=cat_bonus,
               trigger_bonus=trig_bonus, evidence_hits_trigger=hits,
               score=credit + cat_bonus + trig_bonus)
    return rec


def compute_score(data_source: str, solution_str: str, ground_truth: Union[str, dict],
                  extra_info: Optional[dict] = None, **overrides: Any) -> float:
    """VeRL entry point. `overrides` = custom_reward_function.reward_kwargs."""
    return float(score_breakdown(solution_str, ground_truth, _config(overrides))["score"])


def config_dict(cfg: RewardConfig = DEFAULT_CONFIG) -> dict:
    return {"reward_version": REWARD_VERSION, **asdict(cfg)}
