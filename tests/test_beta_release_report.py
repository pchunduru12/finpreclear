"""Static release reports cannot inadvertently authorize a beta deployment."""
import json
from pathlib import Path

from scripts.beta_readiness import collect


REPO = Path(__file__).resolve().parents[1]


def test_static_beta_report_requires_external_evidence():
    out = collect(REPO)
    assert not out["production_beta_authorized"]
    assert out["automated_checks_only"]
    assert out["blockers"]


def test_closed_gates_remain_closed():
    cfg = json.loads((REPO / "configs/gates.json").read_text())
    assert all(not value["open"] for value in cfg.values())
