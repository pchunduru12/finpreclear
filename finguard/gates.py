"""Go/no-go gates from the plan, enforced in code. Training, pilot and release scripts call
require() and refuse to run when a gate is closed. Opening a gate means editing gates.json
in a reviewed commit with who signed off, when, and a link to the evidence."""
from __future__ import annotations

import json
from pathlib import Path

GATES_FILE = Path(__file__).resolve().parent.parent / "configs" / "gates.json"

GATE_ORDER = [
    "pilot_partner_signed",       # before any training run
    "teacher_selected",           # before any teacher labeling
    "v1_targets_met",             # before pilot (shadow mode on partner traffic)
    "independent_review_passed",  # before public release of weights
]


class GateClosed(RuntimeError):
    pass


def load(path: Path = GATES_FILE) -> dict:
    return json.loads(Path(path).read_text())


def is_open(name: str, path: Path = GATES_FILE) -> bool:
    g = load(path).get(name, {})
    return bool(g.get("open")) and bool(g.get("signed_by")) and bool(g.get("evidence"))


def require(name: str, path: Path = GATES_FILE) -> None:
    if name not in GATE_ORDER:
        raise KeyError(name)
    # A later gate implies earlier ones; check all predecessors too.
    for g in GATE_ORDER[: GATE_ORDER.index(name) + 1]:
        if not is_open(g, path):
            raise GateClosed(f"Gate '{g}' is closed. See configs/gates.json and the plan doc.")


if __name__ == "__main__":  # shell scripts: python -m finguard.gates <gate>  (exit 3 if closed)
    import sys
    try:
        require(sys.argv[1])
        print(f"gate {sys.argv[1]}: open")
    except GateClosed as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        sys.exit(3)
