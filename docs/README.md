# FinPreclear — docs folder

Snapshots of every FinPreclear document, exported Oct 24, 2026. The live docs (links below) are the source of truth; edit those, not these copies.

| File | What it is | Live doc |
| --- | --- | --- |
| 00-context-summary.md | One-page summary of the plan (start here) | Claude Project file `finguard-context.md` |
| 01-plan-project-plan.md | Plan doc · Project plan tab: problem, related work, approach, targets, risks | [Plan doc](https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v) |
| 02-plan-design-plan.md | Plan doc · Design plan tab: the 21 steps across 4 phases | [Plan doc](https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v) |
| 03-plan-build-plan.md | Plan doc · Build plan tab: what's built, agent team, effort, plan changes | [Plan doc](https://claude.ai/artifact/KshtvjYLwdGMXXnxcQVR6v) |
| 04-deployment-guide.md | Repo → gateway in a bank, 8 steps, day-to-day ops, release checklist | [Deployment guide](https://claude.ai/artifact/Nc1ZVRTpeTF4B5qBjAxq54) |
| 05-human-task-list.md | Tasks only people can do, by phase, with owners and "done" criteria | [Human task list](https://claude.ai/artifact/FMthR5n6gkpe8ezXK85eqz) |
| 06-design-partner-deck.md | Text of the 18-slide design-partner deck (with speaker notes) | [Deck](https://claude.ai/code/artifact/583cf8a6-e914-41c3-bc9b-7d8764cb0026) |
| 07-claude-project-instructions.md | Rules for Claude on this project; paste into your own Claude Project's instructions | Claude Project file `finguard-instructions.md` |

New to the project? Read in this order: 00 → 01 → 02 → 03 → 05, then the top-level `README.md` and `CLAUDE.md` before touching code.

Live doc links are private Claude artifacts; ask Padmaja to share them with you.

Code: the rest of this repo (298 tests passing).

Known gaps, not yet fixed in the live docs:
- Deployment guide and human task list still say "FinGuard" and "SR 11-7". The plan doc and deck use FinPreclear and SR 26-2.
- Diagrams (roadmap, architecture, timeline, deployment) don't survive markdown export; see the live docs.
