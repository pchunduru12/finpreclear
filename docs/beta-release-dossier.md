# FinPreclear controlled beta: release dossier

**Last revised:** 2026-10-24  
**Status:** **NOT AUTHORIZED FOR REAL FINANCIAL TRANSACTIONS**. Candidate for further isolated, synthetic preview testing only.  
**Tracking:** Draft PR #11, GitHub issues #2–#9, upstream draft PRs #1 and #10.

## Beta operating profiles

| Profile | Network | Data | Execution | Model | Allowed today? |
| --- | --- | --- | --- | --- | --- |
| Local synthetic development | Literal loopback `--insecure-dev` only | Fake fixtures only | Test functions; never real payment systems | Stub allowed | Yes for developers |
| Isolated preview integration | Approved mTLS network, authorized non-production APIs | Synthetic or explicitly approved de-identified | `GuardedToolClient(..., dry_run=True)`; **no registered tool executes** | Stub for plumbing, trained candidate for model study | Code path available, infrastructure validation outstanding |
| Partner shadow study | Approved bank-owned environment | Permissioned bank data under contract | Would require trusted authorization and exfiltration controls before observing real calls | Trained and validated checkpoint | **No**, requires signed partner and risk approval |
| Financial production enforcement | Mutual TLS and reviewed identities | Partner-approved production records/policies | Enforcement true for every action, including unknown tools | Independently validated and signed-off checkpoint | **No**, all release gates closed |

## Eight specialist review workstreams

| Specialist | Issue | Production-beta exit deliverable |
| --- | --- | --- |
| AI Research Architect | #2 | Calibrated model scorecard on consented held-out datasets, genuine trained checkpoint; no stub-result claims |
| Systems Architect | #3 | End-to-end gateway and client integration, startup and failover tests, trusted records adapter |
| Performance Engineer | #4 | Measured p50/p95/p99 latency, throughput, saturation and costs at approved concurrency/hardware |
| Security Architect | #5 | Authenticated caller + tenant-scoped authorization, mTLS certificate verification, least privilege, encryption and secret rotation |
| Financial Risk Specialist | #6 | Bank-approved AP/vendor/wire controls, error budgets, escalation and human sign-offs |
| Red-Team Agent | #7 | Synthetic adversarial matrix plus independent external red-team test |
| MLOps Engineer | #8 | Pinned images/dependencies, SBOM, vulnerability remediation, model registry, rollback and drift alerts |
| Independent QA Agent | #9 | CI/test matrix evidence and independently witnessed security/model governance go/no-go |

## Safeguards implemented in draft PR #11

1. Explicit `GuardedToolClient(dry_run=True)` observes the signed decision but **never calls the registered tool**, including on ALLOW and shadow verdicts.
2. Preview mode on gateway outage raises `ActionStopped` rather than executing an old fail-open action.
3. Production launcher requires mutual TLS configuration, redacted audit logs and non-sample policy/records paths.
4. Launcher disables low-tier rules-only fast approval outside local insecure development.
5. Production rejects shadow override and requires `enforce=true` for the default and every configured tool; fails to start on any fail-open action.
6. Missing judge allow probability escalates for all tiers.
7. Production startup checks the final `independent_review_passed` gate; `gates.require` checks all preceding human-approval gates.
8. Existing release/training gates remain unopened; no real model or bank payment execution is initiated.

These controls are **not** a substitute for identity authorization, tested encryption transport, model validation or a trusted production bank integration.

## Required evidence for a beta authorization

- [ ] **Human-approved pilot, data use and legal agreements:** Named partner, consent, data classification and prohibited actions.
- [ ] **Identity and authorization:** Client cert identity to immutable principal mapping; tenant ID derived from authenticated identity, not request body; deny cross-tenant access in tests.
- [ ] **Confidential information protection:** DLP/PII handling, retention, secrets in managed vault, redaction tests, least-privilege gateway and judge service accounts.
- [ ] **Actual TLS verification:** Test valid and revoked/invalid client certificates, TLS downgrade rejection and key rotation in the chosen deployment environment.
- [ ] **Rules + model evidence:** Independent attack-family/workflow/policy held-out evaluation, 95% confidence bounds, calibration, invalid rate, strict miss rate and benign false-approval cost.
- [ ] **Financial controls:** Prove new bank-account payment blocks, approver separation, limit/FX logic and manual escalation queue with records-system fixtures.
- [ ] **Operational controls:** Immutable external audit-chain anchor, alerting for judge outage/error/slowdown, incident on-call, rollback and disaster recovery.
- [ ] **Supply chain:** Pin release dependencies and base images, scan with current vulnerability databases, sign artifacts, confirm licenses/SBOM.
- [ ] **Performance:** Measured real model p95 and load results with specific GPU and concurrency.
- [ ] **Independent assurance:** Penetration test, privacy assessment, security acceptance, model-risk sign-off and controlled go/no-go decision.
- [ ] **Deployment:** Bank network integration, production-like rehearsal, no production credentials in GitHub, resource limits, backups, staging smoke tests.

## Beta deployment runbook (human-operated)

1. Select one bank-controlled, access-restricted preview environment. Ensure no route exists to execute payments or mutate vendor masters.
2. Provision a segregated mTLS PKI with client identity mapping and the bank's secret manager. **Do not put certificates or credentials in the repository.**
3. Configure policies and records from bank-approved sources; never copy synthetic examples to a production location to defeat fixture-path checks.
4. Run CI and synthetic preview suite against the exact immutable commit SHA; store logs and hashes.
5. Independently verify `dry_run=True` in the client runtime and that no registered tool function can execute. Use synthetic data only.
6. Rehearse outage, invalid-model-output, bad certificate, tampered-audit, replay and large-payload scenarios.
7. Record formal approvals in a reviewed change request, with explicit allowable data, participant count, observation period and rollback owner.
8. **Only after separate external risk, security and legal sign-off** consider a controlled shadow pilot. Live enforcement requires independently validated trained-model evidence and the final ordered gate.

## Do not do

- Do not merge draft PRs automatically or change `configs/gates.json` to make CI pass.
- Do not call 312 passing synthetic tests a trained model's accuracy or production safety score.
- Do not use `--insecure-dev`, fixture records or sample policies with real financial data.
- Do not allow the beta preview to execute real bank actions.
- Do not claim the eight configured review roles replace actual independent human reviewers.

## Exact evidence status

The initial PR #1 suite passed 300 CPU tests. PR #10 passed 304 CPU tests. PR #11 introduces additional synthetic beta tests and stricter enforcement preflight; its **latest commit-specific CI outcome must be checked on GitHub Actions** before interpreting status. Older red CI runs are retained as failed test history.
