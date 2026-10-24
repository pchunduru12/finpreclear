"""Launch the FinGuard gateway from config files and environment variables.

    python -m finguard.gateway.serve \
        --judge-url http://judge:8000 --judge-model finguard-4b \
        --model-version finguard-4b-grpo-2026-03-20-ab12cd \
        --policies /etc/finguard/policies.jsonl \
        --action-types /etc/finguard/action_types.json \
        --rules /etc/finguard/rules.json \
        --records /etc/finguard/records.json \
        --audit-log /var/log/finguard/audit-$(hostname)-$$.jsonl \
        --host 0.0.0.0 --port 8443 --ssl-certfile ... --ssl-keyfile ... --ssl-ca-certs ...

Required env: FINGUARD_RESPONSE_KEY (>= 32 bytes, from the bank's secret manager).
Optional env: FINGUARD_JUDGE_API_KEY.

--records points at a JSON file in the JsonRecordsLookup format (pilot / test only). In
production, replace it with a read-only adapter to the bank's vendor master, approvals and
HR systems implementing gateway.records.RecordsLookup. Without records, every payee,
approval and direct-deposit check escalates (it never passes).

Production startup requires a server certificate, private key and client-CA bundle, so
client certificates are REQUIRED (mTLS). --insecure-dev is permitted only on a literal
loopback address; it never exposes an unauthenticated listener on a network interface.

v1 pilot startup (anything that is not --insecure-dev) also requires:
  - the v1_targets_met gate (which implies pilot_partner_signed and teacher_selected);
    independent_review_passed is the public-release gate and is NOT needed for the pilot;
  - shadow mode for model verdicts: every tool enforce=false, or --force-shadow.
    Deterministic rule blocks (denylist, payee mismatch) are still enforced, as agreed
    with the bank's controls lead. Turning on model-verdict enforcement for any tool is a
    separate, reviewed change after shadow-pilot evidence; this launcher refuses it;
  - --redact, a non-sample policy file and non-sample records;
  - no fail-open tools;
  - no judge-bypass fast path for read-only tools (reads can disclose customer data).
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from pathlib import Path

from .. import gates
from ..judge_client import VLLMJudge, VLLMJudgeConfig
from ..retrieval import PolicyRetriever
from ..rules import RuleEngine
from .records import JsonRecordsLookup
from .service import create_app, tool_entries, validate_action_types

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_POLICIES = REPO_ROOT / "policies" / "sample_policy.jsonl"
SAMPLE_RECORDS = REPO_ROOT / "configs" / "records_sample.json"
FIXTURES_DIR = REPO_ROOT / "fixtures"
PILOT_GATE = "v1_targets_met"


def build_app(a: argparse.Namespace):
    judge = VLLMJudge(VLLMJudgeConfig(base_url=a.judge_url, model=a.judge_model, model_version=a.model_version,
                                      api_key=os.environ.get("FINGUARD_JUDGE_API_KEY"),
                                      structured_mode=a.structured_mode))
    records = JsonRecordsLookup.from_json(a.records) if a.records else None
    rules_cfg = json.loads(Path(a.rules).read_text())
    if not a.insecure_dev:
        # Read-only tools can still disclose customer data: the judge sees every call.
        rules_cfg["fast_path_low_tier"] = False
    return create_app(
        judge=judge,
        retriever=PolicyRetriever.from_jsonl(a.policies, k=a.policy_k),
        action_types=json.loads(Path(a.action_types).read_text()),
        rules=RuleEngine(rules_cfg, records=records),
        audit_path=a.audit_log,
        model_version=a.model_version,
        shadow_override=True if a.force_shadow else None,
        redact_argument_values=a.redact,
    )


def parse(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="python -m finguard.gateway.serve", description=__doc__.split("\n\n")[0])
    ap.add_argument("--judge-url", required=True)
    ap.add_argument("--judge-model", required=True, help="vllm --served-model-name")
    ap.add_argument("--model-version", required=True, help="checkpoint id written to every decision")
    ap.add_argument("--structured-mode", default="both_new",
                    choices=["both_new", "both_legacy", "response_format", "structured_outputs", "guided_json", "none"])
    ap.add_argument("--policies", required=True)
    ap.add_argument("--policy-k", type=int, default=5)
    ap.add_argument("--action-types", default="configs/action_types.json")
    ap.add_argument("--rules", default="configs/rules.json")
    ap.add_argument("--records", help="JSON records file (pilot/test). Production: a RecordsLookup adapter.")
    ap.add_argument("--audit-log", required=True)
    ap.add_argument("--redact", action="store_true", help="hash argument values, evidence and reasons in the log")
    ap.add_argument("--force-shadow", action="store_true", help="shadow mode for every tool, whatever the config says")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--ssl-certfile")
    ap.add_argument("--ssl-keyfile")
    ap.add_argument("--ssl-ca-certs", help="CA for client certificates; when set, clients must present one (mTLS)")
    ap.add_argument("--insecure-dev", action="store_true", help="allow non-mTLS transport on loopback only (local development)")
    return ap.parse_args(argv)


def transport_configuration_error(a: argparse.Namespace) -> str | None:
    """Refuse unprotected network-facing listeners and incomplete production mTLS.

    Development transport is constrained to literal loopback, not a host string which
    may resolve to a public interface or wildcard. The actual server private key
    and CA are loaded and validated by the ASGI server at startup.
    """
    loopback = a.host in ("127.0.0.1", "::1")
    if a.insecure_dev and not loopback:
        return "--insecure-dev is allowed only with --host 127.0.0.1 or ::1"
    if bool(a.ssl_certfile) != bool(a.ssl_keyfile):
        return "TLS requires both --ssl-certfile and --ssl-keyfile"
    if a.ssl_ca_certs and not (a.ssl_certfile and a.ssl_keyfile):
        return "--ssl-ca-certs requires a TLS certificate and private key"
    if not a.insecure_dev and not (a.ssl_certfile and a.ssl_keyfile and a.ssl_ca_certs):
        return "production requires --ssl-certfile, --ssl-keyfile and --ssl-ca-certs for mTLS"
    return None


def _is_fixture(path: str) -> bool:
    p = Path(path).resolve()
    return p in (SAMPLE_POLICIES.resolve(), SAMPLE_RECORDS.resolve()) or FIXTURES_DIR.resolve() in p.parents


def pilot_configuration_error(a: argparse.Namespace) -> str | None:
    """Static checks for a v1 shadow-pilot start. Local development (--insecure-dev on
    loopback) is exempt; anything network-facing is a pilot and must pass all of these."""
    if a.insecure_dev:
        return None
    if not a.redact:
        return "pilot requires --redact so argument values, evidence and reasons are hashed in the audit log"
    if _is_fixture(a.policies):
        return "pilot cannot load sample or fixture policies; configure the bank's approved policy clauses"
    if not a.records:
        return "pilot requires the bank's records (vendor master, approvals) via --records or an adapter"
    if _is_fixture(a.records):
        return "pilot cannot use sample or fixture vendor and approval records"
    try:
        action_types = json.loads(Path(a.action_types).read_text())
        validate_action_types(action_types)
    except (OSError, ValueError, TypeError) as exc:
        return f"action configuration is invalid: {type(exc).__name__}"
    entries = {"_default": action_types["_default"], **tool_entries(action_types)}
    if any(e.get("fail_mode") == "open" for e in entries.values()):
        return "pilot cannot use fail-open tools"
    if not a.force_shadow and any(e.get("enforce") is True for e in entries.values()):
        return ("v1 pilot is shadow-only for model verdicts: set enforce=false for every tool or use "
                "--force-shadow; per-tool enforcement is a separate reviewed change after shadow evidence")
    return None


def main(argv=None) -> int:
    a = parse(argv)
    error = transport_configuration_error(a) or pilot_configuration_error(a)
    if error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2
    if not a.insecure_dev:
        try:
            gates.require(PILOT_GATE, gates.GATES_FILE)
        except gates.GateClosed as exc:
            print(f"REFUSED: pilot gate not satisfied: {exc}", file=sys.stderr)
            return 3
    tls = bool(a.ssl_certfile and a.ssl_keyfile)
    app = build_app(a)
    import uvicorn
    kw = {}
    if tls:
        kw = dict(ssl_certfile=a.ssl_certfile, ssl_keyfile=a.ssl_keyfile)
        if a.ssl_ca_certs:
            kw.update(ssl_ca_certs=a.ssl_ca_certs, ssl_cert_reqs=ssl.CERT_REQUIRED)
    # One worker per process: the audit chain is per file. Scale with more processes, each
    # with its own --audit-log path (see configs/serving.md).
    uvicorn.run(app, host=a.host, port=a.port, workers=1, **kw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
