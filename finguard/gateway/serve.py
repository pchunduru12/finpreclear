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
client certificates are REQUIRED (mTLS). Live startup also requires --redact,
non-fixture policy/records and the v1_targets_met human-approved gate. The read-only
judge-bypass fast path is disabled outside --insecure-dev. Development transport is
allowed only on a literal loopback address.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from pathlib import Path

from ..judge_client import VLLMJudge, VLLMJudgeConfig
from .. import gates
from ..retrieval import PolicyRetriever
from ..rules import RuleEngine
from .records import JsonRecordsLookup
from .service import create_app


def build_app(a: argparse.Namespace):
    judge = VLLMJudge(VLLMJudgeConfig(base_url=a.judge_url, model=a.judge_model, model_version=a.model_version,
                                      api_key=os.environ.get("FINGUARD_JUDGE_API_KEY"),
                                      structured_mode=a.structured_mode))
    records = JsonRecordsLookup.from_json(a.records) if a.records else None
    rules_cfg = json.loads(Path(a.rules).read_text())
    if not a.insecure_dev:
        # A read-only data access can still disclose regulated information.
        # No judge-bypass fast path outside isolated local development.
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
    if not a.insecure_dev:
        if not a.redact:
            return "production requires --redact to minimize sensitive information in audit logs"
        repo_root = Path(__file__).resolve().parents[2]
        if Path(a.policies).resolve() == (repo_root / "policies" / "sample_policy.jsonl").resolve():
            return "production cannot load the sample financial policy; configure partner-approved policies"
        if not a.records:
            return "production requires a bank-controlled records adapter or verified policy data source"
        if Path(a.records).resolve() == (repo_root / "configs" / "records_sample.json").resolve():
            return "production cannot use fixture vendor and approval records"
        if a.force_shadow:
            return "production cannot use --force-shadow: a blocked decision must be enforced"
        try:
            from .service import validate_action_types, tool_entries
            action_types = json.loads(Path(a.action_types).read_text())
            validate_action_types(action_types)
        except (OSError, ValueError, TypeError) as exc:
            return f"production action configuration is invalid: {type(exc).__name__}"
        # Production must not depend on a shadow setting that allows the
        # client wrapper to execute a tool despite BLOCK or ESCALATE.
        entries = {"_default": action_types["_default"], **tool_entries(action_types)}
        if any(entry.get("enforce") is not True for entry in entries.values()):
            return "production requires enforce=true for every configured tool and _default"
        if any(entry.get("fail_mode") == "open" for entry in entries.values()):
            return "production cannot use fail-open actions"
    return None


def main(argv=None) -> int:
    a = parse(argv)
    error = transport_configuration_error(a)
    if error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2
    tls = bool(a.ssl_certfile and a.ssl_keyfile)
    if not a.insecure_dev:
        try:
            gates.require("v1_targets_met")
        except gates.GateClosed as exc:
            print(f"REFUSED: release preflight gate not satisfied: {exc}", file=sys.stderr)
            return 3
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
