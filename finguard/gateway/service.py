"""FinGuard gateway HTTP service. Every planned agent tool call is POSTed to /v1/check and
gets back a Decision (allow / block / escalate) before the tool runs.

Pipeline for one request (each step's outcome is in the audit record):
 1. size cap     the raw body is read with a hard limit. Over `max_request_bytes` (64 KB) the
                 request is NOT scanned: the tool's fail mode applies with escalate as the
                 floor (an unscanned call is never allowed, even on fail-open read-only tools),
                 decided_by="fail_mode", logged with size and digest only. Over the absolute
                 read limit (1 MB) or unparseable -> 413 / 422 (client: local fail mode).
    validate     pydantic CheckRequest (422 on bad input).
    canonicalise the tool name (rules.canonical_tool_name: NFKC, casefold, look-alikes, strip)
                 is the only name used for config lookup, rules, the judge prompt and the
                 signature. Unknown after canonicalisation -> _default (fail closed).
 2. sanitise     caller-sent policy_clauses are DISCARDED (security review C1: the caller must
                 not choose the policy it is judged against). Their ids and a hash are kept in
                 the audit record (gateway.caller_policy_clauses_discarded).
 3. rules        finguard.rules.RuleEngine, run in a worker thread (asyncio.to_thread) under
                 `rules_budget_ms`, so a slow request cannot stall the event loop. Over budget
                 or a crash -> fail mode with escalate floor. Rule block -> final (model
                 skipped). Rule escalate -> floor; the model still runs and may raise it to
                 block. No rule hit on a tier="low" tool -> fast-path allow.
    retrieve     the gateway's own PolicyRetriever ALWAYS supplies the clauses (also in a
                 worker thread under the same budget).
 4. judge        asyncio.wait_for(judge.judge(...), action_type.timeout_ms).
                 timeout / exception / malformed output -> the tool's fail_mode
                 (closed=block, escalate=escalate, open=allow), decided_by="fail_mode".
 5. threshold    model allow with p_verdict["allow"] < allow_threshold -> escalate
                 (decided_by="threshold"). Empty p_verdict -> escalate for every tool except tier="low".
 6. combine      strictest of rule floor and model/fail-mode verdict (block > escalate > allow).
 7. enforce      enforced = action_types[tool].enforce (or shadow_override). enforced=False is
                 shadow mode: the caller may let the action run, but the verdict is logged.
                 Exception: deterministic rule BLOCKS (denylist, payee mismatch) are enforced
                 even in shadow mode while enforce_rule_blocks_in_shadow=True (default).
 8. audit        hash-chained JSONL record. If the audit write fails the service returns 503
                 (no unlogged decisions); the client applies its local fail mode.
 9. sign         HMAC-SHA256 over (request digest, tool name, response body) with the shared
                 key FINGUARD_RESPONSE_KEY, sent in X-FinGuard-Signature. The client rejects
                 unsigned / wrongly signed / mismatched responses (local fail mode). This is
                 defence in depth; mTLS between agent and gateway is the production
                 requirement (configs/serving.md).

Startup refuses to run (ValueError) on an unsafe action_types config: tier "low" only for
tools in `read_only_tools`; read_only_tools may not contain a never-read-only tool or a name
with a write-ish word (pay, wire, send, update ...); allow_threshold >= 0.9 for high and
>= 0.8 for medium; timeout_ms an int in [50, 5000]; no fail-open on non-low tiers; unknown
tiers or fail modes; two config keys that canonicalise to the same tool. No retriever or no
response key also refuses to start.

`confidence` in the Decision: rule -> 1.0 (deterministic); model -> p_verdict of the final
verdict; threshold -> 1 - p_verdict["allow"]; fail_mode or no logprobs -> 0.0 (unknown).
It is never taken from model-written text.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Optional, Union

import re

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

from .. import __version__
from ..judge_api import Judge, JudgeResult
from ..prompt import PROMPT_VERSION
from ..retrieval import PolicyRetriever
from ..rules import RuleEngine, RuleOutcome, canonical_tool_name, strictest
from ..schema import SCHEMA_VERSION, CheckRequest, Decision, RiskCategory, Verdict, evidence_is_grounded
from .audit import AuditLog

log = logging.getLogger("finguard.gateway")

FAIL_MODE_VERDICT = {"closed": Verdict.BLOCK, "escalate": Verdict.ESCALATE, "open": Verdict.ALLOW}


RESPONSE_KEY_ENV = "FINGUARD_RESPONSE_KEY"
SIGNATURE_HEADER = "X-FinGuard-Signature"
TOOL_HEADER = "X-FinGuard-Tool"
REQUEST_DIGEST_HEADER = "X-FinGuard-Request-Sha256"
_SIG_DOMAIN = b"finguard-response-v1"
MIN_KEY_BYTES = 32

# Minimum allow_threshold per tier (security review, mediums). Low tier has no minimum but
# is restricted to the read_only_tools allowlist.
MIN_ALLOW_THRESHOLD = {"high": 0.9, "medium": 0.8}
TIERS = ("high", "medium", "low")
NON_TOOL_KEYS = {"read_only_tools"}
TIMEOUT_MS_RANGE = (50, 5000)
# Tools that can never be read-only, whatever the config says (security review round 2).
NEVER_READ_ONLY = frozenset({"submit_payment", "release_wire", "update_vendor_bank_details", "update_direct_deposit",
                             "export_customer_data", "update_user_permissions", "send_email"})
_WRITE_WORDS = re.compile(r"pay|wire|transfer|export|send|update|delete|create|approve|grant|permission|deposit|bank")

MAX_REQUEST_BYTES = 64 * 1024        # over this: not scanned, fail mode (>= escalate)
ABSOLUTE_MAX_BYTES = 1024 * 1024     # over this: not even read (413)
RULES_BUDGET_MS = 250.0


def tool_entries(action_types: dict) -> dict[str, dict]:
    """Per-tool entries only, keyed by CANONICAL tool name: skips underscore keys (_comment,
    _default) and non-tool keys such as read_only_tools."""
    out: dict[str, dict] = {}
    for k, v in action_types.items():
        if k.startswith("_") or k in NON_TOOL_KEYS or not isinstance(v, dict):
            continue
        out.setdefault(canonical_tool_name(k), v)  # collisions are refused by validate_action_types
    return out


def _read_only(action_types: dict) -> set[str]:
    ro = action_types.get("read_only_tools") or []
    return {canonical_tool_name(t) for t in ro if isinstance(t, str)}


def action_config(action_types: dict, tool: str) -> dict:
    """Per-tool settings for the CANONICAL form of `tool`; unknown tools get _default (fail
    closed). Missing keys in a tool's entry fall back to _default too, so a partial entry
    cannot weaken anything by omission. A tool name that collides with a non-tool key
    (read_only_tools, _comment) gets _default."""
    tool = canonical_tool_name(tool)
    default = action_types.get("_default") or {"tier": "high", "fail_mode": "closed", "timeout_ms": 800,
                                               "allow_threshold": 0.95, "enforce": False}
    entry = tool_entries(action_types).get(tool, {})
    cfg = {**default, **entry}
    if cfg.get("fail_mode") not in FAIL_MODE_VERDICT:
        cfg["fail_mode"] = "closed"
    # Config guard: only read-only (tier "low") tools may fail open. A typo that sets a
    # payment tool to "open" would otherwise turn every judge outage into an allow.
    if cfg["fail_mode"] == "open" and cfg.get("tier") != "low":
        log.error("tool %s: fail_mode=open on tier=%s is not allowed; using closed", tool, cfg.get("tier"))
        cfg["fail_mode"] = "closed"
    # Defence in depth: a "low" tier is only honoured for allowlisted, never-write tools.
    if cfg.get("tier") == "low" and (tool not in _read_only(action_types) or tool in NEVER_READ_ONLY
                                     or _WRITE_WORDS.search(tool)):
        cfg["tier"], cfg["fail_mode"] = "high", "closed"
    return cfg


def validate_action_types(action_types: dict) -> None:
    """Refuse to start on an unsafe config. Raises ValueError listing every problem.
    Checked: _default and every tool entry have a known tier and fail_mode; tier "low" only for
    tools in read_only_tools (and never for _default); read_only_tools holds no
    never-read-only tool and no name containing a write-ish word; fail_mode "open" only on
    tier "low"; allow_threshold numeric, <= 1 and >= the tier minimum (high 0.9, medium 0.8);
    timeout_ms an int in [50, 5000]; no two keys canonicalise to the same tool name."""
    problems: list[str] = []
    ro = action_types.get("read_only_tools")
    if ro is None or not isinstance(ro, list) or not all(isinstance(t, str) for t in ro):
        problems.append("read_only_tools must be a list of tool names (it may be empty)")
        ro = []
    ro_canon = {canonical_tool_name(t) for t in ro}
    for t in sorted(ro_canon):
        if t in NEVER_READ_ONLY:
            problems.append(f"read_only_tools: {t!r} can never be read-only")
        elif _WRITE_WORDS.search(t):
            problems.append(f"read_only_tools: {t!r} has a write-ish word ({_WRITE_WORDS.search(t).group(0)!r}) "
                            "and cannot be read-only")
    seen: dict[str, str] = {}
    for k, v in action_types.items():
        if k.startswith("_") or k in NON_TOOL_KEYS or not isinstance(v, dict):
            continue
        c = canonical_tool_name(k)
        if c in seen:
            problems.append(f"tool keys {seen[c]!r} and {k!r} are the same tool after canonicalisation")
        seen[c] = k
    entries = dict(tool_entries(action_types))
    if not isinstance(action_types.get("_default"), dict):
        problems.append("_default entry is required")
    else:
        entries["_default"] = action_types["_default"]
    lo, hi = TIMEOUT_MS_RANGE
    for name, raw in entries.items():
        cfg = {**action_types.get("_default", {}), **raw} if name != "_default" else raw
        tier, fm, thr, tmo = cfg.get("tier"), cfg.get("fail_mode"), cfg.get("allow_threshold"), cfg.get("timeout_ms")
        if isinstance(tmo, bool) or not isinstance(tmo, int) or not lo <= tmo <= hi:
            problems.append(f"{name}: timeout_ms must be an integer in [{lo}, {hi}] (got {tmo!r})")
        if tier not in TIERS:
            problems.append(f"{name}: unknown tier {tier!r}")
            continue
        if fm not in FAIL_MODE_VERDICT:
            problems.append(f"{name}: unknown fail_mode {fm!r}")
        if tier == "low" and (name == "_default" or name not in ro_canon):
            problems.append(f"{name}: tier 'low' is allowed only for tools in read_only_tools {sorted(ro_canon)}")
        if fm == "open" and tier != "low":
            problems.append(f"{name}: fail_mode 'open' is allowed only on tier 'low' (got tier {tier!r})")
        if isinstance(thr, bool) or not isinstance(thr, (int, float)) or not 0.0 <= float(thr) <= 1.0:
            problems.append(f"{name}: allow_threshold must be a number in [0, 1] (got {thr!r})")
        elif tier in MIN_ALLOW_THRESHOLD and float(thr) < MIN_ALLOW_THRESHOLD[tier]:
            problems.append(f"{name}: allow_threshold {thr} is below the {tier}-tier minimum {MIN_ALLOW_THRESHOLD[tier]}")
    if problems:
        raise ValueError("FinGuard gateway refuses to start: unsafe action_types config:\n  - " + "\n  - ".join(problems))


def _key_bytes(key: Union[str, bytes, None]) -> Optional[bytes]:
    if key is None or key == "" or key == b"":
        return None
    return key.encode() if isinstance(key, str) else bytes(key)


def request_digest(request_json: dict) -> str:
    """SHA-256 of the canonical JSON of a CheckRequest (model_dump(mode="json")). Client and
    gateway compute it independently; it binds a signed response to the exact request."""
    return hashlib.sha256(json.dumps(request_json, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def sign_response(key: bytes, req_digest: str, tool: str, body: bytes) -> str:
    msg = b"\n".join([_SIG_DOMAIN, req_digest.encode(), tool.encode(), body])
    return "v1=" + hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_response_signature(key: bytes, req_digest: str, tool: str, body: bytes, signature: Optional[str]) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign_response(key, req_digest, tool, body), signature)


@dataclass
class _Draft:
    verdict: Verdict
    category: RiskCategory
    reason: str
    evidence: str
    confidence: float
    decided_by: str
    rule_id: Optional[str] = None


def _fail_mode_draft(cfg: dict, why: str, floor_escalate: bool = False, what: str = "Judge unavailable") -> _Draft:
    """The tool's fail mode. floor_escalate=True when the CHECKS themselves could not run
    (oversized request, rule budget exceeded, rule crash): then even a fail-open tool gets
    escalate, because nothing about the call was verified."""
    v = FAIL_MODE_VERDICT[cfg["fail_mode"]]
    if floor_escalate:
        v = strictest(v, Verdict.ESCALATE)
    # No category fits a system failure; POLICY_VIOLATION = "control could not be evaluated".
    cat = RiskCategory.NONE if v == Verdict.ALLOW else RiskCategory.POLICY_VIOLATION
    return _Draft(v, cat, f"{what} ({why}); fail_mode={cfg['fail_mode']}.", "", 0.0, "fail_mode")


def _model_draft(res: JudgeResult, cfg: dict) -> _Draft:
    out = res.output
    assert out is not None
    pv = res.p_verdict or {}
    if out.verdict == Verdict.ALLOW:
        p_allow = pv.get("allow")
        if p_allow is None:
            # Low-risk data reads also require calibrated evidence of an allow.
            # Otherwise a judge could omit logprobs and still approve regulated reads.
            return _Draft(Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                          "Model allow cannot be accepted without verdict-token probability.",
                          "", 0.0, "threshold")
        if p_allow < float(cfg.get("allow_threshold", 0.95)):
            return _Draft(Verdict.ESCALATE, RiskCategory.POLICY_VIOLATION,
                          f"Model allowed with P(allow)={p_allow:.3f} below threshold {cfg.get('allow_threshold')}.",
                          out.evidence, round(1.0 - p_allow, 6), "threshold")
        return _Draft(Verdict.ALLOW, RiskCategory.NONE, out.reason, out.evidence, p_allow, "model")
    return _Draft(out.verdict, out.risk_category, out.reason, out.evidence, float(pv.get(out.verdict.value, 0.0)), "model")


def config_fingerprint(action_types: dict, rules: RuleEngine, model_version: str,
                       retriever_version: Optional[str], shadow_override: Optional[bool],
                       enforce_rule_blocks_in_shadow: bool = True,
                       limits: tuple = (MAX_REQUEST_BYTES, RULES_BUDGET_MS)) -> str:
    blob = {"action_types": action_types, "rules_sha256": rules.config_sha256, "model_version": model_version,
            "retriever_version": retriever_version, "prompt_version": PROMPT_VERSION, "schema_version": SCHEMA_VERSION,
            "shadow_override": shadow_override, "gateway_version": __version__,
            "records_version": rules.records_version, "enforce_rule_blocks_in_shadow": enforce_rule_blocks_in_shadow,
            "limits": list(limits)}
    return hashlib.sha256(json.dumps(blob, sort_keys=True).encode()).hexdigest()


def create_app(judge: Judge, retriever: PolicyRetriever, action_types: dict, rules: RuleEngine,
               audit_path: str, model_version: str, shadow_override: Optional[bool] = None,
               redact_argument_values: bool = False, enforce_rule_blocks_in_shadow: bool = True,
               response_key: Union[str, bytes, None] = None, allow_unsigned_responses: bool = False,
               max_request_bytes: int = MAX_REQUEST_BYTES, rules_budget_ms: float = RULES_BUDGET_MS) -> FastAPI:
    """shadow_override: None = per-tool `enforce` from action_types; True = force shadow for
    every tool (enforced=False); False = force enforcement for every tool.
    enforce_rule_blocks_in_shadow: deterministic rule blocks get enforced=True even in shadow.
    response_key: HMAC key for response signatures; defaults to env FINGUARD_RESPONSE_KEY.
    allow_unsigned_responses: local development only; clients reject unsigned responses anyway.
    max_request_bytes: serialized request cap (see pipeline step 1).
    rules_budget_ms: wall-clock budget for rules + retrieval in worker threads (step 3). A
    timed-out worker thread cannot be killed; the size cap and linear-time scanning bound it.

    Raises ValueError / RuntimeError at startup on an unsafe config (see module docstring)."""
    validate_action_types(action_types)
    if retriever is None:
        raise RuntimeError("FinGuard gateway refuses to start: a PolicyRetriever is required "
                           "(policy clauses come only from the gateway, never from the caller)")
    key = _key_bytes(response_key if response_key is not None else os.environ.get(RESPONSE_KEY_ENV))
    if key is None and not allow_unsigned_responses:
        raise RuntimeError(f"FinGuard gateway refuses to start: no response signing key ({RESPONSE_KEY_ENV})")
    if key is not None and len(key) < MIN_KEY_BYTES:
        raise RuntimeError(f"FinGuard gateway refuses to start: {RESPONSE_KEY_ENV} must be at least {MIN_KEY_BYTES} bytes")
    audit = AuditLog(audit_path, redact_argument_values=redact_argument_values)
    retriever_version = getattr(retriever, "version", None)
    cfg_hash = config_fingerprint(action_types, rules, model_version, retriever_version, shadow_override,
                                  enforce_rule_blocks_in_shadow, (max_request_bytes, rules_budget_ms))
    app = FastAPI(title="FinGuard gateway", version=__version__)
    app.state.audit = audit

    async def _in_thread(fn, *args):
        return await asyncio.wait_for(asyncio.to_thread(fn, *args), rules_budget_ms / 1000.0)

    def _finish(req_id: str, draft: "_Draft", cfg: dict, policy_ids: list[str], t0: float) -> Decision:
        enforced = bool(cfg.get("enforce", False)) if shadow_override is None else (not shadow_override)
        if enforce_rule_blocks_in_shadow and draft.decided_by == "rule" and draft.verdict == Verdict.BLOCK:
            enforced = True  # deterministic blocks (denylist, payee mismatch) are never shadow-only
        d = Decision(
            request_id=req_id, verdict=draft.verdict, risk_category=draft.category,
            reason=draft.reason[:300], evidence=draft.evidence[:1000], confidence=min(max(draft.confidence, 0.0), 1.0),
            decided_by=draft.decided_by, rule_id=draft.rule_id, policy_ids=policy_ids,
            model_version=model_version, enforced=enforced, latency_ms=0.0)
        d.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return d

    async def run_pipeline(req: CheckRequest, t0: Optional[float] = None) -> tuple[Decision, dict]:
        t0 = t0 if t0 is not None else time.perf_counter()
        raw_name = req.tool_call.name
        tool = canonical_tool_name(raw_name)
        if tool != raw_name:  # judge and rules see only the canonical name
            req = req.model_copy(update={"tool_call": req.tool_call.model_copy(update={"name": tool})})
        cfg = action_config(action_types, tool)
        trace: dict[str, Any] = {"tool_config": cfg, "rule_hits": [], "judge": None,
                                 "records_version": rules.records_version, "tool": tool}
        if tool != raw_name:
            trace["tool_name_as_sent"] = raw_name[:200]
        raw_text: Optional[str] = None
        # 0. sanitise: the caller never chooses the policy (C1). Keep ids + hash for the audit.
        if req.policy_clauses:
            sent = [c.model_dump(mode="json") for c in req.policy_clauses]
            trace["caller_policy_clauses_discarded"] = {
                "count": len(sent), "ids": [c["id"] for c in sent],
                "sha256": hashlib.sha256(json.dumps(sent, sort_keys=True).encode()).hexdigest()}
            log.warning("request %s: discarded %d caller-sent policy clauses", req.request_id, len(sent))
            req = req.model_copy(update={"policy_clauses": []})
        policy_ids: list[str] = []
        policy_source: Optional[str] = None

        # 3. rules, off the event loop, under a time budget (a crash is a bug: never allow on it)
        try:
            outcome = await _in_thread(rules.evaluate, req, cfg)
        except asyncio.TimeoutError:
            log.error("request %s: rules exceeded %.0f ms budget", req.request_id, rules_budget_ms)
            outcome = RuleOutcome()
            draft = _fail_mode_draft(cfg, f"exceeded {rules_budget_ms:.0f} ms budget", True, "Rule checks did not finish")
            trace["rules_budget_exceeded"] = True
        except Exception as e:  # noqa: BLE001
            log.exception("rule engine error")
            outcome = RuleOutcome()
            draft = _fail_mode_draft(cfg, f"rule engine error: {type(e).__name__}", True, "Rule checks failed")
        else:
            trace["rule_hits"] = [h.to_dict() for h in outcome.hits]
            draft = None

        floor = outcome.decisive
        if draft is None and floor is not None and floor.verdict == Verdict.BLOCK:
            draft = _Draft(floor.verdict, floor.category, floor.reason, floor.evidence, 1.0, "rule", floor.rule_id)
            policy_ids, policy_source = ([floor.policy_id] if floor.policy_id else []), "rule"
        elif draft is None and outcome.fast_path is not None:
            fp = outcome.fast_path
            draft = _Draft(Verdict.ALLOW, RiskCategory.NONE, fp.reason, fp.evidence, 1.0, "rule", fp.rule_id)

        if draft is None:
            # 3. retrieve: always the gateway's own retriever
            judged_req = req
            try:
                clauses = await _in_thread(retriever.retrieve, req)
                judged_req = req.model_copy(update={"policy_clauses": clauses})
                policy_ids, policy_source = [c.id for c in clauses], "retriever"
            except asyncio.TimeoutError:
                draft = _fail_mode_draft(cfg, f"exceeded {rules_budget_ms:.0f} ms budget", True, "Policy retrieval did not finish")
            except Exception as e:  # noqa: BLE001
                log.exception("retrieval error")
                draft = _fail_mode_draft(cfg, f"retrieval error: {type(e).__name__}", True, "Policy retrieval failed")
            # 4. judge
            if draft is None:
                timeout_s = float(cfg["timeout_ms"]) / 1000.0
                try:
                    res = await asyncio.wait_for(judge.judge(judged_req, timeout_s), timeout_s)
                except asyncio.TimeoutError:
                    draft = _fail_mode_draft(cfg, f"timeout after {cfg['timeout_ms']} ms")
                except Exception as e:  # noqa: BLE001
                    log.warning("judge error: %r", e)
                    draft = _fail_mode_draft(cfg, f"judge error: {type(e).__name__}")
                else:
                    raw_text = res.raw_text
                    trace["judge"] = {"model_version": res.model_version, "latency_ms": res.latency_ms,
                                      "p_verdict": res.p_verdict,
                                      "prompt_seed": getattr(res, "prompt_seed", None),
                                      "prompt_sha256": getattr(res, "prompt_sha256", None),
                                      "finish_reason": getattr(res, "finish_reason", None),
                                      "parsed": res.output is not None,
                                      "evidence_grounded": (evidence_is_grounded(res.output.evidence, judged_req)
                                                            if res.output is not None and res.output.evidence else None)}
                    if res.output is None:
                        draft = _fail_mode_draft(cfg, "malformed judge output")
                    else:
                        draft = _model_draft(res, cfg)
            # 6. combine with rule floor (escalate hits): strictest wins, ties keep the rule.
            if floor is not None and strictest(floor.verdict, draft.verdict) == floor.verdict and draft.verdict != Verdict.BLOCK:
                draft = _Draft(floor.verdict, floor.category, floor.reason, floor.evidence, 1.0, "rule", floor.rule_id)

        # 7. enforce
        trace["enforce_rule_blocks_in_shadow"] = enforce_rule_blocks_in_shadow
        trace["policy_source"] = policy_source
        decision = _finish(req.request_id, draft, cfg, policy_ids, t0)
        return decision, {"raw_text": raw_text, "trace": trace, "request": req}

    async def _read_body(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > ABSOLUTE_MAX_BYTES:
            raise HTTPException(status_code=413, detail="request too large")
        buf = bytearray()
        async for chunk in request.stream():
            buf += chunk
            if len(buf) > ABSOLUTE_MAX_BYTES:
                raise HTTPException(status_code=413, detail="request too large")
        return bytes(buf)

    def _oversize(obj: Any, size: int, t0: float) -> tuple[Decision, dict, str, str]:
        """Over max_request_bytes: no scanning. Fail mode with escalate floor; audit gets
        size + digest only (not the body)."""
        tc = obj.get("tool_call") if isinstance(obj, dict) else None
        name = tc.get("name") if isinstance(tc, dict) else None
        rid = obj.get("request_id") if isinstance(obj, dict) else None
        if not isinstance(name, str) or not isinstance(rid, str) or not rid:
            raise HTTPException(status_code=422, detail="oversized request without request_id / tool_call.name")
        tool = canonical_tool_name(name[:200])
        cfg = action_config(action_types, tool)
        draft = _fail_mode_draft(cfg, f"{size} bytes > {max_request_bytes} byte cap; not scanned", True,
                                 "Request too large to check")
        trace = {"tool": tool, "tool_config": cfg, "oversize": {"bytes": size, "cap": max_request_bytes},
                 "rule_hits": [], "judge": None}
        return _finish(rid[:200], draft, cfg, [], t0), trace, tool, rid[:200]

    @app.post("/v1/check", response_model=Decision)
    async def check(request: Request) -> Response:
        t0 = time.perf_counter()
        raw = await _read_body(request)
        try:
            obj = json.loads(raw)
        except ValueError as e:
            raise HTTPException(status_code=422, detail="body is not JSON") from e
        if len(raw) > max_request_bytes:
            decision, trace, tool, rid = _oversize(obj, len(raw), t0)
            digest = request_digest(obj)
            logged = {"request_id": rid, "tool_call": {"name": tool}, "oversize_bytes": len(raw)}
            info = {"raw_text": None, "trace": trace}
        else:
            try:
                req = CheckRequest.model_validate(obj)
            except ValidationError as e:
                raise HTTPException(status_code=422, detail=json.loads(e.json(include_url=False))[:20]) from e
            digest = request_digest(req.model_dump(mode="json"))  # as sent, before sanitising
            decision, info = await run_pipeline(req, t0)
            tool = info["request"].tool_call.name  # canonical
            logged = info["request"].model_copy(update={"policy_clauses": []}).model_dump(mode="json")
        try:
            audit.append(request=logged, decision=decision.model_dump(mode="json"),
                         policy_ids=decision.policy_ids, policy_retriever_version=retriever_version,
                         prompt_version=PROMPT_VERSION, config_sha256=cfg_hash, raw_judge_text=info["raw_text"],
                         extra={"gateway": info["trace"], "schema_version": SCHEMA_VERSION, "request_sha256": digest})
        except Exception as e:  # noqa: BLE001
            log.exception("audit write failed")
            raise HTTPException(status_code=503, detail=f"audit unavailable: {type(e).__name__}") from e
        body = decision.model_dump_json().encode()
        headers = {TOOL_HEADER: tool, REQUEST_DIGEST_HEADER: digest}
        if key is not None:
            headers[SIGNATURE_HEADER] = sign_response(key, digest, tool, body)
        return Response(content=body, media_type="application/json", headers=headers)

    @app.get("/healthz")
    async def healthz() -> dict:
        seq, head = audit.head
        return {"status": "ok", "audit_seq": seq, "audit_head": head}

    @app.get("/v1/version")
    async def version() -> dict:
        return {"gateway_version": __version__, "model_version": model_version, "judge_model_version": judge.model_version,
                "prompt_version": PROMPT_VERSION, "schema_version": SCHEMA_VERSION, "rules_version": rules.version,
                "rules_sha256": rules.config_sha256, "policy_retriever_version": retriever_version,
                "config_sha256": cfg_hash, "shadow_override": shadow_override,
                "records_version": rules.records_version,
                "enforce_rule_blocks_in_shadow": enforce_rule_blocks_in_shadow, "responses_signed": key is not None,
                "max_request_bytes": max_request_bytes, "rules_budget_ms": rules_budget_ms}

    return app
