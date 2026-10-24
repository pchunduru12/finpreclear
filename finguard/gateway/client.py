"""How an agent framework wraps every tool call with the gateway.

The agent never holds tool functions. The agent runtime builds a GuardedToolClient once,
with a ToolRegistry (canonical tool name -> function) and its OWN copy of action_types.
The agent then calls client.call(tool_name, args). The client looks up the function for
that name itself, builds the CheckRequest from the same name and args, and runs
registry[name](**args) with exactly the arguments that were checked. The caller supplies no
function, so a check for one tool can never run another tool's function (security review
H2 / round 2 #8).

The tool runs only when:
  - the gateway verdict is allow, OR
  - shadow mode is agreed by BOTH sides: the client's own action_types says enforce=false
    for this tool AND the gateway says enforced=false AND the decision is not a
    deterministic rule block (decided_by="rule", verdict=block).

dry_run=True (demo / trace replay): the tool NEVER runs, whatever the verdict or fail mode;
the signed decision is returned for display and audit only.

Every response must carry a valid HMAC signature (shared key, env FINGUARD_RESPONSE_KEY)
over the exact request digest, canonical tool name and body, and must echo the request_id.
A missing/invalid signature, a mismatched request_id / tool / digest, an unreachable
gateway or any 4xx/5xx applies the LOCAL fail mode for that tool, so neither an outage nor
a forged response turns into a silent allow for high-risk tools.

Production transport is mTLS between agent runtime and gateway (configs/serving.md); the
HMAC is an extra end-to-end check, not a replacement.
"""
from __future__ import annotations

import copy
import logging
import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Union

import httpx

from ..rules import canonical_tool_name
from ..schema import CheckRequest, ContextItem, Decision, Verdict
from .service import (FAIL_MODE_VERDICT, REQUEST_DIGEST_HEADER, RESPONSE_KEY_ENV, SIGNATURE_HEADER, TOOL_HEADER,
                      action_config, request_digest, verify_response_signature)

log = logging.getLogger("finguard.client")


class ActionStopped(Exception):
    """Raised instead of running the tool. Carries the decision for the agent to report."""

    def __init__(self, verdict: Verdict, reason: str, decision: Optional[Decision] = None):
        super().__init__(f"{verdict.value}: {reason}")
        self.verdict, self.reason, self.decision = verdict, reason, decision


class UnknownTool(ActionStopped):
    """The agent asked for a tool that is not in the registry. Nothing is sent or run."""

    def __init__(self, tool_name: str):
        super().__init__(Verdict.BLOCK, f"tool {tool_name!r} is not registered")


@dataclass
class GuardOutcome:
    ran: bool
    result: Any
    decision: Optional[Decision]
    local_fail_mode: bool = False
    shadow: bool = False  # ran although the verdict was not allow (both sides in shadow mode)


class ToolRegistry:
    """Immutable map of canonical tool name -> function, fixed when the agent runtime starts.
    Names are canonicalised (rules.canonical_tool_name), and two names that canonicalise to
    the same tool are refused, so 'Submit_Payment ' cannot reach a different function."""

    def __init__(self, tools: Mapping[str, Callable[..., Any]]):
        reg: dict[str, Callable[..., Any]] = {}
        for name, fn in tools.items():
            c = canonical_tool_name(name)
            if not c:
                raise ValueError(f"empty tool name {name!r}")
            if c in reg:
                raise ValueError(f"tool names collide after canonicalisation: {name!r} -> {c!r}")
            if not callable(fn):
                raise TypeError(f"tool {name!r} is not callable")
            reg[c] = fn
        self._tools = MappingProxyType(reg)

    def get(self, name: str) -> Optional[Callable[..., Any]]:
        return self._tools.get(canonical_tool_name(name))

    def names(self) -> list[str]:
        return sorted(self._tools)


class _GatewayRejected(Exception):
    """Response could not be trusted (signature, request_id, tool or digest mismatch)."""


class GuardedToolClient:
    """The only way an agent runs a tool.

    registry: ToolRegistry built by the agent runtime (the agent cannot change it).
    action_types: the CLIENT's own copy of configs/action_types.json, deployed with the
    agent runtime, not received from the gateway.
    response_key: HMAC key; defaults to env FINGUARD_RESPONSE_KEY.
    dry_run: explicit pilot preview mode: never execute registered tool functions."""

    def __init__(self, registry: ToolRegistry, *, gateway_url: str, action_types: dict,
                 response_key: Union[str, bytes, None] = None, http: Optional[httpx.Client] = None,
                 timeout_s: float = 2.0, dry_run: bool = False):
        if not isinstance(registry, ToolRegistry):
            raise TypeError("registry must be a ToolRegistry")
        self._registry = registry
        self._action_types = copy.deepcopy(action_types)
        raw_key = response_key if response_key is not None else os.environ.get(RESPONSE_KEY_ENV)
        self._key = (raw_key.encode() if isinstance(raw_key, str) else raw_key) or None
        self._http = http
        self._gateway_url, self._timeout_s = gateway_url, timeout_s
        self._dry_run = bool(dry_run)  # beta preview: never invoke any registered tool, regardless of verdict

    def _local_fail(self, tool: str, fn: Callable[..., Any], args: dict, why: str,
                    cause: Optional[BaseException] = None) -> GuardOutcome:
        if self._dry_run:
            # Even a historically fail-open tool must not execute on an unverified response.
            raise ActionStopped(Verdict.ESCALATE, f"dry-run gateway failure: {why}; tool was not executed") from cause
        cfg = action_config(self._action_types, tool)
        v = FAIL_MODE_VERDICT[cfg["fail_mode"]]
        if v != Verdict.ALLOW:
            raise ActionStopped(v, f"{why}; local fail_mode={cfg['fail_mode']}") from cause
        log.warning("tool %s running on local fail-open: %s", tool, why)
        return GuardOutcome(True, fn(**args), None, local_fail_mode=True)

    def call(self, tool_name: str, args: dict, *, request_id: str, agent_role: str, user_request: str,
             context: Optional[list[Union[ContextItem, dict]]] = None, workflow: Optional[str] = None) -> GuardOutcome:
        """Check tool_name(args) with the gateway, then run the REGISTERED function for
        tool_name with exactly those args, only if permitted. Escalate raises ActionStopped
        too (the agent framework routes it to a human queue). Policy clauses are never sent."""
        tool = canonical_tool_name(tool_name)
        fn = self._registry.get(tool)
        if fn is None:
            raise UnknownTool(tool_name)
        frozen_args = copy.deepcopy(args)  # the tool runs with exactly what was checked
        req = CheckRequest.model_validate({
            "request_id": request_id, "agent_role": agent_role, "user_request": user_request,
            "tool_call": {"name": tool, "arguments": copy.deepcopy(frozen_args)},
            "context": [c.model_dump(mode="json") if isinstance(c, ContextItem) else c for c in (context or [])],
            "workflow": workflow})
        payload = req.model_dump(mode="json")
        digest = request_digest(payload)

        client = self._http or httpx.Client(base_url=self._gateway_url, timeout=self._timeout_s)
        try:
            if self._key is None:
                raise _GatewayRejected(f"no response verification key ({RESPONSE_KEY_ENV})")
            r = client.post("/v1/check", json=payload)
            r.raise_for_status()
            body = r.content
            if not verify_response_signature(self._key, digest, tool, body, r.headers.get(SIGNATURE_HEADER)):
                raise _GatewayRejected("missing or invalid response signature")
            if r.headers.get(TOOL_HEADER) != tool or r.headers.get(REQUEST_DIGEST_HEADER) != digest:
                raise _GatewayRejected("response is for a different tool or request")
            decision = Decision.model_validate_json(body)
            if decision.request_id != request_id:
                raise _GatewayRejected("decision request_id does not match")
        except Exception as e:  # unreachable, 4xx/5xx, bad body, untrusted response -> local fail mode
            why = str(e) if isinstance(e, _GatewayRejected) else f"gateway unavailable ({type(e).__name__})"
            return self._local_fail(tool, fn, frozen_args, why, e)
        finally:
            if self._http is None:
                client.close()

        if self._dry_run:
            # A signed decision is observable, but absolutely no tool function runs.
            # This includes ALLOW, BLOCK, ESCALATE and shadow-mode verdicts.
            return GuardOutcome(False, None, decision, shadow=True)
        if decision.verdict == Verdict.ALLOW:
            return GuardOutcome(True, fn(**frozen_args), decision)
        local_enforce = bool(action_config(self._action_types, tool).get("enforce", False))
        rule_block = decision.decided_by == "rule" and decision.verdict == Verdict.BLOCK
        if not local_enforce and not decision.enforced and not rule_block:
            log.warning("shadow mode: running %s despite verdict %s (request %s)", tool, decision.verdict.value, request_id)
            return GuardOutcome(True, fn(**frozen_args), decision, shadow=True)
        raise ActionStopped(decision.verdict, decision.reason, decision)


def guarded_call(*_a, **_kw):
    """Removed: it accepted a caller-supplied function. Use GuardedToolClient(registry, ...).call(tool_name, args)."""
    raise TypeError("guarded_call(tool_fn, ...) was removed; use GuardedToolClient(ToolRegistry(...)).call(tool_name, args)")


__all__ = ["ActionStopped", "UnknownTool", "GuardOutcome", "ToolRegistry", "GuardedToolClient"]
