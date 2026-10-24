"""Adapters that map public benchmark items into FinGuard Examples (eval use).

Every adapter calls provenance.check_source(name) BEFORE touching an item, so a
benchmark whose license has not been verified by a human cannot enter any split.
Adapters are pure functions over already-downloaded dicts (no network here); the
download step is a separate, logged action.

TraceSafe (CyCraftAI/TraceSafe, Apache-2.0 per HF card, checked 2026-10-24):
  record = {mutation_category, original_trace, new_trace, difference,
            mutation_metadata{mutator_name, target_tool, rationale, source, model_name, ...},
            golden_meta{category, type: "attacked"|"pure_benign", source_model, ...}}
  trace  = {domain, environment, scenario_description, user_query, tool_lists[...],
            trace[{role: user|agent|tool, content}], agent_model}
  Notes for reviewers:
  - Traces are generic (BFCL-derived code/file agents), not banking: use for transfer
    eval, not as in-domain training data.
  - Agent turns were produced by models such as toolace-8b, a Llama-3.1-8B fine-tune.
    Per project rule (no Llama outputs in training data) TraceSafe rows are tagged
    eval-only via filters_passed=["eval_only:llama_derived_agent_turns"]; the training
    exporter should refuse them. This is flagged in the data-pipeline report.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

from ..dataset import Example
from ..provenance import LicenseError, Provenance, check_source
from ..schema import CheckRequest, ContextItem, RiskCategory, ToolCall, Trust, Verdict

ADAPTER_VERSION = "bench-1.0"

# TraceSafe mutation_category (root vector) -> FinGuard category.
TRACESAFE_CATEGORY = {
    "PROMPT_INJECTION": RiskCategory.INDIRECT_INJECTION,
    "PRIVACY_LEAKAGE": RiskCategory.DATA_EXFILTRATION,
    "HALLUCINATION": RiskCategory.WRONG_TOOL_OR_ARGS,
    "INTERFACE_INCONSISTENCIES": RiskCategory.WRONG_TOOL_OR_ARGS,
}


class AdapterError(ValueError):
    pass


def _parse_call(content: Any, target_tool: Optional[str]) -> Optional[ToolCall]:
    """Agent turns may be JSON ({name, arguments}), a list of such, or free text."""
    obj = content
    if isinstance(content, str):
        try:
            obj = json.loads(content)
        except (ValueError, TypeError):
            obj = None
    if isinstance(obj, list):
        obj = next((o for o in obj if isinstance(o, dict) and (target_tool is None or o.get("name") == target_tool)), None)
    if isinstance(obj, dict) and "name" in obj:
        args = obj.get("arguments", obj.get("parameters", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"raw": args}
        return ToolCall(name=str(obj["name"]), arguments=args if isinstance(args, dict) else {"value": args})
    if target_tool and isinstance(content, str) and target_tool in content:
        return ToolCall(name=target_tool, arguments={"raw": content})
    return None


def map_tracesafe(item: dict, item_id: str, policy_set: str = "tracesafe_none") -> Example:
    """Map one TraceSafe record. The planned call = last agent turn calling target_tool
    in new_trace; everything before it becomes context. Tool outputs are untrusted."""
    lic = check_source("tracesafe")
    meta = item.get("mutation_metadata") or {}
    gm = item.get("golden_meta") or {}
    tr = item.get("new_trace") or item.get("original_trace")
    if not tr or not isinstance(tr.get("trace"), list):
        raise AdapterError(f"{item_id}: no trace")
    target = meta.get("target_tool") or None
    turns = tr["trace"]
    call, call_idx = None, None
    for i in range(len(turns) - 1, -1, -1):
        if turns[i].get("role") == "agent":
            c = _parse_call(turns[i].get("content"), target)
            if c and (target is None or c.name == target):
                call, call_idx = c, i
                break
    if call is None:
        raise AdapterError(f"{item_id}: no agent call to target tool {target!r}")
    context = []
    for t in turns[:call_idx]:
        role = t.get("role")
        content = t.get("content") if isinstance(t.get("content"), str) else json.dumps(t.get("content"))
        trust = Trust.TRUSTED if role == "user" else Trust.UNTRUSTED  # agent+tool text is not authority
        context.append(ContextItem(source=f"trace:{role}", trust=trust, content=content[:20_000]))
    attacked = gm.get("type") == "attacked" or (item.get("mutation_category") not in (None, "BENIGN"))
    root = item.get("mutation_category", "BENIGN")
    if attacked:
        cat = TRACESAFE_CATEGORY.get(root)
        if cat is None:
            raise AdapterError(f"{item_id}: unmapped mutation_category {root!r}")
        verdict = Verdict.BLOCK
    else:
        cat, verdict = RiskCategory.NONE, Verdict.ALLOW
    family = f"tracesafe.{(meta.get('mutator_name') or gm.get('category') or root).lower()}" if attacked else None
    req = CheckRequest(request_id=f"tracesafe-{item_id}", agent_role=tr.get("domain") or "generic_agent",
                       user_request=tr.get("user_query", ""), tool_call=call, context=context, workflow=None)
    return Example(
        example_id=f"tracesafe-{item_id}", request=req, gold_verdict=verdict, gold_category=cat,
        gold_trigger_span=None,  # TraceSafe gives a diff, not a quotable span; evidence-on-trigger is not scored
        is_attack=attacked, attack_family=family, benign_kind=None if attacked else "plain",
        workflow="external_generic", policy_set=policy_set, template_id=f"tracesafe:{family or 'benign'}",
        provenance=Provenance(source_type="public_benchmark", source="tracesafe", source_item_id=item_id,
                              source_license=lic, template_author="external:tracesafe",
                              generator_version=ADAPTER_VERSION,
                              filters_passed=["eval_only:llama_derived_agent_turns"]),
    )


def map_agentdojo(item: dict, item_id: str) -> Example:
    check_source("agentdojo")  # raises LicenseError until a human verifies the license
    raise LicenseError("agentdojo adapter not implemented: verify license first")


def map_injecagent(item: dict, item_id: str) -> Example:
    check_source("injecagent")
    raise LicenseError("injecagent adapter not implemented: verify license first")


ADAPTERS: dict[str, Callable[..., Example]] = {
    "tracesafe": map_tracesafe,
    "agentdojo": map_agentdojo,
    "injecagent": map_injecagent,
}


def get_adapter(name: str) -> Callable[..., Example]:
    check_source(name)  # license gate first, even before looking up the adapter
    if name not in ADAPTERS:
        raise AdapterError(f"no adapter for {name}")
    return ADAPTERS[name]
