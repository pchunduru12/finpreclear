"""Hash-chained audit log: verifies clean, detects edits, deletions, reordering, truncation."""
from __future__ import annotations

import json

import pytest

from finguard.gateway.audit import AuditLog, verify_chain


def _write(path, n=4, redact=False):
    log = AuditLog(path, redact_argument_values=redact)
    for i in range(n):
        log.append(request={"request_id": f"r-{i}", "user_request": "Pay INV-77", "context": [{"content": "secret"}],
                            "tool_call": {"name": "submit_payment", "arguments": {"amount": 100 + i, "payee_account": "ACCT-0000-1111"}}},
                   decision={"verdict": "allow", "evidence": "", "request_id": f"r-{i}"}, policy_ids=["P-PAY-001"],
                   policy_retriever_version="policy-x", prompt_version="p1.0", config_sha256="c" * 64, raw_judge_text="{}")
    return log


def test_clean_chain_verifies_and_reopen_continues(tmp_path):
    p = tmp_path / "a.jsonl"
    log = _write(p)
    rep = verify_chain(p)
    assert rep.ok and rep.count == 4 and rep.head_hash == log.head[1]
    _write(p, n=2)  # reopen appends onto the existing chain
    assert verify_chain(p).count == 6


def test_tampered_line_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    _write(p)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["decision"]["verdict"] = "block"
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    rep = verify_chain(p)
    assert not rep.ok and rep.bad_line == 2 and "edited" in rep.error
    with pytest.raises(RuntimeError):
        AuditLog(p)  # refuses to extend a broken chain


def test_deleted_line_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    _write(p)
    lines = p.read_text().splitlines()
    del lines[2]
    p.write_text("\n".join(lines) + "\n")
    rep = verify_chain(p)
    assert not rep.ok and rep.bad_line == 3


def test_reordered_lines_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    _write(p)
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert not verify_chain(p).ok


def test_tail_truncation_needs_anchor(tmp_path):
    p = tmp_path / "a.jsonl"
    log = _write(p)
    count, head = log.head
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n")
    assert verify_chain(p).ok  # undetectable without an external anchor
    assert not verify_chain(p, expected_head=head, expected_count=count).ok


def test_redaction_stores_hashes_not_values(tmp_path):
    p = tmp_path / "a.jsonl"
    _write(p, n=1, redact=True)
    text = p.read_text()
    assert "ACCT-0000-1111" not in text and "secret" not in text and "Pay INV-77" not in text
    rec = json.loads(text)
    assert set(rec["request"]["tool_call"]["arguments"]["amount"]) == {"sha256"} and rec["redacted"] is True
    assert verify_chain(p).ok


def test_redaction_hashes_judge_text_evidence_reason_on_every_verdict(tmp_path):
    """Before: reason, rule-hit evidence/reason, and raw judge text on verdicts with empty
    decision evidence (e.g. allow) were stored in clear in redact mode."""
    p = tmp_path / "r.jsonl"
    log = AuditLog(p, redact_argument_values=True)
    secret = "ACCT-0000-1111"
    for verdict, ev in (("allow", ""), ("block", f"payee {secret}"), ("escalate", "")):
        log.append(request={"request_id": "r", "user_request": "x", "context": [],
                            "tool_call": {"name": "submit_payment", "arguments": {"payee_account": secret}}},
                   decision={"verdict": verdict, "evidence": ev, "reason": f"Payee {secret} differs.", "request_id": "r"},
                   policy_ids=[], policy_retriever_version=None, prompt_version="p", config_sha256="c" * 64,
                   raw_judge_text=f'{{"verdict": "{verdict}", "evidence": "{secret}"}}',
                   extra={"gateway": {"rule_hits": [{"rule_id": "R-VM-001", "evidence": secret, "reason": f"{secret} bad"}]}})
    text = p.read_text()
    assert secret not in text
    for rec in map(json.loads, text.splitlines()):
        assert set(rec["decision"]["reason"]) == {"sha256"} and set(rec["raw_judge_text"]) == {"sha256"}
        assert set(rec["gateway"]["rule_hits"][0]["evidence"]) == {"sha256"}
    assert verify_chain(p).ok


def test_two_writers_same_file_interleave_without_fork(tmp_path):
    """Before: a second AuditLog on the same path appended from its stale head and forked the chain."""
    p = tmp_path / "shared.jsonl"
    a, b = AuditLog(p), AuditLog(p)
    for i in range(3):
        _append(a, i)
        _append(b, i)
    rep = verify_chain(p)
    assert rep.ok and rep.count == 6


def _append(log, i):
    log.append(request={"request_id": f"r-{i}"}, decision={"verdict": "allow", "evidence": ""}, policy_ids=[],
               policy_retriever_version=None, prompt_version="p", config_sha256="c" * 64, raw_judge_text=None)


def test_multiprocess_writers_keep_one_chain(tmp_path):
    import multiprocessing as mp
    p = tmp_path / "mp.jsonl"
    AuditLog(p)
    ctx = mp.get_context("spawn")  # fork after test threads (TestClient) can deadlock on inherited locks
    procs = [ctx.Process(target=_mp_worker, args=(str(p), w)) for w in range(4)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(25)
        assert pr.exitcode == 0, pr.exitcode
    rep = verify_chain(p)
    assert rep.ok and rep.count == 4 * 25, rep


def _mp_worker(path, w):
    log = AuditLog(path)
    for i in range(25):
        _append(log, w * 100 + i)


def test_chain_fork_is_detected_and_refused(tmp_path):
    from finguard.gateway.audit import AuditChainForkError
    p = tmp_path / "f.jsonl"
    a = AuditLog(p)
    _append(a, 0)
    # an unlocked / foreign writer appends a record that does not extend a's head
    rogue = {"format": "finguard-audit-1", "seq": 1, "prev_hash": "0" * 64, "request": {}, "decision": {}}
    import hashlib
    from finguard.gateway.audit import _canon
    rogue["record_hash"] = hashlib.sha256(_canon(rogue)).hexdigest()
    with p.open("a") as f:
        f.write(json.dumps(rogue, sort_keys=True) + "\n")
    with pytest.raises(AuditChainForkError, match="fork"):
        _append(a, 1)
    # truncation under a live writer is also refused
    b_path = tmp_path / "t.jsonl"
    b = AuditLog(b_path)
    _append(b, 0); _append(b, 1)
    b_path.write_text(b_path.read_text().splitlines()[0] + "\n")
    with pytest.raises(AuditChainForkError, match="shrank"):
        _append(b, 2)
