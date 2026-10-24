"""Append-only, hash-chained JSONL audit log for every gateway decision.

Each line is one JSON record. `record_hash` = SHA-256 over the canonical JSON of the record
without `record_hash`; `prev_hash` = previous line's record_hash (genesis = 64 zeros).
`verify_chain(path)` recomputes every hash and the seq numbers, so an edited, deleted,
inserted or reordered line is detected. Truncation of the LAST lines is only detectable
against an externally anchored head hash (`expected_head`/`expected_count`): ship the
head hash to a separate system (SIEM / WORM storage) on a schedule.

What a bank needs from the log, and which fields answer it:

| Need (SOX ITGC / SR 11-7)                         | Fields |
|---------------------------------------------------|--------|
| Who asked (agent identity, role)                  | request.agent_role, request.request_id, caller (if set) |
| What action, with what inputs                     | request.tool_call (or argument hashes when redacted), request.context |
| When                                              | timestamp (UTC ISO-8601), seq |
| Outcome and why                                   | decision.verdict, risk_category, reason, evidence, decided_by, rule_id, rule_hits |
| Was it enforced (shadow vs live)                  | decision.enforced |
| Model version / inventory (SR 11-7 model id)      | decision.model_version, prompt_version, schema_version |
| Reproducibility (re-run same inputs, same prompt) | request, policy_ids, policy_retriever_version, prompt_version, prompt_seed, prompt_sha256, config_sha256, raw_judge_text, p_verdict |
| Ongoing monitoring (SR 11-7 outcomes analysis)    | p_verdict, confidence, latency_ms, judge_latency_ms, decided_by distribution |
| Integrity / completeness (SOX evidence)           | prev_hash, record_hash, seq, verify_chain() |

redact_argument_values=True: for deployments that keep raw inputs in a separate secure
store. Tool argument values, context content and user_request are replaced by
{"sha256": ...} so the log proves *which* inputs were seen without holding PII. On EVERY
verdict (allow included) the raw judge text, the decision's evidence and reason, and each
rule hit's evidence and reason are hashed too, because all of them can quote inputs.

Concurrency:
- Within a process: a threading lock.
- Across processes: every append takes an exclusive fcntl.flock on the log file, reads
  whatever other writers appended since this instance's last write, verifies that those
  records chain from the head it knows (hash, prev_hash, seq), and only then appends on top
  of the true tail. If the new records do not chain (an unlocked writer, a second log
  rotated onto the same path, a truncation) that is a CHAIN FORK: the append is refused
  with AuditChainForkError and the service returns 503 (no unlogged decisions).
- flock is advisory and only works on local filesystems (not NFS/SMB). At scale use one
  log file per process (e.g. audit-<host>-<pid>.jsonl, each with its own anchored head) or
  a single audit-writer service; a shared file with many workers serialises every decision
  on one lock and one fsync.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

GENESIS = "0" * 64
AUDIT_FORMAT = "finguard-audit-1"


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(obj: Any) -> str:
    return hashlib.sha256(_canon(obj) if not isinstance(obj, (bytes, str)) else (obj.encode() if isinstance(obj, str) else obj)).hexdigest()


def _hash_value(v: Any) -> dict:
    return {"sha256": hashlib.sha256(_canon(v)).hexdigest()}


class AuditChainForkError(RuntimeError):
    """The log file no longer extends the chain this writer knows: refuse to append."""


def redact_request(request: dict) -> dict:
    r = json.loads(json.dumps(request))
    tc = r.get("tool_call", {})
    tc["arguments"] = {k: _hash_value(v) for k, v in (tc.get("arguments") or {}).items()}
    r["user_request"] = _hash_value(r.get("user_request", ""))
    for c in r.get("context", []):
        c["content"] = _hash_value(c.get("content", ""))
    for pc in r.get("policy_clauses") or []:
        pc["text"] = _hash_value(pc.get("text", ""))
    return r


def _hash_text_fields(d: dict, fields: tuple[str, ...]) -> None:
    for f in fields:
        if f in d and d[f] is not None and not (isinstance(d[f], dict) and set(d[f]) == {"sha256"}):
            d[f] = _hash_value(d[f])


def redact_decision(decision: dict) -> dict:
    """Hash evidence and reason on every verdict (they can quote argument values)."""
    dec = dict(decision)
    _hash_text_fields(dec, ("evidence", "reason"))
    return dec


def redact_extra(extra: Optional[dict]) -> Optional[dict]:
    """Hash rule-hit evidence and reason inside the gateway trace."""
    if not extra:
        return extra
    e = copy.deepcopy(extra)
    gw = e.get("gateway")
    if isinstance(gw, dict):
        for h in gw.get("rule_hits") or []:
            if isinstance(h, dict):
                _hash_text_fields(h, ("evidence", "reason"))
    return e


@dataclass
class ChainReport:
    ok: bool
    count: int
    head_hash: str
    error: Optional[str] = None
    bad_line: Optional[int] = None  # 1-based


class AuditLog:
    def __init__(self, path: str | Path, redact_argument_values: bool = False):
        self.path = Path(path)
        self.redact = redact_argument_values
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # Initialization and append MUST use the same inter-process advisory lock.
        # Otherwise another process can append after verify_chain but before stat,
        # making _offset cover bytes that _seq/_prev have not yet verified.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            rep = verify_chain(self.path)
            if not rep.ok:
                # Refuse to extend a broken chain: a silent restart would hide tampering.
                raise RuntimeError(f"audit log {self.path} fails verification: {rep.error} (line {rep.bad_line})")
            self._seq, self._prev = rep.count, rep.head_hash
            self._offset = os.fstat(fd).st_size  # exact byte length covered by verified head
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._prev

    def _catch_up(self, fd: int) -> None:
        """Under the file lock: verify records other writers appended after our offset and
        advance the head to the true tail. Anything that does not chain is a fork."""
        size = os.fstat(fd).st_size
        if size < self._offset:
            raise AuditChainForkError(f"audit log {self.path} shrank from {self._offset} to {size} bytes (truncated or replaced)")
        if size == self._offset:
            return
        os.lseek(fd, self._offset, os.SEEK_SET)
        chunk = b""
        while len(chunk) < size - self._offset:
            part = os.read(fd, size - self._offset - len(chunk))
            if not part:
                break
            chunk += part
        if not chunk.endswith(b"\n"):
            raise AuditChainForkError(f"audit log {self.path} ends with a partial record")
        seq, prev = self._seq, self._prev
        for line in chunk.decode("utf-8").splitlines():
            try:
                rec = json.loads(line)
            except ValueError as e:
                raise AuditChainForkError(f"audit log {self.path}: unparseable record after seq {seq}") from e
            claimed = rec.pop("record_hash", None)
            if hashlib.sha256(_canon(rec)).hexdigest() != claimed:
                raise AuditChainForkError(f"audit log {self.path}: record after seq {seq} fails its hash")
            if rec.get("prev_hash") != prev or rec.get("seq") != seq + 1:
                raise AuditChainForkError(f"audit log {self.path}: chain fork after seq {seq} "
                                          f"(record seq {rec.get('seq')} does not extend head {prev[:12]})")
            seq, prev = rec["seq"], claimed
        self._seq, self._prev, self._offset = seq, prev, size

    def append(self, *, request: dict, decision: dict, policy_ids: list[str], policy_retriever_version: Optional[str],
               prompt_version: str, config_sha256: str, raw_judge_text: Optional[str], extra: Optional[dict] = None) -> dict:
        if self.redact:
            req, dec, ext = redact_request(request), redact_decision(decision), redact_extra(extra)
            raw = _hash_value(raw_judge_text) if raw_judge_text is not None else None
        else:
            req, dec, ext, raw = request, dict(decision), extra, raw_judge_text
        with self._lock:
            fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._catch_up(fd)
                rec = {
                    "format": AUDIT_FORMAT,
                    "seq": self._seq + 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "prev_hash": self._prev,
                    "redacted": self.redact,
                    "request": req,
                    "decision": dec,
                    "policy_ids": policy_ids,
                    "policy_retriever_version": policy_retriever_version,
                    "prompt_version": prompt_version,
                    "config_sha256": config_sha256,
                    "raw_judge_text": raw,
                    **(ext or {}),
                }
                rec["record_hash"] = hashlib.sha256(_canon(rec)).hexdigest()
                data = (json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
                self._seq, self._prev = rec["seq"], rec["record_hash"]
                self._offset = os.fstat(fd).st_size
            finally:
                os.close(fd)  # closing releases the flock
        return rec


def verify_chain(path: str | Path, expected_head: Optional[str] = None, expected_count: Optional[int] = None) -> ChainReport:
    """Recompute every record hash, prev link and seq. Detects edits, deletions, insertions
    and reordering anywhere except tail truncation, which needs expected_head/expected_count."""
    prev, n = GENESIS, 0
    p = Path(path)
    if not p.exists():
        return ChainReport(False, 0, GENESIS, "log file missing")
    with p.open(encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            if not line.strip():
                return ChainReport(False, n, prev, "blank line", i)
            try:
                rec = json.loads(line)
            except ValueError:
                return ChainReport(False, n, prev, "unparseable line", i)
            claimed = rec.pop("record_hash", None)
            if hashlib.sha256(_canon(rec)).hexdigest() != claimed:
                return ChainReport(False, n, prev, "record_hash mismatch (record edited)", i)
            if rec.get("prev_hash") != prev:
                return ChainReport(False, n, prev, "prev_hash mismatch (line deleted, inserted or reordered)", i)
            if rec.get("seq") != n + 1:
                return ChainReport(False, n, prev, f"seq gap: expected {n + 1}, got {rec.get('seq')}", i)
            prev, n = claimed, n + 1
    if expected_count is not None and n != expected_count:
        return ChainReport(False, n, prev, f"record count {n} != anchored {expected_count} (truncated?)")
    if expected_head is not None and prev != expected_head:
        return ChainReport(False, n, prev, "head hash != anchored head (truncated or replaced)")
    return ChainReport(True, n, prev)
