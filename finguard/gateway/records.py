"""Gateway-side systems-of-record lookups used by the deterministic rules.

Why this exists (security review H1): the payee and approval checks used to read "vendor
master" and "approval" records out of the request's own context items. The caller sets
those items and their trust labels, so a compromised or confused agent could supply its
own matching record and pass the check. The gateway now asks the bank's systems of record
directly. Nothing the caller sends can loosen a rule. The request can only name an id
(vendor_id, approval_id), and the gateway looks that id up.

`RecordsLookup` is the interface a bank adapter implements (ERP vendor master, payments
approval workflow). `JsonRecordsLookup` reads a JSON file and is meant for tests and pilot
config only (configs/records_sample.json holds fake values). A production adapter must:
- be read-only and authenticate as the gateway's service identity, not as the agent;
- use short timeouts. Any exception escalates (or blocks) the call; it never allows;
- report a `version` string (adapter + data snapshot) for the audit record (SR 11-7 / SOX).

Mapping: SOX ITGC / AP controls (payee = vendor master, P-PAY-002), P-PAY-001 approval limit,
OWASP LLM06 (excessive agency: the agent cannot self-approve).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

RECORDS_SAMPLE_FILE = Path(__file__).resolve().parents[2] / "configs" / "records_sample.json"


@runtime_checkable
class RecordsLookup(Protocol):
    """Read-only access to the bank's systems of record."""

    version: str

    def vendor_master(self, vendor_id: str) -> Optional[dict]:
        """Approved vendor master record: {"account": ..., ...}, or None if the vendor is unknown."""
        ...

    def approval(self, approval_id: str) -> Optional[dict]:
        """Human approval record, or None if no such approval exists:
        {"payee_account", "amount_max", "currency", "tool", "expires" (ISO-8601 with timezone)}."""
        ...

    def hr_verification(self, employee_id: str) -> Optional[dict]:
        """Completed HR-portal verification of a direct-deposit change (P-HR-001), or None:
        {"status": "verified", "account" (optional), "expires" (optional, ISO-8601 with timezone)}.
        Only a record with status "verified" counts."""
        ...


class JsonRecordsLookup:
    """RecordsLookup over a JSON file: {"vendors": {...}, "approvals": {...}, "hr_verifications": {...}}.
    For tests and pilot config only. Returns copies so callers cannot mutate the store."""

    def __init__(self, data: dict, source: str = "inline"):
        self._vendors = dict(data.get("vendors") or {})
        self._approvals = dict(data.get("approvals") or {})
        self._hr = dict(data.get("hr_verifications") or {})
        digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:12]
        self.version = f"json-records-{digest}"
        self.source = source

    @classmethod
    def from_json(cls, path: str | Path = RECORDS_SAMPLE_FILE) -> "JsonRecordsLookup":
        p = Path(path)
        return cls(json.loads(p.read_text()), source=str(p))

    def vendor_master(self, vendor_id: str) -> Optional[dict]:
        rec = self._vendors.get(str(vendor_id))
        return dict(rec) if isinstance(rec, dict) else None

    def approval(self, approval_id: str) -> Optional[dict]:
        rec = self._approvals.get(str(approval_id))
        return dict(rec) if isinstance(rec, dict) else None

    def hr_verification(self, employee_id: str) -> Optional[dict]:
        rec = self._hr.get(str(employee_id))
        return dict(rec) if isinstance(rec, dict) and rec.get("status") == "verified" else None


__all__ = ["RecordsLookup", "JsonRecordsLookup", "RECORDS_SAMPLE_FILE"]
