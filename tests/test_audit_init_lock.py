"""Regression: audit startup must hold the same interprocess lock as append."""
import fcntl
import os
from finguard.gateway import audit


def test_initial_head_and_offset_are_verified_under_interprocess_lock(tmp_path, monkeypatch):
    path = tmp_path / "audited.jsonl"
    real = audit.verify_chain
    observed = []

    def verify_while_locked(current, *args, **kwargs):
        fd = os.open(current, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                observed.append("held")
            else:
                observed.append("UNSAFE-no-lock")
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return real(current, *args, **kwargs)

    monkeypatch.setattr(audit, "verify_chain", verify_while_locked)
    instance = audit.AuditLog(path)
    assert observed == ["held"]
    assert instance.head[0] == 0
