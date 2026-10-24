"""The launcher builds a working app from the shipped configs and refuses unsafe starts."""
from fastapi.testclient import TestClient

from finguard.gateway import serve

ARGS = ["--judge-url", "http://127.0.0.1:9", "--judge-model", "finguard-4b", "--model-version", "test-v0",
        "--policies", "policies/sample_policy.jsonl", "--records", "configs/records_sample.json"]


def test_launcher_builds_app_from_shipped_configs(tmp_path, monkeypatch):
    monkeypatch.setenv("FINGUARD_RESPONSE_KEY", "k" * 40)
    app = serve.build_app(serve.parse(ARGS + ["--audit-log", str(tmp_path / "a.jsonl")]))
    assert TestClient(app).get("/healthz").status_code == 200


def test_launcher_refuses_without_signing_key(tmp_path, monkeypatch):
    monkeypatch.delenv("FINGUARD_RESPONSE_KEY", raising=False)
    import pytest
    with pytest.raises(RuntimeError):
        serve.build_app(serve.parse(ARGS + ["--audit-log", str(tmp_path / "a.jsonl")]))


def test_launcher_refuses_plain_http(tmp_path):
    assert serve.main(ARGS + ["--audit-log", str(tmp_path / "a.jsonl")]) == 2
