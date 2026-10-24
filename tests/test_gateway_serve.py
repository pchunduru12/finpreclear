"""The launcher builds a working app from the shipped configs and refuses unsafe starts."""
from fastapi.testclient import TestClient

from finguard.gateway import serve

ARGS = ["--judge-url", "http://127.0.0.1:9", "--judge-model", "finguard-4b", "--model-version", "test-v0",
        "--policies", "policies/sample_policy.jsonl", "--records", "configs/records_sample.json",
        "--audit-log", "audit-fixture.jsonl"]


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


def test_insecure_dev_never_binds_non_loopback():
    for host in ("0.0.0.0", "::", "localhost", "192.0.2.5", "example.com"):
        args = serve.parse(ARGS + ["--insecure-dev", "--host", host])
        assert serve.transport_configuration_error(args) is not None, host


def test_local_dev_loopback_accepted():
    for host in ("127.0.0.1", "::1"):
        args = serve.parse(ARGS + ["--insecure-dev", "--host", host])
        assert serve.transport_configuration_error(args) is None


def test_production_requires_mutual_tls():
    for extra in (
        [],
        ["--ssl-certfile", "cert.pem"],
        ["--ssl-keyfile", "key.pem"],
        ["--ssl-certfile", "cert.pem", "--ssl-keyfile", "key.pem"],
        ["--ssl-ca-certs", "clients.pem"],
    ):
        assert serve.transport_configuration_error(serve.parse(ARGS + extra))
    args = serve.parse(ARGS + ["--host", "0.0.0.0",
                              "--ssl-certfile", "cert.pem",
                              "--ssl-keyfile", "key.pem",
                              "--ssl-ca-certs", "clients.pem"])
    assert serve.transport_configuration_error(args) is None


def test_insecure_remote_listener_refused_before_app_initialization(monkeypatch):
    def unexpected_build(_):
        raise AssertionError("unsafe transport must be refused before app initialization")
    monkeypatch.setattr(serve, "build_app", unexpected_build)
    assert serve.main(ARGS + ["--insecure-dev", "--host", "0.0.0.0"]) == 2
