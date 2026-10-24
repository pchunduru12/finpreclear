"""Private synthetic demonstration contract tests."""
import base64
import http.client
import threading
from http.server import ThreadingHTTPServer

import pytest
from scripts.demo_server import make_handler, PAGE


def test_requires_long_local_secret():
    with pytest.raises(ValueError):
        make_handler("")
    with pytest.raises(ValueError):
        make_handler("short")


def test_visible_simulation_disclosure_and_no_external_data():
    page = PAGE.read_text()
    assert page.count("STUB / SIMULATION — NOT A TRAINED MODEL") >= 2
    assert "No tools executed" in page
    assert "Manually select a simulated verdict" in page
    assert "fetch(" not in page and "localStorage" not in page


def test_authentication_and_no_writes():
    secret = "only-local-example-long-secret"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(secret))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        assert response.status == 401
        response.read()
        conn.request("GET", "/", headers={"Authorization": "Basic not-valid-%%"})
        response = conn.getresponse()
        assert response.status == 401
        response.read()
        b64 = base64.b64encode(("demo:" + secret).encode()).decode()
        conn.request("GET", "/", headers={"Authorization": "Basic " + b64})
        response = conn.getresponse()
        assert response.status == 200
        assert b"STUB / SIMULATION" in response.read()
        conn.request("POST", "/", body=b"not-accepted")
        response = conn.getresponse()
        assert response.status == 405
        response.read()
    finally:
        conn.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
