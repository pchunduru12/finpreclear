"""Serve the synthetic demo only on loopback using a required local password."""
import argparse
import base64
import binascii
import hmac
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "demo" / "index.html"


def make_handler(password: str):
    if len(password) < 24:
        raise ValueError("FINPRECLEAR_DEMO_PASSWORD must contain at least 24 characters")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            try:
                prefix, token = auth.split(" ", 1)
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (ValueError, UnicodeError, binascii.Error):
                prefix, decoded = "", ""
            authorized = prefix == "Basic" and hmac.compare_digest(decoded, "demo:" + password)
            if not authorized:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Private synthetic demo"')
                body = b"Unauthorized"
            elif self.path == "/":
                self.send_response(200)
                body = PAGE.read_bytes()
                self.send_header("Content-Type", "text/html; charset=utf-8")
            else:
                self.send_response(404)
                body = b"Not found"
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Private synthetic demo; localhost only")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    handler = make_handler(os.environ.get("FINPRECLEAR_DEMO_PASSWORD", ""))
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as httpd:
        print(f"Open http://127.0.0.1:{args.port}/ and sign in as demo.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
