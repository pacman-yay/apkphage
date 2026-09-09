"""Fake internet web responder for the APKPhage sandbox.

Answers HTTP (80), HTTPS (443) and HTTP-proxy (8080) traffic with canned
content so the Android emulator "sees" a working internet without anything
reaching the real one.

Every response body is the same fake blob; what matters is that C2-style
requests / connectivity probes get a live-looking reply and we log the
request line. DNS NXDOMAIN/redirect is handled separately by dnschef.
"""

import http.server
import socketserver
import ssl
import sys
import threading

FAKE_BODY = b"""<!doctype html><html><head><title>404 - Honeypot Sanitized</title></head>
<body style="font-family:monospace">
<h1>Connection captured by fakenet</h1>
<p>No real internet is reachable from this sandbox. This response is synthetic.</p>
</body></html>"""


class FakeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # quieter: only request lines we care about
        sys.stdout.write("[fakenet] %s\n" % (fmt % args))
        sys.stdout.flush()

    def _respond(self):
        # Endpoint is recorded in access log via log_request/self.path already.

        # Proxy-style absolute URI and plain path both fine.
        sys.stdout.write(f"[fakenet] {self.command} {self.path}\n")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(FAKE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(FAKE_BODY)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        # Drain request body so the socket stays consistent
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)
        self._respond()

    def do_HEAD(self):
        self._respond()

    def do_CONNECT(self):
        # A real proxy would tunnel; we just swallow the TLS handshake bytes.
        sys.stdout.write(f"[fakenet] CONNECT {self.path}\n")
        sys.stdout.flush()
        self.send_response(200, "Connection established")
        self.end_headers()
        # Do not actually tunnel anywhere - keep socket open briefly, ignore bytes.
        try:
            self.rfile.read(0)
        except Exception:
            pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 80), FakeHandler)
    servers = [server]

    try:
        https_server = ThreadingHTTPServer(("0.0.0.0", 443), FakeHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("/certs/fake-all.pem")
        https_server.socket = ctx.wrap_socket(https_server.socket, server_side=True)
        servers.append(https_server)
    except Exception as e:
        print(f"[fakenet] HTTPS endpoint skipped: {e}")

    try:
        proxy_server = ThreadingHTTPServer(("0.0.0.0", 8080), FakeHandler)
        servers.append(proxy_server)
    except Exception as e:
        print(f"[fakenet] Proxy endpoint skipped: {e}")

    for srv in servers:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        print(f"[fakenet] Listening on port {srv.server_address[1]}")

    threading.Event().wait()


if __name__ == "__main__":
    main()
