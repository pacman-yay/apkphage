"""Fake DNS server - answers every A query with a fixed fake IP.

This replaces dnschef (not on PyPI) with a tiny dnslib implementation:
every A record resolves to 10.0.2.2 (the emulator's host alias) unless
overridden via the FAKE_DNS_IP env var. AAAA and everything else gets
NOERROR with no answers, so apps with happy-eyeballs fall back to IPv4.
"""

import os
import socketserver
import threading

from dnslib import QTYPE, RR, A, DNSRecord

FAKE_IP = os.environ.get("FAKE_DNS_IP", "10.0.2.2")


REQUEST_LOG = os.environ.get("FAKENET_LOG", "")


def _log(query: DNSRecord):
    """Record the queried hostname - the network evidence an analyst cares
    about (which C2-ish domains the sample asked DNS for)."""
    qtype = QTYPE.get(query.q.qtype, query.q.qtype)
    line = f"[fakenet-dns] {str(query.q.qname).rstrip('.')} (type {qtype})"
    print(line, flush=True)
    if REQUEST_LOG:
        try:
            with open(REQUEST_LOG, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def build_reply(raw: bytes) -> bytes:
    request = DNSRecord.parse(raw)
    _log(request)
    reply = request.reply()
    qname = request.q.qname
    qtype = request.q.qtype
    if qtype in (QTYPE.A, QTYPE.ANY):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(FAKE_IP), ttl=60))
    return reply.pack()


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(build_reply(data), self.client_address)
        except Exception:
            pass


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCPServerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(4096)
            pipe = self.connection.makefile("wb")
            pipe.write(build_reply(data))
            pipe.flush()
        except Exception:
            pass


def main():
    udp = UDPServer(("0.0.0.0", 53), UDPServerHandler)
    tcp = TCPServer(("0.0.0.0", 53), TCPServerHandler)
    print(f"[fakenet] Fake DNS online on :53 (UDP+TCP) -> {FAKE_IP}", flush=True)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()


if __name__ == "__main__":
    main()
