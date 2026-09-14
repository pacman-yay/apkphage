#!/bin/bash
set -e

echo "[*] Fakenet starting..."

# Self-signed cert for the HTTPS sink
mkdir -p /certs
if [ ! -f /certs/fake-all.pem ]; then
    echo "[*] Generating self-signed certificate for HTTPS sink..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /certs/fake.key -out /certs/fake.pem -days 3650 \
        -subj "/CN=fake.internet" >/dev/null 2>&1
    cat /certs/fake.key /certs/fake.pem > /certs/fake-all.pem
fi

# Fake DNS: every A query answers the fake IP (default 10.0.2.2).
python3 /app/fake_dns.py &

# Fake HTTP/HTTPS + proxy responder
echo "[*] Starting fake web responder on 80, 443, 8080..."
if [ -n "${FAKENET_LOG:-}" ]; then
  : > "${FAKENET_LOG}"
fi
python3 /app/fake_internet.py &

trap 'echo "[*] Shutting down fakenet."; kill 0' EXIT
wait