#!/bin/bash
set -e

adb start-server

echo "[*] Checking for KVM acceleration..."
if [ -e /dev/kvm ] && [ -w /dev/kvm ]; then
    echo "[+] /dev/kvm found - using accelerated emulation"
    EXTRA_ARGS="-accel on"
    GUEST_MEM=2048
else
    echo "[-] No /dev/kvm - falling back to software emulation (boots slowly)"
    echo "    Software emulation is memory-hungry; keep guest RAM modest."
    EXTRA_ARGS="-no-accel"
    GUEST_MEM=1536
fi

# Wire the emulator's DNS + HTTP proxy to fakenet when it's on the network.
# NOTE: -dns-server and -http-proxy both need an IP, not a container name -
# resolve the name through docker's embedded DNS first.
FAKENET_OPTS=""
if [ -n "${FAKENET_HOST:-}" ]; then
    FAKENET_IP=$(getent hosts "${FAKENET_HOST}" | awk '{print $1; exit}')
    if [ -n "${FAKENET_IP}" ]; then
        echo "[+] Fake internet enabled - DNS + proxy -> ${FAKENET_HOST} (${FAKENET_IP})"
        FAKENET_OPTS="-dns-server ${FAKENET_IP} -http-proxy http://${FAKENET_IP}:8080"
    else
        echo "[-] Could not resolve ${FAKENET_HOST} - running WITHOUT fake internet"
    fi
fi

# Software GPU rendering works headless in both modes.
emulator -avd sandbox \
    -no-audio \
    -no-window \
    -no-boot-anim \
    -no-snapshot \
    -no-metrics \
    -gpu swiftshader_indirect \
    -memory ${GUEST_MEM} \
    ${EXTRA_ARGS} \
    ${FAKENET_OPTS} &

# Network capture is ON by default now: the whole point of a sandbox is a
# readable record of what the sample tried to reach. tcpdump dumps raw
# DNS/HTTP/HTTPS/proxy frames to a shared file the orchestrator harvests.
# Set CAPTURE_NET=0 to disable (e.g. to reduce noise on very slow hosts).
if [ "${CAPTURE_NET:-1}" != "0" ]; then
    NET_CAPTURE_FILE=${NET_CAPTURE_FILE:-/app/work/_net_capture.txt}
    echo "[+] Network capture enabled - tcpdump -> ${NET_CAPTURE_FILE}"
    mkdir -p "$(dirname "${NET_CAPTURE_FILE}")"
    (tcpdump -i eth0 -nn -s 0 -A 2>/dev/null > "${NET_CAPTURE_FILE}") &
fi

# The emulator's adb listens on 127.0.0.1:5555. Expose it on the container's
# docker-network IP so the analyzer can reach it as <name>:5555. Binding to
# the eth0 IP (not 0.0.0.0) avoids clashing with the emulator's localhost port.
HOST_IP=$(hostname -I | awk '{print $1}')
echo "[*] Exposing adb on ${HOST_IP}:5555"
socat tcp-listen:5555,bind=${HOST_IP},fork,reuseaddr tcp:127.0.0.1:5555 &

echo "[*] Waiting for device..."
BOOT_TIMEOUT=1500   # generous for slow software emulation
BOOT_START=$(date +%s)
adb wait-for-device || true

while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - BOOT_START))
    if [ "${ELAPSED}" -gt "${BOOT_TIMEOUT}" ]; then
        echo "[!] Emulator failed to boot within ${BOOT_TIMEOUT}s." >&2
        echo "    Check the ROM logs above. Container stays up for docker logs." >&2
        tail -f /dev/null
    fi
    echo "[*] still booting... (${ELAPSED}s)"
    sleep 5
done

echo "[+] Emulator fully booted and adb ready on :5555"
tail -f /dev/null