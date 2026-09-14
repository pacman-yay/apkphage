#!/usr/bin/env bash
#
# Docker-only static analysis + optional AI summary, one command.
#
# 1. Builds/refreshes the apk-analyzer image (incremental docker build - this
#    also fixes stale-image bugs automatically).
# 2. Runs the static stage container with --network none, APKs read-only.
# 3. Fixes output ownership (container runs as root).
# 4. If GROQ_API_KEY is set, runs the host-side Groq summarizer.
#
# Usage:
#   export GROQ_API_KEY=<your-key>   # optional; enables AI stage
#   ./run_analysis.sh [samples_dir]    # default ./samples
#
# Example:
#   ./run_analysis.sh samples1
#
set -euo pipefail
cd "$(dirname "$0")"

SAMPLES_DIR="${1:-./samples}"
WORK_DIR="./work"

if [ ! -d "$SAMPLES_DIR" ] || ! compgen -G "$SAMPLES_DIR/*.apk" > /dev/null; then
    echo "[-] No .apk files found in $SAMPLES_DIR/ - drop your sample(s) there first." >&2
    exit 1
fi

echo "[*] Building image (incremental)..."
docker build -t apk-analyzer .

mkdir -p "$WORK_DIR"

echo "[*] Running static analysis on $SAMPLES_DIR/ with --network none..."
docker run --rm \
    --network none \
    -v "$(pwd)/$SAMPLES_DIR:/app/samples:ro" \
    -v "$(pwd)/$WORK_DIR:/app/work" \
    apk-analyzer

# Container runs as root -> return output ownership to the host user so the
# host-side AI stage and you can write reports.
if command -v sudo > /dev/null 2>&1; then
    sudo chown -R "$(id -u):$(id -g)" "$WORK_DIR" 2>/dev/null || true
fi

echo "[+] Static analysis done:"
find "$WORK_DIR" -name report.json -print

# Host-side AI stage (Groq) - automatic when a key is present.
if [ -n "${GROQ_API_KEY:-}" ]; then
    echo ""
    echo "[*] GROQ_API_KEY present - running AI summarization..."
    ./run_ai_summaries.sh
else
    echo ""
    echo "[*] AI stage skipped (no GROQ_API_KEY). For Groq summaries:"
    echo "    export GROQ_API_KEY=<your-key>"
    echo "    ./run_analysis.sh ${1:-./samples}"
fi