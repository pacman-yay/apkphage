#!/usr/bin/env bash
#
# Host-side AI summarizer for apk-phage.
#
# Runs OUTSIDE the --network none container (which can't reach an LLM API).
# Reads a work/<SampleName>/llm_stage.json, calls Groq via ai_summarizer.py,
# prints per-file + final summaries to the terminal, and merges the structured
# LLM output into work/<SampleName>/report.json.
#
# One-time setup is automatic: creates ./.venv and installs groq.
#
# Usage:
#   export GROQ_API_KEY=<your-key>
#   ./run_ai_summaries.sh                          # first llm_stage.json under ./work/
#   ./run_ai_summaries.sh work/RTO_Challan/llm_stage.json
#
set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${GROQ_API_KEY:-}" ]; then
    echo "[-] GROQ_API_KEY is not set. Export it first:" >&2
    echo "    export GROQ_API_KEY=<your-key>" >&2
    exit 1
fi

STAGE="${1:-}"
if [ -z "$STAGE" ]; then
    STAGE="$(find work -name llm_stage.json 2>/dev/null | head -n1 || true)"
fi
if [ -z "$STAGE" ] || [ ! -f "$STAGE" ]; then
    echo "[-] No llm_stage.json found. Run ./run_analysis.sh samples1 first." >&2
    exit 1
fi

# One-time venv setup (Kali/system Python is PEP 668 externally-managed).
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Setting up .venv and installing groq (one-time)..."
    python3 -m venv .venv
    .venv/bin/pip install -q groq
fi
PYTHON=".venv/bin/python"
if ! "$PYTHON" -c "import groq" 2>/dev/null; then
    echo "[*] Installing groq into .venv..."
    .venv/bin/pip install -q groq
fi

echo "[*] Summarizing $(basename "$(dirname "$STAGE")") via Groq..."
"$PYTHON" ai_summarizer.py "$STAGE"
