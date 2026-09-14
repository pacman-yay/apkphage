# APKPhage — Dockerized Android APK Static-Analysis Pipeline

Static analysis pipeline for (suspected malicious) Android APKs. Unpacks with
apktool + jadx, flags high-risk manifest permission/component patterns, entropy-
scans `assets/` for likely-encrypted payloads, and triages decompiled source for
suspicious patterns. Outputs a JSON report per sample.

**Static analysis is fully containerized; the AI stage runs host-side.** The
container runs with `--network none`, so it never calls an LLM API — it stages
the flagged-file prompts to `work/<Sample>/llm_stage.json`. You then run
`./run_ai_summaries.sh` on the VM host (which has internet) to summarize via
Groq and merge a structured `final_synthesis` into `report.json`.

## Build

```bash
docker build -t apk-analyzer .
```

## Interactive CLI

The easiest way to use APKPhage is via the interactive Python CLI. It automatically sets up its own environment and provides menus for all operations:

```bash
python cli.py
```

## Run manually

```bash
mkdir -p samples work
cp <YourSample>.apk samples/

docker run --rm \
    --network none \
    -v "$(pwd)/samples:/app/samples:ro" \
    -v "$(pwd)/work:/app/work" \
    apk-analyzer
```

Or use the wrapper (builds on first run, accepts a samples dir, runs the AI
stage automatically when `GROQ_API_KEY` is set):

```bash
./run_analysis.sh samples1
```

- Samples are mounted **read-only** (`:ro`) — the container cannot modify them.
- `--network none` — the container has no network interface at all. Even a
  parser exploit (apktool/jadx) has no route to phone home. **Do not run
  without this flag.**
- The pipeline analyzes every `.apk` in `samples/` and writes
  `work/<SampleName>/report.json` plus `work/<SampleName>/llm_stage.json`.

Intended use: on a disposable/isolated host (e.g. a VM) — this container runs
malware analysis tooling and should not live on a machine that matters to you.

## AI stage (host-side Groq)

```bash
pip install groq
export GROQ_API_KEY=<your-key>
./run_ai_summaries.sh                      # uses first llm_stage.json under ./work/
```

Prints each per-file summary + the final synthesis to the terminal, then merges
into `work/<Sample>/report.json`.

## Output

`work/<SampleName>/report.json` (after the AI stage):

```json
{
  "sample": "...",
  "analyzed_at": "...",
  "manifest_findings": { "package": "...", "permissions": [...], "declared_component_permissions": [...], "high_risk_permission_combos": [...], "suspicious_components": [...], "referenced_external_packages": [...] },
  "entropy_flagged_assets": [ { "path": "...", "size_bytes": ..., "entropy": ..., "detected_type": "..." } ],
  "per_file_ai_summaries": [ { "file": "sources/...java", "summary": "..." } ],
  "final_synthesis": {
    "executive_summary": "...",
    "malware_classification": ["..."],
    "key_capabilities": ["..."],
    "iocs": ["..."],
    "recommended_next_steps": ["..."]
  }
}
```

## Phases

- **Phase 1 (this image):** static analysis only, fully containerized, no
  emulator.
- **Phase 2 (separate):** dynamic analysis — emulator + Frida + fakenet via
  `docker-compose.yml` on an `internal: true` network. Not part of this MVP
  image; see `APK_ANALYZER_BUILD_GUIDE.md`.