"""Host-side AI summarizer.

Runs OUTSIDE the network-isolated container, on the Kali host. Reads the
llm_stage.json produced by the static stage, calls Groq for each flagged
file, synthesizes a structured summary, merges everything into report.json,
and prints the output to the terminal.

Usage:
    python3 ai_summarizer.py <path/to/llm_stage.json>

Requires GROQ_API_KEY to be set and groq installed on this host.
"""

import json
import os
import sys

from ai_agent import build_synthesis_prompt, parse_json_response
from example_llm_call import call_llm


def _merge_dynamic_evidence(work_dir: str, report: dict):
    """Merge the dynamic-stage evidence (frida attach grade + network capture)
    into the report so the final artifact reflects the whole pipeline."""
    evidence_path = os.path.join(work_dir, "dynamic_evidence.json")
    if os.path.exists(evidence_path):
        try:
            with open(evidence_path) as f:
                report["dynamic_evidence"] = json.load(f)
        except (OSError, ValueError):
            pass


def summarize_stage(stage_path: str):
    with open(stage_path) as f:
        stage = json.load(f)

    work_dir = os.path.dirname(stage_path)
    per_file_calls = stage["per_file_calls"]
    total = len(per_file_calls)

    per_file_summaries = []
    failed = 0
    for i, call in enumerate(per_file_calls, 1):
        print(f"[+] [{i}/{total}] Summarizing {call['file']} ...", flush=True)
        try:
            summary = call_llm(call["prompt"])
            per_file_summaries.append({"file": call["file"], "summary": summary})
            print(f"--- {call['file']} ---")
            print(summary)
            print()
        except Exception as e:
            failed += 1
            print(f"    [!] Failed: {e.__class__.__name__}: {e}", flush=True)
            per_file_summaries.append(
                {
                    "file": call["file"],
                    "summary": f"[LLM ERROR: {e.__class__.__name__}]",
                }
            )
            continue

    if failed:
        print(
            f"\n[!] {failed}/{total} files failed "
            "(transient API errors). Continuing with partial results.\n"
        )

    print("[+] Synthesizing final structured report ...", flush=True)
    prompt = build_synthesis_prompt(
        stage["manifest_findings"],
        stage.get("entropy_findings", []),
        per_file_summaries,
        stage.get("trust_facts", {}),
        stage.get("yara_findings", []),
    )
    try:
        raw = call_llm(prompt)
        synthesis = parse_json_response(raw)
    except Exception as e:
        print(f"[-] Synthesis failed: {e.__class__.__name__}: {e}", file=sys.stderr)
        synthesis = {"error": str(e), "per_file_only": True}

    report_path = os.path.join(work_dir, "report.json")
    with open(report_path) as f:
        report = json.load(f)
    report["per_file_ai_summaries"] = per_file_summaries
    report["final_synthesis"] = synthesis
    if "trust_facts" not in report:
        report["trust_facts"] = stage.get("trust_facts", {})
    if "yara_findings" not in report:
        report["yara_findings"] = stage.get("yara_findings", [])
    _merge_dynamic_evidence(work_dir, report)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print("\n==================== FINAL SYNTHESIS ====================")
    print(json.dumps(synthesis, indent=2))
    print("=========================================================")
    print(f"[+] AI summaries merged into {report_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ai_summarizer.py <path/to/llm_stage.json>")
        sys.exit(1)
    try:
        summarize_stage(sys.argv[1])
    except Exception as e:
        print(f"[-] AI stage failed: {e}", file=sys.stderr)
        print("    Make sure GROQ_API_KEY is set and groq is installed.", file=sys.stderr)
        sys.exit(1)
