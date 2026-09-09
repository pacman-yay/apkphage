import json
import os
import subprocess
import sys

from ai_agent import build_agent_calls
from entropy_scanner import scan_assets
from manifest_parser import parse_manifest
from report_template import build_report, write_report

SAMPLES_DIR = "/app/samples"
WORK_DIR = "/app/work"


def run_apktool(apk_path: str, out_dir: str):
    subprocess.run(
        ["apktool", "d", apk_path, "-o", out_dir, "-f"],
        check=True,
    )


def run_jadx(apk_path: str, out_dir: str):
    # non-zero exit on the encrypted-asset noise is expected - don't
    # treat it as fatal, same as we saw manually
    subprocess.run(["jadx", "-d", out_dir, apk_path])


def analyze_sample(apk_path: str):
    sample_name = os.path.basename(apk_path)
    sample_work_dir = os.path.join(WORK_DIR, sample_name.replace(".apk", ""))
    apktool_out = os.path.join(sample_work_dir, "apktool")
    jadx_out = os.path.join(sample_work_dir, "jadx")
    os.makedirs(sample_work_dir, exist_ok=True)

    print(f"[+] Running apktool on {sample_name}...")
    run_apktool(apk_path, apktool_out)

    print(f"[+] Running jadx on {sample_name}...")
    run_jadx(apk_path, jadx_out)

    manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")
    print("[+] Parsing manifest...")
    manifest_findings = parse_manifest(manifest_path)

    assets_dir = os.path.join(apktool_out, "assets")
    print("[+] Scanning assets for high-entropy (likely encrypted) files...")
    entropy_findings = scan_assets(assets_dir) if os.path.isdir(assets_dir) else []

    sources_dir = os.path.join(jadx_out, "sources")
    print("[+] Triaging decompiled source for suspicious patterns...")
    per_file_calls = build_agent_calls(sources_dir)

    print(f"[+] {len(per_file_calls)} files flagged for AI review.")

    # Timer: the container runs --network none, so it can never reach an LLM
    # API. Stage the prompts (+ findings) to disk instead; run
    # ./run_ai_summaries.sh on the HOST to summarize and merge into
    # report.json. This keeps the malicious APK network-isolated.
    stage_path = os.path.join(sample_work_dir, "llm_stage.json")
    with open(stage_path, "w") as f:
        json.dump(
            {
                "sample": sample_name,
                "manifest_findings": manifest_findings,
                "entropy_findings": entropy_findings,
                "per_file_calls": per_file_calls,
            },
            f,
            indent=2,
        )
    print(f"[+] AI stage written to {stage_path}")
    print("    (run ./run_ai_summaries.sh on the host to generate summaries)")

    final_synthesis = "Pending AI stage - run ./run_ai_summaries.sh to summarize."
    per_file_summaries = []  # populated host-side by ai_summarizer.py

    report = build_report(
        sample_name,
        manifest_findings,
        entropy_findings,
        per_file_summaries,
        final_synthesis,
    )
    report_path = os.path.join(sample_work_dir, "report.json")
    write_report(report, report_path)
    print(f"[+] Report written to {report_path}")


def run_dynamic_stage(apk_path: str, manifest_findings: dict, sample_work_dir: str):
    from dynamic.dynamic_runner import (
        get_package_name,
        install_apk,
        run_frida_hooks,
        wait_for_device,
    )

    print("[+] Waiting for emulator...")
    wait_for_device()

    print("[+] Installing APK on emulator...")
    install_apk(apk_path)

    package_name = get_package_name(manifest_findings)

    print(f"[+] Launching {package_name} and attaching Frida hooks...")
    frida_log = run_frida_hooks(
        package_name,
        "/app/dynamic/frida_hooks.js",
        duration_seconds=180,
    )

    log_path = os.path.join(sample_work_dir, "frida_log.txt")
    with open(log_path, "w") as f:
        f.writelines(frida_log)
    print(f"[+] Frida log written to {log_path}")


def main():
    dynamic = "--dynamic" in sys.argv

    apks = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".apk")]
    if not apks:
        print("No .apk files found in /app/samples")
        sys.exit(1)

    os.makedirs(WORK_DIR, exist_ok=True)
    for apk in apks:
        apk_path = os.path.join(SAMPLES_DIR, apk)
        sample_work_dir = os.path.join(WORK_DIR, apk.replace(".apk", ""))
        analyze_sample(apk_path)
        if dynamic:
            manifest_path = os.path.join(sample_work_dir, "apktool", "AndroidManifest.xml")
            manifest_findings = parse_manifest(manifest_path)
            run_dynamic_stage(apk_path, manifest_findings, sample_work_dir)


if __name__ == "__main__":
    main()
