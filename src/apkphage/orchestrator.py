import json
import os
import queue
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

from ai_agent import build_agent_calls
from apk_trust import build_trust_facts
from entropy_scanner import scan_assets
from manifest_parser import parse_manifest
from report_template import build_report, write_report
from yara_scan import scan_apk

from apkphage.progress import Pipeline

SAMPLES_DIR = "/app/samples"
WORK_DIR = "/app/work"

# Rotating loader characters - visible "motion" so long phases never
# look frozen. Mirrors dynamic_runner's loader so output feels consistent.
_SPIN = "|/-\\"
_HEARTBEAT_EVERY = 10  # seconds between heartbeat lines while idle


class _LoaderThread(threading.Thread):
    """Animated in-place spinner proving a CPU-bound phase is alive."""

    def __init__(self, label: str):
        super().__init__(daemon=True)
        self.label = label
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        i = 0
        while not self._stop.wait(0.5):
            i += 1
            sys.stdout.write(f"\r[*] {self.label}... {_SPIN[i % 4]} ")
            sys.stdout.flush()
        # Clear the spinner line so the next [*] output starts clean.
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()


@contextmanager
def _loading(label: str):
    """Show a rotating loader while the wrapped (non-subprocess) work runs."""
    t = _LoaderThread(label)
    t.start()
    try:
        yield
    finally:
        t.stop()


def _run_streamed(args: list, label: str, status_fn=None) -> str:
    """Run a command streaming its output live, with heartbeat ticks while idle.

    Proves apktool / jadx are alive even when they emit nothing for a while
    (both can go quiet mid-file). Real output prints as-is; gaps fill with a
    rotating heartbeat. Uses a reader thread so it is portable (Windows host
    and Linux container alike)."""
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    q = queue.Queue()

    def _reader():
        for line in iter(proc.stdout.readline, ""):
            q.put(line)

    threading.Thread(target=_reader, daemon=True).start()

    start = time.time()
    last_beat = start
    out_lines = []
    while proc.poll() is None:
        try:
            line = q.get(timeout=1)
            out_lines.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
            last_beat = time.time()  # real output is a heartbeat too
        except queue.Empty:
            if time.time() - last_beat >= _HEARTBEAT_EVERY:
                elapsed = int(time.time() - start)
                char = _SPIN[elapsed % len(_SPIN)]
                status = f" | {status_fn()}" if status_fn else ""
                print(f"\r[*] {label}... ({elapsed}s) {char}{status}   ", flush=True)
                last_beat = time.time()
    # Drain any trailing output
    while not q.empty():
        out_lines.append(q.get_nowait())
    return "".join(out_lines)


def run_apktool(apk_path: str, out_dir: str):
    _run_streamed(
        ["apktool", "d", apk_path, "-o", out_dir, "-f"],
        "Running apktool (decoding resources)",
    )


def run_jadx(apk_path: str, out_dir: str):
    # non-zero exit on the encrypted-asset noise is expected - don't
    # treat it as fatal, same as we saw manually. -j 2 keeps the JVM from
    # spawning one decompile thread per core (memory hog on this box).
    _run_streamed(
        ["jadx", "-d", out_dir, "-j", "2", apk_path],
        "Running jadx (decompiling classes)",
    )


def analyze_sample(apk_path: str, pipe: Pipeline):
    sample_name = os.path.basename(apk_path)
    sample_work_dir = os.path.join(WORK_DIR, sample_name.replace(".apk", ""))
    apktool_out = os.path.join(sample_work_dir, "apktool")
    jadx_out = os.path.join(sample_work_dir, "jadx")
    os.makedirs(sample_work_dir, exist_ok=True)

    print(f"[+] Running apktool on {sample_name}...")
    with pipe.phase("apktool"):
        run_apktool(apk_path, apktool_out)

    print(f"[+] Running jadx on {sample_name}...")
    with pipe.phase("jadx"):
        run_jadx(apk_path, jadx_out)

    manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")
    print("[+] Parsing manifest...")
    with pipe.phase("manifest"):
        manifest_findings = parse_manifest(manifest_path)

    assets_dir = os.path.join(apktool_out, "assets")
    print("[+] Scanning assets for high-entropy (likely encrypted) files...")
    with pipe.phase("assets"):
        with _loading("Scanning assets"):
            entropy_findings = scan_assets(assets_dir) if os.path.isdir(assets_dir) else []
    print(f"[+] {len(entropy_findings)} high-entropy asset(s) flagged.")

    print("[+] Extracting APK trust facts (signer, SDK levels, packers)...")
    with pipe.phase("trust"):
        with _loading("Extracting trust facts"):
            trust_facts = build_trust_facts(apk_path, apktool_out)
    print(
        f"[+] Trust facts: signer={bool(trust_facts.get('signer'))} "
        f"sdk={trust_facts.get('sdk_levels', {})} packers={trust_facts.get('packers', [])}"
    )

    print("[+] Running YARA rules over decoded app...")
    with pipe.phase("yara"):
        with _loading("Running YARA rules"):
            yara_findings = scan_apk(sample_work_dir)
    print(f"[+] {len(yara_findings)} YARA rule hit(s).")

    sources_dir = os.path.join(jadx_out, "sources")
    print("[+] Triaging decompiled source for suspicious patterns...")
    with pipe.phase("triage"):
        with _loading("Triaging decompiled source"):
            per_file_calls = build_agent_calls(sources_dir)
    print(f"[+] {len(per_file_calls)} files flagged for AI review.")

    # Timer: the container runs --network none, so it can never reach an LLM
    # API. Stage the prompts (+ findings) to disk instead; run
    # ./run_ai_summaries.sh on the HOST to summarize and merge into
    # report.json. This keeps the malicious APK network-isolated.
    stage_path = os.path.join(sample_work_dir, "llm_stage.json")
    with pipe.phase("stage"):
        with open(stage_path, "w") as f:
            json.dump(
                {
                    "sample": sample_name,
                    "manifest_findings": manifest_findings,
                    "trust_facts": trust_facts,
                    "yara_findings": yara_findings,
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
        trust_facts,
        yara_findings,
    )
    report_path = os.path.join(sample_work_dir, "report.json")
    write_report(report, report_path)
    print(f"[+] Report written to {report_path}")


def run_dynamic_stage(apk_path: str, manifest_findings: dict, sample_work_dir: str, pipe: Pipeline):
    from apkphage.dynamic.dynamic_runner import (
        get_package_name,
        install_apk,
        run_frida_hooks,
        wait_for_device,
    )

    print("[+] Waiting for emulator...")
    with pipe.phase("emulator"):
        wait_for_device()

    print("[+] Installing APK on emulator...")
    with pipe.phase("install"):
        install_apk(apk_path)

    package_name = get_package_name(manifest_findings)

    print(f"[+] Launching {package_name} and attaching Frida hooks...")
    with pipe.phase("frida"):
        frida_result = run_frida_hooks(
            package_name,
            "/app/dynamic/frida_hooks.js",
            duration_seconds=180,
        )

    log_path = os.path.join(sample_work_dir, "frida_log.txt")
    with open(log_path, "w") as f:
        f.writelines(frida_result["log"])
    if frida_result["attached"]:
        print(f"[+] Frida attached (attempt {frida_result['attempts']}) - log in {log_path}")
    else:
        print(
            f"[-] Frida never attached after {frida_result['attempts']} attempts - log in {log_path}"
        )

    # Collect whatever raw network traffic the sandbox captured (if any) and
    # persist the graded evidence next to the frida log for the host-side
    # report merge.
    captured = os.path.join(WORK_DIR, "_net_capture.txt")
    if os.path.exists(captured):
        net_path = os.path.join(sample_work_dir, "network_capture.txt")
        try:
            os.replace(captured, net_path)
            print(f"[+] Network capture saved to {net_path}")
        except OSError:
            pass

    # Fakenet logs every DNS query + HTTP/HTTPS/proxy request it answered for
    # the sample; harvest it into the sample dir alongside the tcpdump.capture.
    fakenet_log = os.path.join(WORK_DIR, "fakenet_requests.log")
    if os.path.exists(fakenet_log):
        flat = os.path.join(sample_work_dir, "fakenet_requests.log")
        try:
            os.replace(fakenet_log, flat)
            print(f"[+] Fakenet request log saved to {flat}")
        except OSError:
            pass

    evidence = {
        "frida": {
            "attached": frida_result["attached"],
            "attempts": frida_result["attempts"],
            "quit_marker": frida_result["quit_marker"],
            "output_lines": frida_result["output_lines"],
            "log_file": "frida_log.txt",
        },
        "network_capture": "network_capture.txt"
        if os.path.exists(os.path.join(sample_work_dir, "network_capture.txt"))
        else None,
        "fakenet_requests": "fakenet_requests.log"
        if os.path.exists(os.path.join(sample_work_dir, "fakenet_requests.log"))
        else None,
    }
    evidence_path = os.path.join(sample_work_dir, "dynamic_evidence.json")
    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"[+] Dynamic evidence written to {evidence_path}")


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
        pipe = Pipeline(sample_work_dir, dynamic=dynamic)
        try:
            analyze_sample(apk_path, pipe)
            if dynamic:
                manifest_path = os.path.join(sample_work_dir, "apktool", "AndroidManifest.xml")
                manifest_findings = parse_manifest(manifest_path)
                run_dynamic_stage(apk_path, manifest_findings, sample_work_dir, pipe)
        finally:
            pipe.close()


if __name__ == "__main__":
    main()
