# Dockerized APK Analysis Pipeline — Build Guide

Two phases:

- **Phase 1 — Static pipeline.** apktool + jadx run automatically, an entropy
  scanner flags likely-encrypted assets, an AI agent reads the flagged
  decompiled source and produces a structured report. No emulator, no
  execution of the sample. This alone reproduces everything we found
  manually in the RTO Challan sample.
- **Phase 2 — Dynamic pipeline.** Adds a Dockerized Android emulator +
  Frida for runtime confirmation, for samples that pass static triage
  and need behavioral proof. Harder, optional, and — as we saw with the
  `chk()` emulator-detection routine — not guaranteed to work against
  every sample.

Build Phase 1 fully, test it against a real sample, then decide if you
need Phase 2 at all.

---

## Phase 1 — Static Analysis Pipeline

### Project layout

```
apk-analyzer/
├── Dockerfile
├── requirements.txt
├── orchestrator.py
├── entropy_scanner.py
├── manifest_parser.py
├── ai_agent.py
├── report_template.py
└── samples/          ← mount as a volume, never bake APKs into the image
```

### 1. `Dockerfile`

```dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    unzip \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# --- apktool ---
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
      -O /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool && \
    APKTOOL_VER=$(curl -s https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d 'v') && \
    wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VER}.jar" \
      -O /usr/local/bin/apktool.jar

# --- jadx ---
RUN JADX_VER=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep tag_name | cut -d'"' -f4) && \
    wget -q "https://github.com/skylot/jadx/releases/download/${JADX_VER}/jadx-${JADX_VER#v}.zip" -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm /tmp/jadx.zip

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

COPY orchestrator.py entropy_scanner.py manifest_parser.py ai_agent.py report_template.py ./

ENTRYPOINT ["python3", "orchestrator.py"]
```

Build it:
```bash
docker build -t apk-analyzer .
```

Run it against a sample (mount your samples folder read-only, output folder writable):
```bash
docker run --rm \
  -v $(pwd)/samples:/samples:ro \
  -v $(pwd)/output:/output \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  apk-analyzer /samples/RTO_Challan.apk /output
```

### 2. `requirements.txt`

```
lxml==5.3.0
anthropic==0.39.0
```

### 3. `entropy_scanner.py`

This is the piece that automates what we did by eyeballing `unzip -l` output —
flagging files like `assets/116adbd0` and the random `.dat` blobs as likely
encrypted before anyone reads a single line of code.

```python
"""
Scans an unpacked APK's asset/resource files for high-entropy blobs —
the fingerprint of encrypted or compressed payloads hiding among normal
resources. Flags anything that doesn't look like a recognizable file type
but has entropy close to the theoretical max (8.0 bits/byte for random data).
"""

import math
import os
from collections import Counter

# Known magic bytes for common legitimate file types.
# Anything NOT matching one of these, with high entropy, is suspicious.
KNOWN_MAGIC = {
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
    b"RIFF": "webp/riff",
    b"PK\x03\x04": "zip/apk/jar",
    b"dex\n": "dex",
    b"<?xm": "xml",
    b"{\n": "json",
    b'{"': "json",
}

ENTROPY_THRESHOLD = 7.5  # out of 8.0 max; encrypted/compressed data sits ~7.9-8.0
MIN_SIZE_TO_CHECK = 64  # skip tiny files, entropy is meaningless on them


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_known_type(data: bytes) -> str | None:
    for magic, label in KNOWN_MAGIC.items():
        if data.startswith(magic):
            return label
    return None


def scan_directory(root_dir: str) -> list[dict]:
    """
    Walks the unpacked APK directory (apktool output) and returns a list of
    flagged files: high entropy + unrecognized type + suspicious naming.
    """
    flagged = []

    for dirpath, _, filenames in os.walk(root_dir):
        # Skip AndroidX/AppCompat boilerplate resource dirs — same noise
        # we learned to ignore manually in res/drawable-*, res/anim, etc.
        if any(
            seg in dirpath
            for seg in ("res/drawable", "res/anim", "res/layout", "res/color", "res/interpolator")
        ):
            continue

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue

            if size < MIN_SIZE_TO_CHECK:
                continue

            with open(fpath, "rb") as f:
                data = f.read()

            known_type = looks_like_known_type(data)
            entropy = shannon_entropy(data)

            # Naming heuristic: random-looking hex/alphanumeric filename,
            # no extension — matches assets/116adbd0, assets/lbpjafn/*.dat etc.
            name_no_ext = os.path.splitext(fname)[0]
            looks_random_name = (
                len(name_no_ext) >= 6
                and name_no_ext.isalnum()
                and not name_no_ext.isalpha()  # mixes letters+digits, not a word
            )

            suspicious = entropy >= ENTROPY_THRESHOLD and known_type is None

            if suspicious or (looks_random_name and entropy >= 6.5):
                flagged.append(
                    {
                        "path": os.path.relpath(fpath, root_dir),
                        "size": size,
                        "entropy": round(entropy, 3),
                        "recognized_type": known_type,
                        "random_looking_name": looks_random_name,
                    }
                )

    # Largest / highest-entropy first — likely payload candidates float to top
    flagged.sort(key=lambda x: (x["entropy"], x["size"]), reverse=True)
    return flagged


if __name__ == "__main__":
    import sys
    import json

    results = scan_directory(sys.argv[1])
    print(json.dumps(results, indent=2))
```

Test it standalone against the apktool output you already have:
```bash
python3 entropy_scanner.py ~/Downloads/apktool_out
```
You should see `assets/116adbd0` and the `.dat` files surface near the top.

### 4. `manifest_parser.py`

Automates reading `AndroidManifest.xml` for the exact red flags we checked
by hand — dangerous permission combos, exported components, VPN/job
service bindings, boot receivers.

```python
"""
Parses apktool's decoded AndroidManifest.xml and flags permission/component
patterns known to correlate with dropper/banking-trojan behavior.
"""

from lxml import etree

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Permission combos that, together, are a strong dropper/persistence signal —
# same combination we found in the RTO Challan manifest.
HIGH_SIGNAL_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES": "Can silently prompt-install additional APKs (dropper capability)",
    "android.permission.QUERY_ALL_PACKAGES": "Can enumerate every installed app (used for AV/security-app detection)",
    "android.permission.BIND_VPN_SERVICE": "Can intercept/redirect all device network traffic",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Can read screen content and inject input (overlay/OTP theft)",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Persists across device reboot",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "Can read all incoming notification content (OTP theft without SMS permission)",
    "com.google.android.c2dm.permission.RECEIVE": "Uses Firebase Cloud Messaging — possible push-based C2 channel",
    "android.permission.READ_SMS": "Direct SMS content theft",
    "android.permission.RECEIVE_SMS": "Direct SMS interception",
}


def parse_manifest(manifest_path: str) -> dict:
    tree = etree.parse(manifest_path)
    root = tree.getroot()

    package = root.get("package", "")

    permissions = [p.get(f"{ANDROID_NS}name") for p in root.findall("uses-permission")]

    flagged_permissions = {
        p: HIGH_SIGNAL_PERMISSIONS[p] for p in permissions if p in HIGH_SIGNAL_PERMISSIONS
    }

    app = root.find("application")
    app_class = app.get(f"{ANDROID_NS}name") if app is not None else None

    exported_components = []
    if app is not None:
        for tag in ("activity", "service", "receiver", "provider"):
            for comp in app.findall(tag):
                exported = comp.get(f"{ANDROID_NS}exported")
                name = comp.get(f"{ANDROID_NS}name")
                if exported == "true":
                    exported_components.append({"type": tag, "name": name})

    queries = [q.get(f"{ANDROID_NS}name") for q in root.findall(".//queries/package")]

    return {
        "package": package,
        "custom_application_class": app_class,
        "all_permissions": permissions,
        "flagged_permissions": flagged_permissions,
        "exported_components": exported_components,
        "queried_packages": queries,  # e.g. references to a second-stage APK package
        "risk_signal_count": len(flagged_permissions),
    }


if __name__ == "__main__":
    import sys
    import json

    print(json.dumps(parse_manifest(sys.argv[1]), indent=2))
```

Test standalone:
```bash
python3 manifest_parser.py ~/Downloads/apktool_out/AndroidManifest.xml
```

### 5. `ai_agent.py`

This is the triage + summarization stage. Two-step design, same reasoning
we used manually: **grep for high-signal patterns first**, only send the
matching files to the LLM (token limits, and it keeps the agent focused),
then run one synthesis pass over all the per-file findings.

```python
"""
AI agent stage: greps decompiled source for high-signal patterns, sends
only the matching files to an LLM for per-file analysis, then synthesizes
a final report from all findings.
"""

import os
import re
import json
from anthropic import Anthropic

client = Anthropic()  # reads ANTHROPIC_API_KEY from env

# Same keyword set we manually searched for in jadx-gui this session.
TRIAGE_PATTERNS = [
    r"\bCipher\b",
    r"\bVpnService\b",
    r"\bAccessibilityService\b",
    r"\bNotificationListenerService\b",
    r"DexClassLoader|BaseDexClassLoader",
    r"getDeclaredField|setAccessible|getDeclaredMethod",
    r"SmsManager|sendTextMessage|content://sms",
    r"getDeviceId|getSimSerialNumber|getLine1Number",
    r"Base64\.decode",
    r"okhttp3|HttpURLConnection|DatagramSocket",
    r"setHiddenApiExemptions",
]

TRIAGE_REGEX = re.compile("|".join(TRIAGE_PATTERNS))

PER_FILE_PROMPT = """You are a mobile malware reverse engineer reviewing decompiled \
Android Java source from a suspected malicious APK. Analyze the following file.

Respond in this exact structure:
1. PURPOSE: one sentence, what this class does.
2. TECHNIQUES: bullet list of any evasion, obfuscation, persistence, data-theft, \
or C2 techniques present. Be specific (name the API/pattern).
3. IOCS: any hardcoded domains, IPs, URLs, cryptographic keys/IVs, or package names. \
List "none found" if none.
4. MITRE_ATTACK_MOBILE: relevant technique IDs if applicable (e.g. T1406, T1437), \
or "none clearly applicable".

File path: {path}

```java
{content}
```
"""

SYNTHESIS_PROMPT = """You are producing a final incident-style summary for a malware \
analyst who ran automated static analysis on an Android APK. Below are per-file \
findings from the flagged, highest-signal decompiled classes. Synthesize them into:

1. OVERALL VERDICT: benign / suspicious / malicious, with one-sentence justification.
2. MALWARE FAMILY GUESS: if the behavior matches a known family/pattern, note it, \
otherwise say "unclassified".
3. KEY CAPABILITIES: consolidated bullet list across all files.
4. ALL IOCS: consolidated, deduplicated list of domains/IPs/keys/package names.
5. RECOMMENDED NEXT STEPS: what a human analyst should verify manually or via \
dynamic analysis.

Per-file findings:
{findings}
"""


def find_flagged_files(source_dir: str, max_files: int = 25) -> list[str]:
    """Walk decompiled Java source, return paths matching triage patterns."""
    flagged = []
    for dirpath, _, filenames in os.walk(source_dir):
        for fname in filenames:
            if not fname.endswith(".java"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            if TRIAGE_REGEX.search(content):
                flagged.append(fpath)
    # Cap it — if a payload has hundreds of matching classes, prioritizing
    # matters more than exhaustiveness. Sort by file size descending as a
    # crude proxy for "more logic packed in here."
    flagged.sort(key=lambda p: os.path.getsize(p), reverse=True)
    return flagged[:max_files]


def analyze_file(path: str, source_dir: str) -> dict:
    with open(path, "r", errors="ignore") as f:
        content = f.read()

    # Truncate very large files to keep per-call cost sane.
    if len(content) > 12000:
        content = content[:12000] + "\n... [TRUNCATED]"

    rel_path = os.path.relpath(path, source_dir)
    prompt = PER_FILE_PROMPT.format(path=rel_path, content=content)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(block.text for block in response.content if block.type == "text")
    return {"file": rel_path, "analysis": text}


def synthesize(per_file_results: list[dict]) -> str:
    findings_blob = "\n\n---\n\n".join(
        f"FILE: {r['file']}\n{r['analysis']}" for r in per_file_results
    )
    prompt = SYNTHESIS_PROMPT.format(findings=findings_blob)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def run_ai_agent(source_dir: str) -> dict:
    flagged_files = find_flagged_files(source_dir)
    per_file_results = [analyze_file(p, source_dir) for p in flagged_files]
    final_summary = synthesize(per_file_results) if per_file_results else \
        "No high-signal patterns found in decompiled source."

    return {
        "flagged_file_count": len(flagged_files),
        "per_file_results": per_file_results,
        "final_summary": final_summary,
    }


if __name__ == "__main__":
    import sys
    result = run_ai_agent(sys.argv[1])
    print(json.dumps(result, indent=2))
```

Test standalone (needs `ANTHROPIC_API_KEY` set):
```bash
export ANTHROPIC_API_KEY=your_key_here
python3 ai_agent.py ~/Downloads/jadx_out/sources
```

### 6. `report_template.py`

```python
"""Combines all three stages into one human-readable Markdown report."""

from datetime import datetime, timezone


def build_report(
    apk_name: str, manifest_data: dict, entropy_flags: list[dict], ai_results: dict
) -> str:
    lines = []
    lines.append(f"# APK Analysis Report: {apk_name}")
    lines.append(f"_Generated {datetime.now(timezone.utc).isoformat()}_\n")

    lines.append("## Manifest Findings")
    lines.append(f"- Package: `{manifest_data['package']}`")
    lines.append(f"- Custom Application class: `{manifest_data['custom_application_class']}`")
    lines.append(f"- Risk signal count: **{manifest_data['risk_signal_count']}**\n")

    if manifest_data["flagged_permissions"]:
        lines.append("### Flagged Permissions")
        for perm, reason in manifest_data["flagged_permissions"].items():
            lines.append(f"- `{perm}` — {reason}")
        lines.append("")

    if manifest_data["queried_packages"]:
        lines.append("### Referenced External Packages")
        for pkg in manifest_data["queried_packages"]:
            lines.append(f"- `{pkg}` (possible second-stage payload)")
        lines.append("")

    lines.append("## Entropy Scan — Suspicious Assets")
    if entropy_flags:
        lines.append("| Path | Size | Entropy | Recognized Type |")
        lines.append("|---|---|---|---|")
        for f in entropy_flags[:20]:
            lines.append(
                f"| `{f['path']}` | {f['size']} | {f['entropy']} | "
                f"{f['recognized_type'] or 'unknown'} |"
            )
    else:
        lines.append("No high-entropy unrecognized files found.")
    lines.append("")

    lines.append("## AI Agent — Final Synthesis")
    lines.append(ai_results["final_summary"])
    lines.append("")

    lines.append(
        f"## AI Agent — Per-File Detail ({ai_results['flagged_file_count']} files flagged)"
    )
    for r in ai_results["per_file_results"]:
        lines.append(f"### `{r['file']}`")
        lines.append(r["analysis"])
        lines.append("")

    return "\n".join(lines)
```

### 7. `orchestrator.py`

Ties everything together — this is the container's entrypoint.

```python
"""
Orchestrator: unpacks the APK with apktool + jadx, runs the entropy scanner
and manifest parser, feeds flagged source to the AI agent, writes the report.

Usage: python3 orchestrator.py <path_to_apk> <output_dir>
"""

import os
import sys
import subprocess

from entropy_scanner import scan_directory
from manifest_parser import parse_manifest
from ai_agent import run_ai_agent
from report_template import build_report


def run(apk_path: str, output_dir: str):
    apk_name = os.path.basename(apk_path)
    apktool_out = os.path.join(output_dir, "apktool_out")
    jadx_out = os.path.join(output_dir, "jadx_out")

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Running apktool on {apk_name} ...")
    subprocess.run(
        ["apktool", "d", "-f", apk_path, "-o", apktool_out],
        check=True,
    )

    print(f"[*] Running jadx on {apk_name} ...")
    subprocess.run(
        ["jadx", "-d", jadx_out, apk_path],
        check=False,  # jadx exits non-zero on partial failures (encrypted
        # assets it can't parse) — same noise we saw manually.
        # We still want the sources it DID produce.
    )

    print("[*] Parsing manifest ...")
    manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")
    manifest_data = parse_manifest(manifest_path)

    print("[*] Scanning for high-entropy assets ...")
    entropy_flags = scan_directory(apktool_out)

    print("[*] Running AI agent on decompiled source ...")
    sources_dir = os.path.join(jadx_out, "sources")
    ai_results = run_ai_agent(sources_dir)

    print("[*] Building report ...")
    report_md = build_report(apk_name, manifest_data, entropy_flags, ai_results)

    report_path = os.path.join(output_dir, "report.md")
    with open(report_path, "w") as f:
        f.write(report_md)

    print(f"[+] Done. Report written to {report_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: orchestrator.py <apk_path> <output_dir>")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2])
```

### Running Phase 1 end to end

```bash
mkdir -p samples output
cp ~/Downloads/RTO_Challan.apk samples/

docker build -t apk-analyzer .

docker run --rm \
  -v $(pwd)/samples:/samples:ro \
  -v $(pwd)/output:/output \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  apk-analyzer /samples/RTO_Challan.apk /output

cat output/report.md
```

At this point you should get a Markdown report that independently reproduces
what we found manually: the flagged permissions, the high-entropy
`assets/116adbd0` and `.dat` blobs, and an AI summary describing the loader,
the VPN/DNS-filter behavior, and IOCs — without ever running the sample.

---

## Phase 2 — Dynamic Analysis (Emulator + Frida)

Only build this once Phase 1 works reliably. It's heavier infra, and — as
we found firsthand with this exact sample's `chk()` method — some malware
will simply refuse to activate inside a stock emulator. Treat Phase 2 as
"best-effort confirmation," not a replacement for Phase 1.

### Design

```
apk-analyzer-dynamic/
├── docker-compose.yml
├── emulator/          (uses a prebuilt Android-in-Docker image)
├── frida_hooks/
│   └── generic_hooks.js
└── dynamic_runner.py
```

### 1. `docker-compose.yml`

Uses `budtmo/docker-android` as the emulator image (actively maintained,
supports noVNC + ADB over the network). Requires `/dev/kvm` on the host
for hardware acceleration — without it, boot times are extremely slow.

```yaml
version: "3.8"
services:
  android-emulator:
    image: budtmo/docker-android:emulator_11.0
    privileged: true
    devices:
      - /dev/kvm
    environment:
      - EMULATOR_DEVICE=Samsung Galaxy S10
      - WEB_VNC=true
    ports:
      - "6080:6080"   # noVNC web viewer
      - "5555:5555"   # ADB
    volumes:
      - ./samples:/samples:ro

  frida-runner:
    build: ./frida_hooks
    depends_on:
      - android-emulator
    volumes:
      - ./frida_hooks:/hooks
      - ./output:/output
```

Bring it up:
```bash
docker compose up -d android-emulator
# wait for boot — check http://localhost:6080 to watch it visually
adb connect localhost:5555
```

### 2. Installing the sample (still requires care)

Even in an isolated Dockerized emulator, don't casually `adb install` an
unknown sample without the network already contained. Confirm the
emulator's outbound network is routed through your isolated segment
(FakeNet-NG/INetSim container) **before** installing:

```bash
adb -s localhost:5555 install /samples/RTO_Challan.apk
```

### 3. `frida_hooks/generic_hooks.js`

A starting hook script — matches the specific behaviors we identified
manually this session (AES decryption calls, VPN service, DNS handling).

```javascript
// Generic hooks for encrypted-payload droppers and VPN-based DNS filtering,
// modeled on the RTO_Challan.apk sample analyzed manually.

Java.perform(function () {

    // Hook Cipher.doFinal to catch runtime decryption — dumps whatever the
    // sample decrypts, even if the key/IV weren't found statically.
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);
        console.log("[Cipher.doFinal] input len=" + input.length +
                     " output len=" + result.length);
        // Dump first 64 bytes of output as hex for quick inspection
        var preview = "";
        for (var i = 0; i < Math.min(64, result.length); i++) {
            preview += ("0" + (result[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[Cipher.doFinal] output preview: " + preview);
        return result;
    };

    // Hook AssetManager.open to see exactly which asset files get read
    // at runtime — confirms which blob is the real payload.
    var AssetManager = Java.use("android.content.res.AssetManager");
    AssetManager.open.overload("java.lang.String").implementation = function (name) {
        console.log("[AssetManager.open] " + name);
        return this.open(name);
    };

    // Hook VpnService.Builder.establish to confirm VPN tunnel setup.
    try {
        var VpnBuilder = Java.use("android.net.VpnService$Builder");
        VpnBuilder.establish.implementation = function () {
            console.log("[VpnService.Builder.establish] called");
            return this.establish();
        };
    } catch (e) {
        console.log("[!] VpnService.Builder hook failed: " + e);
    }

    // Hook DatagramSocket.send to see every UDP packet sent — this is how
    // the DNS-filtering behavior we found manually can be confirmed live.
    var DatagramSocket = Java.use("java.net.DatagramSocket");
    DatagramSocket.send.overload("java.net.DatagramPacket").implementation = function (packet) {
        var addr = packet.getAddress().getHostAddress();
        var port = packet.getPort();
        console.log("[DatagramSocket.send] -> " + addr + ":" + port);
        return this.send(packet);
    };

    console.log("[+] Hooks installed.");
});
```

### 4. `dynamic_runner.py`

```python
"""
Launches the sample on the connected emulator with Frida attached,
running the generic hook script, and captures output for a fixed window.
"""

import subprocess
import time
import sys

PACKAGE_NAME = sys.argv[1] if len(sys.argv) > 1 else "com.ytzhypq.nchzal.kdpn"
RUN_SECONDS = 60


def main():
    print(f"[*] Spawning {PACKAGE_NAME} under Frida ...")
    proc = subprocess.Popen(
        ["frida", "-U", "-f", PACKAGE_NAME, "-l", "/hooks/generic_hooks.js", "--no-pause"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    start = time.time()
    log_lines = []
    while time.time() - start < RUN_SECONDS:
        line = proc.stdout.readline()
        if line:
            print(line, end="")
            log_lines.append(line)

    proc.terminate()

    with open("/output/frida_log.txt", "w") as f:
        f.writelines(log_lines)
    print("\n[+] Dynamic run complete. Log saved to /output/frida_log.txt")


if __name__ == "__main__":
    main()
```

Run it:
```bash
docker compose run frida-runner python3 dynamic_runner.py com.ytzhypq.nchzal.kdpn
```

### Known limitation — emulator detection

Recall `Cghiqeqs.chk()` checks `Build.FINGERPRINT`, `Build.HARDWARE`
(`goldfish`/`ranchu`), and `/dev/qemu_pipe`. Against this exact sample,
`docker-android`'s default emulator profile will very likely trip that
check and the payload will never decrypt/load — you'd see the
`AssetManager.open` hook fire for other assets but never for
`116adbd0`, and no VPN/DatagramSocket activity.

Two ways to work around this, roughly in order of effort:

1. **Patch `ro.kernel.qemu` and related build.prop values** on the running
   emulator via `adb shell setprop`, and rename recognizable `ro.hardware`
   strings before installing the sample. Doesn't fix `/dev/qemu_pipe`
   existing on real QEMU-based emulators.
2. **Use a physical test device or `Cuttlefish`/`Waydroid`-based container**
   with better fingerprint control — more setup, much more convincing to
   fingerprinting checks.

For this reason: treat Phase 1 (static + AI) as your primary pipeline, and
Phase 2 as a bonus you run selectively, expecting some samples to
no-op deliberately.

---

## Suggested build order

1. Get `entropy_scanner.py` and `manifest_parser.py` working standalone
   against the apktool/jadx output you already have on disk from this
   session — no Docker needed yet, just plain Python.
2. Get `ai_agent.py` working standalone the same way, with your API key
   exported locally.
3. Wire them together in `orchestrator.py`, still running locally
   (no Docker) — confirms the logic before adding container complexity.
4. Containerize with the `Dockerfile` once the local run works end to end.
5. Only then consider Phase 2.
