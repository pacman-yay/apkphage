"""APK trust facts: who signed it, what SDK levels it targets, and whether it
carries a known packer/obfuscator runtime.

Runs inside the static-stage container (network none). keytool ships with the
openjdk-17-jdk already installed; app distribution certs are read straight off
the APK's signature block via `keytool -printcert -jarfile`.
"""

import os
import re
import subprocess

# Signer cert fields (keytool -printcert output) worth surfacing in the report.
_CERT_FIELDS = [
    ("owner", r"^Owner:\s*(.+)$"),
    ("issuer", r"^Issuer:\s*(.+)$"),
    ("serial", r"^Serial number:\s*(.+)$"),
    ("sha256", r"^SHA256:\s*([0-9A-F:]+)$"),
    ("sha1", r"^SHA1:\s*([0-9A-F:]+)$"),
    ("valid_from", r"^Valid from:\s*(.+)$"),
]

# Well-known Android packer/obfuscator runtimes and the .so / asset names that
# pin them. Detection is signature-based (file names only) - a real malware
# lab would also check string content, but these lib names are distinctive.
PACKER_MARKERS = {
    "Qihoo 360 (jiagu)": ["libjiagu.so", "libjiagu_x86.so", "libjiagu_64.so"],
    "Bangcle (DexHelper)": [
        "libDexHelper.so",
        "libDexHelper-x86.so",
        "libdexhelper.so",
    ],
    "Tencent Legu": ["libshella-4.7.8.so", "libshella-4.8.0.so", "libshellx.so", "libBugly.so"],
    "ijiami (Shield)": ["libjiagu.so", "libexec.so", "libexecmain.so"],
    "Naga (verify)": ["libverify.so", "libVShell.so", "libverifyX86.so"],
    "SecNeo": ["libsecneo.so", "secneo.dat", "secdata.bin"],
    "libapkprotect (Bangcle/Ali flesh)": ["libAPKProtect.so"],
    "Tencent Legu generic": ["libsdkex.so"],
    "2C8P / Alibaba zenith": ["libsentry.so"],
}


def _run_keytool(apk_path: str) -> str:
    try:
        res = subprocess.run(
            ["keytool", "-printcert", "-jarfile", apk_path],
            capture_output=True,
            text=True,
            timeout=90,
        )
        return res.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def get_signer_facts(apk_path: str) -> dict:
    """Parse keytool output into structured cert facts. Returns empty dict on
    failure (unsigned/stub APK or keytool unavailable)."""
    out = _run_keytool(apk_path)
    facts = {}
    for key, pattern in _CERT_FIELDS:
        m = re.search(pattern, out, re.IGNORECASE)
        if m:
            facts[key] = m.group(1).strip()
    if facts:
        facts["scheme_v1_v2"] = (
            "v1/v2 signature block present" if "jar" in out.lower() else "unknown"
        )
        facts["keytool_raw_samples"] = out[:2000]
    else:
        # Empty output often means the cert line says "not found" or the APK is
        # protected (e.g. v2-only signatures are fine here; stub certs aren't).
        facts["error"] = "no certificate found (unsigned or unreadable)"
    return facts


def get_sdk_levels(apktool_out: str) -> dict:
    """Pull minSdk/targetSdk from apktool.yml (the decoded manifest summary)."""
    apktool_yml = os.path.join(apktool_out, "apktool.yml")
    sdk = {}
    try:
        with open(apktool_yml) as f:
            text = f.read()
        for key in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
            m = re.search(rf"^\s*{key}:\s*['\"]?([^'\"]+)", text, re.MULTILINE)
            if m:
                sdk[key] = m.group(1).strip()
    except OSError:
        pass
    return sdk


def get_packer_signals(apktool_out: str) -> list:
    """Walk lib/ + assets/ for known packer/obfuscator signatures."""
    hits = []
    root = os.path.join(apktool_out, "lib")
    if not os.path.isdir(root):
        root = apktool_out
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            for packer, markers in PACKER_MARKERS.items():
                if name in markers:
                    hits.append(
                        {
                            "packer": packer,
                            "file": os.path.relpath(os.path.join(dirpath, name), apktool_out),
                        }
                    )
    # Dedup by packer name, keep first file
    seen = set()
    unique = []
    for hit in hits:
        if hit["packer"] not in seen:
            seen.add(hit["packer"])
            unique.append(hit)
    return unique


def build_trust_facts(apk_path: str, apktool_out: str) -> dict:
    """Compose all trust/identity facts for one APK."""
    return {
        "signer": get_signer_facts(apk_path),
        "sdk_levels": get_sdk_levels(apktool_out),
        "packers": get_packer_signals(apktool_out),
    }
