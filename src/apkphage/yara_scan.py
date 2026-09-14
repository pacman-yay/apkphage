"""YARA scan stage: run self-authored rules over the decoded APK.

yara-python is installed in the analyzer container; rules live in
/rules/android_malware.yar. We scan the apktool output (smali, manifest,
resources) and the jadx sources - any hit becomes a structured finding in the
report. This is deliberately separate from ai_agent's regex triage: YARA targets
byte-level/string patterns in decoded apps, including obfuscated resources.
"""

import os
import sys

try:
    import yara
except ImportError:  # pragma: no cover - container installs yara-python
    yara = None

RULES_PATH = "/app/rules/android_malware.yar"
_TARGET_DIRS = ["apktool", "jadx"]
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ttf", ".otf", ".wav")
_MAX_FILE_BYTES = 5 * 1024 * 1024  # skip huge binaries (apps, videos) - not rule targets


def _compile_rules(rules_path: str = RULES_PATH):
    if yara is None:
        return None
    if not os.path.exists(rules_path):
        return None
    try:
        return yara.compile(filepath=rules_path)
    except yara.SyntaxError as e:
        print(f"[!] YARA rules failed to compile: {e}", file=sys.stderr)
        return None


def _iter_target_files(work_dir: str):
    for d in _TARGET_DIRS:
        base = os.path.join(work_dir, d)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for name in files:
                if name.endswith(_SKIP_SUFFIXES):
                    continue
                yield os.path.join(root, name)


def scan_apk(work_dir: str, rules_path: str = RULES_PATH) -> list:
    """Scan a decoded sample tree; return [{rule, description, file, severity}]."""
    if yara is None:
        print("[!] yara-python unavailable - skipping YARA stage.", file=sys.stderr)
        return []
    rules = _compile_rules(rules_path)
    if rules is None:
        return []
    findings = []
    for path in _iter_target_files(work_dir):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if not data:
            continue
        if len(data) > _MAX_FILE_BYTES:
            continue
        for match in rules.match(data=data):
            rel = os.path.relpath(path, work_dir)
            rule = str(match.rule)
            findings.append(
                {
                    "rule": rule,
                    "file": rel,
                    "description": match.meta.get("description", ""),
                    "severity": match.meta.get("severity", "medium"),
                }
            )
    # Sort: highest severity first, rule name second.
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["rule"]))
    return findings
