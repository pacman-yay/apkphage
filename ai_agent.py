import glob
import json
import os
import re

# Keywords that earn a file a closer look. Drawn directly from what we
# found by hand: Cipher (AES loader), VpnService (DNS filter class),
# reflection-based ClassLoader injection, Base64+XOR string obfuscation.
TRIAGE_PATTERNS = [
    r"\bCipher\b",
    r"\bVpnService\b",
    r"\bAccessibilityService\b",
    r"\bNotificationListenerService\b",
    r"DexClassLoader|BaseDexClassLoader",
    r"getDeclaredField|setAccessible",
    r"SmsManager|sendTextMessage",
    r"Base64\.decode",
    r"getSystemService\(\"notification\"\)",
    r"\bokhttp3\b|HttpURLConnection",
]


def triage_source_tree(sources_dir: str) -> list:
    """Returns file paths whose content matches at least one triage pattern."""
    compiled = [re.compile(p) for p in TRIAGE_PATTERNS]
    flagged = []

    for java_file in glob.glob(os.path.join(sources_dir, "**", "*.java"), recursive=True):
        try:
            with open(java_file, errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        matches = [p.pattern for p in compiled if p.search(content)]
        if matches:
            flagged.append(
                {
                    "path": java_file,
                    "matched_patterns": matches,
                    "size_bytes": len(content),
                }
            )

    # Sort by number of matches descending - files hitting more patterns
    # are usually the highest-value reads (mirrors how Cghiqeqs.java and
    # MgrQrjnpicw.java stood out in the manual walkthrough)
    flagged.sort(key=lambda x: len(x["matched_patterns"]), reverse=True)
    return flagged


PER_FILE_PROMPT = """You are analyzing decompiled Java source from a suspected Android malware sample.

File: {filepath}
Matched suspicious patterns: {patterns}

Source code:
```java
{code}
```

Provide, in this exact structure:
1. PURPOSE: one sentence, what this class does
2. TECHNIQUE: which malicious technique(s) this implements (if any) - be specific (e.g. "AES-CBC decryption of a hidden asset into an in-memory DEX via reflection-based ClassLoader injection")
3. IOCS: any hardcoded domains, IPs, keys, package names found (list them verbatim, or "none")
4. ATTACK_MAPPING: relevant MITRE ATT&CK for Mobile technique ID if applicable, or "none"
5. SEVERITY: low/medium/high/critical
"""

SYNTHESIS_PROMPT = """You are producing a final malware analysis summary for an Android APK sample. \
Below are per-file findings from static analysis of the decompiled source, plus manifest analysis, plus \
entropy-flagged assets.

MANIFEST FINDINGS:
{manifest_findings}

ENTROPY-FLAGGED ASSETS (likely encrypted payloads):
{entropy_findings}

PER-FILE CODE FINDINGS:
{file_findings}

Respond with ONLY a valid JSON object. No markdown fences, no commentary, no trailing text. Use exactly these keys:
- "executive_summary": string, 2-3 sentences
- "malware_classification": list of strings (e.g. ["dropper", "banking trojan"]; use ["unclassified"] if none)
- "key_capabilities": list of strings
- "iocs": list of strings (domains, IPs, hardcoded keys, package names; empty list if none)
- "recommended_next_steps": list of strings for a human analyst
"""


def build_synthesis_prompt(
    manifest_findings: dict, entropy_findings: list, file_findings: list
) -> str:
    """Formats the synthesis prompt. Findings are dicts/lists, so serialize
    them for readable presentation to the LLM."""
    return SYNTHESIS_PROMPT.format(
        manifest_findings=json.dumps(manifest_findings, indent=2, default=str),
        entropy_findings=json.dumps(entropy_findings, indent=2, default=str),
        file_findings=json.dumps(file_findings, indent=2, default=str),
    )


def parse_json_response(raw: str) -> dict:
    """Best-effort parse of an LLM response that is supposed to be JSON.
    Strips markdown fences if present; falls back to wrapping the raw text
    under executive_summary if the model didn't comply."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    return {
        "executive_summary": raw or "",
        "malware_classification": [],
        "key_capabilities": [],
        "iocs": [],
        "recommended_next_steps": [],
    }


def build_agent_calls(sources_dir: str) -> list:
    """
    Returns per-file prompt dicts ready to send to your LLM client. This
    function deliberately doesn't call the API itself - the container that
    runs the static stage has --network none, so summarization happens
    host-side in ai_summarizer.py.
    """
    flagged_files = triage_source_tree(sources_dir)

    per_file_calls = []
    for entry in flagged_files[:20]:  # cap to avoid runaway cost on huge payloads
        with open(entry["path"], errors="ignore") as f:
            code = f.read()
        # truncate very large files - send first ~8000 chars, most loader/
        # payload classes of interest are far smaller than that anyway
        code = code[:8000]
        rel_path = os.path.relpath(entry["path"], sources_dir)
        prompt = PER_FILE_PROMPT.format(
            filepath=rel_path,
            patterns=", ".join(entry["matched_patterns"]),
            code=code,
        )
        per_file_calls.append({"prompt": prompt, "file": rel_path})

    return per_file_calls
