import math
import os
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Known magic bytes for common file types - if a file's entropy is high
# AND it doesn't match any known signature, flag it as "likely encrypted/packed"
MAGIC_BYTES = {
    b"PK\x03\x04": "zip/apk/jar",
    b"\x89PNG": "png",
    b"dex\n": "dex",
    b"\x1f\x8b": "gzip",
    b"\xff\xd8\xff": "jpeg",
}


def identify_file_type(data: bytes) -> str:
    for magic, name in MAGIC_BYTES.items():
        if data.startswith(magic):
            return name
    return "unknown"


def scan_assets(assets_dir: str, entropy_threshold: float = 7.5) -> list:
    """
    Returns a list of dicts for every file in assets/ with entropy above
    threshold AND unrecognized file type - these are the ones worth
    flagging as probable encrypted payloads (mirrors assets/116adbd0,
    assets/mpuenfad, the *.dat chunk files from the manual walkthrough).
    """
    flagged = []
    for root, _, files in os.walk(assets_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
            except Exception:
                continue

            ent = shannon_entropy(data)
            ftype = identify_file_type(data)

            if ent >= entropy_threshold and ftype == "unknown":
                flagged.append(
                    {
                        "path": os.path.relpath(fpath, assets_dir),
                        "size_bytes": len(data),
                        "entropy": round(ent, 3),
                        "detected_type": ftype,
                    }
                )
    return flagged
