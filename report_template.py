import json
from datetime import UTC, datetime


def build_report(
    sample_name: str,
    manifest_findings: dict,
    entropy_findings: list,
    per_file_summaries: list,
    final_synthesis: str,
) -> dict:
    return {
        "sample": sample_name,
        "analyzed_at": datetime.now(UTC).isoformat(),
        "manifest_findings": manifest_findings,
        "entropy_flagged_assets": entropy_findings,
        "per_file_ai_summaries": per_file_summaries,
        "final_synthesis": final_synthesis,
    }


def write_report(report: dict, out_path: str):
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
