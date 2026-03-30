import json
import os
from pathlib import Path

def merge_check_stats(stats_files, output_file):
    merged = {
        "last_index": 0,
        "total": 0,
        "range_start": 0,
        "range_end": 60205,
        "remaining": 0,
        "languages": {},
        "mcp-check": {
            "total": 0,
            "percentage": 0.0,
            "languages": {},
            "suites": {},
            "tests": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "warnings": 0,
                "success_rate": 0.0
            },
            "errors": {},
            "warnings": {},
            "failure_reasons": {
                "total": 0,
                "percentage": 0.0,
                "counts": {}
            }
        }
    }

    all_data = []
    for f in stats_files:
        if os.path.exists(f):
            with open(f, 'r', encoding='utf-8') as file:
                all_data.append(json.load(file))

    if not all_data:
        print("No stats files found.")
        return

    for data in all_data:
        # Global fields
        merged["total"] += data.get("total", 0)
        merged["last_index"] = max(merged["last_index"], data.get("last_index", 0))
        merged["remaining"] += data.get("remaining", 0)

        for lang, count in data.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

        # mcp-check specific fields
        chk = data.get("mcp-check", {})
        mchk = merged["mcp-check"]

        mchk["total"] += chk.get("total", 0)

        # Merge languages
        for lang, count in chk.get("languages", {}).items():
            mchk["languages"][lang] = mchk["languages"].get(lang, 0) + count

        # Merge suites (count-based)
        for suite, count in chk.get("suites", {}).items():
            if isinstance(count, (int, float)):
                mchk["suites"][suite] = mchk["suites"].get(suite, 0) + count
            elif isinstance(count, dict):
                # If suites contain nested dicts, merge them
                if suite not in mchk["suites"]:
                    mchk["suites"][suite] = {}
                for k, v in count.items():
                    if isinstance(v, (int, float)):
                        mchk["suites"][suite][k] = mchk["suites"][suite].get(k, 0) + v

        # Merge tests
        tests = chk.get("tests", {})
        mtests = mchk["tests"]
        mtests["total"] += tests.get("total", 0)
        mtests["passed"] += tests.get("passed", 0)
        mtests["failed"] += tests.get("failed", 0)
        mtests["skipped"] += tests.get("skipped", 0)
        mtests["warnings"] += tests.get("warnings", 0)

        # Merge errors
        for err, count in chk.get("errors", {}).items():
            if isinstance(count, (int, float)):
                mchk["errors"][err] = mchk["errors"].get(err, 0) + count

        # Merge warnings
        for warn, count in chk.get("warnings", {}).items():
            if isinstance(count, (int, float)):
                mchk["warnings"][warn] = mchk["warnings"].get(warn, 0) + count

        # Merge failure_reasons
        fr = chk.get("failure_reasons", {})
        mfr = mchk["failure_reasons"]
        mfr["total"] += fr.get("total", 0)
        for reason, count in fr.get("counts", {}).items():
            mfr["counts"][reason] = mfr["counts"].get(reason, 0) + count

    # Recalculate derived values
    mchk = merged["mcp-check"]

    if merged["total"] > 0:
        mchk["percentage"] = round(mchk["total"] / merged["total"] * 100, 2)

    mtests = mchk["tests"]
    if mtests["total"] > 0:
        mtests["success_rate"] = round(mtests["passed"] / mtests["total"] * 100, 2)

    mfr = mchk["failure_reasons"]
    if merged["total"] > 0:
        mfr["percentage"] = round(mfr["total"] / merged["total"] * 100, 2)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=4, ensure_ascii=False)
    print(f"Merged mcp-check stats saved to {output_file}")


if __name__ == "__main__":
    check_dir = Path(__file__).parent
    files = [str(check_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files")
    if existing:
        merge_check_stats(existing, str(check_dir / "mcp_check_stats.json"))
