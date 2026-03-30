import json
import os
from pathlib import Path

def merge_fuzzing_stats(stats_files, output_file):
    merged = {
        "last_index": 0,
        "total": 0,
        "languages": {},
        "fuzzing": {
            "total_servers": 0,
            "percentage": 0.0,
            "languages": {},
            "total_tools": 0,
            "total_fuzzing_runs": 0,
            "total_successful": 0,
            "total_exceptions": 0,
            "total_safety_blocked": 0,
            "success_rate": 0.0,
            "exceptions_by_message": {},
            "protocol_types": {
                "total_types_tested": 0,
                "total_runs": 0,
                "total_successful": 0,
                "total_errors": 0,
                "success_rate": 0.0,
                "by_type": {}
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

        for lang, count in data.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

        # Fuzzing-specific fields
        fz = data.get("fuzzing", {})
        mfz = merged["fuzzing"]

        mfz["total_servers"] += fz.get("total_servers", 0)
        mfz["total_tools"] += fz.get("total_tools", 0)
        mfz["total_fuzzing_runs"] += fz.get("total_fuzzing_runs", 0)
        mfz["total_successful"] += fz.get("total_successful", 0)
        mfz["total_exceptions"] += fz.get("total_exceptions", 0)
        mfz["total_safety_blocked"] += fz.get("total_safety_blocked", 0)

        # Merge languages
        for lang, count in fz.get("languages", {}).items():
            mfz["languages"][lang] = mfz["languages"].get(lang, 0) + count

        # Merge exceptions_by_message
        for msg, count in fz.get("exceptions_by_message", {}).items():
            mfz["exceptions_by_message"][msg] = mfz["exceptions_by_message"].get(msg, 0) + count

        # Merge protocol_types
        pt = fz.get("protocol_types", {})
        mpt = mfz["protocol_types"]
        mpt["total_types_tested"] += pt.get("total_types_tested", 0)
        mpt["total_runs"] += pt.get("total_runs", 0)
        mpt["total_successful"] += pt.get("total_successful", 0)
        mpt["total_errors"] += pt.get("total_errors", 0)

        for pt_type, pt_data in pt.get("by_type", {}).items():
            if pt_type not in mpt["by_type"]:
                mpt["by_type"][pt_type] = {"runs": 0, "successful": 0, "errors": 0}
            mpt["by_type"][pt_type]["runs"] += pt_data.get("runs", 0)
            mpt["by_type"][pt_type]["successful"] += pt_data.get("successful", 0)
            mpt["by_type"][pt_type]["errors"] += pt_data.get("errors", 0)

    # Recalculate derived values
    mfz = merged["fuzzing"]

    if merged["total"] > 0:
        mfz["percentage"] = round(mfz["total_servers"] / merged["total"] * 100, 2)

    if mfz["total_fuzzing_runs"] > 0:
        mfz["success_rate"] = round(mfz["total_successful"] / mfz["total_fuzzing_runs"], 6)

    mpt = mfz["protocol_types"]
    if mpt["total_runs"] > 0:
        mpt["success_rate"] = round(mpt["total_successful"] / mpt["total_runs"] * 100, 2)

    # Per-type success rates
    for pt_type, pt_data in mpt["by_type"].items():
        if pt_data["runs"] > 0:
            pt_data["success_rate"] = round(pt_data["successful"] / pt_data["runs"] * 100, 2)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=4, ensure_ascii=False)
    print(f"Merged fuzzing stats saved to {output_file}")


if __name__ == "__main__":
    fuzzing_dir = Path(__file__).parent
    files = [str(fuzzing_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files")
    if existing:
        merge_fuzzing_stats(existing, str(fuzzing_dir / "fuzzing_stats.json"))
