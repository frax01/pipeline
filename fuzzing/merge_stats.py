"""
Merge fuzzing stats from multiple VM runs into a single consolidated file.

Usage:
    python -m fuzzing.merge_stats
"""
import json
from pathlib import Path


def _merge_dict_counts(all_stats: list[dict], *keys: str) -> dict:
    merged = {}
    for s in all_stats:
        block = s
        for k in keys:
            block = block.get(k, {})
        if isinstance(block, dict):
            for name, count in block.items():
                if isinstance(count, (int, float)):
                    merged[name] = merged.get(name, 0) + count
    return merged


def _merge_sum(all_stats: list[dict], *keys: str):
    total = 0
    for s in all_stats:
        block = s
        for k in keys:
            block = block.get(k, {})
        if isinstance(block, (int, float)):
            total += block
    return total


def merge_fuzzing_stats(stats_files: list[str], output_file: str):
    all_stats = []
    for f in stats_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if data and "total" in data:
                    all_stats.append(data)
        except Exception as e:
            print(f"  Skipping {f}: {e}")

    if not all_stats:
        print("No valid stats files found!")
        return

    merged = {
        "last_index": max(s.get("last_index", 0) for s in all_stats),
        "total": sum(s.get("total", 0) for s in all_stats),
        "languages": {},
    }

    for s in all_stats:
        for lang, count in s.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

    # Fuzzing aggregate
    fz_total_servers = _merge_sum(all_stats, "fuzzing", "total_servers")
    fz_languages = _merge_dict_counts(all_stats, "fuzzing", "languages")
    fz_total_tools = _merge_sum(all_stats, "fuzzing", "total_tools")
    fz_total_runs = _merge_sum(all_stats, "fuzzing", "total_fuzzing_runs")
    fz_total_successful = _merge_sum(all_stats, "fuzzing", "total_successful")
    fz_total_exceptions = _merge_sum(all_stats, "fuzzing", "total_exceptions")
    fz_total_safety = _merge_sum(all_stats, "fuzzing", "total_safety_blocked")
    fz_exceptions_by_msg = _merge_dict_counts(all_stats, "fuzzing", "exceptions_by_message")

    fz_percentage = round((fz_total_servers / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    fz_success_rate = round(fz_total_successful / fz_total_runs, 6) if fz_total_runs > 0 else 0.0

    # Protocol types aggregate
    pt_total_tested = _merge_sum(all_stats, "fuzzing", "protocol_types", "total_types_tested")
    pt_total_runs = _merge_sum(all_stats, "fuzzing", "protocol_types", "total_runs")
    pt_total_successful = _merge_sum(all_stats, "fuzzing", "protocol_types", "total_successful")
    pt_total_errors = _merge_sum(all_stats, "fuzzing", "protocol_types", "total_errors")
    pt_success_rate = round(pt_total_successful / pt_total_runs * 100, 2) if pt_total_runs > 0 else 0.0

    # Merge by_type
    pt_by_type = {}
    for s in all_stats:
        by_type = s.get("fuzzing", {}).get("protocol_types", {}).get("by_type", {})
        for pt_type, pt_data in by_type.items():
            if pt_type not in pt_by_type:
                pt_by_type[pt_type] = {"runs": 0, "successful": 0, "errors": 0}
            pt_by_type[pt_type]["runs"] += pt_data.get("runs", 0)
            pt_by_type[pt_type]["successful"] += pt_data.get("successful", 0)
            pt_by_type[pt_type]["errors"] += pt_data.get("errors", 0)

    # Calc success_rate per type
    for pt_type, pt_data in pt_by_type.items():
        if pt_data["runs"] > 0:
            pt_data["success_rate"] = round(pt_data["successful"] / pt_data["runs"] * 100, 2)
        else:
            pt_data["success_rate"] = 0.0

    merged["fuzzing"] = {
        "total_servers": fz_total_servers,
        "percentage": fz_percentage,
        "languages": fz_languages,
        "total_tools": fz_total_tools,
        "total_fuzzing_runs": fz_total_runs,
        "total_successful": fz_total_successful,
        "total_exceptions": fz_total_exceptions,
        "total_safety_blocked": fz_total_safety,
        "success_rate": fz_success_rate,
        "exceptions_by_message": fz_exceptions_by_msg,
        "protocol_types": {
            "total_types_tested": pt_total_tested,
            "total_runs": pt_total_runs,
            "total_successful": pt_total_successful,
            "total_errors": pt_total_errors,
            "success_rate": pt_success_rate,
            "by_type": pt_by_type
        }
    }

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)

    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Fuzzing completed: {fz_total_servers} ({fz_percentage}%)")
    print(f"  Tools: {fz_total_tools} | Runs: {fz_total_runs} | Exceptions: {fz_total_exceptions}")
    print(f"  Success rate: {fz_success_rate:.4f}")
    print(f"  Protocol types tested: {pt_total_tested} | Runs: {pt_total_runs}")
    print(f"  -> {output_file}")


def merge_fuzzing_all(base_pull_dir, out_dir):
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nInizio merge fuzzing da {base_pull_dir} a {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("Nessuna cartella vm trovata in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_fuzzing" / "fuzzing_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_fuzzing_stats(stats_files, str(out_dir / "fuzzing_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_fuzzing" / "fuzzing_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception:
                pass
    if merged_servers:
        with open(out_dir / "fuzzing_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Merge servers completato! Totale entry: {len(merged_servers)}")

    # 3. Merge Exception Subdirectories
    _merge_subdirectory(vm_dirs, out_dir, "exceptions", "servers")

    # 4. Merge Protocol Subdirectories
    _merge_subdirectory(vm_dirs, out_dir, "protocol", "servers")

    print(f"Merge profondo fuzzing completato in {out_dir}")


def _merge_subdirectory(vm_dirs, out_dir, subdir_name: str, list_key: str):
    """Merge JSON files from a subdirectory across all VMs."""
    all_json_names = set()
    for vm_d in vm_dirs:
        sub_dir = vm_d / "tool_fuzzing" / subdir_name
        if sub_dir.exists() and sub_dir.is_dir():
            for jf in sub_dir.glob("*.json"):
                all_json_names.add(jf.name)

    if not all_json_names:
        return

    out_sub_dir = out_dir / subdir_name
    out_sub_dir.mkdir(parents=True, exist_ok=True)

    for json_name in sorted(all_json_names):
        merged_items = []
        metadata = {}
        for vm_d in vm_dirs:
            jf = vm_d / "tool_fuzzing" / subdir_name / json_name
            if jf.exists():
                try:
                    with open(jf, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        merged_items.extend(data.get(list_key, []))
                        # Keep metadata from first file found
                        if not metadata:
                            metadata = {k: v for k, v in data.items() if k not in (list_key, "total", "total_servers", "total_runs", "total_successful", "total_errors")}
                except Exception as e:
                    print(f"Errore lettura {jf}: {e}")

        if merged_items:
            out_data = dict(metadata)
            out_data[list_key] = merged_items

            # Ricalcola totali
            if subdir_name == "exceptions":
                out_data["total"] = len(merged_items)
            elif subdir_name == "protocol":
                out_data["total_servers"] = len(merged_items)
                out_data["total_runs"] = sum(s.get("runs", 0) for s in merged_items)
                out_data["total_successful"] = sum(s.get("successful", 0) for s in merged_items)
                out_data["total_errors"] = sum(s.get("errors", 0) for s in merged_items)

            with open(out_sub_dir / json_name, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=4, ensure_ascii=False)

    print(f"  Merge {subdir_name}/: {len(all_json_names)} file")


if __name__ == "__main__":
    pass
