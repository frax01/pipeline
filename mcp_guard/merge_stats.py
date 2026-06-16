import json
import os
from pathlib import Path

def merge_stats(stats_files, output_file):
    merged = {
        "last_index": 0,
        "total": 0,
        "range_start": 0,
        "range_end": 0,
        "remaining": 0,
        "languages": {},
        "mcp-guard": {
            "total": 0,
            "servers_fuzzed": 0,
            "servers_scanned_static": 0,
            "percentage": 0.0,
            "languages": {},
            "categories_static": {},
            "categories_fuzzing": {},
            "percentage_of_vulnerability": {},
            "percentage_of_vulnerability_static": {},
            "percentage_of_vulnerability_fuzzing": {},
            "vulnerabilities": {
                "total": 0,
                "average_per_server": 0,
                "counts": {},
                "percentage_of_severity": {}
            },
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
            try:
                with open(f, 'r', encoding='utf-8') as file:
                    all_data.append(json.load(file))
            except Exception as e:
                print(f"Error loading {f}: {e}")

    if not all_data:
        print("No stats files found.")
        return

    # Sum up global fields
    for data in all_data:
        merged["total"] += data.get("total", 0)
        merged["last_index"] = max(merged["last_index"], data.get("last_index", 0))

        # Track range bounds across all VMs
        rs = data.get("range_start", 0)
        re_ = data.get("range_end", 0)
        if merged["range_start"] == 0 or rs < merged["range_start"]:
            merged["range_start"] = rs
        if re_ > merged["range_end"]:
            merged["range_end"] = re_

        # Merge languages
        for lang, count in data.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

        # Merge mcp-guard specific fields
        mg = data.get("mcp-guard", {})
        merged_mg = merged["mcp-guard"]
        merged_mg["total"] += mg.get("total", 0)
        merged_mg["servers_fuzzed"] += mg.get("servers_fuzzed", 0)
        merged_mg["servers_scanned_static"] += mg.get("servers_scanned_static", 0)

        # Merge languages in mcp-guard
        for lang, count in mg.get("languages", {}).items():
            merged_mg["languages"][lang] = merged_mg["languages"].get(lang, 0) + count

        # Merge categories_static and categories_fuzzing
        for cat, count in mg.get("categories_static", {}).items():
            merged_mg["categories_static"][cat] = merged_mg["categories_static"].get(cat, 0) + count
        for cat, count in mg.get("categories_fuzzing", {}).items():
            merged_mg["categories_fuzzing"][cat] = merged_mg["categories_fuzzing"].get(cat, 0) + count

        # Backward compat: old single "categories" dict → route to fuzzing
        for cat, count in mg.get("categories", {}).items():
            merged_mg["categories_fuzzing"][cat] = merged_mg["categories_fuzzing"].get(cat, 0) + count

        # Merge vulnerabilities
        vult = mg.get("vulnerabilities", {})
        merged_v = merged_mg["vulnerabilities"]
        merged_v["total"] += vult.get("total", 0)

        for sev, count in vult.get("counts", {}).items():
            merged_v["counts"][sev] = merged_v["counts"].get(sev, 0) + count

        # Merge failure_reasons
        fr = mg.get("failure_reasons", {})
        merged_fr = merged_mg["failure_reasons"]
        merged_fr["total"] += fr.get("total", 0)
        for reason, count in fr.get("counts", {}).items():
            merged_fr["counts"][reason] = merged_fr["counts"].get(reason, 0) + count

    # Remaining = range_end - last_index (how many left overall)
    merged["remaining"] = max(0, merged["range_end"] - merged["last_index"])

    # Re-calculate percentages and averages
    if merged["total"] > 0:
        merged["mcp-guard"]["percentage"] = round((merged["mcp-guard"]["total"] / merged["total"]) * 100, 2)

    if merged["mcp-guard"]["total"] > 0:
        fw_total = merged["mcp-guard"]["total"]
        total_v = merged["mcp-guard"]["vulnerabilities"]["total"]

        merged["mcp-guard"]["vulnerabilities"]["average_per_server"] = round(
            total_v / fw_total, 2
        )

        # Calculate percentage_of_severity
        if total_v > 0:
            for sev, count in merged["mcp-guard"]["vulnerabilities"]["counts"].items():
                merged["mcp-guard"]["vulnerabilities"]["percentage_of_severity"][sev] = round((count / total_v) * 100, 2)

        # Calculate per-bucket percentages
        cats_static = merged["mcp-guard"]["categories_static"]
        cats_fuzzing = merged["mcp-guard"]["categories_fuzzing"]
        total_static = sum(cats_static.values()) if cats_static else 0
        total_fuzzing = sum(cats_fuzzing.values()) if cats_fuzzing else 0

        merged["mcp-guard"]["percentage_of_vulnerability_static"] = {
            cat: round((count / total_static) * 100, 4)
            for cat, count in sorted(cats_static.items(), key=lambda x: x[1], reverse=True)
        } if total_static > 0 else {}

        merged["mcp-guard"]["percentage_of_vulnerability_fuzzing"] = {
            cat: round((count / total_fuzzing) * 100, 4)
            for cat, count in sorted(cats_fuzzing.items(), key=lambda x: x[1], reverse=True)
        } if total_fuzzing > 0 else {}

        # Combined percentages (all vulns)
        all_cats = {}
        for cat, count in cats_static.items():
            all_cats[cat] = all_cats.get(cat, 0) + count
        for cat, count in cats_fuzzing.items():
            all_cats[cat] = all_cats.get(cat, 0) + count

        if total_v > 0 and all_cats:
            merged["mcp-guard"]["percentage_of_vulnerability"] = {
                cat: round((count / total_v) * 100, 4)
                for cat, count in sorted(all_cats.items(), key=lambda x: x[1], reverse=True)
            }

            # Grouped percentages (aggregate sensitive-information-disclosed variants)
            grouped = {}
            for cat, count in all_cats.items():
                if cat.startswith("sensitive-information-disclosed"):
                    grouped["sensitive-information-disclosed"] = grouped.get("sensitive-information-disclosed", 0) + count
                else:
                    grouped[cat] = grouped.get(cat, 0) + count

            merged["mcp-guard"]["percentage_of_vulnerability_grouped"] = {
                cat: round((count / total_v) * 100, 4)
                for cat, count in sorted(grouped.items(), key=lambda x: x[1], reverse=True)
            }

    # Calculate failure_reasons percentage
    if merged["total"] > 0 and merged["mcp-guard"]["failure_reasons"]["total"] > 0:
        merged["mcp-guard"]["failure_reasons"]["percentage"] = round(
            (merged["mcp-guard"]["failure_reasons"]["total"] / merged["total"]) * 100, 2
        )

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=4, ensure_ascii=False)
    print(f"Merged stats saved to {output_file}")

def merge_guard_all(base_pull_dir, out_dir):
    """Aggregate everything: global stats, server logs, and all category folders."""
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nStarting MCP Guard deep merge from {base_pull_dir} to {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("No vm folders found in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_guard" / "mcp_guard_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_stats(stats_files, str(out_dir / "mcp_guard_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_guard" / "mcp_guard_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception:
                pass
    if merged_servers:
        with open(out_dir / "mcp_guard_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Server logs merge completed! Total: {len(merged_servers)}")

    # 3. Merge Folder Categories (fuzzing, protocol, static, dynamic)
    analysis_types = ["static", "dynamic", "fuzzing", "protocol"]
    for atype in analysis_types:
        atype_out_dir = out_dir / atype

        # Collect all categories for this type across all VMs
        all_categories = set()
        for vm_d in vm_dirs:
            atype_vm_dir = vm_d / "tool_mcp_guard" / atype
            if atype_vm_dir.exists() and atype_vm_dir.is_dir():
                for cat_dir in atype_vm_dir.iterdir():
                    if cat_dir.is_dir():
                        all_categories.add(cat_dir.name)

        for cat_name in all_categories:
            cat_out_dir = atype_out_dir / cat_name
            cat_out_dir.mkdir(parents=True, exist_ok=True)

            # Collect all JSON files for this category across all VMs
            all_json_names = set()
            for vm_d in vm_dirs:
                cat_vm_dir = vm_d / "tool_mcp_guard" / atype / cat_name
                if cat_vm_dir.exists() and cat_vm_dir.is_dir():
                    for jf in cat_vm_dir.glob("*.json"):
                        all_json_names.add(jf.name)

            for json_name in all_json_names:
                merged_vulns = []
                for vm_d in vm_dirs:
                    json_file = vm_d / "tool_mcp_guard" / atype / cat_name / json_name
                    if json_file.exists():
                        try:
                            with open(json_file, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                merged_vulns.extend(data.get("vulnerabilities", []))
                        except Exception as e:
                            print(f"Error reading {json_file}: {e}")

                if merged_vulns:
                    out_file = cat_out_dir / json_name
                    out_data = {
                        "total": len(merged_vulns),
                        "vulnerabilities": merged_vulns
                    }
                    with open(out_file, "w", encoding="utf-8") as f:
                        json.dump(out_data, f, indent=4, ensure_ascii=False)

    print(f"Deep merge of MCP Guard vulnerabilities completed in {out_dir}")

if __name__ == "__main__":
    # Standard entry point if called as script
    import sys
    if len(sys.argv) > 2:
        merge_guard_all(sys.argv[1], sys.argv[2])
    else:
        # Default fallback for VM collection
        base_pull = Path("pullFromVM")
        if base_pull.exists():
            merge_guard_all(base_pull, Path("."))
        else:
            print("Usage: python merge_stats.py <base_pull_dir> <out_dir>")
