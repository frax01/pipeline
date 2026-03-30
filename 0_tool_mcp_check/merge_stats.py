import json
import os
from pathlib import Path

def merge_stats_json(stats_files, output_file):
    merged = {
        "last_index": 0,
        "total": 0,
        "range_start": 0,
        "range_end": 0,
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
                "success_rate": 0.0,
                "average_failed_per_server": 0.0
            },
            "errors": {},
            "errors_reorganized": {},
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
            try:
                with open(f, 'r', encoding='utf-8') as file:
                    all_data.append(json.load(file))
            except Exception as e:
                print(f"Error loading {f}: {e}")

    if not all_data:
        print("No stats files found.")
        return

    for data in all_data:
        merged["total"] += data.get("total", 0)
        merged["last_index"] = max(merged["last_index"], data.get("last_index", 0))
        
        rs = data.get("range_start", 0)
        re_ = data.get("range_end", 0)
        if merged["range_start"] == 0 or rs < merged["range_start"]:
            merged["range_start"] = rs
        if re_ > merged["range_end"]:
            merged["range_end"] = re_

        for lang, count in data.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

        mc = data.get("mcp-check", {})
        merged_mc = merged["mcp-check"]
        merged_mc["total"] += mc.get("total", 0)
        
        for lang, count in mc.get("languages", {}).items():
            merged_mc["languages"][lang] = merged_mc["languages"].get(lang, 0) + count
        
        # Suites
        res_suites = mc.get("suites", {})
        fw_suites = merged_mc["suites"]
        for s_name, s_data in res_suites.items():
            s_block = fw_suites.setdefault(s_name, {"passed": 0, "failed": 0, "warnings": 0, "total": 0})
            s_block["passed"] += s_data.get("passed", 0)
            s_block["failed"] += s_data.get("failed", 0)
            s_block["warnings"] += s_data.get("warnings", 0)
            s_block["total"] += s_data.get("total", 0)

        # Tests
        res_tests = mc.get("tests", {})
        fw_tests = merged_mc["tests"]
        for key in ["total", "passed", "failed", "skipped", "warnings"]:
            fw_tests[key] += res_tests.get(key, 0)

        # Reorganized Errors
        er_res = mc.get("errors_reorganized", {})
        er_fw = merged_mc["errors_reorganized"]
        for s_name, cats in er_res.items():
            s_er = er_fw.setdefault(s_name, {})
            for cat, count in cats.items():
                s_er[cat] = s_er.get(cat, 0) + count

        # Failure Reasons
        fr = mc.get("failure_reasons", {})
        merged_fr = merged_mc["failure_reasons"]
        merged_fr["total"] += fr.get("total", 0)
        for reason, count in fr.get("counts", {}).items():
            merged_fr["counts"][reason] = merged_fr["counts"].get(reason, 0) + count

    # Percentages
    merged["remaining"] = max(0, merged["range_end"] - merged["last_index"])
    if merged["total"] > 0:
        merged["mcp-check"]["percentage"] = round((merged["mcp-check"]["total"] / merged["total"]) * 100, 2)
    
    mc_total = merged["mcp-check"]["total"]
    if mc_total > 0:
        fw_tests = merged["mcp-check"]["tests"]
        if fw_tests["total"] > 0:
            fw_tests["success_rate"] = round((fw_tests["passed"] / fw_tests["total"]) * 100, 2)
        fw_tests["average_failed_per_server"] = round(fw_tests["failed"] / mc_total, 2)

    # Re-calculate failure_reasons percentage
    fr_block = merged["mcp-check"]["failure_reasons"]
    if merged["total"] > 0 and fr_block["total"] > 0:
        fr_block["percentage"] = round((fr_block["total"] / merged["total"]) * 100, 2)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=4, ensure_ascii=False)
    print(f"Merged check stats saved to {output_file}")

def merge_check_all(base_pull_dir, out_dir):
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nStarting MCP Check deep merge from {base_pull_dir} to {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("No vm folders found in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_check" / "mcp_check_stats.json"
        if not sf.exists():
            # Fallback if it was in analysis subfolder (old structure)
            sf = vm_d / "analysis" / "0_tool_mcp_check" / "mcp_check_stats.json"
        
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_stats_json(stats_files, str(out_dir / "mcp_check_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_check" / "mcp_check_servers.json"
        if not sf.exists():
            sf = vm_d / "analysis" / "0_tool_mcp_check" / "mcp_check_servers.json"
        
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception: pass
    if merged_servers:
        with open(out_dir / "mcp_check_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Server logs merge completed! Total: {len(merged_servers)}")

    # 3. Merge Folder Categories (handshake, tool_discovery, tool_invocation)
    suites = ["handshake", "tool_discovery", "tool_invocation"]
    for suite in suites:
        suite_out_dir = out_dir / suite
        
        # Collect all categories for this suite across all VMs
        all_categories = set()
        for vm_d in vm_dirs:
            suite_vm_dir = vm_d / "tool_mcp_check" / suite
            if suite_vm_dir.exists() and suite_vm_dir.is_dir():
                for cat_dir in suite_vm_dir.iterdir():
                    if cat_dir.is_dir():
                        all_categories.add(cat_dir.name)
        
        for cat_name in all_categories:
            cat_out_dir = suite_out_dir / cat_name
            cat_out_dir.mkdir(parents=True, exist_ok=True)
            
            # Collect all JSON files for this category across all VMs
            all_json_names = set()
            for vm_d in vm_dirs:
                cat_vm_dir = vm_d / "tool_mcp_check" / suite / cat_name
                if cat_vm_dir.exists() and cat_vm_dir.is_dir():
                    for jf in cat_vm_dir.glob("*.json"):
                        all_json_names.add(jf.name)
            
            for json_name in all_json_names:
                merged_entries = []
                for vm_d in vm_dirs:
                    json_file = vm_d / "tool_mcp_check" / suite / cat_name / json_name
                    if json_file.exists():
                        try:
                            with open(json_file, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                merged_entries.extend(data.get("entries", []))
                        except Exception as e:
                            print(f"Error reading {json_file}: {e}")
                
                if merged_entries:
                    # Group by server_url to handle potential duplicates across VMs
                    final_entries = {}
                    for e in merged_entries:
                        s_url = e["server_url"]
                        if s_url not in final_entries:
                            final_entries[s_url] = e
                        else:
                            # Merge errors/warnings lists if they exist
                            if "errors" in e:
                                final_entries[s_url].setdefault("errors", []).extend(e["errors"])
                            if "warnings" in e:
                                final_entries[s_url].setdefault("warnings", []).extend(e["warnings"])
                    
                    entries_list = list(final_entries.values())
                    out_file = cat_out_dir / json_name
                    out_data = {
                        "total": len(entries_list),
                        "entries": entries_list
                    }
                    with open(out_file, "w", encoding="utf-8") as f:
                        json.dump(out_data, f, indent=4, ensure_ascii=False)


    print(f"Deep merge of MCP Check suites completed in {out_dir}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        merge_check_all(sys.argv[1], sys.argv[2])
    else:
        base_pull = Path("pullFromVM")
        if base_pull.exists():
            merge_check_all(base_pull, Path("."))
        else:
            print("Usage: python merge_stats.py <base_pull_dir> <out_dir>")
