"""
Merge mcp-shield stats from multiple VM runs into a single consolidated file.

Usage:
    python -m tool_mcp_shield.merge_stats
"""
import json
import sys
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

def _merge_sum(all_stats: list[dict], *keys: str) -> int:
    total = 0
    for s in all_stats:
        block = s
        for k in keys:
            block = block.get(k, {})
        if isinstance(block, (int, float)):
            total += block
    return total

def _pct_of_vulnerability(categories: dict, total: int) -> dict:
    if total <= 0 or not categories:
        return {}
    return {cat: round((count / total) * 100, 2) for cat, count in categories.items()}

def _pct_of_severity(counts: dict, total: int) -> dict:
    if total <= 0 or not counts:
        return {}
    return {sev: round(count / total, 6) for sev, count in counts.items()}

def merge_shield_stats(stats_files: list[str], output_file: str):
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

    shield_total = _merge_sum(all_stats, "mcp-shield", "total")
    shield_languages = _merge_dict_counts(all_stats, "mcp-shield", "languages")

    tools_total = _merge_sum(all_stats, "mcp-shield", "tools", "total")
    tools_safe = _merge_sum(all_stats, "mcp-shield", "tools", "safe")
    
    tools_vuln_total = _merge_sum(all_stats, "mcp-shield", "tools", "vulnerable", "total")
    tools_vuln_static_categories = _merge_dict_counts(all_stats, "mcp-shield", "tools", "vulnerable", "static-analysis", "categories")
    tools_vuln_static_counts = _merge_dict_counts(all_stats, "mcp-shield", "tools", "vulnerable", "static-analysis", "counts")
    tools_vuln_llm = _merge_dict_counts(all_stats, "mcp-shield", "tools", "vulnerable", "llm-description-analysis")

    # Merge LLM failures separatamente (è un dict annidato, non viene catturato da _merge_dict_counts)
    llm_failures_total = _merge_sum(all_stats, "mcp-shield", "tools", "vulnerable", "llm-description-analysis", "failures", "total")
    llm_failures_reasons = _merge_dict_counts(all_stats, "mcp-shield", "tools", "vulnerable", "llm-description-analysis", "failures", "reasons")
    tools_vuln_llm["failures"] = {
        "total": llm_failures_total,
        "reasons": llm_failures_reasons
    }

    shield_percentage = round((shield_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0

    total_vuln_static_cats = sum(tools_vuln_static_categories.values())
    total_vuln_static_counts = sum(tools_vuln_static_counts.values())

    tools_vuln_avg = round(tools_vuln_total / shield_total, 2) if shield_total > 0 else 0.0
    tools_avg = round(tools_total / shield_total, 2) if shield_total > 0 else 0.0
    
    pct_vuln_safe = round((tools_safe / tools_total) * 100, 2) if tools_total > 0 else 0.0
    pct_vuln_vuln = round((tools_vuln_total / tools_total) * 100, 2) if tools_total > 0 else 0.0

    # Merge descriptions (dict with counts per category)
    merged_descriptions = {}
    for s in all_stats:
        desc_block = (s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {})
                       .get("static-analysis", {}).get("descriptions", {}))
        for cat_name, desc_dict in desc_block.items():
            existing = merged_descriptions.setdefault(cat_name, {})
            if isinstance(desc_dict, dict):
                for desc, count in desc_dict.items():
                    existing[desc] = existing.get(desc, 0) + count

    merged["mcp-shield"] = {
        "total": shield_total,
        "percentage": shield_percentage,
        "languages": shield_languages,
        "tools": {
            "total": tools_total,
            "safe": tools_safe,
            "vulnerable": {
                "total": tools_vuln_total,
                "average_vulnerable_per_server": tools_vuln_avg,
                "static-analysis": {
                    "categories": tools_vuln_static_categories,
                    "percentage_of_vulnerability": _pct_of_vulnerability(tools_vuln_static_categories, total_vuln_static_cats),
                    "counts": tools_vuln_static_counts,
                    "percentage_of_severity": _pct_of_vulnerability(tools_vuln_static_counts, total_vuln_static_counts),
                    "descriptions": merged_descriptions
                },
                "llm-description-analysis": tools_vuln_llm
            },
            "average_per_server": tools_avg,
            "percentage_of_vulnerability": {
                "safe": pct_vuln_safe,
                "vulnerable": pct_vuln_vuln
            }
        }
    }

    merged["percentage"] = shield_percentage

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)
        
    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Shield completed: {shield_total} ({shield_percentage}%)")
    print(f"  Tools: {tools_total} (safe: {tools_safe}, vulnerable: {tools_vuln_total})")
    print(f"  LLM analysis: {tools_vuln_llm}")
    if llm_failures_total > 0:
        print(f"  LLM failures: {llm_failures_total} | reasons: {llm_failures_reasons}")
    print(f"  -> {output_file}")

def merge_shield_all(base_pull_dir, out_dir):
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nInizio merge mcp-shield da {base_pull_dir} a {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("Nessuna cartella vm trovata in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_shield" / "mcp_shield_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_shield_stats(stats_files, str(out_dir / "mcp_shield_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_shield" / "mcp_shield_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception as e:
                pass
    if merged_servers:
        with open(out_dir / "mcp_shield_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Merge servers completato! Totale entry combinate: {len(merged_servers)}")

    # 3. Merge Folder Categories (es. sensitive-file-access/sensitive_file_access_HIGH.json)
    all_categories = set()
    for vm_d in vm_dirs:
        shield_dir = vm_d / "tool_mcp_shield"
        if shield_dir.exists() and shield_dir.is_dir():
            for folder in shield_dir.iterdir():
                if folder.is_dir() and not folder.name.startswith(".") and not folder.name.startswith("_"):
                    all_categories.add(folder.name)

    for cat in all_categories:
        out_cat_dir = out_dir / cat
        out_cat_dir.mkdir(parents=True, exist_ok=True)
        
        all_json_names = set()
        for vm_d in vm_dirs:
            cat_dir = vm_d / "tool_mcp_shield" / cat
            if cat_dir.exists() and cat_dir.is_dir():
                for jf in cat_dir.glob("*.json"):
                    all_json_names.add(jf.name)
                    
        for json_name in all_json_names:
            merged_vulns = []
            file_found = False
            for vm_d in vm_dirs:
                cat_file = vm_d / "tool_mcp_shield" / cat / json_name
                if cat_file.exists():
                    file_found = True
                    try:
                        with open(cat_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            merged_vulns.extend(data.get("findings", []))
                    except Exception as e:
                        print(f"Errore lettura {cat_file}: {e}")
            
            if file_found and merged_vulns:
                out_file = out_cat_dir / json_name
                out_data = {
                    "total": len(merged_vulns),
                    "findings": merged_vulns
                }
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(out_data, f, indent=4, ensure_ascii=False)

    print(f"Merge profondo delle vulnerabilità Shield completato in {out_dir}")

if __name__ == "__main__":
    pass
