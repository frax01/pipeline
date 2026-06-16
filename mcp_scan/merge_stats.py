"""
Merge mcp-scan stats from multiple VM runs into a single consolidated file.

Usage:
    python -m tool_mcp_scan.merge_stats
    # or called from deploy.py --merge-scan
"""
import json
import sys
from pathlib import Path


def _merge_dict_counts(all_stats: list[dict], *keys: str) -> dict:
    """Sum dict values across all stats at a nested key path."""
    merged = {}
    for s in all_stats:
        block = s
        for k in keys:
            block = block.get(k, {})
        if isinstance(block, dict):
            for name, count in block.items():
                merged[name] = merged.get(name, 0) + count
    return merged


def _merge_sum(all_stats: list[dict], *keys: str) -> int:
    """Sum a scalar value across all stats at a nested key path."""
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


def _build_vuln_sub_block(all_stats: list[dict], sub_key: str, scan_total: int) -> dict:
    """Build a server_vulnerabilities or tool_vulnerabilities block."""
    sub_total = _merge_sum(all_stats, "mcp-scan", sub_key, "total")
    sub_counts = _merge_dict_counts(all_stats, "mcp-scan", sub_key, "counts")
    sub_categories = _merge_dict_counts(all_stats, "mcp-scan", sub_key, "categories")
    sub_issue_codes = _merge_dict_counts(all_stats, "mcp-scan", sub_key, "issue_codes")

    block = {
        "total": sub_total,
        "average_per_server": round(sub_total / scan_total, 6) if scan_total > 0 else 0.0,
        "counts": sub_counts,
        "percentage_of_severity": _pct_of_severity(sub_counts, sub_total),
        "categories": sub_categories,
        "percentage_of_vulnerability": _pct_of_vulnerability(sub_categories, sub_total),
        "issue_codes": sub_issue_codes,
    }

    # trigger_words only exists in tool_vulnerabilities
    if sub_key == "tool_vulnerabilities":
        block["trigger_words"] = _merge_dict_counts(all_stats, "mcp-scan", sub_key, "trigger_words")

    return block


def merge_scan_stats(stats_files: list[str], output_file: str):
    """Merge multiple vm*_stats.json files into a single mcp_scan_stats.json."""
    all_stats = []
    for f in stats_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if data and "total" in data:
                    all_stats.append(data)
                    print(f"  Loaded {f}: total={data.get('total', 0)}, last_index={data.get('last_index', 0)}")
        except Exception as e:
            print(f"  ⚠️ Skipping {f}: {e}")

    if not all_stats:
        print("No valid stats files found!")
        return

    # --- Global fields ---
    merged = {
        "last_index": max(s.get("last_index", 0) for s in all_stats),
        "total": sum(s.get("total", 0) for s in all_stats),
        "languages": {},
    }

    # Merge global languages
    for s in all_stats:
        for lang, count in s.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

    # --- mcp-scan block ---
    scan_total = _merge_sum(all_stats, "mcp-scan", "total")

    # Merge scan languages
    scan_languages = _merge_dict_counts(all_stats, "mcp-scan", "languages")

    # Merge categories (global: tool + server + toxic flows combined)
    merged_categories = _merge_dict_counts(all_stats, "mcp-scan", "categories")

    # Merge vulnerabilities (global)
    vuln_total = _merge_sum(all_stats, "mcp-scan", "vulnerabilities", "total")
    merged_severity_counts = _merge_dict_counts(all_stats, "mcp-scan", "vulnerabilities", "counts")

    # Merge tools
    tools_total = _merge_sum(all_stats, "mcp-scan", "tools", "total")
    tools_safe = _merge_sum(all_stats, "mcp-scan", "tools", "safe")
    tools_vulnerable = _merge_sum(all_stats, "mcp-scan", "tools", "vulnerable")

    # --- Recalculate percentages ---
    scan_percentage = round((scan_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    vuln_avg = round(vuln_total / scan_total, 2) if scan_total > 0 else 0.0

    # Tools percentages
    tools_pov_safe = round((tools_safe / tools_total) * 100, 2) if tools_total > 0 else 0.0
    tools_pov_vuln = round((tools_vulnerable / tools_total) * 100, 2) if tools_total > 0 else 0.0
    tools_avg = round(tools_total / scan_total, 2) if scan_total > 0 else 0.0
    tools_vuln_avg = round(tools_vulnerable / scan_total, 2) if scan_total > 0 else 0.0

    merged["mcp-scan"] = {
        "total": scan_total,
        "percentage": scan_percentage,
        "languages": scan_languages,
        "percentage_of_vulnerability": _pct_of_vulnerability(merged_categories, vuln_total),
        "categories": merged_categories,
        "vulnerabilities": {
            "total": vuln_total,
            "average_per_server": vuln_avg,
            "counts": merged_severity_counts,
            "percentage_of_severity": _pct_of_severity(merged_severity_counts, vuln_total),
        },
        "server_vulnerabilities": _build_vuln_sub_block(all_stats, "server_vulnerabilities", scan_total),
        "tool_vulnerabilities": _build_vuln_sub_block(all_stats, "tool_vulnerabilities", scan_total),
        "tools": {
            "total": tools_total,
            "safe": tools_safe,
            "vulnerable": tools_vulnerable,
            "average_vulnerable_per_server": tools_vuln_avg,
            "percentage_of_vulnerability": {
                "safe": tools_pov_safe,
                "vulnerable": tools_pov_vuln,
            },
            "average_per_server": tools_avg,
        }
    }

    # Recalculate percentage (scan_total / total * 100)
    merged["percentage"] = scan_percentage

    # Write output
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)

    scan = merged["mcp-scan"]
    srv_v = scan["server_vulnerabilities"]
    tool_v = scan["tool_vulnerabilities"]

    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Scan completed: {scan_total} ({scan_percentage}%)")
    print(f"  Vulnerabilities: {vuln_total} (avg {vuln_avg}/server)")
    print(f"    Server vulns: {srv_v['total']} | issue_codes: {srv_v['issue_codes']}")
    print(f"    Tool vulns:   {tool_v['total']} | issue_codes: {tool_v['issue_codes']}")
    print(f"    Trigger words: {tool_v.get('trigger_words', {})}")
    print(f"  Tools: {tools_total} (safe: {tools_safe}, vulnerable: {tools_vulnerable})")
    print(f"  Categories: {len(merged_categories)}")
    print(f"  -> {output_file}")


def merge_scan_all(base_pull_dir, out_dir):
    """Aggrega tutto: stats globali, server logs e tutte le categorie JSON scaricate (server-level e tool-level)."""
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nInizio merge mcp-scan da {base_pull_dir} a {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("Nessuna cartella vm trovata in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_scan" / "mcp_scan_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_scan_stats(stats_files, str(out_dir / "mcp_scan_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_scan" / "mcp_scan_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception as e:
                pass
    if merged_servers:
        with open(out_dir / "mcp_scan_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Merge servers completato! Totale entry combinate: {len(merged_servers)}")

    # 3. Merge Folder Categories (server-level e tool-level)
    for folder_type in ["server-level", "tool-level"]:
        out_cat_dir = out_dir / folder_type
        out_cat_dir.mkdir(parents=True, exist_ok=True)
        
        all_json_names = set()
        for vm_d in vm_dirs:
            cat_dir = vm_d / "tool_mcp_scan" / folder_type
            if cat_dir.exists() and cat_dir.is_dir():
                for jf in cat_dir.glob("*.json"):
                    all_json_names.add(jf.name)
        
        for json_name in all_json_names:
            merged_vulns = []
            file_found = False
            for vm_d in vm_dirs:
                cat_file = vm_d / "tool_mcp_scan" / folder_type / json_name
                if cat_file.exists():
                    file_found = True
                    try:
                        with open(cat_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            merged_vulns.extend(data.get("vulnerabilities", []))
                    except Exception as e:
                        print(f"Errore lettura {cat_file}: {e}")
            
            if file_found and merged_vulns:
                out_file = out_cat_dir / json_name
                out_data = {
                    "total": len(merged_vulns),
                    "vulnerabilities": merged_vulns
                }
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(out_data, f, indent=4, ensure_ascii=False)

    print(f"Merge profondo delle vulnerabilità Snyk completato in {out_dir}")

if __name__ == "__main__":
    pass
