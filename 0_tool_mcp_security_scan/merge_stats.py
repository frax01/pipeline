"""
Merge mcp-security-scan stats from multiple VM runs into a single consolidated file.

Usage:
    python -m tool_mcp_security_scan.merge_stats
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
    return {sev: round((count / total) * 100, 2) for sev, count in counts.items()}

def merge_security_scan_stats(stats_files: list[str], output_file: str):
    all_stats = []
    for f in stats_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if data and "total" in data:
                    all_stats.append(data)
        except Exception as e:
            print(f"  ⚠️ Skipping {f}: {e}")

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

    scan_total = _merge_sum(all_stats, "mcp-security-scan", "total")
    scan_languages = _merge_dict_counts(all_stats, "mcp-security-scan", "languages")
    
    merged_categories = _merge_dict_counts(all_stats, "mcp-security-scan", "categories")
    merged_categories_passed = _merge_dict_counts(all_stats, "mcp-security-scan", "categories_passed")
    
    vuln_total = _merge_sum(all_stats, "mcp-security-scan", "vulnerabilities", "total")
    merged_severity_counts = _merge_dict_counts(all_stats, "mcp-security-scan", "vulnerabilities", "counts")

    findings_total = _merge_sum(all_stats, "mcp-security-scan", "findings", "total")
    findings_passed = _merge_sum(all_stats, "mcp-security-scan", "findings", "passed")
    findings_failed = _merge_sum(all_stats, "mcp-security-scan", "findings", "failed")

    scan_percentage = round((scan_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    vuln_avg = round(vuln_total / scan_total, 2) if scan_total > 0 else 0.0

    percentage_passed = round((findings_passed / findings_total) * 100, 2) if findings_total > 0 else 0.0

    merged["mcp-security-scan"] = {
        "total": scan_total,
        "percentage": scan_percentage,
        "languages": scan_languages,
        "percentage_of_vulnerability": _pct_of_vulnerability(merged_categories, vuln_total),
        "categories": merged_categories,
        "categories_passed": merged_categories_passed,
        "vulnerabilities": {
            "total": vuln_total,
            "average_per_server": vuln_avg,
            "counts": merged_severity_counts,
            "percentage_of_severity": _pct_of_severity(merged_severity_counts, vuln_total),
        },
        "findings": {
            "total": findings_total,
            "passed": findings_passed,
            "failed": findings_failed,
            "percentage_passed": percentage_passed
        }
    }

    merged["percentage"] = scan_percentage

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)
        
    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Scan completed: {scan_total} ({scan_percentage}%)")
    print(f"  Vulnerabilities (failed): {vuln_total}")
    print(f"  Passed Findings: {findings_passed} / {findings_total}")
    print(f"  -> {output_file}")


def merge_security_scan_all(base_pull_dir, out_dir):
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nInizio merge mcp-security-scan da {base_pull_dir} a {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("Nessuna cartella vm trovata in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_security_scan" / "mcp_security_scan_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_security_scan_stats(stats_files, str(out_dir / "mcp_security_scan_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_security_scan" / "mcp_security_scan_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception as e:
                pass
    if merged_servers:
        with open(out_dir / "mcp_security_scan_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Merge servers completato! Totale entry combinate: {len(merged_servers)}")

    # 3. Merge Folder Categories (es. dangerous-capabilities/dangerous_capabilities_high.json)
    all_categories = set()
    for vm_d in vm_dirs:
        scan_dir = vm_d / "tool_mcp_security_scan"
        if scan_dir.exists() and scan_dir.is_dir():
            for folder in scan_dir.iterdir():
                if folder.is_dir() and not folder.name.startswith(".") and not folder.name.startswith("_"):
                    all_categories.add(folder.name)

    for cat in all_categories:
        out_cat_dir = out_dir / cat
        out_cat_dir.mkdir(parents=True, exist_ok=True)
        
        all_json_names = set()
        for vm_d in vm_dirs:
            cat_dir = vm_d / "tool_mcp_security_scan" / cat
            if cat_dir.exists() and cat_dir.is_dir():
                for jf in cat_dir.glob("*.json"):
                    all_json_names.add(jf.name)
                    
        for json_name in all_json_names:
            merged_vulns = []
            file_found = False
            for vm_d in vm_dirs:
                cat_file = vm_d / "tool_mcp_security_scan" / cat / json_name
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

    print(f"Merge profondo delle vulnerabilità Security Scan completato in {out_dir}")

if __name__ == "__main__":
    pass
