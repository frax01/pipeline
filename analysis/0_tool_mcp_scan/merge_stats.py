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


if __name__ == "__main__":
    scan_dir = Path(__file__).parent
    pull_dir = scan_dir / "pullFromVM"
    # Look in pullFromVM/ first, fallback to current dir
    search_dir = pull_dir if pull_dir.exists() else scan_dir
    files = [str(search_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files in {search_dir}")
    if existing:
        merge_scan_stats(existing, str(scan_dir / "mcp_scan_stats.json"))
