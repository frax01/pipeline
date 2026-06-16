"""
Merge mcp-watch stats from multiple VM runs into a single consolidated file.

Usage:
    python merge_stats.py
    # or called from deploy.py --merge-watch
"""
import json
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
                if isinstance(count, (int, float)):
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


def merge_watch_stats(stats_files: list[str], output_file: str):
    """Merge multiple vm*_stats.json files into a single mcp_watch_stats.json."""
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
        "range_start": min(s.get("range_start", 0) for s in all_stats),
        "range_end": max(s.get("range_end", 0) for s in all_stats),
        "remaining": 0,
        "languages": {},
    }

    # Merge global languages
    for s in all_stats:
        for lang, count in s.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

    # Remaining = range_end - last_index
    merged["remaining"] = max(0, merged["range_end"] - merged["last_index"])

    # --- mcp-watch block ---
    watch_total = _merge_sum(all_stats, "mcp-watch", "total")

    # Merge watch languages
    watch_languages = _merge_dict_counts(all_stats, "mcp-watch", "languages")

    # Merge categories
    merged_categories = _merge_dict_counts(all_stats, "mcp-watch", "categories")

    # Merge vulnerabilities
    vuln_total = _merge_sum(all_stats, "mcp-watch", "vulnerabilities", "total")
    merged_severity_counts = _merge_dict_counts(all_stats, "mcp-watch", "vulnerabilities", "counts")

    # Merge failure_reasons
    fr_total = _merge_sum(all_stats, "mcp-watch", "failure_reasons", "total")
    fr_counts = _merge_dict_counts(all_stats, "mcp-watch", "failure_reasons", "counts")

    # --- Recalculate percentages ---
    watch_percentage = round((watch_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    vuln_avg = round(vuln_total / watch_total, 2) if watch_total > 0 else 0.0
    fr_percentage = round((fr_total / merged["total"]) * 100, 2) if merged["total"] > 0 and fr_total > 0 else 0.0

    merged["mcp-watch"] = {
        "total": watch_total,
        "percentage": watch_percentage,
        "languages": watch_languages,
        "categories": merged_categories,
        "percentage_of_vulnerability": _pct_of_vulnerability(merged_categories, vuln_total),
        "vulnerabilities": {
            "total": vuln_total,
            "average_per_server": vuln_avg,
            "counts": merged_severity_counts,
            "percentage_of_severity": _pct_of_severity(merged_severity_counts, vuln_total),
        },
        "failure_reasons": {
            "total": fr_total,
            "percentage": fr_percentage,
            "counts": fr_counts,
        },
    }

    # Write output
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)

    watch = merged["mcp-watch"]
    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Watch completed: {watch_total} ({watch_percentage}%)")
    print(f"  Vulnerabilities: {vuln_total} (avg {vuln_avg}/server)")
    print(f"  Severity: {merged_severity_counts}")
    print(f"  Categories: {len(merged_categories)}")
    print(f"  Failure reasons: {fr_total} ({fr_percentage}%)")
    print(f"  -> {output_file}")


def merge_watch_all(base_pull_dir, out_dir):
    """Aggrega tutto: stats globali, server logs e tutte le categorie JSON scaricate."""
    base_pull_dir = Path(base_pull_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nInizio merge mcp-watch da {base_pull_dir} a {out_dir}")

    vm_dirs = sorted([d for d in base_pull_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        print("Nessuna cartella vm trovata in pullFromVM/")
        return

    # 1. Merge Stats
    stats_files = []
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_watch" / "mcp_watch_stats.json"
        if sf.exists():
            stats_files.append(str(sf))
    if stats_files:
        merge_watch_stats(stats_files, str(out_dir / "mcp_watch_stats.json"))

    # 2. Merge Server Logs
    merged_servers = {}
    for vm_d in vm_dirs:
        sf = vm_d / "tool_mcp_watch" / "mcp_watch_servers.json"
        if sf.exists():
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    merged_servers.update(json.load(f))
            except Exception as e:
                pass
    if merged_servers:
        with open(out_dir / "mcp_watch_servers.json", "w", encoding="utf-8") as f:
            json.dump(merged_servers, f, indent=4, ensure_ascii=False)
        print(f"Merge servers completato! Totale entry combinate: {len(merged_servers)}")

    # 3. Merge Categories
    categories = ["toxic-flow", "credential-leak", "tool-poisoning", "prompt-injection", 
                  "tool-mutation", "data-exfiltration", "steganographic-attack", 
                  "protocol-violation", "input-validation", "server-spoofing", "access-control"]
    severities = ["critical", "high", "medium", "low"]

    for cat in categories:
        cat_out_dir = out_dir / cat
        cat_out_dir.mkdir(exist_ok=True)
        for sev in severities:
            json_name = f"{cat.replace('-', '_')}_{sev}.json"
            merged_vulns = []
            file_found = False
            for vm_d in vm_dirs:
                cat_file = vm_d / "tool_mcp_watch" / cat / json_name
                if cat_file.exists():
                    file_found = True
                    try:
                        with open(cat_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            merged_vulns.extend(data.get("findings", data.get("vulnerabilities", [])))
                    except Exception as e:
                        print(f"Errore lettura {cat_file}: {e}")
            
            if file_found and merged_vulns:
                out_file = cat_out_dir / json_name
                out_data = {
                    "category": cat,
                    "severity": sev,
                    "total": len(merged_vulns),
                    "findings": merged_vulns
                }
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(out_data, f, indent=4, ensure_ascii=False)

    print(f"Merge profondo delle categorie completato in {out_dir}")

if __name__ == "__main__":
    pass
