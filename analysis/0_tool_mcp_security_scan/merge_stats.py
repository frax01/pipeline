"""
Merge mcp-security-scan stats from multiple VM runs into a single consolidated file.

Usage:
    python -m tool_mcp_security_scan.merge_stats
    # or called from deploy.py --merge-security-scan
"""
import json
import sys
from pathlib import Path


def merge_security_scan_stats(stats_files: list[str], output_file: str):
    """Merge multiple vm*_stats.json files into a single mcp_security_scan_stats.json."""
    all_stats = []
    for f in stats_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if data and "total" in data:
                    all_stats.append(data)
                    print(f"  Loaded {f}: total={data.get('total', 0)}, last_index={data.get('last_index', 0)}")
        except Exception as e:
            print(f"  Skipping {f}: {e}")

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

    # --- mcp-security-scan block ---
    fw_key = "mcp-security-scan"
    fw_total = sum(s.get(fw_key, {}).get("total", 0) for s in all_stats)

    # Merge framework languages
    fw_languages = {}
    for s in all_stats:
        for lang, count in s.get(fw_key, {}).get("languages", {}).items():
            fw_languages[lang] = fw_languages.get(lang, 0) + count

    # Merge categories
    merged_categories = {}
    for s in all_stats:
        for cat, count in s.get(fw_key, {}).get("categories", {}).items():
            merged_categories[cat] = merged_categories.get(cat, 0) + count

    # Merge categories_passed
    merged_categories_passed = {}
    for s in all_stats:
        for cat, count in s.get(fw_key, {}).get("categories_passed", {}).items():
            merged_categories_passed[cat] = merged_categories_passed.get(cat, 0) + count

    # Merge vulnerabilities
    vuln_total = sum(s.get(fw_key, {}).get("vulnerabilities", {}).get("total", 0) for s in all_stats)

    # Merge severity counts
    merged_severity_counts = {}
    for s in all_stats:
        for sev, count in s.get(fw_key, {}).get("vulnerabilities", {}).get("counts", {}).items():
            merged_severity_counts[sev] = merged_severity_counts.get(sev, 0) + count

    # Severity percentages (0-100 scale, consistent with per-VM stats)
    percentage_of_severity = {}
    if vuln_total > 0 and merged_severity_counts:
        percentage_of_severity = {
            sev: round((count / vuln_total) * 100, 2)
            for sev, count in merged_severity_counts.items()
        }

    # Merge findings
    findings_total = sum(s.get(fw_key, {}).get("findings", {}).get("total", 0) for s in all_stats)
    findings_passed = sum(s.get(fw_key, {}).get("findings", {}).get("passed", 0) for s in all_stats)
    findings_failed = sum(s.get(fw_key, {}).get("findings", {}).get("failed", 0) for s in all_stats)

    # --- Recalculate percentages ---
    fw_percentage = round((fw_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    vuln_avg = round(vuln_total / fw_total, 2) if fw_total > 0 else 0.0
    findings_pct_passed = round((findings_passed / findings_total) * 100, 2) if findings_total > 0 else 0.0

    # percentage_of_vulnerability: distribution of categories over total vulnerabilities
    percentage_of_vulnerability = {}
    if vuln_total > 0 and merged_categories:
        percentage_of_vulnerability = {
            cat: round((count / vuln_total) * 100, 2)
            for cat, count in merged_categories.items()
        }

    merged[fw_key] = {
        "total": fw_total,
        "percentage": fw_percentage,
        "languages": fw_languages,
        "percentage_of_vulnerability": percentage_of_vulnerability,
        "categories": merged_categories,
        "categories_passed": merged_categories_passed,
        "vulnerabilities": {
            "total": vuln_total,
            "average_per_server": vuln_avg,
            "counts": merged_severity_counts,
            "percentage_of_severity": percentage_of_severity,
        },
        "findings": {
            "total": findings_total,
            "passed": findings_passed,
            "failed": findings_failed,
            "percentage_passed": findings_pct_passed,
        }
    }

    # Write output
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)

    print(f"\nMerge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Security scan completed: {fw_total} ({fw_percentage}%)")
    print(f"  Vulnerabilities: {vuln_total} (avg {vuln_avg}/server)")
    print(f"  Findings: {findings_total} (passed: {findings_passed}, failed: {findings_failed}, {findings_pct_passed}% passed)")
    print(f"  Categories: {len(merged_categories)}")
    print(f"  -> {output_file}")


if __name__ == "__main__":
    scan_dir = Path(__file__).parent
    files = [str(scan_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files")
    if existing:
        merge_security_scan_stats(existing, str(scan_dir / "mcp_security_scan_stats.json"))
