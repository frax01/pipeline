"""
Merge mcp-shield stats from multiple VM runs into a single consolidated file.

Usage:
    python -m tool_mcp_shield.merge_stats
    # or called from deploy.py --merge-shield
"""
import json
import sys
from pathlib import Path


def merge_shield_stats(stats_files: list[str], output_file: str):
    """Merge multiple vm*_stats.json files into a single mcp_shield_stats.json."""
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

    # --- mcp-shield block ---
    shield_total = sum(s.get("mcp-shield", {}).get("total", 0) for s in all_stats)

    # Merge shield languages
    shield_languages = {}
    for s in all_stats:
        for lang, count in s.get("mcp-shield", {}).get("languages", {}).items():
            shield_languages[lang] = shield_languages.get(lang, 0) + count

    # --- Tools ---
    tools_total = sum(s.get("mcp-shield", {}).get("tools", {}).get("total", 0) for s in all_stats)
    tools_safe = sum(s.get("mcp-shield", {}).get("tools", {}).get("safe", 0) for s in all_stats)

    # Vulnerable block
    vuln_total = sum(
        s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {}).get("total", 0)
        for s in all_stats
    )

    # static-analysis: merge categories, counts, percentage_of_vulnerability, percentage_of_severity
    sa_categories = {}
    sa_counts = {}
    for s in all_stats:
        sa = s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {}).get("static-analysis", {})
        for cat, count in sa.get("categories", {}).items():
            sa_categories[cat] = sa_categories.get(cat, 0) + count
        for sev, count in sa.get("counts", {}).items():
            sa_counts[sev] = sa_counts.get(sev, 0) + count

    # Recalculate static-analysis percentages
    sa_percentage_of_vulnerability = {}
    if vuln_total > 0 and sa_categories:
        sa_percentage_of_vulnerability = {
            cat: round((count / vuln_total) * 100, 2)
            for cat, count in sa_categories.items()
        }

    sa_total_counts = sum(sa_counts.values())
    sa_percentage_of_severity = {}
    if sa_total_counts > 0:
        sa_percentage_of_severity = {
            sev: round((count / sa_total_counts) * 100, 2)
            for sev, count in sa_counts.items()
        }

    # llm-description-analysis: merge LOW, MEDIUM, HIGH
    llm_low = sum(
        s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {}).get("llm-description-analysis", {}).get("LOW", 0)
        for s in all_stats
    )
    llm_medium = sum(
        s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {}).get("llm-description-analysis", {}).get("MEDIUM", 0)
        for s in all_stats
    )
    llm_high = sum(
        s.get("mcp-shield", {}).get("tools", {}).get("vulnerable", {}).get("llm-description-analysis", {}).get("HIGH", 0)
        for s in all_stats
    )

    # --- Recalculate percentages ---
    shield_percentage = round((shield_total / merged["total"]) * 100, 2) if merged["total"] > 0 else 0.0
    vuln_avg = round(vuln_total / shield_total, 2) if shield_total > 0 else 0.0
    tools_avg = round(tools_total / shield_total, 2) if shield_total > 0 else 0.0
    tools_pov_safe = round((tools_safe / tools_total) * 100, 2) if tools_total > 0 else 0.0
    tools_pov_vuln = round(((vuln_total) / tools_total) * 100, 2) if tools_total > 0 else 0.0

    merged["mcp-shield"] = {
        "total": shield_total,
        "percentage": shield_percentage,
        "languages": shield_languages,
        "tools": {
            "total": tools_total,
            "safe": tools_safe,
            "vulnerable": {
                "total": vuln_total,
                "average_vulnerable_per_server": vuln_avg,
                "static-analysis": {
                    "categories": sa_categories,
                    "percentage_of_vulnerability": sa_percentage_of_vulnerability,
                    "counts": sa_counts,
                    "percentage_of_severity": sa_percentage_of_severity,
                },
                "llm-description-analysis": {
                    "LOW": llm_low,
                    "MEDIUM": llm_medium,
                    "HIGH": llm_high,
                },
            },
            "average_per_server": tools_avg,
            "percentage_of_vulnerability": {
                "safe": tools_pov_safe,
                "vulnerable": tools_pov_vuln,
            },
        },
    }

    # Write output
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=4, ensure_ascii=False)

    print(f"\n✅ Merge completato!")
    print(f"  Total servers: {merged['total']}")
    print(f"  Shield completed: {shield_total} ({shield_percentage}%)")
    print(f"  Tools: {tools_total} (safe: {tools_safe}, vulnerable: {vuln_total})")
    print(f"  Static-analysis categories: {len(sa_categories)}")
    print(f"  LLM analysis: LOW={llm_low}, MEDIUM={llm_medium}, HIGH={llm_high}")
    print(f"  -> {output_file}")


if __name__ == "__main__":
    shield_dir = Path(__file__).parent
    files = [str(shield_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files")
    if existing:
        merge_shield_stats(existing, str(shield_dir / "mcp_shield_stats.json"))
