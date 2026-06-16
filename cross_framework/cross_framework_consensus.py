#!/usr/bin/env python3
"""
cross_framework_consensus.py — Aggrega VP da 7 framework, tier classification.

Output:
  cross_framework_consensus_vp.json  — per-server tier + framework breakdown
  top_50_vulnerable_servers.json      — top 50 server più vulnerabili
  cross_framework_stats.json          — statistiche aggregate

Esecuzione:
  py -X utf8 cross_framework_consensus.py
"""

import json
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

BASE = Path(__file__).parent
# Dopo il merge per-tool i dati stanno in <repo>/*/postprocessing/...: la root e' il parent.
REPO = BASE.parent

# Map directory → framework name
FRAMEWORK_MAP = {
    "mcp_guard": "mcp-guard",
    "mcp_watch": "mcp-watch",
    "mcp_scan": "mcp-scan",
    "mcp_shield": "mcp-shield",
    "mcp_security_scan": "mcp-security-scan",
    "mcp_check": "mcp-check",
    "fuzzing": "tool_fuzzing",
}


def get_framework(path: Path) -> str | None:
    """Estrai nome framework da path."""
    parts = path.parts
    for p in parts:
        if p in FRAMEWORK_MAP:
            return FRAMEWORK_MAP[p]
    return None


def get_category(path: Path) -> str:
    """Estrai categoria da path (relative dirname)."""
    # Path tipo: mcp_guard/sql-injection-static/filtered/llm_analysis/vp.json
    # Categoria = parent of 'filtered'
    parts = list(path.parts)
    try:
        idx = parts.index("filtered")
        # Take all parts between framework dir and 'filtered'
        for p in parts[:idx]:
            if p in FRAMEWORK_MAP:
                cat_parts = parts[parts.index(p) + 1:idx]
                # salta il livello 'analysis/' introdotto dal merge per-tool
                if cat_parts and cat_parts[0] == "postprocessing":
                    cat_parts = cat_parts[1:]
                return "/".join(cat_parts) if cat_parts else "?"
    except ValueError:
        pass
    return "?"


def normalize_server_url(url: str) -> str:
    """Normalizza URL per merging."""
    if not url:
        return ""
    u = url.strip().rstrip("/")
    # Normalizza https://github.com → consistent format
    u = u.replace("http://github.com/", "https://github.com/")
    return u


def main():
    print("=== Cross-framework Consensus VP Aggregator ===\n")

    # Collect all VP findings
    # Structure: {server_url: {framework: [vp_records]}}
    server_vps = defaultdict(lambda: defaultdict(list))
    framework_totals = Counter()
    category_totals = defaultdict(Counter)  # framework → category → count

    vp_files = sorted(REPO.rglob("vp.json"))
    vp_files = [p for p in vp_files if "llm_analysis" in p.parts]
    print(f"Found {len(vp_files)} vp.json files\n")

    total_vp_loaded = 0
    for vp_file in vp_files:
        framework = get_framework(vp_file)
        if not framework:
            continue
        category = get_category(vp_file)

        try:
            with open(vp_file, encoding="utf-8") as f:
                d = json.load(f)
        except Exception as e:
            print(f"  [WARN] cannot read {vp_file}: {e}")
            continue

        # Support: 'findings' (most), 'entries' (mcp-check)
        if isinstance(d, dict):
            findings = d.get("findings") or d.get("entries") or []
        else:
            findings = d
        for fi in findings:
            if not isinstance(fi, dict):
                continue
            # Support: 'server_url' (most), 'github_url' (mcp-watch)
            server_url = normalize_server_url(
                fi.get("server_url") or fi.get("github_url") or ""
            )
            if not server_url:
                continue

            vp_record = {
                "framework": framework,
                "category": category,
                "tool_name": fi.get("tool_name", "") or fi.get("protocol_type", ""),
                "file": fi.get("file", ""),
                "vuln_id": fi.get("id", "") or fi.get("category", ""),
                "stage": fi.get("_stage", "?"),
                "reason": fi.get("_hc_reason") or fi.get("_llm_reason") or "-",
            }
            server_vps[server_url][framework].append(vp_record)
            framework_totals[framework] += 1
            category_totals[framework][category] += 1
            total_vp_loaded += 1

    print(f"Total VP loaded: {total_vp_loaded:,}")
    print(f"Unique servers with VP: {len(server_vps):,}\n")

    # Framework summary
    print("VP per framework:")
    for fw, c in framework_totals.most_common():
        print(f"  {c:>6,}  {fw}")
    print()

    # Tier classification per server
    server_summary = {}
    tier_counts = Counter()

    for server_url, by_framework in server_vps.items():
        n_frameworks = len(by_framework)
        total_vps = sum(len(vps) for vps in by_framework.values())
        if n_frameworks >= 4:
            tier = "Tier 1"
        elif n_frameworks >= 2:
            tier = "Tier 2"
        else:
            tier = "Tier 3"
        tier_counts[tier] += 1

        # Categories cross-framework
        all_categories = set()
        for fw, vps in by_framework.items():
            for v in vps:
                all_categories.add(f"{fw}:{v['category']}")

        server_summary[server_url] = {
            "tier": tier,
            "n_frameworks": n_frameworks,
            "frameworks": sorted(by_framework.keys()),
            "total_vps": total_vps,
            "vps_per_framework": {fw: len(vps) for fw, vps in by_framework.items()},
            "unique_categories": len(all_categories),
            "categories": sorted(all_categories),
        }

    print("Tier distribution:")
    for tier in ["Tier 1", "Tier 2", "Tier 3"]:
        c = tier_counts.get(tier, 0)
        print(f"  {tier}: {c:,} servers")
    print()

    # Top 50 most vulnerable
    sorted_servers = sorted(
        server_summary.items(),
        key=lambda x: (-x[1]["n_frameworks"], -x[1]["total_vps"]),
    )
    top_50 = sorted_servers[:50]

    print("=== Top 10 Most Vulnerable Servers ===")
    for i, (url, info) in enumerate(top_50[:10], 1):
        short = url.replace("https://github.com/", "")
        fwks = ", ".join(info["frameworks"])
        print(f"  {i:>2}. [{info['tier']}] {short[:50]:50} "
              f"| {info['n_frameworks']} fw | {info['total_vps']:>4} VPs | {fwks}")
    print()

    # Save outputs
    print("Saving outputs...")

    # 1. cross_framework_consensus_vp.json
    out1 = {
        "_meta": {
            "total_vp_loaded": total_vp_loaded,
            "unique_servers": len(server_summary),
            "tier_distribution": dict(tier_counts),
            "framework_totals": dict(framework_totals),
        },
        "servers": server_summary,
    }
    with open(BASE / "cross_framework_consensus_vp.json", "w", encoding="utf-8") as f:
        json.dump(out1, f, ensure_ascii=False, indent=2)
    print(f"  → cross_framework_consensus_vp.json ({len(server_summary):,} servers)")

    # 2. top_50_vulnerable_servers.json
    top_50_payload = {
        "_meta": {
            "total_vp": total_vp_loaded,
            "unique_servers": len(server_summary),
            "framework_totals": dict(framework_totals),
        },
        "top_50": [
            {
                "rank": i,
                "server_url": url,
                "tier": info["tier"],
                "n_frameworks": info["n_frameworks"],
                "frameworks": info["frameworks"],
                "total_vps": info["total_vps"],
                "vps_per_framework": info["vps_per_framework"],
                "unique_categories": info["unique_categories"],
                "categories": info["categories"][:30],  # limita output
            }
            for i, (url, info) in enumerate(top_50, 1)
        ],
    }
    with open(BASE / "top_50_vulnerable_servers.json", "w", encoding="utf-8") as f:
        json.dump(top_50_payload, f, ensure_ascii=False, indent=2)
    print(f"  → top_50_vulnerable_servers.json")

    # 3. cross_framework_stats.json
    # Categories breakdown per framework
    cat_stats = {fw: dict(cats) for fw, cats in category_totals.items()}

    # Tier breakdown by framework — quanti server tier1 trovati da ogni framework
    tier_per_framework = defaultdict(lambda: defaultdict(int))
    for url, info in server_summary.items():
        for fw in info["frameworks"]:
            tier_per_framework[fw][info["tier"]] += 1

    stats = {
        "totals": {
            "total_vp_loaded": total_vp_loaded,
            "unique_servers_with_vp": len(server_summary),
            "framework_totals": dict(framework_totals),
        },
        "tiers": {
            "Tier 1 (4+ frameworks)": tier_counts.get("Tier 1", 0),
            "Tier 2 (2-3 frameworks)": tier_counts.get("Tier 2", 0),
            "Tier 3 (1 framework)": tier_counts.get("Tier 3", 0),
        },
        "categories_per_framework": cat_stats,
        "tier_per_framework": {
            fw: dict(tiers) for fw, tiers in tier_per_framework.items()
        },
    }
    with open(BASE / "cross_framework_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"  → cross_framework_stats.json")

    print("\nDone.")


if __name__ == "__main__":
    main()
