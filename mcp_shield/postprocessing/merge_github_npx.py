"""
Merge GitHub + NPX in mcp_shield/.

Layout finale identico a mcp-watch / mcp-check / mcp-security-scan / mcp-scan:
- 4 categorie tutte presenti in entrambi i run → raw + llm_analysis MERGED
- Ogni finding mergiato ha campo `_origin: "github" | "npx"`
- mcp-shield ha struttura semplice: <cat>/<cat>_HIGH.json + <cat>_MEDIUM.json + llm_analysis/

Idempotent: rileva se `_origin` è già presente.
"""
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
NPX = HERE / "npx"

CATEGORIES = [
    "hidden-instructions",
    "shadowing-detected",
    "potential-exfiltration",
    "sensitive-file-access",
]


def tag_findings(findings, origin):
    for f in findings:
        if "_origin" not in f:
            f["_origin"] = origin
    return findings


def load_json(p):
    return json.load(open(p, "r", encoding="utf-8"))


def save_json(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def merge_findings(gh_list, npx_list):
    """Concatena GH + NPX, dedupe per (server_name, tool_name, category, _origin)."""
    tag_findings(gh_list, "github")
    tag_findings(npx_list, "npx")
    seen = set()
    out = []
    for f in gh_list + npx_list:
        key = (
            f.get("server_name", ""),
            f.get("tool_name", ""),
            f.get("category", ""),
            f.get("_origin", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def merge_raw_category(category):
    """Merge <cat>/<cat>_HIGH.json + <cat>_MEDIUM.json."""
    cat_name = category.replace("-", "_")
    for sev in ("HIGH", "MEDIUM"):
        gh_f = HERE / category / f"{cat_name}_{sev}.json"
        npx_f = NPX / category / f"{cat_name}_{sev}.json"
        if not npx_f.exists() and not gh_f.exists():
            continue
        if not npx_f.exists():
            # solo GH: tag _origin
            data = load_json(gh_f)
            if isinstance(data, list):
                tag_findings(data, "github")
                save_json(gh_f, data)
            elif isinstance(data, dict) and "findings" in data:
                tag_findings(data["findings"], "github")
                save_json(gh_f, data)
            continue
        if not gh_f.exists():
            # solo NPX: copy + tag
            data = load_json(npx_f)
            if isinstance(data, list):
                tag_findings(data, "npx")
            elif isinstance(data, dict) and "findings" in data:
                tag_findings(data["findings"], "npx")
            save_json(gh_f, data)
            continue
        # Entrambi
        gh_data = load_json(gh_f)
        npx_data = load_json(npx_f)
        gh_list = gh_data if isinstance(gh_data, list) else gh_data.get("findings", [])
        npx_list = npx_data if isinstance(npx_data, list) else npx_data.get("findings", [])
        merged = merge_findings(gh_list, npx_list)
        if isinstance(gh_data, list):
            save_json(gh_f, merged)
        else:
            gh_data["findings"] = merged
            gh_data["total"] = len(merged)
            save_json(gh_f, gh_data)


def merge_llm_analysis_category(category):
    """Merge llm_analysis/{hc_vp,hc_fp,uncertain,vp,fp,audit}.json + cache."""
    gh_dir = HERE / category / "llm_analysis"
    npx_dir = NPX / category / "llm_analysis"
    if not npx_dir.exists():
        if gh_dir.exists():
            for fname in ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]:
                p = gh_dir / fname
                if p.exists():
                    data = load_json(p)
                    if "findings" in data:
                        tag_findings(data["findings"], "github")
                        save_json(p, data)
        return

    for fname in ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]:
        gh_f = gh_dir / fname
        npx_f = npx_dir / fname
        if not npx_f.exists():
            if gh_f.exists():
                data = load_json(gh_f)
                if "findings" in data:
                    tag_findings(data["findings"], "github")
                    save_json(gh_f, data)
            continue
        if not gh_f.exists():
            data = load_json(npx_f)
            if "findings" in data:
                tag_findings(data["findings"], "npx")
            save_json(gh_f, data)
            continue
        gh_data = load_json(gh_f)
        npx_data = load_json(npx_f)
        gh_list = gh_data.get("findings", [])
        npx_list = npx_data.get("findings", [])
        merged = merge_findings(gh_list, npx_list)
        gh_data["findings"] = merged
        gh_data["total"] = len(merged)
        save_json(gh_f, gh_data)

    # Cache: union
    gh_cache_f = gh_dir / "_llm_api_cache.json"
    npx_cache_f = npx_dir / "_llm_api_cache.json"
    if npx_cache_f.exists():
        npx_cache = load_json(npx_cache_f)
        gh_cache = load_json(gh_cache_f) if gh_cache_f.exists() else {}
        gh_cache.update(npx_cache)
        save_json(gh_cache_f, gh_cache)


def main():
    print("=" * 70)
    print("  MERGE GitHub + NPX (mcp-shield)")
    print("=" * 70)

    # Stats GH backup
    gh_stats = HERE / "mcp_shield_stats.json"
    gh_servers = HERE / "mcp_shield_servers.json"
    if gh_stats.exists() and not (HERE / "mcp_shield_stats_github.json").exists():
        shutil.copy(gh_stats, HERE / "mcp_shield_stats_github.json")
    if gh_servers.exists() and not (HERE / "mcp_shield_servers_github.json").exists():
        shutil.copy(gh_servers, HERE / "mcp_shield_servers_github.json")

    # NPX stats
    npx_stats = NPX / "mcp_shield_stats.json"
    npx_servers = NPX / "mcp_shield_servers.json"
    if npx_stats.exists():
        shutil.copy(npx_stats, HERE / "mcp_shield_stats_npx.json")
    if npx_servers.exists():
        shutil.copy(npx_servers, HERE / "mcp_shield_servers_npx.json")

    for cat in CATEGORIES:
        print(f"\n  Categoria: {cat}")
        merge_raw_category(cat)
        merge_llm_analysis_category(cat)
        print(f"    OK")

    print(f"\nMerge complete: {len(CATEGORIES)} categorie")


if __name__ == "__main__":
    main()
