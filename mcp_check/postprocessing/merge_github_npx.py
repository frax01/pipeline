"""
Merge GitHub + NPX in mcp_check/.

Layout finale identico a mcp-watch / mcp-security-scan / mcp-scan:
- Categorie analizzate in entrambi → raw + filtered + llm_analysis MERGED
- Categorie analizzate solo in GitHub → kept as-is
- Categorie analizzate solo in NPX → integrate con suffisso file _npx dove serve
- Categorie noise (not_connected, timeout, ...) → skip
- Ogni entry mergiato ha campo _origin: "github" | "npx"

Idempotent: rilevarne se _origin è già presente.
"""
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
NPX = HERE / "npx"

PHASES = ["handshake", "tool_discovery", "tool_invocation"]
SKIP_CATEGORIES = {
    "not_connected", "connection_refused", "timeout",
    "file_not_found", "docker_missing", "macos_specific_failed",
}


def tag_entries(entries, origin):
    """Add _origin only if not already present."""
    for e in entries:
        if "_origin" not in e:
            e["_origin"] = origin
    return entries


def load_json(p):
    return json.load(open(p, "r", encoding="utf-8"))


def save_json(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def merge_entries_lists(gh_entries, npx_entries):
    """Dedupe by (server_url, test_name). Conserva _origin di entrambi."""
    tag_entries(gh_entries, "github")
    tag_entries(npx_entries, "npx")
    seen = set()
    merged = []
    for e in gh_entries + npx_entries:
        # Chiave per dedupe: server + primo test name
        key_test = ""
        for er in e.get("errors", []) or e.get("warnings", []):
            key_test = er.get("test", "")
            break
        key = (e.get("server_url", ""), e.get("_origin", ""), key_test)
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)
    return merged


def merge_raw_category(phase, category):
    """Merge raw files <phase>/<category>/*.json (GH + NPX)."""
    gh_dir = HERE / phase / category
    npx_dir = NPX / phase / category
    if not npx_dir.exists():
        # solo GH: tag entries con _origin
        if gh_dir.exists():
            for f in gh_dir.glob("*.json"):
                if f.name == "details.md":
                    continue
                try:
                    data = load_json(f)
                    if "entries" in data:
                        tag_entries(data["entries"], "github")
                        save_json(f, data)
                except Exception:
                    pass
        return ("github_only", 0, 0)
    if not gh_dir.exists():
        # solo NPX: copy
        shutil.copytree(npx_dir, gh_dir)
        for f in gh_dir.glob("*.json"):
            try:
                data = load_json(f)
                if "entries" in data:
                    tag_entries(data["entries"], "npx")
                    save_json(f, data)
            except Exception:
                pass
        return ("npx_only", 0, 0)

    # Entrambi presenti
    gh_total = 0
    npx_total = 0
    # Process per-file: NPX → GH
    for npx_file in npx_dir.glob("*.json"):
        if npx_file.name == "details.md":
            continue
        try:
            npx_data = load_json(npx_file)
        except Exception:
            continue
        npx_entries = npx_data.get("entries", [])
        if not npx_entries:
            continue
        gh_file = gh_dir / npx_file.name
        if gh_file.exists():
            try:
                gh_data = load_json(gh_file)
            except Exception:
                gh_data = {"entries": []}
            merged_entries = merge_entries_lists(
                gh_data.get("entries", []),
                npx_entries,
            )
            gh_data["entries"] = merged_entries
            gh_data["total"] = len(merged_entries)
            save_json(gh_file, gh_data)
        else:
            # Nuovo file da NPX
            tag_entries(npx_entries, "npx")
            npx_data["entries"] = npx_entries
            save_json(gh_file, npx_data)
        npx_total += len(npx_entries)

    # Tag GH-only files (file presenti in GH ma non in NPX) con _origin: github
    for gh_file in gh_dir.glob("*.json"):
        if gh_file.name == "details.md":
            continue
        npx_file = npx_dir / gh_file.name
        try:
            data = load_json(gh_file)
        except Exception:
            continue
        if "entries" not in data:
            continue
        if not npx_file.exists():
            tag_entries(data["entries"], "github")
            save_json(gh_file, data)
        gh_total += len(data.get("entries", []))

    return ("merged", gh_total, npx_total)


def merge_filtered_category(phase, category):
    """Merge filtered.json se presente in entrambi."""
    cat_short = category.replace("/", "_")
    gh_filt = HERE / phase / category / "filtered" / f"{category}_filtered.json"
    npx_filt = NPX / phase / category / "filtered" / f"{category}_filtered.json"
    if not npx_filt.exists():
        if gh_filt.exists():
            data = load_json(gh_filt)
            tag_entries(data.get("entries", []), "github")
            save_json(gh_filt, data)
        return
    if not gh_filt.exists():
        # copy npx, tag npx
        data = load_json(npx_filt)
        tag_entries(data.get("entries", []), "npx")
        save_json(gh_filt, data)
        return
    gh_data = load_json(gh_filt)
    npx_data = load_json(npx_filt)
    merged = merge_entries_lists(
        gh_data.get("entries", []),
        npx_data.get("entries", []),
    )
    gh_data["entries"] = merged
    gh_data["total"] = len(merged)
    save_json(gh_filt, gh_data)


def merge_llm_analysis_category(phase, category):
    """Merge vp/fp/audit/uncertain/hc_*/cache."""
    gh_dir = HERE / phase / category / "filtered" / "llm_analysis"
    npx_dir = NPX / phase / category / "filtered" / "llm_analysis"
    if not npx_dir.exists():
        if gh_dir.exists():
            for fname in ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]:
                p = gh_dir / fname
                if p.exists():
                    data = load_json(p)
                    if "entries" in data:
                        tag_entries(data["entries"], "github")
                        save_json(p, data)
        return
    if not gh_dir.exists():
        shutil.copytree(npx_dir, gh_dir)
        for fname in ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]:
            p = gh_dir / fname
            if p.exists():
                data = load_json(p)
                if "entries" in data:
                    tag_entries(data["entries"], "npx")
                    save_json(p, data)
        return

    for fname in ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]:
        gh_f = gh_dir / fname
        npx_f = npx_dir / fname
        if not npx_f.exists():
            if gh_f.exists():
                data = load_json(gh_f)
                if "entries" in data:
                    tag_entries(data["entries"], "github")
                    save_json(gh_f, data)
            continue
        if not gh_f.exists():
            data = load_json(npx_f)
            if "entries" in data:
                tag_entries(data["entries"], "npx")
            save_json(gh_f, data)
            continue
        gh_data = load_json(gh_f)
        npx_data = load_json(npx_f)
        gh_entries = gh_data.get("entries", [])
        npx_entries = npx_data.get("entries", [])
        merged = merge_entries_lists(gh_entries, npx_entries)
        gh_data["entries"] = merged
        gh_data["total"] = len(merged)
        save_json(gh_f, gh_data)

    # Cache: union (chiavi server|cat sono uniche)
    gh_cache_f = gh_dir / "_llm_api_cache.json"
    npx_cache_f = npx_dir / "_llm_api_cache.json"
    if npx_cache_f.exists():
        npx_cache = load_json(npx_cache_f)
        gh_cache = load_json(gh_cache_f) if gh_cache_f.exists() else {}
        gh_cache.update(npx_cache)
        save_json(gh_cache_f, gh_cache)


def main():
    print("=" * 70)
    print("  MERGE GitHub + NPX (mcp-check)")
    print("=" * 70)

    # Save stats NPX → mcp_check_stats_npx.json
    npx_stats = NPX / "mcp_check_stats.json"
    npx_servers = NPX / "mcp_check_servers.json"
    if npx_stats.exists():
        shutil.copy(npx_stats, HERE / "mcp_check_stats_npx.json")
    if npx_servers.exists():
        shutil.copy(npx_servers, HERE / "mcp_check_servers_npx.json")
    gh_stats = HERE / "mcp_check_stats.json"
    gh_servers = HERE / "mcp_check_servers.json"
    if gh_stats.exists() and not (HERE / "mcp_check_stats_github.json").exists():
        shutil.copy(gh_stats, HERE / "mcp_check_stats_github.json")
    if gh_servers.exists() and not (HERE / "mcp_check_servers_github.json").exists():
        shutil.copy(gh_servers, HERE / "mcp_check_servers_github.json")

    summary = []
    for phase in PHASES:
        npx_phase = NPX / phase
        if not npx_phase.exists():
            continue
        for cat_dir in sorted(npx_phase.iterdir()):
            if not cat_dir.is_dir():
                continue
            category = cat_dir.name
            if category in SKIP_CATEGORIES:
                print(f"  SKIP {phase}/{category}: noise")
                continue
            status, gh_n, npx_n = merge_raw_category(phase, category)
            merge_filtered_category(phase, category)
            merge_llm_analysis_category(phase, category)
            print(f"  {phase}/{category}: {status} (GH raw={gh_n} NPX raw={npx_n})")
            summary.append((phase, category, status, gh_n, npx_n))

    # Tag anche le categorie GH-only (presenti in GH ma NON in NPX)
    for phase in PHASES:
        gh_phase = HERE / phase
        for cat_dir in sorted(gh_phase.iterdir()):
            if not cat_dir.is_dir():
                continue
            category = cat_dir.name
            if category in SKIP_CATEGORIES:
                continue
            if (NPX / phase / category).exists():
                continue
            # GH-only: tag with _origin: github
            merge_raw_category(phase, category)
            merge_filtered_category(phase, category)
            merge_llm_analysis_category(phase, category)
            print(f"  {phase}/{category}: github_only_tagged")

    print(f"\nMerge complete: {len(summary)} categorie processate")


if __name__ == "__main__":
    main()
