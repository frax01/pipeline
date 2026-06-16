#!/usr/bin/env python3
"""
Merge GitHub + NPX per mcp-guard (19 categorie).

Tutte le 19 categorie esistono in entrambi i run. Merge:
  <cat>/filtered/<safe>_filtered.json           raw MERGED (+ _origin)
  <cat>/filtered/llm_analysis/{vp,fp,audit,hc_vp,hc_fp,uncertain}.json  MERGED

I server_url NPX sono nomi pacchetto npm (no github.com) → namespace disgiunto
da GitHub, nessuna collisione. Ogni finding ha _origin: github|npx.

Idempotente: rileva _origin gia' presente.
"""
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
NPX = HERE / "npx"

CATEGORIES = [
    "command-injection-static", "code-injection-static", "insecure-deserialization-static",
    "prompt-injection-static", "dangerous-tool-handler-static", "path-traversal-static",
    "sql-injection-static", "hardcoded-credential-static", "ssrf-static",
    "code-injection-fuzzing", "information-disclosure-fuzzing", "command-injection-fuzzing",
    "path-traversal-fuzzing", "command-execution-fuzzing", "sensitive-info-disclosed-fuzzing",
    "protocol-information-disclosure", "protocol-path-traversal", "protocol-missing-id",
    "protocol-invalid-jsonrpc-version",
]
LLM_FILES = ["vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json"]


def origin_of(url):
    u = url or ""
    return "github" if u.startswith("http://github.com/") or u.startswith("https://github.com/") else "npx"


def load(p):
    return json.load(open(p, encoding="utf-8"))


def save(p, d):
    json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


def tag(findings, origin):
    for f in findings:
        if "_origin" not in f:
            f["_origin"] = origin
    return findings


def get_list(d):
    """findings key varia: 'findings'."""
    return d.get("findings", [])


def merge_json(gh_path, npx_path, default_origin_gh="github"):
    """Merge un singolo file json con chiave 'findings'."""
    if not npx_path.exists():
        if gh_path.exists():
            d = load(gh_path); tag(get_list(d), default_origin_gh); save(gh_path, d)
        return
    npx_d = load(npx_path)
    npx_f = tag(get_list(npx_d), "npx")
    if gh_path.exists():
        gh_d = load(gh_path)
        gh_f = tag(get_list(gh_d), "github")
        gh_d["findings"] = gh_f + npx_f
        if "kept_total" in gh_d:
            gh_d["kept_total"] = len(gh_d["findings"])
        if "total" in gh_d:
            gh_d["total"] = len(gh_d["findings"])
        save(gh_path, gh_d)
    else:
        npx_d["findings"] = npx_f
        save(gh_path, npx_d)


def main():
    print("=" * 64)
    print("  MERGE GitHub + NPX (mcp-guard, 19 categorie)")
    print("=" * 64)

    # stats backup
    for nm in ("mcp_guard_stats.json", "mcp_guard_servers.json"):
        npx_s = NPX / nm
        if npx_s.exists():
            shutil.copy(npx_s, HERE / nm.replace(".json", "_npx.json"))

    for cat in CATEGORIES:
        safe = cat.replace("/", "_").replace("-", "_")
        gh_filt = HERE / cat / "filtered" / f"{safe}_filtered.json"
        npx_filt = NPX / cat / "filtered" / f"{safe}_filtered.json"
        merge_json(gh_filt, npx_filt)
        gh_la = HERE / cat / "filtered" / "llm_analysis"
        npx_la = NPX / cat / "filtered" / "llm_analysis"
        for fn in LLM_FILES:
            merge_json(gh_la / fn, npx_la / fn)
        # cache union
        gh_cache = gh_la / "_llm_api_cache.json"
        npx_cache = npx_la / "_llm_api_cache.json"
        if npx_cache.exists():
            nc = load(npx_cache)
            gc = load(gh_cache) if gh_cache.exists() else {}
            if isinstance(gc, dict) and isinstance(nc, dict):
                gc.update(nc); save(gh_cache, gc)
        # conteggio
        try:
            vp = load(gh_la / "vp.json"); fp = load(gh_la / "fp.json")
            v = get_list(vp); f = get_list(fp)
            nvp = sum(1 for x in v if x.get("_origin") == "npx")
            print(f"  {cat:34s} VP={len(v):4d} (npx +{nvp:3d})  FP={len(f):5d}")
        except Exception as e:
            print(f"  {cat}: {e}")

    print("\nMerge completato.")


if __name__ == "__main__":
    main()
