#!/usr/bin/env python3
"""
merge6.py — unisce gli shard scaricati da pull6.py in un unico set per tool.

Gli shard di uno stesso tool hanno struttura identica: ogni file di categoria e'
{"total": N, "<chiave_lista>": [...]} dove la chiave e' vulnerabilities /
findings / entries a seconda del tool. Il merge concatena le liste per *percorso
relativo* (quindi funziona anche con l'annidamento di guard, static/other/..., e
di check, <fase>/<categoria>/...).

Output in <DEST>/_merged/<tool>/ con la stessa struttura relativa degli shard:
e' esattamente il layout che gli stage1_filter.py / stage2_pipeline.py si
aspettano dentro <tool>/postprocessing/.

Uso:
    python autorun/merge6.py --merge                 # unisce tutti i tool
    python autorun/merge6.py --merge --tool guard
    python autorun/merge6.py --install               # copia i merged in <tool>/postprocessing/
"""
import argparse
import json
import shutil
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEST = Path(r"C:\Users\francesco\Desktop\pipeline_rerun_pull")
MERGED = DEST / "_merged"

LIST_KEYS = ("vulnerabilities", "findings", "entries", "servers")

# tool -> cartella del repo che ospita il postprocessing
TOOL_DIR = {
    "guard": "mcp_guard", "watch": "mcp_watch", "fuzzing": "fuzzing",
    "scan": "mcp_scan", "shield": "mcp_shield",
    "security_scan": "mcp_security_scan", "check": "mcp_check",
}

STATS_SUFFIX = "_stats.json"
SERVERS_SUFFIX = "_servers.json"


def list_key(d: dict):
    for k in LIST_KEYS:
        if isinstance(d.get(k), list):
            return k
    return None


def merge_tool(tool: str) -> dict:
    src = DEST / tool
    if not src.is_dir():
        return {"tool": tool, "errore": "nessuno shard scaricato"}
    shards = sorted(p for p in src.iterdir() if p.is_dir())
    out_root = MERGED / tool
    if out_root.exists():
        shutil.rmtree(out_root)

    # 1) file di categoria, raggruppati per percorso relativo
    by_rel = defaultdict(list)
    stats_files, servers_files = [], []
    for sh in shards:
        for p in sh.rglob("*.json"):
            rel = p.relative_to(sh)
            if len(rel.parts) == 1:                       # file di primo livello
                if p.name.endswith(STATS_SUFFIX):
                    stats_files.append(p); continue
                if p.name.endswith(SERVERS_SUFFIX):
                    servers_files.append(p); continue
            by_rel[rel].append(p)

    n_files = n_items = 0
    for rel, paths in sorted(by_rel.items()):
        merged, key = [], None
        for p in paths:
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception as e:
                print(f"    [WARN] illeggibile {p}: {e}")
                continue
            if isinstance(d, list):
                merged.extend(d); key = key or "findings"; continue
            k = list_key(d)
            if k is None:
                continue
            key = key or k
            merged.extend(d.get(k, []))
        if not merged:
            continue
        outp = out_root / rel
        outp.parent.mkdir(parents=True, exist_ok=True)
        json.dump({"total": len(merged), key: merged}, open(outp, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        n_files += 1
        n_items += len(merged)

    # 2) servers: mappa url -> stato, unione
    servers = {}
    for p in servers_files:
        try:
            d = json.load(open(p, encoding="utf-8"))
            if isinstance(d, dict):
                servers.update(d)
        except Exception:
            pass
    if servers:
        name = servers_files[0].name
        json.dump(servers, open(out_root / name, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)

    # 3) stats: tiene i singoli + un riepilogo di copertura
    per_shard = []
    for p in sorted(stats_files):
        try:
            d = json.load(open(p, encoding="utf-8"))
            per_shard.append({"shard": p.parent.name, "range_start": d.get("range_start"),
                              "range_end": d.get("range_end"), "last_index": d.get("last_index"),
                              "total": d.get("total")})
        except Exception:
            pass
    if per_shard:
        json.dump({"shards": per_shard}, open(out_root / "_stats_per_shard.json", "w",
                                              encoding="utf-8"), ensure_ascii=False, indent=1)

    return {"tool": tool, "shard": len(shards), "file_categoria": n_files,
            "findings_totali": n_items, "server_nel_registro": len(servers)}


def cmd_merge(only=None):
    tools = [only] if only else [t for t in TOOL_DIR if (DEST / t).is_dir()]
    print(f"{'tool':<15} {'shard':>6} {'file':>6} {'findings':>12} {'registro':>9}")
    for t in tools:
        r = merge_tool(t)
        if "errore" in r:
            print(f"{t:<15} {r['errore']}")
        else:
            print(f"{r['tool']:<15} {r['shard']:>6} {r['file_categoria']:>6} "
                  f"{r['findings_totali']:>12,} {r['server_nel_registro']:>9,}")
    print(f"\nmerged in: {MERGED}")


def cmd_install(only=None):
    """Copia i merged dentro <tool>/postprocessing/ dove gli stage li cercano."""
    tools = [only] if only else [t for t in TOOL_DIR if (MERGED / t).is_dir()]
    for t in tools:
        src = MERGED / t
        dst = REPO / TOOL_DIR[t] / "postprocessing"
        dst.mkdir(parents=True, exist_ok=True)
        n = 0
        for p in src.rglob("*"):
            if p.is_file():
                target = dst / p.relative_to(src)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, target)
                n += 1
        print(f"  {t:<15} {n:>5} file -> {dst.relative_to(REPO)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--merge", action="store_true")
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--tool", default=None, choices=sorted(TOOL_DIR))
    a = ap.parse_args()
    if a.merge or not (a.merge or a.install):
        cmd_merge(a.tool)
    if a.install:
        cmd_install(a.tool)


if __name__ == "__main__":
    main()
