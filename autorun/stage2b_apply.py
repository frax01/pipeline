#!/usr/bin/env python3
"""
stage2b_apply.py — riapplica i verdetti Sonnet dello Stage 2B.

Espande i verdetti per *cluster* (prodotti dai subagent in
autorun/stage2b/verdicts/) sui singoli finding UNCERTAIN e li scrive nel file
`_llm_api_cache.json` che ogni stage2_pipeline.py gia' usa. Dopodiche' il merge
ufficiale della pipeline (`stage2_pipeline.py --category all --merge`) produce
vp.json / fp.json / audit.json senza che serva alcun LLM.

Ogni tool ha il suo schema di chiave di cache: qui sono replicati fedelmente
(guard: server|file|line oppure server|cat|payload; shield: server/tool/cat;
security_scan: server; check: server|fase/categoria).

Uso:
    python autorun/stage2b_apply.py --check      # valida copertura dei verdetti
    python autorun/stage2b_apply.py --apply      # scrive le cache
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "autorun" / "stage2b"
VERDICTS = OUT / "verdicts"

TOOL_OF = {"mcp_guard": "guard", "mcp_watch": "watch", "fuzzing": "fuzzing",
           "mcp_scan": "scan", "mcp_shield": "shield",
           "mcp_security_scan": "security_scan", "mcp_check": "check"}


def server_short(url):
    return (url or "").replace("https://github.com/", "")


def extract_line(desc):
    m = re.search(r"at line (\d+)", desc or "")
    return m.group(1) if m else "?"


def cat_from_src(src: str, tool: str) -> str:
    """Ricava la chiave di categoria dal percorso di uncertain.json."""
    parts = src.split("/")
    i = parts.index("postprocessing")
    tail = parts[i + 1:]
    # taglia i livelli di servizio finali
    for stop in ("filtered", "llm_analysis"):
        if stop in tail:
            tail = tail[:tail.index(stop)]
    return "/".join(tail)


def cache_key(tool: str, f: dict, cat: str) -> str:
    if tool == "guard":
        payload = f.get("payload", "")
        if payload:
            return f"{server_short(f.get('server_url', ''))}|{cat}|{payload[:40]}"
        return (f"{server_short(f.get('server_url', ''))}|{f.get('file', '')}"
                f"|{extract_line(f.get('description', ''))}")
    if tool == "shield":
        return f"{f.get('server_name', '')}/{f.get('tool_name', '')}/{f.get('category', '')}"
    if tool == "security_scan":
        return server_short(f.get("server_url", ""))
    if tool == "check":
        return f"{server_short(f.get('server_url', ''))}|{cat}"
    if tool == "watch":
        return (f"{f.get('server_name', '')}/{f.get('file', '')}"
                f"/{f.get('line', 0)}/{f.get('id', '')}")
    return server_short(f.get("server_url", ""))


def load_verdicts() -> dict:
    """cluster_id -> {verdict, reason}"""
    v = {}
    dupes = 0
    for p in sorted(VERDICTS.glob("verdict_*.json")):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  [ERRORE] {p.name} illeggibile: {e}")
            continue
        for r in d.get("verdetti", []):
            cid, vd = r.get("id"), (r.get("verdetto") or "").upper()
            if not cid or vd not in ("VP", "FP"):
                continue
            if cid in v:
                dupes += 1
                continue
            v[cid] = {"verdict": vd, "reason": f"sonnet: {r.get('motivo', '')}"[:300]}
    if dupes:
        print(f"  [nota] {dupes} verdetti duplicati ignorati (tenuto il primo)")
    return v


def load_index() -> dict:
    return json.load(open(OUT / "index.json", encoding="utf-8"))


def build_member_map(index: dict) -> dict:
    """(src, i) -> cluster_id"""
    m = {}
    for cid, members in index.items():
        for mem in members:
            m[(mem["src"], mem["i"])] = cid
    return m


def iter_uncertain_files():
    for p in sorted(REPO.glob("*/postprocessing/**/uncertain.json")):
        tool = TOOL_OF.get(p.relative_to(REPO).parts[0])
        if tool:
            yield tool, p


def run(apply: bool):
    verdicts = load_verdicts()
    index = load_index()
    member = build_member_map(index)
    print(f"cluster con verdetto : {len(verdicts):,} / {len(index):,}")

    tot = mapped = missing = 0
    per_tool = defaultdict(Counter)
    written = 0

    for tool, p in iter_uncertain_files():
        rel = p.relative_to(REPO).as_posix()
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        items = d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])
        if not items:
            continue
        cat = (d.get("category") if isinstance(d, dict) else None) or cat_from_src(rel, tool)
        cat_path = cat_from_src(rel, tool)

        # ogni tool ha il suo nome di file di cache: watch usa _ollama_cache.json,
        # gli altri _llm_api_cache.json (vedi _cache_path/_load_cache nei rispettivi
        # stage2_pipeline.py). Scrivere il nome sbagliato fa ripartire le chiamate LLM.
        cache_name = "_ollama_cache.json" if tool == "watch" else "_llm_api_cache.json"
        cache_path = p.parent / cache_name
        cache = {}
        if cache_path.exists():
            try:
                cache = json.load(open(cache_path, encoding="utf-8"))
            except Exception:
                cache = {}

        for i, f in enumerate(items):
            tot += 1
            cid = member.get((rel, i))
            vd = verdicts.get(cid) if cid else None
            if not vd:
                missing += 1
                continue
            mapped += 1
            per_tool[tool][vd["verdict"]] += 1
            key = cache_key(tool, f, cat if tool == "guard" else cat_path)
            cache[key] = vd

        if apply and cache:
            json.dump(cache, open(cache_path, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=2)
            written += 1

    print(f"finding UNCERTAIN    : {tot:,}")
    print(f"  con verdetto       : {mapped:,}")
    print(f"  SENZA verdetto     : {missing:,}")
    print()
    for tool, c in sorted(per_tool.items()):
        print(f"  {tool:<16} VP={c['VP']:>5}  FP={c['FP']:>5}")
    if apply:
        print(f"\ncache scritte: {written} file _llm_api_cache.json")
    else:
        print("\n(dry-run: nessun file scritto — usa --apply)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    run(apply=a.apply)


if __name__ == "__main__":
    main()
