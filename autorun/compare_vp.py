#!/usr/bin/env python3
"""
compare_vp.py — confronta i Veri Positivi della rirun con quelli della prima analisi.

  nuovo:   <repo>/<tool_dir>/postprocessing/<categoria>/filtered/llm_analysis/vp.json
  vecchio: pipeline_DATI_BACKUP/analysisAllData/0_<tool_dir>/<categoria>/filtered/llm_analysis/vp.json

La struttura delle categorie e' identica fra le due run, quindi l'accoppiamento
avviene sul percorso relativo. Il confronto e' su tre livelli:

  1. per tool      — VP e server distinti, con delta
  2. per categoria — VP, con delta (evidenzia dove la rirun diverge)
  3. per server    — insiemi: in entrambe / solo prima / solo rirun

ATTENZIONE alla scopertura del dataset: la prima analisi copriva 60.205 server
GitHub piu' una run NPX separata poi unita; la rirun ha coperto i 69.104 del
dataset unico in un'unica passata. I confronti assoluti vanno letti con questo
in mente.

Uso:
    python autorun/compare_vp.py                 # riepilogo a schermo
    python autorun/compare_vp.py --categorie     # anche il dettaglio per categoria
    python autorun/compare_vp.py --out report.md # scrive un report Markdown
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OLD = Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData"

# nome tool -> (cartella nel repo, cartella nel backup)
TOOLS = {
    "guard":         ("mcp_guard", "0_tool_mcp_guard"),
    "watch":         ("mcp_watch", "0_tool_mcp_watch"),
    "fuzzing":       ("fuzzing", "0_tool_fuzzing"),
    "scan":          ("mcp_scan", "0_tool_mcp_scan"),
    "shield":        ("mcp_shield", "0_tool_mcp_shield"),
    "security_scan": ("mcp_security_scan", "0_tool_mcp_security_scan"),
    "check":         ("mcp_check", "0_tool_mcp_check"),
}


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def server_of(f):
    u = f.get("server_url") or f.get("github_url") or f.get("url") or ""
    return str(u).replace("https://github.com/", "").replace("http://github.com/", "").rstrip("/")


def load(root: Path, tooldir: str, new: bool):
    """categoria(relpath) -> (n_vp, set(server))"""
    base = REPO / tooldir / "postprocessing" if new else root / tooldir
    out = {}
    if not base.is_dir():
        return out
    for p in base.rglob("vp.json"):
        rel = p.relative_to(base).as_posix()
        rel = rel.replace("/filtered/llm_analysis/vp.json", "").replace("/llm_analysis/vp.json", "")
        try:
            its = items(json.load(open(p, encoding="utf-8")))
        except Exception:
            continue
        srv = {s for s in (server_of(f) for f in its) if s}
        n, s0 = out.get(rel, (0, set()))
        out[rel] = (n + len(its), s0 | srv)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--categorie", action="store_true")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    righe = []
    def w(s=""):
        righe.append(s)
        print(s)

    if not OLD.is_dir():
        w(f"[ERRORE] backup non trovato: {OLD}")
        return

    w("# Confronto Veri Positivi — prima analisi vs rirun")
    w()
    w(f"- prima analisi : `{OLD}`")
    w(f"- rirun         : `{REPO}` (*/postprocessing/)")
    w()
    w("> La prima analisi copriva 60.205 server GitHub + una run NPX separata poi unita;")
    w("> la rirun ha coperto i 69.104 del dataset unico in un'unica passata.")
    w()

    w("## Per tool")
    w()
    w("| tool | VP prima | VP rirun | delta | server prima | server rirun | delta |")
    w("|------|---------:|---------:|------:|-------------:|-------------:|------:|")

    tot_o = tot_n = 0
    srv_o_all, srv_n_all = set(), set()
    per_cat = {}
    for tool, (newdir, olddir) in TOOLS.items():
        o = load(OLD, olddir, new=False)
        n = load(OLD, newdir, new=True)
        per_cat[tool] = (o, n)
        vo = sum(v[0] for v in o.values()); vn = sum(v[0] for v in n.values())
        so = set().union(*[v[1] for v in o.values()]) if o else set()
        sn = set().union(*[v[1] for v in n.values()]) if n else set()
        tot_o += vo; tot_n += vn; srv_o_all |= so; srv_n_all |= sn
        d = vn - vo
        ds = len(sn) - len(so)
        w(f"| {tool} | {vo:,} | {vn:,} | {d:+,} | {len(so):,} | {len(sn):,} | {ds:+,} |")
    w(f"| **totale** | **{tot_o:,}** | **{tot_n:,}** | **{tot_n-tot_o:+,}** | "
      f"**{len(srv_o_all):,}** | **{len(srv_n_all):,}** | **{len(srv_n_all)-len(srv_o_all):+,}** |")
    w()

    w("## Per server (unione di tutti i tool)")
    w()
    both = srv_o_all & srv_n_all
    only_o = srv_o_all - srv_n_all
    only_n = srv_n_all - srv_o_all
    w(f"- confermati in entrambe : **{len(both):,}**")
    w(f"- solo prima analisi     : **{len(only_o):,}**")
    w(f"- solo rirun             : **{len(only_n):,}**")
    if srv_o_all | srv_n_all:
        w(f"- concordanza (Jaccard)  : {len(both)/len(srv_o_all | srv_n_all)*100:.1f}%")
    w()
    w("Esempi di server trovati **solo dalla rirun** (primi 15):")
    for s in sorted(only_n)[:15]:
        w(f"  - {s}")
    w()
    w("Esempi di server trovati **solo dalla prima analisi** (primi 15):")
    for s in sorted(only_o)[:15]:
        w(f"  - {s}")
    w()

    if a.categorie:
        w("## Per categoria")
        w()
        for tool, (o, n) in per_cat.items():
            cats = sorted(set(o) | set(n))
            if not cats:
                continue
            w(f"### {tool}")
            w()
            w("| categoria | VP prima | VP rirun | delta |")
            w("|-----------|---------:|---------:|------:|")
            for c in cats:
                vo = o.get(c, (0, set()))[0]
                vn = n.get(c, (0, set()))[0]
                w(f"| {c} | {vo:,} | {vn:,} | {vn-vo:+,} |")
            w()

    if a.out:
        Path(a.out).write_text("\n".join(righe), encoding="utf-8")
        print(f"\nreport scritto in {a.out}")


if __name__ == "__main__":
    main()
