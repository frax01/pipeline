#!/usr/bin/env python3
"""
analisi_concordanza.py — perche' e' calato il consenso cross-framework?

Confronta server per server i due `cross_framework_consensus_vp.json` (prima
analisi e rirun) e ricostruisce **da quale framework** viene la perdita di
concordanza: per ogni server declassato (Tier 1/2 -> Tier 3 o sparito) elenca i
framework che prima lo segnalavano e ora no.

Uso:
    python autorun/analisi_concordanza.py
    python autorun/analisi_concordanza.py --out CONCORDANZA.md
"""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OLD = (Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData"
       / "cross_framework_consensus_vp.json")
NEW = REPO / "cross_framework" / "cross_framework_consensus_vp.json"


def norm(u):
    return str(u).replace("https://github.com/", "").replace("http://github.com/", "").rstrip("/")


def load(p):
    d = json.load(open(p, encoding="utf-8"))
    return {norm(k): v for k, v in d.get("servers", {}).items()}


def tier_of(rec):
    return rec["tier"] if rec else "assente"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    righe = []
    def w(s=""):
        righe.append(s); print(s)

    o, n = load(OLD), load(NEW)
    tutti = set(o) | set(n)

    w("# Perche' e' calato il consenso cross-framework")
    w()
    w(f"- prima analisi : {len(o):,} server con VP")
    w(f"- rirun         : {len(n):,} server con VP")
    w()

    # ── matrice di transizione ────────────────────────────────────────────
    TIERS = ["Tier 1", "Tier 2", "Tier 3", "assente"]
    mat = defaultdict(Counter)
    for s in tutti:
        mat[tier_of(o.get(s))][tier_of(n.get(s))] += 1

    w("## Matrice di transizione (righe = prima, colonne = rirun)")
    w()
    w("| prima \\ rirun | " + " | ".join(TIERS) + " | totale |")
    w("|---|" + "---:|" * (len(TIERS) + 1))
    for t in TIERS:
        r = mat[t]
        tot = sum(r.values())
        if not tot:
            continue
        w(f"| **{t}** | " + " | ".join(f"{r[x]:,}" for x in TIERS) + f" | {tot:,} |")
    w()

    # ── declassati: quali framework sono spariti ──────────────────────────
    persi = Counter()          # framework -> quante volte perso da un declassato
    persi_tutti = Counter()    # framework -> quante volte perso in generale
    declassati = []
    for s in tutti:
        ro, rn = o.get(s), n.get(s)
        fo = set(ro["frameworks"]) if ro else set()
        fn = set(rn["frameworks"]) if rn else set()
        for f in fo - fn:
            persi_tutti[f] += 1
        # declassamento = prima concordavano >=2 framework, ora <2
        if len(fo) >= 2 and len(fn) < 2:
            declassati.append((s, fo, fn))
            for f in fo - fn:
                persi[f] += 1

    w(f"## Server che hanno perso la concordanza: **{len(declassati):,}**")
    w()
    w("(prima segnalati da >= 2 framework, ora da meno di 2)")
    w()
    w("Framework che il server aveva prima e ora non ha piu':")
    w()
    w("| framework | volte perso nei declassati | volte perso in totale |")
    w("|---|---:|---:|")
    for f, c in persi.most_common():
        w(f"| {f} | {c:,} | {persi_tutti[f]:,} |")
    w()

    # ── quanti declassati sono spariti del tutto ──────────────────────────
    spariti = sum(1 for s, fo, fn in declassati if not fn)
    w(f"Di questi, **{spariti:,}** non hanno piu' alcun VP da nessun framework "
      f"e **{len(declassati)-spariti:,}** ne conservano uno solo.")
    w()

    # ── combinazioni perse piu' frequenti ─────────────────────────────────
    combo = Counter(tuple(sorted(fo - fn)) for s, fo, fn in declassati)
    w("Combinazioni di framework perse piu' frequenti:")
    w()
    w("| framework persi | server |")
    w("|---|---:|")
    for c, k in combo.most_common(10):
        w(f"| {', '.join(c) if c else '(nessuno)'} | {k:,} |")
    w()

    # ── promossi ──────────────────────────────────────────────────────────
    promossi = [s for s in tutti
                if len(set(n[s]["frameworks"]) if s in n else set()) >= 2
                and len(set(o[s]["frameworks"]) if s in o else set()) < 2]
    w(f"## Server che hanno **guadagnato** concordanza: **{len(promossi):,}**")
    w()
    guad = Counter()
    for s in promossi:
        fo = set(o[s]["frameworks"]) if s in o else set()
        for f in set(n[s]["frameworks"]) - fo:
            guad[f] += 1
    w("| framework | volte guadagnato |")
    w("|---|---:|")
    for f, c in guad.most_common():
        w(f"| {f} | {c:,} |")
    w()

    if a.out:
        Path(a.out).write_text("\n".join(righe), encoding="utf-8")
        print(f"\nreport scritto in {a.out}")


if __name__ == "__main__":
    main()
