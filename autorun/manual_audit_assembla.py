#!/usr/bin/env python3
"""
manual_audit_assembla.py — costruisce docs/rirun/MANUAL_RIRUN.md dai verdetti dei lotti.

Unisce i file verdetti_*.json prodotti dagli analisti, li ordina per categoria
seguendo la stessa numerazione di docs/MANUAL.md e scrive il documento nello
stesso formato: una tabella per categoria con
    | # | Server | File:Line | Verdetto | Note |
dove il verdetto e' riportato come  VERDETTO_MANUALE (verdetto_pipeline).

Uso:
    python autorun/manual_audit_assembla.py
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
IN = REPO / "autorun" / "manual_audit"
OUT = REPO / "docs" / "rirun" / "MANUAL_RIRUN.md"

# ordine e titoli come in docs/MANUAL.md
ORDINE = [
    ("sql-injection", "mcp-guard"),
    ("dangerous-capabilities", "mcp-security-scan, X-01"),
    ("credential-leak", "mcp-watch"),
    ("ssrf", "mcp-guard"),
    ("untrusted-content", "mcp-scan W015"),
    ("path-traversal-static", "mcp-guard"),
    ("command-injection-static", "mcp-guard"),
    ("code-injection-static", "mcp-guard"),
    ("input-validation", "mcp-watch"),
    ("protocol-violation", "mcp-watch"),
    ("prompt-injection", "mcp-scan E001"),
    ("insecure-deserialization", "mcp-guard"),
    ("sensitive-file-access", "mcp-shield"),
    ("sensitive-info-disclosure", "multi-source"),
    ("access-control", "mcp-watch"),
    ("data-exfiltration", "mcp-watch"),
    ("tool-shadowing", "mcp-shield"),
]


def main():
    per_cat = defaultdict(list)
    for p in sorted(IN.glob("verdetti_*.json")):
        try:
            dati = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  [WARN] {p.name}: {e}")
            continue
        for r in dati:
            per_cat[r.get("categoria")].append(r)

    righe = []
    def w(s=""):
        righe.append(s)

    tot = Counter()
    w("# Validazione manuale — rirun")
    w()
    w("Stessa metodologia di [MANUAL.md](MANUAL.md) e [MANUAL_CHECKLIST.md]"
      "(MANUAL_CHECKLIST.md): campione stratificato per server, verdetto deciso "
      "leggendo il **codice sorgente reale** preso da GitHub (o, per le categorie "
      "il cui entry point e' la descrizione del tool, la descrizione stessa).")
    w()
    w("Formato del verdetto: `VERDETTO_MANUALE (verdetto_pipeline)`.")
    w()
    w("| Sigla | Significato |")
    w("|-------|-------------|")
    w("| **VP-C** | Vero Positivo Confermato — vulnerabilita' sfruttabile sul codice attuale |")
    w("| **VP-L** | Vero Positivo Latente / by-design — capability dichiarata del server |")
    w("| **VP-D** | Vero Positivo Debole — pattern reale ma blast radius limitato |")
    w("| **FP**   | Falso Positivo — pattern matchato ma codice benigno |")
    w("| **n/d**  | Non determinabile — repo o file non piu' recuperabile |")
    w()
    w("> Differenza dichiarata rispetto alla prima analisi: il criterio del "
      "*parameter binding* non e' stato usato, su indicazione dell'autore, perche' "
      "non faceva parte del processo originale.")
    w()
    w("---")
    w()

    for i, (cat, tool) in enumerate(ORDINE, 1):
        casi = sorted(per_cat.get(cat, []), key=lambda r: r.get("n", 0))
        if not casi:
            continue
        c = Counter(r["verdetto"] for r in casi)
        tot.update(c)
        distr = ", ".join(f"{k} {v}" for k, v in
                          sorted(c.items(), key=lambda x: (-x[1], x[0])))
        w(f"## {i}. {cat} ({tool}) — {len(casi)} casi validati — {distr}")
        w()
        w("| # | Server | File:Line | Verdetto | Note |")
        w("|---|--------|-----------|:--------:|------|")
        for r in casi:
            f = r.get("file") or ""
            l = r.get("line")
            fl = f"`{f}:{l}`" if f and l else (f"`{f}`" if f else "—")
            vp = r.get("verdetto_pipeline") or "VP"
            nota = str(r.get("nota", "")).replace("|", "\\|").replace("\n", " ")
            w(f"| {r.get('n','')} | `{r.get('repo','')}` | {fl} | "
              f"**{r['verdetto']} ({vp})** | {nota} |")
        w()

    n = sum(tot.values())
    w("---")
    w()
    w(f"## Sintesi — {n} casi validati")
    w()
    w("| Verdetto | Casi | % |")
    w("|----------|-----:|--:|")
    for k in ("VP-C", "VP-L", "VP-D", "FP", "n/d"):
        if tot.get(k):
            w(f"| **{k}** | {tot[k]} | {tot[k]/n*100:.1f}% |")
    w(f"| **totale** | **{n}** | |")
    w()
    vp_reali = tot.get("VP-C", 0) + tot.get("VP-L", 0) + tot.get("VP-D", 0)
    w(f"Veri positivi in senso lato (VP-C + VP-L + VP-D): **{vp_reali}/{n} = "
      f"{vp_reali/n*100:.1f}%**; falsi positivi: **{tot.get('FP',0)}/{n} = "
      f"{tot.get('FP',0)/n*100:.1f}%**.")
    w()
    w("> Il campione e' stratificato per server ma **non casuale** (ordine "
      "alfabetico, come nella prima analisi): queste percentuali descrivono il "
      "campione, non sono stime estrapolabili all'intera popolazione dei VP.")
    w()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(righe), encoding="utf-8")
    print(f"{n} casi -> {OUT}")
    for k, v in tot.most_common():
        print(f"   {k:<5} {v:>4}")


if __name__ == "__main__":
    main()
