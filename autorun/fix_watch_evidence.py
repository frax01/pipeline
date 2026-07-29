#!/usr/bin/env python3
"""
fix_watch_evidence.py — normalizza `evidence: null` negli output dello Stage 1 di watch.

`mcp_watch/postprocessing/stage2_pipeline.py:173` legge il campo con
`f.get("evidence", "")`: se la chiave e' presente ma vale `null`, restituisce
None e la prima regex su di esso solleva
`TypeError: expected string or bytes-like object, got 'NoneType'`.
Gli altri campi della stessa funzione usano l'idioma `(f.get(...) or "")`, quindi
si tratta di una svista: l'intento e' una stringa.

Qui la correzione e' applicata al DATO (null -> "") invece che al codice, per non
modificare gli script della tesi. Semanticamente equivalente: un'evidenza nulla e'
un'evidenza vuota. In alternativa, la correzione definitiva nel codice e' cambiare
quella riga in `ev = f.get("evidence") or ""`.

Uso:
    python autorun/fix_watch_evidence.py
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FILTERED = REPO / "mcp_watch" / "postprocessing"


def main():
    tot_file = tot_fix = 0
    for p in sorted(FILTERED.glob("*/filtered/*_filtered.json")):
        d = json.load(open(p, encoding="utf-8"))
        findings = d.get("findings")
        if not isinstance(findings, list):
            continue
        n = 0
        for f in findings:
            if f.get("evidence") is None:
                f["evidence"] = ""
                n += 1
        if n:
            json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
            tot_file += 1
            tot_fix += n
            print(f"  {p.relative_to(REPO)}: {n} evidence null -> \"\"")
    print(f"\n{tot_fix} finding normalizzati in {tot_file} file")


if __name__ == "__main__":
    main()
