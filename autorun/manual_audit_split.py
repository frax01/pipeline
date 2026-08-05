#!/usr/bin/env python3
"""
manual_audit_split.py — spezza il campione in lotti per la validazione manuale.

Scrive autorun/manual_audit/lotti/lotto_<X>.json, uno per assegnatario, cosi'
chi giudica carica solo i propri casi invece dell'intero campione.

Uso:
    python autorun/manual_audit_split.py
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "manual_audit"
LOTTI = OUT / "lotti"

# lotto -> [(categoria, primo_indice_incluso)]  (None = tutti)
ASSEGNAZIONE = {
    "A": [("sql-injection", 8), ("ssrf", 0), ("path-traversal-static", 0)],
    "B": [("credential-leak", 0), ("code-injection-static", 0),
          ("command-injection-static", 0)],
    "C": [("input-validation", 0), ("protocol-violation", 0),
          ("insecure-deserialization", 0)],
    "D": [("dangerous-capabilities", 0), ("untrusted-content", 0),
          ("prompt-injection", 0)],
    "E": [("sensitive-file-access", 0), ("sensitive-info-disclosure", 0),
          ("access-control", 0), ("data-exfiltration", 0), ("tool-shadowing", 0)],
}


def main():
    camp = json.load(open(OUT / "campione.json", encoding="utf-8"))
    LOTTI.mkdir(parents=True, exist_ok=True)
    for lotto, cats in ASSEGNAZIONE.items():
        casi = []
        for cat, start in cats:
            for i, rec in enumerate(camp.get(cat, [])):
                if i < start:
                    continue
                r = dict(rec)
                r["n"] = i + 1
                casi.append(r)
        p = LOTTI / f"lotto_{lotto}.json"
        json.dump(casi, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        cats_str = ", ".join(f"{c}[da #{s+1}]" if s else c for c, s in cats)
        print(f"  lotto {lotto}: {len(casi):>3} casi — {cats_str}")
    print(f"\n-> {LOTTI}")


if __name__ == "__main__":
    main()
