#!/usr/bin/env python3
"""
audit_hardcoded_credential.py — audit integrale di guard/hardcoded-credential-static.

E' la seconda meta' della classe "Credential leak" della prima analisi
(che era watch/credential-leak + guard/hardcoded-credential-static = 1.342).
Come per l'altra meta', l'audit e' integrale e non campionario: i criteri della
sezione 3 di MANUAL_CHECKLIST.md (formato/prefisso del provider, entropia, tipo
di file, segnaposto espliciti, corrispondenza nome-variabile/valore) sono
decidibili dallo snippet di codice contenuto nel finding.

Uso:
    python autorun/audit_hardcoded_credential.py
"""
import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = "mcp_guard/postprocessing/hardcoded-credential-static/**/vp.json"
OUT = REPO / "autorun" / "manual_audit" / "verdetti_HC.json"


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def code(f):
    d = f.get("description", "") or ""
    i = d.find("Code: ")
    return d[i + 6:].strip() if i >= 0 else ""


def verdetto(f):
    c, p = code(f), (f.get("file") or "").lower()

    # 3. tipo di file: test / esempio / dipendenza / build
    for k in (".env.example", "node_modules", "vendor/", "/test", "test/", ".test.",
              "spec/", "__tests__", "example", "sample", "demo", "docs/", ".md",
              "dist/", ".min."):
        if k in p:
            return "FP", "file di test/esempio/dipendenza/build"

    # 5. il valore non e' hardcoded: viene dall'ambiente
    if re.search(r"(os\.getenv|process\.env|getenv\(|System\.getenv)", c):
        return "FP", "valore letto da variabile d'ambiente, non hardcoded"

    # 6. nome variabile == valore -> segnaposto auto-descrittivo
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\"']([^\"']+)", c)
    if m:
        var = re.sub(r"[^a-z0-9]", "", m.group(1).lower())
        val = re.sub(r"[^a-z0-9]", "", m.group(2).lower())
        if val and (val == var or val in var or var in val):
            return "FP", "nome della variabile uguale al valore: segnaposto auto-descrittivo"

    # 2. segnaposto espliciti
    if re.search(r"(your[_-]|placeholder|xxx+|changeme|change_me|<[^>]{2,}>|todo|"
                 r"inserisci|replace_me|dummy|fakekey|notreal)", c, re.I):
        return "FP", "segnaposto esplicito nel valore"

    # 1. formato con prefisso di provider riconoscibile
    if re.search(r"(sk-ant-|sk-proj-|sk-|ghp_|gho_|AIzaSy|xox[bp]-|AKIA|eyJ|glpat-|"
                 r"hf_|csk-|gsk_|dckr_pat_)", c):
        return "VP-C", "chiave con prefisso di provider riconoscibile"

    # entropia
    if re.search(r"[\"'][0-9a-f]{32,}[\"']", c):
        return "VP-C", "stringa esadecimale di 32+ caratteri"
    if re.search(r"[\"'][A-Za-z0-9+/=_-]{20,}[\"']", c):
        return "VP-C", "stringa ad alta entropia"
    if re.search(r"(password|passwd|pwd|secret|token)\s*[:=]\s*[\"'][^\"']{6,}", c, re.I):
        return "VP-C", "password o segreto valorizzato in chiaro"

    return "VP-D", "pattern reale ma valore corto o poco entropico"


def main():
    tot = []
    for p in REPO.glob(SRC):
        tot += items(json.load(open(p, encoding="utf-8")))

    out, c = [], Counter()
    for i, f in enumerate(tot, 1):
        v, motivo = verdetto(f)
        c[v] += 1
        out.append({
            "n": i,
            "sotto_categoria": "guard/hardcoded-credential",
            "categoria_madre": "Credential leak",
            "repo": str(f.get("server_url", "")).replace("https://github.com/", ""),
            "file": f.get("file"),
            "verdetto": v,
            "verdetto_pipeline": "VP",
            "nota": motivo,
        })
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    n = len(out)
    conf = c["VP-C"] + c["VP-D"]
    print(f"guard/hardcoded-credential — audit integrale su {n:,} VP")
    for k in ("VP-C", "VP-L", "VP-D", "FP"):
        if c[k]:
            print(f"   {k:<6}{c[k]:>5}  {c[k]/n*100:>5.1f}%")
    print(f"\n   confermato (VP-C+VP-D): {conf:,}/{n:,} = {conf/n*100:.1f}%")
    print(f"   -> {OUT}")


if __name__ == "__main__":
    main()
