#!/usr/bin/env python3
"""
credleak_audit_prepare.py — prepara l'audit INTEGRALE di credential-leak.

Nella prima analisi la classe credential-leak e' stata auditata per intero
(1.342/1.342): essendo la piu' pesante, e' quella che determina la precisione
ponderata. Qui si fa lo stesso sui 1.176 VP della rirun.

I criteri sono quelli di MANUAL_CHECKLIST.md §3 (formato/prefisso del provider,
entropia, tipo di file, commenti espliciti, corrispondenza nome-variabile/valore),
che sono decidibili da `evidence` + percorso del file senza aprire il sorgente:
per questo l'audit integrale e' praticabile.

I finding vengono raggruppati in cluster con **evidenza equivalente**: stessa
forma del valore, stesso tipo di file, stesso provider. Il verdetto si da' una
volta per cluster e si propaga ai membri.

Uso:
    python autorun/credleak_audit_prepare.py --prepara
    python autorun/credleak_audit_prepare.py --stat
"""
import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "mcp_watch" / "postprocessing" / "credential-leak"
OUT = REPO / "autorun" / "credleak_audit"
BATCHES = OUT / "batches"
BATCH = 45


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def carica():
    out = []
    for p in SRC.rglob("vp.json"):
        out += items(json.load(open(p, encoding="utf-8")))
    return out


def tipo_file(f):
    p = (f.get("file") or "").lower()
    for k, lab in ((".env.example", "env-example"), (".env.sample", "env-example"),
                   (".env.template", "env-example"), ("node_modules", "dipendenza"),
                   ("vendor/", "dipendenza"), ("/test", "test"), ("test/", "test"),
                   ("spec/", "test"), ("_test.", "test"), (".test.", "test"),
                   ("example", "esempio"), ("sample", "esempio"), ("demo", "esempio"),
                   ("docs/", "documentazione"), (".md", "documentazione"),
                   ("dist/", "build"), ("build/", "build"), (".min.js", "build")):
        if k in p:
            return lab
    if p.endswith(".env") or "/.env" in p:
        return "env-committato"
    return "sorgente"


def forma(ev):
    """Classifica la FORMA del valore, che e' cio' che decide il verdetto."""
    e = str(ev or "")
    m = re.search(r"(sk-proj-|sk-ant-|sk-|csk-|ghp_|gho_|github_pat_|AIzaSy|xoxb-|xoxp-|"
                  r"AKIA|ASIA|eyJ|glpat-|hf_|pk_live_|sk_live_|rk_live_|SG\.|dop_v1_)", e)
    if m:
        return f"provider:{m.group(1)}"
    if re.search(r"(your[_-]?|placeholder|xxx+|changeme|change_me|example|dummy|fake|"
                 r"<[^>]{2,}>|\.\.\.|todo|inserisci|replace)", e, re.I):
        return "placeholder"
    if re.search(r"(os\.getenv|process\.env|getenv\(|System\.getenv|ENV\[)", e):
        return "letto-da-env"
    if re.search(r"[\"'][0-9a-f]{32,}[\"']", e):
        return "hex-32+"
    if re.search(r"[\"'][A-Za-z0-9+/_-]{24,}[\"']", e):
        return "stringa-alta-entropia"
    if re.search(r"[\"'][^\"']{0,8}[\"']", e):
        return "stringa-corta"
    return "altro"


def nome_var(ev):
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]", str(ev or ""))
    return (m.group(1) if m else "").lower()


def sig(f):
    return hashlib.sha1("|".join([
        str(f.get("id")), tipo_file(f), forma(f.get("evidence")),
        str(f.get("filter_confidence")), nome_var(f.get("evidence")),
    ]).encode()).hexdigest()[:12]


def cmd_prepara():
    tot = carica()
    gruppi = defaultdict(list)
    for f in tot:
        gruppi[sig(f)].append(f)

    OUT.mkdir(parents=True, exist_ok=True)
    if BATCHES.exists():
        for p in BATCHES.glob("*.json"):
            p.unlink()
    BATCHES.mkdir(parents=True, exist_ok=True)

    cluster = []
    indice = {}
    for s, membri in sorted(gruppi.items(), key=lambda x: -len(x[1])):
        m0 = membri[0]
        cluster.append({
            "id": s,
            "n_finding": len(membri),
            "n_server": len({x.get("server_name") for x in membri}),
            "tipo_segnalazione": m0.get("id"),
            "provider_rilevato": m0.get("filter_confidence"),
            "tipo_file": tipo_file(m0),
            "forma_valore": forma(m0.get("evidence")),
            "esempi": [{"server": x.get("server_name"), "file": x.get("file"),
                        "line": x.get("line"), "evidence": str(x.get("evidence"))[:220]}
                       for x in membri[:4]],
        })
        indice[s] = [{"server": x.get("server_name"), "github_url": x.get("github_url"),
                      "file": x.get("file"), "line": x.get("line")} for x in membri]

    for i in range(0, len(cluster), BATCH):
        n = i // BATCH + 1
        json.dump({"batch": n, "cluster": cluster[i:i + BATCH]},
                  open(BATCHES / f"cl_{n:02d}.json", "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    json.dump(indice, open(OUT / "indice.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    print(f"finding credential-leak : {len(tot):,}")
    print(f"cluster di decisione     : {len(cluster):,} (fattore {len(tot)/len(cluster):.1f}x)")
    print(f"batch da {BATCH}            : {(len(cluster)+BATCH-1)//BATCH}")
    print()
    print("composizione:")
    for k, v in Counter((tipo_file(f), forma(f.get('evidence'))) for f in tot).most_common(12):
        print(f"   {v:>5}  {k[0]:<18}{k[1]}")


def cmd_stat():
    tot = carica()
    print(f"{len(tot):,} finding")
    for lab, fn in (("tipo file", tipo_file), ("forma valore", lambda f: forma(f.get('evidence')))):
        print(f"\n{lab}:")
        for k, v in Counter(fn(f) for f in tot).most_common():
            print(f"   {v:>5}  {k}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepara", action="store_true")
    ap.add_argument("--stat", action="store_true")
    a = ap.parse_args()
    if a.stat:
        cmd_stat()
    else:
        cmd_prepara()


if __name__ == "__main__":
    main()
