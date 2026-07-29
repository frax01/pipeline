#!/usr/bin/env python3
"""
import_scan_prima_analisi.py — importa i risultati di mcp-scan dalla PRIMA analisi.

Perche': nella rirun mcp-scan non produce nulla. Causa accertata sui log e
sull'endpoint live: l'analisi che genera E001/W001/W015/W016 e' server-side, e
(1) l'endpoint free `mcp.invariantlabs.ai` non ha piu' record DNS, (2) il default
della CLI punta a `api.snyk.io/...` che risponde `{"detail":"Push key is
required"}` -> HTTP 400 (110.658 volte nei log). Ogni tool torna `safe`.

Questo script NON rianalizza nulla: copia i risultati di scan della prima
analisi dentro `mcp_scan/postprocessing/`, marcando **ogni finding** con

    "_provenance": "prima_analisi"

cosi' l'origine resta tracciabile e i totali si possono sempre ricalcolare con o
senza scan importato. I dati della rirun (l'artefatto `tool-level/W003.json`)
non vengono toccati.

ATTENZIONE metodologica: dopo l'import il confronto scan-vs-scan e' per
costruzione a delta zero, e i tier del consenso cross-framework mescolano due
momenti temporali diversi (scan della prima analisi + gli altri 6 tool della
rirun). Vale come reintegro di un tool non piu' eseguibile, non come rirun.

Uso:
    python autorun/import_scan_prima_analisi.py --dry-run
    python autorun/import_scan_prima_analisi.py --import
    python autorun/import_scan_prima_analisi.py --rimuovi     # annulla l'import
"""
import argparse
import json
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData" / "0_tool_mcp_scan"
DST = REPO / "mcp_scan" / "postprocessing"
MARK = "prima_analisi"
BUCKETS = ("vp.json", "fp.json", "audit.json", "hc_vp.json", "hc_fp.json", "uncertain.json")


def items(d):
    if isinstance(d, list):
        return d, None
    for k in ("findings", "entries", "vulnerabilities"):
        if isinstance(d.get(k), list):
            return d[k], k
    return [], None


def marca(path_src: Path, path_dst: Path) -> int:
    d = json.load(open(path_src, encoding="utf-8"))
    its, key = items(d)
    for f in its:
        if isinstance(f, dict):
            f["_provenance"] = MARK
    path_dst.parent.mkdir(parents=True, exist_ok=True)
    json.dump(d, open(path_dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return len(its)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--import", dest="imp", action="store_true")
    ap.add_argument("--rimuovi", action="store_true")
    a = ap.parse_args()

    if a.rimuovi:
        n = 0
        for p in list(DST.rglob("*.json")):
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            its, _ = items(d)
            if its and all(isinstance(f, dict) and f.get("_provenance") == MARK for f in its):
                p.unlink(); n += 1
        for d0 in sorted(DST.rglob("*"), reverse=True):
            if d0.is_dir() and not any(d0.iterdir()):
                d0.rmdir()
        print(f"rimossi {n} file importati dalla prima analisi")
        return

    if not SRC.is_dir():
        raise SystemExit(f"sorgente non trovata: {SRC}")

    tot = 0
    for p in sorted(SRC.rglob("*.json")):
        if p.name not in BUCKETS:
            continue
        rel = p.relative_to(SRC)
        dst = DST / rel
        if a.dry_run:
            d = json.load(open(p, encoding="utf-8"))
            its, _ = items(d)
            print(f"  {rel.as_posix():58s} {len(its):>6,} finding")
            if p.name == "vp.json":
                tot += len(its)
            continue
        n = marca(p, dst)
        if p.name == "vp.json":
            tot += n
        print(f"  {rel.as_posix():58s} {n:>6,} finding -> importati")

    print(f"\nVP di scan importati: {tot:,}"
          + ("  (dry-run: nessun file scritto)" if a.dry_run else ""))
    if not a.dry_run:
        print("Ogni finding porta \"_provenance\": \"prima_analisi\".")
        print("Ricordarsi di rilanciare cross_framework_consensus.py.")


if __name__ == "__main__":
    main()
