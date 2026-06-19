#!/usr/bin/env python3
"""
run_all.py — Punto d'avvio unico del web_crawler.

Ogni scraper `NN_*.py` è uno script indipendente (vedi README). Questo runner li
lancia in ordine come **sottoprocessi isolati** (`python NN_*.py`), continua anche
se uno fallisce e stampa un riepilogo finale. Usare i sottoprocessi (anziché gli
import) è obbligatorio: i nomi iniziano con una cifra e alcuni scraper eseguono a
livello-modulo o usano Playwright/Selenium.

Uso:
    python run_all.py                 # esegue tutti gli scraper, in ordine
    python run_all.py --list          # elenca gli scraper senza eseguirli
    python run_all.py --only 01,06,14 # esegue solo quelli con quei prefissi-numero
    python run_all.py --skip 13,17    # salta quelli con quei prefissi-numero
    python run_all.py --stop-on-error # interrompe al primo errore (default: continua)

Chiavi opzionali (via variabile d'ambiente — vedi README). Se mancano, lo scraper
relativo viene SALTATO con un avviso:
    SMITHERY_API_KEY   per 04_smithery.py
    GITHUB_TOKEN       per 16_github_search.py

Nota: è un'esecuzione SEQUENZIALE e alcuni scraper sono molto lunghi (decine di
migliaia di server) e richiedono browser headless installati
(`pip install playwright selenium && playwright install chromium`).
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Scraper che richiedono una chiave via variabile d'ambiente
REQUIRES_ENV = {
    "04_smithery.py": "SMITHERY_API_KEY",
    "16_github_search.py": "GITHUB_TOKEN",
}


def discover_scrapers():
    """Tutti gli script NN_*.py, ordinati per numero/nome (esclude run_all.py)."""
    return sorted(p.name for p in HERE.glob("[0-9][0-9]_*.py"))


def selected(name, prefixes):
    """True se il numero-prefisso dello scraper (es. '14') è nell'insieme dato."""
    num = name.split("_", 1)[0]
    return num in prefixes


def main():
    ap = argparse.ArgumentParser(
        description="Esegue in sequenza tutti gli scraper del web_crawler."
    )
    ap.add_argument("--list", action="store_true",
                    help="Elenca gli scraper senza eseguirli.")
    ap.add_argument("--only", default="",
                    help="Esegui solo questi numeri-prefisso (es. 01,06,14).")
    ap.add_argument("--skip", default="",
                    help="Salta questi numeri-prefisso (es. 13,17).")
    ap.add_argument("--stop-on-error", action="store_true",
                    help="Interrompi al primo errore (default: continua).")
    args = ap.parse_args()

    scrapers = discover_scrapers()
    only = {x.strip() for x in args.only.split(",") if x.strip()}
    skip = {x.strip() for x in args.skip.split(",") if x.strip()}
    if only:
        scrapers = [s for s in scrapers if selected(s, only)]
    if skip:
        scrapers = [s for s in scrapers if not selected(s, skip)]

    if args.list:
        print(f"{len(scrapers)} scraper nel web_crawler:")
        for s in scrapers:
            env = REQUIRES_ENV.get(s)
            print(f"  {s}" + (f"   (richiede ${env})" if env else ""))
        return 0

    if not scrapers:
        print("Nessuno scraper selezionato.")
        return 1

    print(f"== web_crawler: {len(scrapers)} scraper | python={sys.executable} ==")

    results = []
    try:
        for i, s in enumerate(scrapers, 1):
            env = REQUIRES_ENV.get(s)
            if env and not os.environ.get(env):
                print(f"\n[{i}/{len(scrapers)}]  {s} — SALTATO (manca ${env})")
                results.append((s, f"saltato (manca ${env})", 0.0))
                continue

            print(f"\n[{i}/{len(scrapers)}] {s}")
            start = time.time()
            rc = subprocess.run([sys.executable, str(HERE / s)], cwd=HERE).returncode
            dur = time.time() - start
            status = "ok" if rc == 0 else f"errore (rc={rc})"
            results.append((s, status, dur))
            print(f"  └─ {status} in {dur:.1f}s")
            if rc != 0 and args.stop_on_error:
                print("[!] Interrompo (--stop-on-error).")
                break
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente.")

    print("\n== Riepilogo ==")
    ok = 0
    for s, st, dur in results:
        mark = "+" if st == "ok" else ("-" if st.startswith("saltato") else "x")
        if st == "ok":
            ok += 1
        print(f"  {mark} {s:<34} {st:<22} {dur:6.1f}s")
    print(f"\n{ok}/{len(results)} completati con successo.")
    return 0 if ok == len([r for r in results if not r[1].startswith('saltato')]) else 1


if __name__ == "__main__":
    sys.exit(main())
