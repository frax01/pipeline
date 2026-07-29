#!/usr/bin/env python3
"""
stage2b_status.py — stato della classificazione Stage 2B, batch per batch.

Per ogni batch confronta gli id dei cluster con quelli presenti nel file di
verdetti corrispondente e segnala: mancanti (nessun verdetto), estranei (id non
appartenenti al batch) e verdetti non validi. Stampa in fondo la lista dei
batch da rilanciare, pronta da passare a un nuovo classificatore.

Uso:
    python autorun/stage2b_status.py
    python autorun/stage2b_status.py --solo-incompleti
"""
import argparse
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "stage2b"
BATCHES = OUT / "batches"
VERDICTS = OUT / "verdicts"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solo-incompleti", action="store_true")
    a = ap.parse_args()

    da_rifare, tot_cluster, tot_ok = [], 0, 0
    righe = []
    for bp in sorted(BATCHES.glob("batch_*.json")):
        n = int(bp.stem.split("_")[1])
        b = json.load(open(bp, encoding="utf-8"))
        ids = {c["id"] for c in b["cluster"]}
        tot_cluster += len(ids)

        vp = VERDICTS / f"verdict_{n:03d}.json"
        if not vp.exists():
            da_rifare.append(n)
            righe.append((n, len(ids), 0, len(ids), 0, 0, "ASSENTE"))
            continue
        try:
            v = json.load(open(vp, encoding="utf-8"))
        except Exception as e:
            da_rifare.append(n)
            righe.append((n, len(ids), 0, len(ids), 0, 0, f"ILLEGGIBILE ({e.__class__.__name__})"))
            continue

        visti, invalidi, estranei = set(), 0, 0
        nvp = nfp = 0
        for r in v.get("verdetti", []):
            cid = r.get("id")
            vd = (r.get("verdetto") or "").upper()
            if cid not in ids:
                estranei += 1
                continue
            if vd not in ("VP", "FP"):
                invalidi += 1
                continue
            visti.add(cid)
            nvp += vd == "VP"
            nfp += vd == "FP"
        mancanti = len(ids - visti)
        tot_ok += len(visti)
        stato = "ok" if mancanti == 0 and invalidi == 0 else "INCOMPLETO"
        if stato != "ok":
            da_rifare.append(n)
        righe.append((n, len(ids), len(visti), mancanti, nvp, nfp,
                      stato + (f" estranei={estranei}" if estranei else "")))

    if not a.solo_incompleti:
        print(f"{'batch':>5} {'clst':>5} {'fatti':>6} {'manc':>5} {'VP':>5} {'FP':>5}  stato")
        for r in righe:
            print(f"{r[0]:>5} {r[1]:>5} {r[2]:>6} {r[3]:>5} {r[4]:>5} {r[5]:>5}  {r[6]}")

    print(f"\ncluster totali: {tot_cluster:,} — classificati: {tot_ok:,} "
          f"({tot_ok/max(tot_cluster,1)*100:.1f}%)")
    if da_rifare:
        print(f"batch da rilanciare ({len(da_rifare)}): "
              + ", ".join(f"{n:03d}" for n in da_rifare))
    else:
        print("tutti i batch sono completi.")


if __name__ == "__main__":
    main()
