#!/usr/bin/env python3
"""
relist_diff.py — confronta l'inventario dei tool di maggio con quello ri-listato
oggi, e classifica i cambiamenti.

A differenza di `rugpull_diff.py` (che confronta cio' che due scanner avevano
salvato per caso dentro i finding), qui il confronto e' **esatto e completo**:
entrambi i lati sono l'output integrale di `tools/list` sullo stesso server.
Niente bias di selezione, niente inventari parziali.

L'unico filtro che resta e' la raggiungibilita': un server che oggi non parte
piu' non e' un rug pull, e' un server morto — e va contato a parte, perche' la
mortalita' dell'ecosistema e' un risultato di per se'.

Uso:
    python autorun/relist_diff.py --out docs/rirun/RELIST.md
"""
import argparse
import difflib
import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "autorun" / "baseline_maggio_tools.json"
RELIST = REPO / "autorun" / "relist_risultati.json"

PERICOLOSE = (r"\b(execute|exec|run|spawn|shell|command|eval|subprocess|bash|"
              r"powershell|delete|remove|drop|destroy|purge|truncate|wipe|erase|"
              r"admin|root|sudo|privileg|grant|elevat|write|create|update)\b")
INIETTIVI = (r"(ignore (all )?(previous|prior)|do not (tell|mention|inform)|"
             r"without (telling|informing|asking)|<IMPORTANT>|system prompt|"
             r"you must|always call|before (using|calling) any other)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    if not RELIST.exists():
        print(f"[!] manca {RELIST}: eseguire prima relist_run.py sulle VM")
        return
    ril = json.loads(RELIST.read_text(encoding="utf-8"))

    esiti = Counter(v["esito"] for v in ril.values())
    vivi = {s: v for s, v in ril.items() if v["esito"] == "ok"}

    agg, rim, cam = [], [], []
    for s, v in vivi.items():
        prima = base[s]["tools"]
        dopo = v["tools"] or {}
        for t in sorted(set(dopo) - set(prima)):
            d = dopo[t] or ""
            agg.append({"server": s, "tool": t, "descrizione": d,
                        "pericolosa": bool(re.search(PERICOLOSE, d.lower())),
                        "iniettivo": bool(re.search(INIETTIVI, d, re.I))})
        for t in sorted(set(prima) - set(dopo)):
            rim.append({"server": s, "tool": t})
        for t in sorted(set(prima) & set(dopo)):
            x = (prima[t]["description"] or "").strip()
            y = (dopo[t] or "").strip()
            if x == y or not x or not y:
                continue
            cam.append({"server": s, "tool": t,
                        "similarita": round(difflib.SequenceMatcher(None, x, y).ratio(), 3),
                        "iniettivo_comparso": bool(re.search(INIETTIVI, y, re.I))
                        and not bool(re.search(INIETTIVI, x, re.I)),
                        "prima": x, "dopo": y})

    out = []
    def w(s=""):
        out.append(s)
        print(s)

    w("# Ri-listing dei tool — maggio 2026 vs oggi")
    w()
    w("Confronto **esatto**: entrambi i lati sono l'output integrale di")
    w("`tools/list` sullo stesso server, non frammenti estratti dai finding.")
    w()
    w("| | |")
    w("|---|---:|")
    w(f"| server nella baseline di maggio | {len(base):,} |")
    w(f"| server ri-tentati | {len(ril):,} |")
    w(f"| **server ancora avviabili** | **{len(vivi):,}** |")
    for e, n in esiti.most_common():
        if e != "ok":
            w(f"| non avviabili: `{e}` | {n:,} |")
    w()
    if len(ril):
        w(f"**Mortalita' dell'ecosistema**: {(1 - len(vivi) / len(ril)) * 100:.1f}% "
          f"dei server analizzabili a maggio oggi non parte piu'.")
        w()
    w("> **Asimmetria da rispettare.** L'elenco di oggi e' completo, quello di")
    w("> maggio no (i finding registravano solo i tool segnalati). Quindi i tool")
    w("> **spariti** sono un dato affidabile, i tool **aggiunti** no: un tool che")
    w("> compare oggi poteva esistere a maggio senza essere stato flaggato.")
    w("> Vedi `docs/rirun/RUGPULL.md` §6.")
    w()
    w("## Cambiamenti sui server ancora vivi")
    w()
    w("| | |")
    w("|---|---:|")
    w(f"| tool comparsi *(NON interpretabili come aggiunti)* | {len(agg):,} |")
    w(f"| di cui con capability pericolose | {sum(1 for x in agg if x['pericolosa']):,} |")
    w(f"| di cui con linguaggio direttivo | {sum(1 for x in agg if x['iniettivo']):,} |")
    w(f"| **tool spariti** *(dato affidabile)* | **{len(rim):,}** |")
    w(f"| descrizioni cambiate | {len(cam):,} |")
    w(f"| di cui con linguaggio direttivo comparso | {sum(1 for x in cam if x['iniettivo_comparso']):,} |")
    w()

    per = Counter(x["server"] for x in agg)
    mirati = [x for x in agg if x["pericolosa"] and per[x["server"]] <= 3]
    w(f"## Da leggere a mano: {len(mirati)} aggiunte mirate e pericolose")
    w()
    for x in sorted(mirati, key=lambda z: z["server"]):
        w(f"### `{x['server']}` :: `{x['tool']}`")
        w(f"{x['descrizione'][:400]}")
        w()

    sost = sorted([c for c in cam if c["similarita"] < 0.9],
                  key=lambda c: c["similarita"])
    w(f"## Descrizioni riscritte in modo sostanziale: {len(sost)}")
    w()
    for c in sost[:80]:
        w(f"### `{c['server']}` :: `{c['tool']}` — similarita' {c['similarita']:.0%}")
        w(f"- **maggio**: {c['prima'][:300]}")
        w(f"- **oggi**: {c['dopo'][:300]}")
        w()

    if a.out:
        Path(a.out).write_text("\n".join(out), encoding="utf-8")
        print(f"\n-> {a.out}")
    (REPO / "autorun" / "relist_cambi.json").write_text(
        json.dumps({"aggiunti": agg, "rimossi": rim, "cambiati": cam},
                   ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
