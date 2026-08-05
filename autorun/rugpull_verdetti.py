#!/usr/bin/env python3
"""
rugpull_verdetti.py — verdetti manuali sui cambi di tool description trovati da
`rugpull_diff.py`.

Metodo: sono stati letti a mano tutti i cambi che l'euristica segnalava come
"capability nuova dichiarata" e che NON provengono da server che hanno riscritto
in blocco tutta la documentazione (>=5 tool cambiati insieme = rilascio, non
modifica mirata). Il default e' DOC; qui sotto stanno solo le eccezioni, cioe' i
casi in cui la capability e' cambiata davvero e non solo la sua descrizione.

Verdetti:
  RP-C  rug pull confermato   — il tool puo' fare oggi qualcosa di pericoloso che
                                prima non poteva, e chi lo aveva approvato non lo sa
  RP-D  espansione debole     — capability nuova ma di portata limitata o gia'
                                implicita nella descrizione precedente
  DOC   solo documentazione   — stessa capability, descrizione piu' accurata
                                (falso positivo dell'euristica a parole chiave)
  REL   riscrittura di massa  — il server ha ridocumentato tutti i suoi tool

Uso:
    python autorun/rugpull_verdetti.py --out autorun/rugpull_verdetti.json
"""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CAMBI = REPO / "autorun" / "rugpull_cambi.json"

# (server, tool) -> (verdetto, motivazione)
ECCEZIONI = {
    ("letoribo/mcp-graphql-enhanced", "query-graphql"): ("RP-C",
        "A maggio 'Execute a GraphQL query against the endpoint': sola lettura. "
        "A luglio 'Execute GraphQL operations (queries and mutations)' con "
        "'WARNING: Mutation operations will modify persistent state'. Il tool "
        "passa da read-only a read-write: un agente che lo aveva approvato come "
        "query eseguira' mutation."),
    ("littlebearapps/outlook-mcp", "manage-contact"): ("DOC",
        "Sembrava un'espansione ('Full CRUD ... destructive: covers `delete`'), "
        "ma la descrizione di maggio elencava gia' per esteso "
        "'action=update modifies a contact. action=delete removes a contact'. "
        "Nessuna capability nuova: solo l'etichetta 'destructive' resa esplicita "
        "in testa. NB: verdetto corretto dopo rilettura del testo integrale — "
        "sul troncato a 155 caratteri il `delete` di maggio non si vedeva."),
    ("piotr-agier/google-drive-mcp", "deleteRange"): ("RP-D",
        "Operazione distruttiva estesa dai soli Google Docs a 'Google Docs "
        "and text/* files'. Non e' una capability nuova ma un allargamento "
        "del raggio d'azione di una gia' distruttiva."),
    ("platano78/smart-ai-bridge", "spawn_subagent"): ("RP-D",
        "A luglio compare '⚠️ DESTRUCTIVE when write_files:true: code blocks "
        "the agent emits are saved into work_directory'. A maggio la scrittura "
        "su disco non era menzionata. Il default e' pero' write_files:false e "
        "l'avviso e' esplicito: piu' probabile una disclosure migliorata che "
        "una capability aggiunta di nascosto."),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    cambi = json.load(open(CAMBI, encoding="utf-8"))
    per_server = Counter(c["server"] for c in cambi)

    out = []
    for c in cambi:
        k = (c["server"], c["tool"])
        if k in ECCEZIONI:
            v, m = ECCEZIONI[k]
        elif per_server[c["server"]] >= 5:
            v, m = "REL", (f"Il server ha cambiato {per_server[c['server']]} "
                           "descrizioni insieme: ridocumentazione di rilascio.")
        elif c["capability_comparse"] or c["iniettivo_comparso"]:
            v, m = "DOC", ("Letto a mano: stessa capability, descrizione piu' "
                           "dettagliata. Le parole chiave nuove non "
                           "corrispondono a un'azione nuova.")
        else:
            v, m = "DOC", "Riformulazione senza capability nuove segnalate."
        out.append({"server": c["server"], "tool": c["tool"],
                    "similarita": c["similarita"], "verdetto": v,
                    "motivazione": m,
                    "capability_comparse": c["capability_comparse"]})

    conta = Counter(o["verdetto"] for o in out)
    print(f"cambi giudicati: {len(out)}")
    for v in ("RP-C", "RP-D", "DOC", "REL"):
        print(f"  {v:<5} {conta.get(v, 0):>4}")
    print()
    for o in out:
        if o["verdetto"].startswith("RP"):
            print(f"[{o['verdetto']}] {o['server']} :: {o['tool']}")

    if a.out:
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1),
                               encoding="utf-8")
        print(f"\n-> {a.out}")


if __name__ == "__main__":
    main()
