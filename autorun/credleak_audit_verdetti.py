#!/usr/bin/env python3
"""
credleak_audit_verdetti.py — verdetti dell'audit integrale di credential-leak.

Un verdetto per ognuno dei 141 cluster di decisione, assegnato leggendo il valore
concreto di `evidence` e il percorso del file secondo MANUAL_CHECKLIST.md §3
(formato/prefisso del provider, entropia, tipo di file, commenti espliciti,
corrispondenza nome-variabile/valore). Il verdetto si propaga ai membri del
cluster, che per costruzione hanno evidenza equivalente.

Scala: VP-C / VP-L / VP-D / FP, come nella prima analisi.

Uso:
    python autorun/credleak_audit_verdetti.py --applica
"""
import argparse
import json
from collections import Counter
from pathlib import Path

OUT = Path(__file__).resolve().parent / "credleak_audit"

# cluster -> (verdetto, motivazione)
V = {
    # ── il pattern dominante: cache runtime del token OAuth dell'utente ──
    "2de8edebf536": ("FP", "token.write(creds.to_json()): boilerplate OAuth di Google che salva in cache locale il token dell'utente a runtime. Nessun segreto committato nel repository."),
    "6047ad754c37": ("FP", "writeFileSync(tokenPath, JSON.stringify(token)): cache locale del token ottenuto a runtime."),
    "e3d668e251b4": ("FP", "writeFile(keyPath, secret, {mode: 0o600}): scrittura deliberatamente protetta con permessi restrittivi."),
    "dbad9bd7dfd4": ("FP", "writeFileSync con mode 0o600: gestione corretta del segreto, non un leak."),
    "7ea0333a932e": ("FP", "Scrittura a runtime del token di accesso ottenuto dall'utente."),
    "5f04423feacd": ("FP", "Script di setup che scrive nel .env locale la chiave fornita dall'utente."),
    "62eb739e4812": ("FP", "Esempio che salva a runtime le credenziali dell'utente."),
    "eb778a9b46ff": ("FP", "Scrittura a runtime del token nella config locale."),
    "9a05f127434c": ("FP", "Scrittura a runtime della chiave dell'utente nel .env condiviso."),
    "a5e30cb5e1dd": ("FP", "authToken npm scritto a runtime in .npmrc temporaneo."),
    "4168f80f99b6": ("FP", "Script di setup: scrive nel .env la chiave fornita dall'utente."),
    "edf409813bd7": ("FP", "Script di setup: scrive nel .env la chiave fornita dall'utente."),
    "e3e51a0b340a": ("FP", "authToken npm in .npmrc temporaneo di rilascio."),
    "4faa366d8a27": ("FP", "writeFileSync del token con mode 0o600."),
    "c81dd2d523e9": ("FP", "Persistenza a runtime del token di sessione."),
    "32e3c2897b5e": ("FP", "Scrive un .npmrc segnaposto con il commento esplicito 'Do not add your actual token here'."),
    "fd8c625b39e3": ("FP", "Genera un .env con la riga del token commentata come segnaposto."),
    "e31d939d7511": ("FP", "Scrive letteralmente OPENAI_API_KEY=your-api-key: segnaposto."),

    # ── chiavi pubbliche per design ──
    "4e9535e8b20f": ("FP", "Firebase web config: la apiKey del client web e' pubblica per design, documentato da Google."),
    "1a41187db1f1": ("FP", "Firebase web config in examples/ e demos/: chiave pubblica per design."),
    "42b5da1239ad": ("FP", "Chiave Google Maps Embed incorporata nell'HTML generato: chiave client-side, protetta da restrizione per referrer."),
    "72c45c53056a": ("FP", "Chiave Google Maps JS API in demos/: client-side, pubblica per design."),
    "32a2d842aaa7": ("FP", "MAPS_API_KEY client-side in un playground."),
    "55eae583784e": ("FP", "Chiave Google Maps JS in demo Angular."),
    "edf49852b32d": ("FP", "Chiave Google Maps esportata per uso client-side."),
    "d6cb09e4962b": ("FP", "Chiave Chrome CrUX (chromeuxreport.googleapis.com): documentata da Google come chiave di lettura pubblica non ristretta."),
    "0d48dc749bc3": ("FP", "SUPABASE_ANON_KEY: la chiave anon e' pubblica per design (le restrizioni sono le RLS policy)."),

    # ── segnaposto e valori dichiaratamente finti ──
    "9018aa7a3bad": ("FP", "Commento esplicito nel .env: chiave di esempio senza credito."),
    "0d457817ffa1": ("FP", "Commento esplicito 'Replace with your own API Key'."),
    "e6ab9a0ed70a": ("FP", "Commento esplicito in cinese: 'sostituisci con la tua API key'."),
    "a354342aeedc": ("FP", "AKIA seguito da soli zeri: segnaposto evidente."),
    "ec394ea00919": ("FP", "Client dimostrativo di uno strumento di redazione: i valori mostrati sono dati campione della demo."),
    "eebe301ea681": ("FP", "Frammento di service account dentro documentazione generata di un SDK, con project_id segnaposto."),
    "aff4dc8d7d6b": ("FP", "Bundle minificato di libreria di terze parti (social-share-kit)."),

    # ── fixture didattiche / repo dichiaratamente vulnerabili ──
    "dc983687c433": ("VP-L", "Token dentro challenges/hard/: fixture di un ambiente di esercitazione, vulnerabile per costruzione."),
    "ca680e008f11": ("VP-L", "Token ghp_ in formato corretto ma con sequenza alfabetica (A1bC2dE3...): repository dimostrativo, valore fittizio."),

    # ── chiavi reali in directory di esempio: pattern reale, contesto attenuante ──
    "1ca013ca5680": ("VP-D", "Chiave Gemini reale ma dentro #sample_example/: valore vero in area dichiaratamente d'esempio."),
    "200f093fc110": ("VP-D", "Chiave Gemini in formato reale dentro examples/."),
    "66c8165c8eb1": ("VP-D", "Chiave AWS AKIA in formato reale dentro examples/demo.ts."),
    "c60d60fe28fa": ("VP-D", "Chiave OpenAI reale in kg_example.py."),
    "ac481b5a835b": ("VP-D", "Chiave OpenAI reale in un file demo."),
    "f38b9e22b247": ("VP-D", "Token GitHub ghp_ reale dentro examples/."),
    "37c05b1de385": ("VP-D", "Access token Google ya29 reale dentro examples/, ma i token ya29 scadono in circa un'ora."),
}

# tutti i cluster non elencati sopra sono credenziali reali in codice di
# produzione o in .env committati -> VP-C
DEFAULT = ("VP-C", "Segreto con formato ed entropia reali, hardcoded in codice di produzione o in un .env committato.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--applica", action="store_true")
    ap.parse_args()

    cluster = []
    for p in sorted((OUT / "batches").glob("cl_*.json")):
        cluster += json.load(open(p, encoding="utf-8"))["cluster"]

    out, per_verdetto, per_finding = [], Counter(), Counter()
    for c in cluster:
        v, motivo = V.get(c["id"], DEFAULT)
        out.append({**{k: c[k] for k in ("id", "n_finding", "n_server", "tipo_segnalazione",
                                         "tipo_file", "forma_valore")},
                    "verdetto": v, "nota": motivo})
        per_verdetto[v] += 1
        per_finding[v] += c["n_finding"]

    json.dump(out, open(OUT / "verdetti_cluster.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    tot = sum(per_finding.values())
    print(f"cluster giudicati : {len(out)}")
    print(f"finding coperti   : {tot:,}\n")
    print(f"{'verdetto':<8}{'cluster':>9}{'finding':>10}{'%':>8}")
    for k in ("VP-C", "VP-L", "VP-D", "FP"):
        if per_finding.get(k):
            print(f"{k:<8}{per_verdetto[k]:>9}{per_finding[k]:>10,}{per_finding[k]/tot*100:>7.1f}%")
    conf = per_finding["VP-C"] + per_finding["VP-D"]
    print(f"\nconfermato (VP-C + VP-D): {conf:,}/{tot:,} = {conf/tot*100:.1f}%")
    print(f"solo VP-C                : {per_finding['VP-C']:,}/{tot:,} = {per_finding['VP-C']/tot*100:.1f}%")


if __name__ == "__main__":
    main()
