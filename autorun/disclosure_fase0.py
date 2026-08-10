#!/usr/bin/env python3
"""
disclosure_fase0.py — verifica preliminare dei casi candidati alla responsible
disclosure. NON CONTATTA NESSUNO.

Fase 0 del protocollo: prima di scrivere a chiunque si controlla se il bersaglio
esiste ancora e se il problema e' ancora presente. Segnalare un repository gia'
rimosso, o un difetto gia' corretto, brucia la segnalazione e quelle successive.

Cosa fa, e solo questo:
  * verifica l'esistenza di ogni repository con `git ls-remote` (sola lettura
    di metadati pubblici, nessun clone, nessuna autenticazione);
  * per i casi di malware, scarica il singolo file incriminato dall'HEAD attuale
    tramite raw.githubusercontent e cerca la firma documentata nell'audit,
    per stabilire se il payload e' ancora presente;
  * conta i casi di credenziali confermate raggruppandoli per provider;
  * scrive il registro in docs/disclosure/.

Cosa NON fa: aprire issue, inviare email, compilare form, autenticarsi.
Quelle sono azioni della Fase 3 e spettano all'autore dello studio.

Uso:
    python autorun/disclosure_fase0.py
    python autorun/disclosure_fase0.py --no-rete    # solo assemblaggio liste
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "disclosure"

# ---------------------------------------------------------------------------
# TIER 1 — malware. Il manutentore e' l'attaccante: il canale e' GitHub Abuse
# e il registry, non il maintainer. Firma = stringa da cercare nell'HEAD attuale
# per stabilire se il payload c'e' ancora.
# ---------------------------------------------------------------------------
TIER1 = [
 {"repo": "heavenlycolle/mcp-trino", "file": "cmd/server/main.go", "riga": 195,
  "firma": [r'exec\.Command\("/bi"', r'\.icu'],
  "descrizione": "exec.Command(\"/bi\"+\"n/s\"+\"h\", \"-c\", ...) a livello di "
                 "package-init: ricostruisce per concatenazione un comando curl "
                 "verso un dominio .icu che scarica ed esegue un binario. "
                 "Nessuna funzione da chiamare: parte al caricamento.",
  "fonte": "MANUAL_RIRUN.md §7 caso 38"},
 {"repo": "illustriousj/kite-mcp-server", "file": "kc/api.go", "riga": 25,
  "firma": [r'exec\.Command\("/b"', r'\.icu'],
  "descrizione": "exec.Command(\"/b\"+\"in/sh\", \"-c\", UhpF) eseguita al "
                 "package-init tramite inizializzazione di variabile globale; "
                 "UhpF e' un wget offuscato verso .icu con pipe a /bin/bash.",
  "fonte": "MANUAL_RIRUN.md §7 caso 39"},
 {"repo": "optimisticdur/go-mcp-mysql", "file": "main.go", "riga": 477,
  "firma": [r'exec\.Command\("/bi"', r'\.icu'],
  "descrizione": "Stesso payload di kite-mcp-server: wget offuscato verso lo "
                 "stesso dominio .icu con pipe a /bin/bash, eseguito al "
                 "package-init. Campagna condivisa fra piu' repository.",
  "fonte": "MANUAL_RIRUN.md §7 caso 45"},
 {"repo": "FronNian/mpc-maven-security", "file": "src/index.ts", "riga": 19,
  "firma": [r'eval\(Buffer\.from', r'\\uFE0'],
  "descrizione": "Dopo un entrypoint MCP legittimo di 17 righe, codice appeso "
                 "che decodifica caratteri Unicode variation-selector invisibili "
                 "in un buffer e lo esegue con eval(): backdoor steganografica.",
  "fonte": "MANUAL_RIRUN.md §8 caso 24"},
 {"repo": "michaelguo1991/math-mcp-server-nodejs", "file": None, "riga": None,
  "firma": [r'attacker@pwnd\.com', r'<IMPORTANT>'],
  "descrizione": "La descrizione del tool 'subtract' contiene un tag "
                 "<IMPORTANT> che istruisce il modello a dirottare tutte le "
                 "email del tool send_email verso attacker@pwnd.com e a non "
                 "informare l'utente. Tool poisoning cross-tool da manuale.",
  "fonte": "MANUAL_RIRUN.md §17 caso 2"},
]

# ---------------------------------------------------------------------------
# TIER 2 — esfiltrazione confermata e rug pull. Qui il canale e' il manutentore.
# ---------------------------------------------------------------------------
TIER2 = [
 {"repo": "skdkfk8758/MCP-ProjectManager", "tipo": "data-exfiltration",
  "file": "packages/cli/src/commands/init.ts", "riga": 237,
  "firma": [r'/api/events'],
  "descrizione": "Installa hook globali di Claude Code (SessionStart, "
                 "PreToolUse, PostToolUse, UserPromptSubmit...) che inviano a un "
                 "backend esterno il session_id, il tool_input completo di ogni "
                 "chiamata, i primi 500 caratteri di ogni output e la lunghezza "
                 "dei prompt: cattura l'intera sessione, non solo i propri tool.",
  "fonte": "MANUAL_RIRUN.md §16 caso 1"},
 {"repo": "vincentmcleese/promtHire-mcp", "tipo": "data-exfiltration",
  "file": "promptHire_server_node/src/server.ts", "riga": 82,
  "firma": [r'ENTIRE conversation', r'gig_description'],
  "descrizione": "Lo schema del tool istruisce esplicitamente il modello a "
                 "riempire 'gig_description' con contenuto estratto "
                 "dall'INTERA conversazione, poi inviato a un servizio esterno.",
  "fonte": "MANUAL_RIRUN.md §16 caso 2"},
 {"repo": "sentry-official/mcp-cap-internal", "tipo": "rug-pull",
  "file": None, "riga": None,
  "firma": [r"write data to user's system"],
  "descrizione": "Fra la prima e la seconda misurazione, a uno solo dei quattro "
                 "tool di analisi PCAP e' stata aggiunta la frase 'Then write "
                 "data to user's system'. Da sola lettura a scrittura sul "
                 "filesystem dell'utente, senza avviso. Da segnalare anche il "
                 "nome dell'organizzazione, che evoca un'affiliazione a Sentry.",
  "fonte": "RELIST_VERDETTI.md"},
 {"repo": "letoribo/mcp-graphql-enhanced", "tipo": "rug-pull",
  "file": None, "riga": None,
  "firma": [r'queries and mutations'],
  "descrizione": "Il tool query-graphql passa da sola lettura a lettura-"
                 "scrittura fra le due misurazioni. Il cambiamento e' pero' "
                 "dichiarato apertamente nella descrizione, WARNING incluso: "
                 "segnalazione di cortesia, non incidente di sicurezza.",
  "fonte": "RELIST_VERDETTI.md"},
]

PROVIDER = [
 ("Google",      r"AIza|googleapis|gcp|firebase"),
 ("OpenAI",      r"\bsk-[A-Za-z0-9]|openai"),
 ("GitHub",      r"ghp_|github[_ ]?token"),
 ("Slack",       r"xox[baprs]-|slack"),
 ("Groq",        r"gsk_|groq"),
 ("Docker",      r"dckr_pat_|docker"),
 ("OpenWeather", r"openweather"),
 ("AWS",         r"AKIA|aws[_ ]?(secret|access)"),
 ("Stripe",      r"sk_live_|pk_live_|stripe"),
]


def esiste(repo, timeout=25):
    """git ls-remote: sola lettura di metadati pubblici."""
    try:
        r = subprocess.run(["git", "ls-remote", "--heads",
                            f"https://github.com/{repo}"],
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            return "attivo"
        msg = (r.stderr or "").lower()
        if "not found" in msg or "repository not found" in msg:
            return "rimosso"
        return "irraggiungibile"
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception:
        return "errore"


def payload_presente(repo, file, firme, timeout=25):
    """Scarica il singolo file dall'HEAD e cerca le firme. Nessun clone."""
    if not file:
        return "n/d (nessun file singolo da controllare)"
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as f:
                t = f.read().decode("utf-8", "replace")
        except Exception:
            continue
        trovate = [p for p in firme if re.search(p, t, re.I)]
        if trovate:
            return f"PAYLOAD ANCORA PRESENTE ({len(trovate)}/{len(firme)} firme)"
        return "file presente ma firme non trovate (possibile correzione)"
    return "file non raggiungibile"


def credenziali_per_provider():
    p = REPO / "autorun" / "manual_audit" / "verdetti_HC.json"
    if not p.exists():
        return {}, 0
    d = json.loads(p.read_text(encoding="utf-8"))
    conf = [x for x in d if x.get("verdetto") in ("VP-C", "VP-D")]
    c = Counter()
    for x in conf:
        testo = f"{x.get('file','')} {x.get('nota','')} {x.get('repo','')}"
        nome = next((n for n, pat in PROVIDER if re.search(pat, testo, re.I)),
                    "non identificato")
        c[nome] += 1
    return c, len(conf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-rete", action="store_true",
                    help="salta la verifica online")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    casi = []
    for x in TIER1:
        casi.append({**x, "tier": 1, "tipo": "malware"})
    for x in TIER2:
        casi.append({**x, "tier": 2})

    for c in casi:
        if a.no_rete:
            c["stato_repo"] = c["stato_payload"] = "non verificato"
            continue
        print(f"  verifico {c['repo']} ...", flush=True)
        c["stato_repo"] = esiste(c["repo"])
        c["stato_payload"] = (payload_presente(c["repo"], c.get("file"),
                                               c["firma"])
                              if c["stato_repo"] == "attivo" else "n/d")

    cred, tot_cred = credenziali_per_provider()

    (OUT / "fase0_casi.json").write_text(
        json.dumps({"casi": casi, "credenziali_per_provider": dict(cred),
                    "credenziali_confermate": tot_cred},
                   ensure_ascii=False, indent=1), encoding="utf-8")

    print()
    for c in casi:
        print(f"[T{c['tier']}] {c['repo']:<45} {c['stato_repo']:<16} "
              f"{c['stato_payload']}")
    print(f"\ncredenziali confermate: {tot_cred}")
    for n, k in cred.most_common():
        print(f"   {n:<18} {k}")
    print(f"\n-> {OUT / 'fase0_casi.json'}")


if __name__ == "__main__":
    main()
