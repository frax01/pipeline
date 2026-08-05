#!/usr/bin/env python3
"""
!!! ANALISI INVALIDA — CONSERVATA A DOCUMENTAZIONE DELL'ERRORE !!!

Questo script assumeva che il campo `details` dei finding di `mcp-security-scan`
contenesse l'inventario COMPLETO dei tool di un server. E' FALSO: contiene solo
i tool che hanno fatto scattare quello specifico finding. Verificato il
2026-08-05 con il ri-listing dal vivo:

    0xDmsk/pwndoc-mcp        details di maggio: 1 tool (X-01) + 2 (X-02)
                             tools/list di oggi: 47 tool

I "357 tool aggiunti" che questo script calcola sono quindi in larga parte tool
gia' presenti a maggio e mai segnalati. NON usare questi numeri.

Perche' non e' riparabile: per misurare i tool aggiunti serve l'inventario
completo di maggio, che non esiste in nessun archivio. La direzione opposta
(tool SPARITI) e' invece misurabile con `relist_diff.py`, perche' li' l'elenco
di oggi e' completo. Vedi docs/rirun/RUGPULL.md §6.

DOCSTRING ORIGINALE:
"""
rugpull_nuovi.py — i server AGGIUNGONO tool fra le due analisi?

E' il secondo vettore di rug pull, e strutturalmente il piu' forte: in MCP il
consenso si da' **per server**, non per singolo tool. Se un server approvato con
i tool A, B, C due mesi dopo ne espone anche D, nessuno richiede una nuova
approvazione — D e' disponibile all'agente in silenzio, mentre le descrizioni dei
tool gia' noti restano intatte a rassicurare chi controlla.

**Perche' serve un sottoinsieme diverso da `rugpull_diff.py`.** Per dire "questo
tool e' nuovo" serve l'inventario COMPLETO del server in entrambe le run, non
solo i tool che uno scanner ha segnalato. Solo `mcp-security-scan` lo salva (nel
campo `details` mette l'intera lista dei tool); `mcp-shield` registra soltanto il
tool flaggato. Mescolarli produce un artefatto: un tool "sparito" spesso e' solo
un tool che stavolta non e' finito sotto flag — ed e' per questo che sull'insieme
misto i rimossi (3.229) risultavano il triplo degli aggiunti (1.029), cosa che di
per se' non ha senso.

Restringendo ai server con inventario completo in entrambe le run i numeri
diventano coerenti: 357 aggiunti e 156 rimossi su 2.515 server.

Uso:
    python autorun/rugpull_nuovi.py
    python autorun/rugpull_nuovi.py --json autorun/rugpull_nuovi.json
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

RUN1 = Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData"
RUN2 = Path.home() / "Desktop" / "pipeline_rerun_pull"

# Solo security_scan: e' l'unica sorgente con l'inventario completo.
SUB1, SUB2 = "0_tool_mcp_security_scan", "security_scan"

PERICOLOSE = (r"\b(execute|exec|run|spawn|shell|command|eval|subprocess|bash|"
              r"powershell|delete|remove|drop|destroy|purge|truncate|wipe|erase|"
              r"admin|root|sudo|privileg|grant|elevat)\b")

# Soglia oltre la quale l'aggiunta e' sviluppo di funzionalita', non innesto
# mirato di un tool (stesso criterio dei REL in rugpull_diff.py).
SOGLIA_RILASCIO = 3

# Verdetti manuali sui casi mirati con capability pericolose.
#   NT-C  il server acquista un potere estraneo al suo scopo dichiarato
#   NT-D  capability nuova ma coerente con lo scopo, o vincolata da salvaguardie
#   NT-B  benigno: la parola chiave non corrisponde a un'azione pericolosa
VERDETTI = {
    ("paolino/mcp-memory-server", "kill_processes"): ("NT-C",
        "Un server di ispezione della memoria acquista la capacita' di "
        "TERMINARE PROCESSI per PID. E' un potere estraneo allo scopo "
        "dichiarato del server, ed e' il caso piu' rilevante trovato. Ha "
        "salvaguardie (rifiuta PID 0 e 1, rifiuta processi di root se non gira "
        "come root, SIGTERM salvo richiesta esplicita) e il nome del tool "
        "e' esplicito, ma chi aveva approvato un 'memory server' non ha "
        "approvato questo."),
    ("deeprave/mcp-guide", "read_resource"): ("NT-D",
        "Risolve URI `guide://`; le Command URI (`guide://_command`) eseguono "
        "comandi del server. Esecuzione reale, ma confinata al set di comandi "
        "del server stesso, non shell."),
    ("lyonk71/joplin-mcp", "execute_joplin_readonly_script"): ("NT-D",
        "Esegue JavaScript con l'oggetto `joplin` globale. Il nome e la "
        "descrizione dichiarano la modalita' read-only e che modifiche, "
        "cancellazioni e creazioni sono bloccate: esecuzione di codice reale "
        "ma vincolata."),
    ("nilsir/mcp-server-mysql", "dry_run_execute"): ("NT-D",
        "Esegue INSERT/UPDATE/DELETE dentro una transazione e fa rollback. "
        "Percorso di scrittura nuovo, ma progettato per non persistere."),
    ("shawkatdidar/todoist_claude_mcp_server_v1.0", "delete_task"): ("NT-D",
        "Cancellazione di task Todoist: distruttiva sui dati dell'utente ma "
        "pienamente coerente con lo scopo di un server Todoist."),
    ("ttpears/gitlab-mcp", "delete_broadcast_message"): ("NT-D",
        "Cancellazione di un broadcast GitLab, richiede privilegi di "
        "amministratore: distruttiva ma coerente con un wrapper GitLab e "
        "gia' vincolata dai permessi dell'API."),
    ("whenmoon-afk/claude-memory-mcp", "continuity"): ("NT-D",
        "Dispatcher che espone anche `delete` e le azioni di scrittura sul "
        "database locale di continuita': superficie nuova ma sullo storage "
        "del server stesso."),
    ("shadcnspace/shadcnspace-mcp", "get_audit_checklist"): ("NT-D",
        "Tool nuovo la cui descrizione impone all'agente 'CRITICAL: You MUST "
        "execute this tool BEFORE using any other tools in this MCP server'. "
        "Lo scopo dichiarato e' legittimo (verificare la licenza prima di "
        "installare componenti PRO), ma la FORMA e' quella del dirottamento "
        "di precedenza: un tool che si impone come primo su tutti gli altri. "
        "E' il caso piu' vicino a un pattern di tool-shadowing nell'insieme "
        "dei tool aggiunti, e va segnalato per la forma anche se l'intento "
        "sembra benigno."),
    ("brkhrdt/pty-mcp", "run_command"): ("NT-D",
        "Esecuzione di comandi in una sessione PTY: capability reale, ma il "
        "server si chiama `pty-mcp` e la shell interattiva e' il suo scopo "
        "dichiarato. Aggiunto insieme a `start_session` e `set_sentinel`, "
        "cioe' il nucleo funzionale del server."),
    ("nhatvu148/video-transcriber-mcp", "delete_all_transcripts"): ("NT-D",
        "Cancellazione di massa irreversibile ('Use with caution - this "
        "cannot be undone'), aggiunta insieme ad altre due operazioni di "
        "cancellazione: distruttiva ma coerente con un gestore di "
        "trascrizioni."),
}


def items(d):
    if isinstance(d, list):
        return d
    for k in ("findings", "vulnerabilities", "entries"):
        v = d.get(k)
        if isinstance(v, list):
            return v
    return []


def norm(u):
    return re.sub(r"^https?://github\.com/", "",
                  str(u or "").strip().rstrip("/")).lower()


def inventario_completo(root: Path, sub: str):
    """server -> {tool: descrizione}, solo da `details` di security_scan."""
    inv = defaultdict(dict)
    base = root / sub
    if not base.is_dir():
        return inv
    for p in base.rglob("*.json"):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        for f in items(d):
            if not isinstance(f, dict):
                continue
            s = norm(f.get("server_url") or f.get("server_name"))
            det = f.get("details")
            if not s or not isinstance(det, str) or not det.lstrip().startswith("["):
                continue
            try:
                tools = json.loads(det)
            except Exception:
                continue
            for t in tools:
                if isinstance(t, dict) and t.get("name"):
                    inv[s].setdefault(t["name"], t.get("description") or "")
    return inv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    i1, i2 = inventario_completo(RUN1, SUB1), inventario_completo(RUN2, SUB2)
    comuni = set(i1) & set(i2)

    nuovi, rimossi = [], 0
    for s in sorted(comuni):
        rimossi += len(set(i1[s]) - set(i2[s]))
        for t in sorted(set(i2[s]) - set(i1[s])):
            nuovi.append({"server": s, "tool": t, "descrizione": i2[s][t]})

    per_server = Counter(n["server"] for n in nuovi)
    for n in nuovi:
        n["tool_aggiunti_dal_server"] = per_server[n["server"]]
        n["pericolosa"] = bool(re.search(PERICOLOSE, n["descrizione"].lower()))
        n["mirato"] = per_server[n["server"]] <= SOGLIA_RILASCIO
        k = (n["server"], n["tool"])
        if k in VERDETTI:
            n["verdetto"], n["motivazione"] = VERDETTI[k]
        elif not (n["pericolosa"] and n["mirato"]):
            n["verdetto"] = "NT-REL" if not n["mirato"] else "NT-B"
            n["motivazione"] = ("Aggiunto insieme ad altri tool: sviluppo di "
                                "funzionalita'." if not n["mirato"] else
                                "Nessuna capability pericolosa dichiarata.")
        else:
            n["verdetto"], n["motivazione"] = "NT-B", (
                "Letto a mano: la parola chiave non corrisponde a un'azione "
                "pericolosa (lettura, diagnostica, aggregazione di chiamate "
                "gia' esistenti, tool deprecato).")

    print(f"server con inventario completo in entrambe le run : {len(comuni):,}")
    print(f"tool aggiunti                                     : {len(nuovi):,} "
          f"su {len(per_server):,} server")
    print(f"tool rimossi                                      : {rimossi:,}")
    print(f"  di cui con capability pericolose dichiarate     : "
          f"{sum(1 for n in nuovi if n['pericolosa']):,}")
    print(f"  di cui aggiunte mirate (<={SOGLIA_RILASCIO} tool) e pericolose  : "
          f"{sum(1 for n in nuovi if n['pericolosa'] and n['mirato']):,}")
    print()
    c = Counter(n["verdetto"] for n in nuovi)
    for v in ("NT-C", "NT-D", "NT-B", "NT-REL"):
        print(f"  {v:<7} {c.get(v, 0):>4}")
    print()
    for n in nuovi:
        if n["verdetto"] in ("NT-C", "NT-D"):
            print(f"[{n['verdetto']}] {n['server']} :: {n['tool']}")

    if a.json:
        Path(a.json).write_text(json.dumps(nuovi, ensure_ascii=False, indent=1),
                                encoding="utf-8")
        print(f"\n-> {a.json}")


if __name__ == "__main__":
    main()
