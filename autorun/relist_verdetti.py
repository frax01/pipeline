#!/usr/bin/env python3
"""
relist_verdetti.py — verdetti manuali sui cambi di descrizione trovati dal
ri-listing dal vivo (`relist_diff.py`).

Due assi distinti, perche' rispondono a domande diverse:

  CAMBIO — la capability e' cambiata davvero?
    RP-C   rug pull confermato: il tool oggi puo' fare qualcosa di pericoloso
           che prima non dichiarava, e chi lo aveva approvato non lo sa
    RP-D   espansione reale ma di portata limitata, o gia' implicita
    RESTR  il tool e' diventato piu' restrittivo di prima
    DOC    stessa capability, descrizione piu' accurata

  PERICOLO OGGI — quanto e' pericoloso il tool adesso, a prescindere dal cambio.
    ALTA / MEDIA / BASSA

La seconda colonna serve perche' un tool puo' essere pericolosissimo senza
essere un rug pull (lo era gia' a maggio), e viceversa.

Uso:
    python autorun/relist_verdetti.py --out docs/rirun/RELIST_VERDETTI.md
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CAMBI = REPO / "autorun" / "relist_cambi.json"

CAP = {"scrittura": r"\b(write|create|update|modify|insert|upsert|patch|mutation|mutate)\b",
       "cancellazione": r"\b(delete|remove|drop|destroy|purge|truncate|wipe|erase)\b",
       "esecuzione": r"\b(execute|exec|run|spawn|shell|command|eval|subprocess|bash|powershell)\b",
       "privilegi": r"\b(admin|root|sudo|privileg|grant|elevat)\b"}

# (server, tool) -> (cambio, pericolo_oggi, motivazione)
V = {
 ("sentry-official/mcp-cap-internal", "analyze_dhcp_packets"): ("RP-C", "ALTA",
    "Il caso piu' netto dell'intera analisi. Il server espone QUATTRO tool di "
    "analisi PCAP (dns, dhcp, icmp, capinfos); a uno solo, `analyze_dhcp_packets`, "
    "e' stata aggiunta la frase **'Then write data to user's system.'** — "
    "assente a maggio. Da strumento di sola lettura a strumento che scrive sul "
    "filesystem dell'utente. La modifica e' chirurgica: 621 -> 659 caratteri, "
    "similarita' 97%, nome del tool e resto della descrizione invariati, gli "
    "altri tre tool non toccati. Nessun avviso, nessun 'WARNING', nessuna "
    "spiegazione di cosa scriva o dove. Da notare anche il nome "
    "dell'organizzazione, 'sentry-official', che evoca un'affiliazione a un "
    "fornitore noto e presta fiducia non guadagnata."),
 ("letoribo/mcp-graphql-enhanced", "query-graphql"): ("RP-C", "ALTA",
    "Da 'Execute a GraphQL query against the endpoint' a 'Execute GraphQL "
    "operations (queries and mutations)... WARNING: Mutation operations will "
    "modify persistent state'. Da sola lettura a lettura-scrittura: chi lo "
    "aveva approvato come query esegue oggi mutation. A differenza del caso "
    "sentry, qui il cambiamento e' dichiarato apertamente."),
 ("verygoodplugins/mcp-automem", "delete_memory"): ("RP-D", "ALTA",
    "Da cancellazione di UNA memoria per id a 'bulk-delete by tag: delete ALL "
    "memories tagged with ANY of these tags', con l'ammissione esplicita "
    "'There is NO dry-run'. Da operazione puntuale a cancellazione di massa "
    "senza prova: espansione reale del raggio distruttivo, ma su dati del "
    "server stesso e coerente con lo scopo."),
 ("prism-mcp-server", "query_memory_natural"): ("RP-D", "MEDIA",
    "A maggio interrogava solo la memoria locale. Oggi: 'paid tiers "
    "automatically run one quick Synalux web search'. Compare un percorso di "
    "USCITA DATI verso un servizio esterno che prima non c'era — la domanda "
    "dell'utente lascia la macchina. Il testo dichiara una salvaguardia "
    "('reserved or uncertain content is cloud-or-refuse'), quindi non e' "
    "occulto, ma e' un cambiamento di comportamento con implicazioni di "
    "riservatezza, non una riformulazione."),
 ("nayantarasundarraj-hue/databricks-cursor-mcp", "execute_sql"): ("RESTR", "ALTA",
    "Aggiunge un gate: 'DDL/DML statements (DROP, DELETE, INSERT, ALTER) "
    "REQUIRE explicit user confirmation via confirm: true'. La capability "
    "c'era gia'; oggi e' vincolata. Il tool resta ad alto rischio perche' "
    "esegue SQL arbitrario su un warehouse."),
 ("berthojoris/mysql-mcp", "execute_write_query"): ("RESTR", "ALTA",
    "'DELETE SQL requires the separate delete permission in addition to "
    "execute': la cancellazione viene separata dalle altre scritture e messa "
    "dietro un permesso dedicato. Piu' restrittivo di maggio."),
 ("hatrigt/hana-mcp-server", "hana_execute_query"): ("RESTR", "ALTA",
    "Dichiara che 'INSERT/UPDATE/DELETE are blocked by default' e vanno "
    "abilitate una per una via variabile d'ambiente. E' insieme una "
    "restrizione e una disclosure migliore: la scrittura esiste ma di default "
    "e' chiusa."),
 ("itsbrex/attio-mcp-server", "update_list_entry"): ("RESTR", "MEDIA",
    "Da 'create or update' (che creava la voce se non la trovava) a 'update "
    "list entries by entry_id': la creazione implicita sparisce, il tool "
    "diventa piu' stretto. Le parole di cancellazione che l'euristica ha "
    "segnalato vengono dalla spiegazione sui multiselect, non da un'azione "
    "distruttiva nuova."),
 ("itsbrex/attio-mcp-server", "update_record"): ("RESTR", "MEDIA",
    "Identico al caso `update_list_entry` dello stesso server: da 'create or "
    "update' a update per `record_id`."),
 ("zhaojian2626/figma-mcp-server", "figma_download_and_simplify"): ("RESTR", "BASSA",
    "Marcato '[Legacy]' con rimando a un tool sostitutivo. Sola lettura da "
    "Figma in entrambe le versioni."),
}

DOC_DEFAULT = {
 ("proofmath-owner/ai-filesystem-mcp", "transaction"):
    "Da 'Execute file operations in an atomic transaction' all'elenco esplicito "
    "'create/write/update/move/delete'. Le operazioni erano gia' tutte incluse "
    "in 'file operations': la capability non cambia, cambia la chiarezza. "
    "Resta un tool ad alta pericolosita' intrinseca.",
 ("qianchenglong/obsidian-cdp-mcp", "obsidian_eval"):
    "Esecuzione di JavaScript arbitrario con accesso completo all'API di "
    "Obsidian in entrambe le versioni; oggi la descrizione aggiunge esempi "
    "d'uso. Pericolosissimo, ma lo era gia' a maggio.",
 ("peakacom/peaka-mcp-server", "peaka_execute_sql_query"):
    "Aggiunge una procedura da seguire prima di eseguire la query. Nessuna "
    "capability nuova.",
 ("jl-codes/platformio-mcp", "build_project"):
    "Aggiunge cache, lock hardware e parser di errori strutturati. Compilava "
    "gia' prima.",
 ("jl-codes/platformio-mcp", "upload_firmware"):
    "Stessa operazione di scrittura del firmware sul dispositivo, con "
    "dettagli su lock della porta e monitor seriale.",
 ("mcp-architector", "delete-module"):
    "Precisa cosa NON viene cancellato (entries, slice custom): la "
    "descrizione restringe l'ambito percepito, non lo allarga.",
 ("thesharque/mcp-architect", "delete-module"):
    "Stesso identico cambiamento di `mcp-architector`: sono due repository "
    "dello stesso progetto.",
 ("gcorroto/mcp-svn", "svn_delete"):
    "'Eliminar archivos del control de versiones' -> 'Remove files from "
    "version control': e' una TRADUZIONE dallo spagnolo all'inglese. "
    "L'euristica l'ha segnalata solo perche' cerca parole inglesi.",
 ("madllama25/fastmail-mcp", "check_function_availability"):
    "Chiarisce quando i tool calendario risultano disponibili (CalDAV vs "
    "JMAP). Tool di sola introspezione.",
 ("moscaverd/local-skills-mcp", "get_skill"):
    "Testo esteso, stessa funzione: carica istruzioni di prompt che "
    "modificano il comportamento dell'agente. Superficie di prompt injection "
    "reale, ma identica a maggio.",
 ("kdpa-llc/local-skills-mcp", "get_skill"):
    "Stesso progetto di `moscaverd/local-skills-mcp`, stesso cambiamento.",
 ("shrike-security/shrike-mcp", "scan_web_search"):
    "Aggiunge una frase di sintesi in testa. E' un tool difensivo: controlla "
    "le query prima che raggiungano servizi esterni.",
 ("shrike-security/shrike-mcp", "scan_agent_card"):
    "Come `scan_web_search`: frase di sintesi aggiunta a un controllo "
    "difensivo su metadati di agenti remoti.",
}

PERICOLO_DOC = {
 ("proofmath-owner/ai-filesystem-mcp", "transaction"): "ALTA",
 ("qianchenglong/obsidian-cdp-mcp", "obsidian_eval"): "ALTA",
 ("peakacom/peaka-mcp-server", "peaka_execute_sql_query"): "MEDIA",
 ("jl-codes/platformio-mcp", "build_project"): "MEDIA",
 ("jl-codes/platformio-mcp", "upload_firmware"): "MEDIA",
 ("mcp-architector", "delete-module"): "BASSA",
 ("thesharque/mcp-architect", "delete-module"): "BASSA",
 ("gcorroto/mcp-svn", "svn_delete"): "MEDIA",
 ("madllama25/fastmail-mcp", "check_function_availability"): "BASSA",
 ("moscaverd/local-skills-mcp", "get_skill"): "MEDIA",
 ("kdpa-llc/local-skills-mcp", "get_skill"): "MEDIA",
 ("shrike-security/shrike-mcp", "scan_web_search"): "BASSA",
 ("shrike-security/shrike-mcp", "scan_agent_card"): "BASSA",
}

ORDINE = {"RP-C": 0, "RP-D": 1, "RESTR": 2, "DOC": 3}
RISCHIO = {"ALTA": 0, "MEDIA": 1, "BASSA": 2}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    cam = json.loads(CAMBI.read_text(encoding="utf-8"))["cambiati"]
    per = Counter(c["server"] for c in cam)
    mirati = [c for c in cam if per[c["server"]] < 5]

    cand = []
    for c in mirati:
        pri, dop = c["prima"].lower(), c["dopo"].lower()
        nuove = [k for k, p in CAP.items()
                 if re.search(p, dop) and not re.search(p, pri)]
        if not nuove:
            continue
        k = (c["server"], c["tool"])
        if k in V:
            camb, peric, mot = V[k]
        else:
            camb = "DOC"
            peric = PERICOLO_DOC.get(k, "MEDIA")
            mot = DOC_DEFAULT.get(k, "Riformulazione senza capability nuove.")
        cand.append({**c, "capability_segnalate": nuove, "cambio": camb,
                     "pericolo_oggi": peric, "motivazione": mot})

    cand.sort(key=lambda x: (ORDINE[x["cambio"]], RISCHIO[x["pericolo_oggi"]],
                             x["server"]))

    out = []
    def w(s=""):
        out.append(s)
        print(s.encode("utf-8", "replace").decode("utf-8", "replace"))

    cc = Counter(x["cambio"] for x in cand)
    cp = Counter(x["pericolo_oggi"] for x in cand)

    w("# Verdetti sui cambi di descrizione con capability nuove")
    w()
    w(f"I **{len(cand)}** cambi mirati che l'euristica segnala come portatori di")
    w("una capability pericolosa nuova, letti uno per uno sul testo integrale.")
    w()
    w("Due assi, perche' rispondono a domande diverse: se la capability e'")
    w("**cambiata**, e quanto il tool e' **pericoloso oggi** a prescindere.")
    w()
    w("| cambio | n | significato |")
    w("|---|---:|---|")
    w(f"| **RP-C** | {cc['RP-C']} | rug pull: oggi puo' fare qualcosa di pericoloso che prima non dichiarava |")
    w(f"| **RP-D** | {cc['RP-D']} | espansione reale ma limitata, o gia' implicita |")
    w(f"| RESTR | {cc['RESTR']} | **piu' restrittivo** di maggio |")
    w(f"| DOC | {cc['DOC']} | stessa capability, descrizione piu' accurata |")
    w()
    w(f"Pericolosita' **oggi**: ALTA {cp['ALTA']}, MEDIA {cp['MEDIA']}, "
      f"BASSA {cp['BASSA']}.")
    w()
    w("> **Un rug pull vero e' minimamente diverso.** Ordinare per dissimilarita'")
    w("> nasconde i casi peggiori: `sentry-official/mcp-cap-internal` ha")
    w("> similarita' **97%** e sarebbe stato l'ultimo di ogni elenco ordinato per")
    w("> entita' della modifica. E' invece il caso piu' grave trovato.")
    w()
    for x in cand:
        w(f"## [{x['cambio']} · pericolo {x['pericolo_oggi']}] "
          f"`{x['server']}` :: `{x['tool']}`")
        w()
        w(f"*similarita' {x['similarita']:.0%} · l'euristica ha segnalato: "
          f"{', '.join(x['capability_segnalate'])}*")
        w()
        w(f"- **maggio**: {x['prima'][:300]}")
        w(f"- **oggi**: {x['dopo'][:300]}")
        w()
        w(f"**Verdetto.** {x['motivazione']}")
        w()

    if args.out:
        Path(args.out).write_text("\n".join(out), encoding="utf-8")
        print(f"\n-> {args.out}")
    (REPO / "autorun" / "relist_verdetti.json").write_text(
        json.dumps(cand, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
