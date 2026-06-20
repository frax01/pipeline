# Pipeline — Analisi di sicurezza di server MCP

Pipeline distribuita per l'analisi di sicurezza di **69.104 server MCP (Model
Context Protocol)** raccolti da GitHub (60.205) e npm/NPX (8.899). L'analisi è
condotta con **7 strumenti** eseguiti in parallelo su **9 VM**, seguita da un
processo di triage e validazione che riduce milioni di finding grezzi a un
insieme di **veri positivi (VP)** azionabili.

Questo repository contiene il **codice** della pipeline (raccolta del dataset,
esecuzione, wrapper dei tool, post-processing, aggregazione) e la
**documentazione/risultati** in forma leggibile. I dataset grezzi e gli output
JSON pesanti (decine di GB) sono archiviati separatamente — vedere [§ Dati](#dati).

## Pipeline end-to-end

```
web_crawler/        raccolta degli URL dei server MCP da 17 directory pubbliche
      │
      ▼
hashAnalysis/       deduplica per hash del contenuto  ──►  dataset unico (69.104)
      │
      ▼
deploy.py / launch.py    esecuzione dei 7 tool su 9 VM (uno per VM)
      │                  (frameworks/ esegue+parsa, npm_runner/ builda i repo)
      ▼
<tool>/merge_stats.py    merge degli shard delle 9 VM, per ogni tool
      │
      ▼
<tool>/postprocessing/   triage a 3 stadi (filtro regex → classificatori → merge)
      │
      ▼
cross_framework/    consenso dei VP tra i 7 tool (Tier 1/2/3)
      │
      ▼
docs/               validazione manuale + report finali
```

## Documentazione

| Documento | Contenuto |
|-----------|-----------|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Architettura, i 7 tool, workflow di triage a 3 stadi, consenso cross-framework |
| [docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md) | Report completo dei risultati per categoria di minaccia |
| [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md) | Sintesi della validazione manuale dei VP contro il codice sorgente reale |
| [docs/MANUAL.md](docs/MANUAL.md) | Tabelle dettagliate di verifica manuale per categoria (verdetto per ogni server) |
| [docs/MANUAL_CHECKLIST.md](docs/MANUAL_CHECKLIST.md) | Checklist dei controlli manuali eseguiti per ciascuna delle 17 categorie |
| [docs/STATE_OF_THE_ART.md](docs/STATE_OF_THE_ART.md) | Stato dell'arte: paper accademici analizzati per la tesi |
| [web_crawler/README.md](web_crawler/README.md) | Dettaglio degli scraper di raccolta del dataset (17 sorgenti) |

## Struttura del repository

```
pipeline/
├── README.md                     questo file
├── deploy.py                     orchestratore VM (deploy / launch / pull / merge / status / tail)
├── launch.py                     launcher locale dei tool (start / resume / status / kill)
├── pull_partial_results.sh       aggregazione risultati parziali dalle VM
├── 0.0. All servers unified (69104).xlsx   dataset unico di input
├── requirements.txt              dipendenze Python
├── package.json / tsconfig.json  progetto Node/TS per l'helper MCP SDK (frameworks/listTools.ts)
│
├── web_crawler/                  raccolta URL dei server MCP (17 scraper + run_all.py) — vedi suo README
├── hashAnalysis/                 deduplica del dataset per hash del contenuto
│   ├── hash_analyzer.py             clona ogni repo e calcola l'hash del contenuto
│   ├── remove_true_duplicates.py    rimozione dei duplicati esatti
│   ├── remove_from_excel.py         pulizia delle righe nel dataset .xlsx
│   ├── clean_slashes_and_git.py     normalizzazione degli URL
│   └── vm/                          varianti per l'esecuzione su VM
│
├── functions/                    utility condivise
│   ├── config.py                    path, comandi, VM, mappe delle categorie (config centrale)
│   ├── helper.py                    esecuzione processi e helper generici
│   ├── buildConfig.py               clone repo, build della config MCP, ensure bun/npm
│   ├── hash.py / hashCache.py       hashing del contenuto (per la deduplica)
│   ├── stats.py                     aggregazione delle statistiche per tool
│   └── recapFramework.py            riepilogo per server
│
├── frameworks/                   wrapper di esecuzione/parsing dei tool
│   ├── mcpGuard.py mcpWatch.py mcpScan.py mcpShield.py
│   ├── mcpSecurityScan.py mcpCheck.py fuzzing.py llmAnalysis.py
│   └── listTools.ts                 (TS) si connette a un server MCP via stdio e ne elenca i tool
│
├── npm_runner/                   build dei repo prima dell'analisi (`npm run build`)
│   ├── npm_build.sh                 versione bash (Linux/VM)
│   └── npm_build.ps1                versione PowerShell (Windows)
│
├── monitorVM/                    monitor.py — dashboard a terminale dello stato dei tool sulle 9 VM
│
├── mcp_guard/             un tool — STESSA struttura per tutti i 7:
│   ├── run_<tool>.py               esecuzione (locale o su VM)
│   ├── merge_stats.py              merge degli shard delle 9 VM
│   ├── commands.md  howDoesItWork.md   doc del tool (+ changes.md dove presente)
│   └── postprocessing/             triage dei risultati:
│       ├── stage1_filter.py            Stage 1 — filtro regex
│       ├── stage2_pipeline.py          Stage 2A/2B + merge
│       ├── classifiers/                classificatori Stage 2B (per categoria)
│       └── special/                    script per scopi specifici
├── mcp_watch/  fuzzing/  mcp_scan/  mcp_shield/  mcp_security_scan/  mcp_check/   (idem)
│
├── cross_framework/      aggregazione dei VP tra i 7 tool (consenso Tier 1/2/3)
│   ├── cross_framework_consensus.py    consenso principale
│   ├── _aggregate_threats.py           aggregazione per categoria di minaccia
│   ├── _verify_credleak.py             verifica mirata dei credential leak
│   ├── _find_missing.py                ricerca dei finding mancanti tra i tool
│   └── check_pt_fuzz.py                cross-check path-traversal vs fuzzing
│
└── docs/                 documentazione e report (vedi tabella sopra)
```

> Il prefisso numerico `NN_` degli scraper in `web_crawler/` segue la numerazione
> delle fonti nella tesi. Gli scraper sono **17** ma le fonti **18**: `17_npm.py`
> raccoglie dal registry npm sia i server **npm** sia i **npx-runnable** (sono
> pacchetti npm, stesso scrape → fonti 17 e 18). `npm_runner/` **non** è una fonte
> di raccolta: è lo step di build (`npm run build`) usato in fase di analisi.

## I 7 strumenti

| Tool | VM | Cosa rileva |
|------|----|-------------|
| **mcp-guard** | VM1 | Path traversal, command/SQL/code injection, SSRF, credenziali (SAST + fuzzing) |
| **mcp-watch** | VM2 | Credenziali hardcoded, data exfiltration, protocol violation, tool poisoning |
| **tool_fuzzing** | VM3 | Crash/DoS, error disclosure, injection eseguita (input malformati) |
| **mcp-scan** | VM4 | Prompt injection, untrusted content, capability distruttive |
| **mcp-shield** | VM5 | Hidden instructions / tool shadowing (analisi semantica LLM) |
| **mcp-security-scan** | VM6 | Capability pericolose, rug pull, accesso a file sensibili |
| **mcp-check** | VM7 | Conformance al protocollo MCP |

Le VM8–VM9 ospitano ruoli aggiuntivi di aggregazione/validazione (`scanorama`,
`validator`) — vedi la mappa delle VM nel docstring di [`deploy.py`](deploy.py).

## Avvio rapido

```bash
pip install -r requirements.txt
npm install                 # solo se serve l'helper TypeScript frameworks/listTools.ts (MCP SDK)
# I 7 framework di scanning si installano a parte (vedi i commands.md dei tool).
```

Ogni entry point supporta `--help`. **Non** esiste un singolo comando che esegua
l'intera analisi (69.104 server × 7 tool): è distribuita su 9 VM per progetto.
Percorso consigliato:

```bash
# 0. (opzionale) ricostruire il dataset dalle directory MCP pubbliche
python web_crawler/run_all.py             # --list, --only, --skip ; vedi web_crawler/README.md
#    poi deduplica per ottenere il dataset unico (es.):
python hashAnalysis/hash_analyzer.py
python hashAnalysis/remove_true_duplicates.py

# 1. provare UN tool in locale su pochi server (funziona ovunque, Windows incluso)
python launch.py scan --start 0           # oppure: python mcp_scan/run_scan.py --start 0 --end 20

# 2. esecuzione distribuita completa, orchestrata da deploy.py
python deploy.py --help                   # deploy / launch / pull / merge / status / tail
python deploy.py --status                 # stato dei tool su tutte le VM
#    i comandi esatti per ogni tool sono in <tool>/commands.md

# 3. monitorare l'avanzamento sulle VM
python monitorVM/monitor.py

# 4. post-processing / triage a 3 stadi (per ogni tool)
python mcp_guard/postprocessing/stage1_filter.py
python mcp_guard/postprocessing/stage2_pipeline.py --category all --merge

# 5. consenso cross-tool dei VP
python cross_framework/cross_framework_consensus.py
```

I parametri di configurazione (path del dataset, directory dei framework,
comandi, indirizzi delle VM) sono centralizzati in
[`functions/config.py`](functions/config.py).

## Dati

Per mantenere il repository leggero e pulito, **non** sono versionati:
i pull grezzi dalle VM, gli output JSON degli scanner, gli `.xlsx` per-sorgente
del `web_crawler/` e gli intermedi del post-processing (decine di GB). Restano
invece il **codice** che li produce e i **report** leggibili. Per ri-eseguire gli
`stage2_pipeline.py` in `*/postprocessing/` è necessario ripristinare i dati
grezzi.

> Nota sui dati pubblicati: i valori delle credenziali di terze parti emerse come
> *findings* dell'analisi sono **mascherati** (placeholder) nei report e nel
> dataset `.xlsx` versionati.

## Risultati in sintesi

L'analisi produce, dopo il triage a 3 stadi e la validazione manuale, l'insieme
dei veri positivi per categoria di minaccia (SQL injection, credential leak,
SSRF, prompt injection, command/code injection, dangerous capabilities, untrusted
content, ecc.). Il dettaglio completo è in
[docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md), la validazione
manuale di sintesi in [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md) e
le tabelle dettagliate per categoria in [docs/MANUAL.md](docs/MANUAL.md).
