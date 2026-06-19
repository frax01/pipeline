# Pipeline — Analisi di sicurezza di server MCP

Pipeline distribuita per l'analisi di sicurezza di **69.104 server MCP (Model
Context Protocol)** raccolti da GitHub (60.205) e npm/NPX (8.899). L'analisi è
condotta con **7 strumenti** eseguiti in parallelo su **9 VM**, seguita da un
processo di triage e validazione che riduce milioni di finding grezzi a un
insieme di **veri positivi (VP)** azionabili.

Questo repository contiene il **codice** della pipeline (esecuzione, wrapper dei
tool, post-processing, aggregazione) e la **documentazione/risultati** in forma
leggibile. I dataset grezzi e gli output JSON pesanti (decine di GB) sono
archiviati separatamente — vedere [§ Dati](#dati).

## Documentazione

| Documento | Contenuto |
|-----------|-----------|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Architettura, i 7 tool, workflow di triage a 3 stadi, consenso cross-framework |
| [docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md) | Report completo dei risultati per categoria di minaccia |
| [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md) | Validazione manuale dei VP contro il codice sorgente reale |
| [docs/STATE_OF_THE_ART.md](docs/STATE_OF_THE_ART.md) | Stato dell'arte |

## Struttura del repository

```
pipeline/
├── README.md                     questo file
├── deploy.py                     orchestratore VM (deploy / launch / pull / status)
├── launch.py                     launcher locale dei tool
├── pull_partial_results.sh       aggregazione risultati dalle VM
├── 0.0. All servers unified (69104).xlsx   dataset unico di input
│
├── functions/                    utility condivise (config, helper, stats, buildConfig)
├── frameworks/                   wrapper Python dei 7 tool
├── monitorVM/                    monitoraggio stato VM
│
├── mcp_guard/             un tool — STESSA struttura per tutti i 7:
│   ├── run_<tool>.py               esecuzione sulle VM
│   ├── merge_stats.py              merge degli shard delle 9 VM
│   ├── *.md                        doc (howDoesItWork.md, commands.md)
│   └── postprocessing/             triage dei risultati:
│       ├── stage1_filter.py            Stage 1 — filtro regex
│       ├── stage2_pipeline.py          Stage 2A/2B + merge
│       ├── classifiers/                classificatori Stage 2B (per categoria)
│       └── special/                    script per scopi specifici
├── mcp_watch/  mcp_scan/  mcp_shield/  mcp_security_scan/  mcp_check/  fuzzing/   (idem)
│
├── cross_framework/      aggregazione dei VP tra i 7 tool (consenso Tier 1/2/3)
├── hashAnalysis/         script di deduplica del dataset
└── docs/                 documentazione e report
```

## I 7 strumenti

| Tool | Cosa rileva |
|------|-------------|
| **mcp-guard** | Path traversal, command/SQL/code injection, SSRF, credenziali (SAST + fuzzing) |
| **mcp-watch** | Credenziali hardcoded, data exfiltration, protocol violation, tool poisoning |
| **tool_fuzzing** | Crash/DoS, error disclosure, injection eseguita (input malformati) |
| **mcp-scan** | Prompt injection, untrusted content, capability distruttive |
| **mcp-shield** | Hidden instructions / tool shadowing (analisi semantica LLM) |
| **mcp-security-scan** | Capability pericolose, rug pull, accesso a file sensibili |
| **mcp-check** | Conformance al protocollo MCP |

## Avvio rapido

```bash
pip install -r requirements.txt
# I 7 framework di scanning si installano a parte (vedi i commands.md dei tool).
```

Ogni entry point supporta `--help`. **Non** esiste un singolo comando che esegua
l'intera analisi (69.104 server × 7 tool): è distribuita su 9 VM per progetto.
Percorso consigliato:

```bash
# 1. (opzionale) ricostruire il dataset dai cataloghi MCP
python web_crawler/run_all.py                     # --help, --list, --only, --skip

# 2. provare UN tool in locale su pochi server (funziona ovunque, Windows incluso)
python mcp_scan/run_scan.py --start 0 --end 20    # ogni run_*.py ha --help

# 3. esecuzione distribuita completa, orchestrata da deploy.py
python deploy.py --help                           # tutti i comandi: deploy/launch/pull/status
python deploy.py --status                         # stato dei tool su tutte le VM
#   i comandi esatti per ogni tool sono in <tool>/commands.md

# 4. post-processing / triage a 3 stadi (per ogni tool)
python mcp_guard/postprocessing/stage1_filter.py
python mcp_guard/postprocessing/stage2_pipeline.py --category all --merge
```

I parametri di configurazione (path del dataset, directory dei framework,
comandi) sono centralizzati in [`functions/config.py`](functions/config.py).

## Dati

Per mantenere il repository leggero e pulito, **non** sono versionati:
i pull grezzi dalle VM, gli output JSON degli scanner e gli intermedi del
post-processing (decine di GB). Restano invece il **codice** che li produce e i
**report** leggibili. Per ri-eseguire gli `stage2_pipeline.py` in `*/postprocessing/`
è necessario ripristinare i dati grezzi.

## Risultati in sintesi

L'analisi produce, dopo il triage a 3 stadi e la validazione manuale, l'insieme
dei veri positivi per categoria di minaccia (SQL injection, credential leak,
SSRF, prompt injection, command/code injection, dangerous capabilities, untrusted
content, ecc.). Il dettaglio completo è in
[docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md) e la validazione
manuale in [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md).
