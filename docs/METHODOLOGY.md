# Metodologia — Analisi di sicurezza di server MCP

Questo documento descrive l'architettura, il dataset e la metodologia di analisi
del progetto. È la sintesi delle note di lavoro interne, riorganizzata per la
lettura. Per i risultati di dettaglio vedere
[THREAT_ANALYSIS_REPORT.md](THREAT_ANALYSIS_REPORT.md) e
[MANUAL_AUDIT_REPORT.md](MANUAL_AUDIT_REPORT.md).

## 1. Obiettivo e dataset

Il progetto valuta la sicurezza dei **server MCP (Model Context Protocol)**
pubblicati pubblicamente, analizzandoli con 7 strumenti diversi ed eseguendo
l'analisi in parallelo su 9 VM.

Il dataset finale è **unico**: `0.0. All servers unified (69104).xlsx`
(**69.104 server**), unione di:
- **60.205 server GitHub** (repository con implementazioni di server MCP),
- **8.899 server NPX** (pacchetti npm eseguibili con `npx -y <pkg>`).

Ogni riga ha una colonna `Type` (`github` | `npx`). Il file unico è costruito da
[`fuzzing/build_unified_excel.py`](../fuzzing/build_unified_excel.py)
e referenziato da tutti i tool tramite `EXCEL_PATH` in
[`functions/config.py`](../functions/config.py).

## 2. Architettura distribuita

Ogni tool gira su **tutte le 9 VM**; ogni VM processa un sotto-intervallo del
dataset (sharding per indice). L'orchestrazione (deploy, launch, pull, status)
è in [`deploy.py`](../deploy.py); il lancio locale in
[`launch.py`](../launch.py); il monitoraggio delle VM in
[`monitorVM/monitor.py`](../monitorVM/monitor.py).

Ogni tool salva due file di tracciamento per ripresa:
- `*_stats.json` — progresso (ultimo indice, conteggi, percentuali);
- `*_servers.json` — mappa URL → risultato/errore per ogni server.

## 3. I 7 strumenti di analisi

| Tool | Directory launcher | Cosa rileva |
|------|--------------------|-------------|
| **mcp-guard** | `mcp_guard/` | Path traversal, command/SQL/code injection, SSRF, credenziali (SAST + fuzzing) |
| **mcp-watch** | `mcp_watch/` | Credenziali hardcoded, data exfiltration, protocol violation, tool poisoning |
| **tool_fuzzing** | `fuzzing/` | Input malformati: crash/DoS, error disclosure, injection eseguita |
| **mcp-scan** | `mcp_scan/` | Prompt injection, untrusted content, capability distruttive (Snyk) |
| **mcp-shield** | `mcp_shield/` | Hidden instructions / shadowing nelle tool description (analisi semantica LLM) |
| **mcp-security-scan** | `mcp_security_scan/` | Capability pericolose, rug pull, path traversal, accesso a file sensibili |
| **mcp-check** | `mcp_check/` | Conformance al protocollo MCP (handshake, tool discovery, tool invocation) |

I wrapper Python di ciascun framework sono in [`frameworks/`](../frameworks/);
le utility condivise (config, helper, statistiche, costruzione config MCP) in
[`functions/`](../functions/).

## 4. Workflow di triage a 3 stadi

Gli scanner producono milioni di finding grezzi, in larga parte falsi positivi
(FP). L'obiettivo è ridurli a **veri positivi (VP)** azionabili. Per ogni
categoria di ogni tool si applica lo stesso schema:

```
Stage 1  (filtro regex)        milioni  → centinaia   (filter_*.py)
Stage 2A (regole HC dominio)   centinaia → HC-VP + HC-FP + UNCERTAIN
Stage 2B (classificatori)      UNCERTAIN → VP / FP
Merge                          → vp.json / fp.json / audit.json
```

- **Stage 1** — filtri aggressivi verso il FP: scarta file di test/vendor,
  honeypot dichiarati, codice commentato, placeholder.
- **Stage 2A** — regole "high-confidence" di dominio che marcano solo i VP/FP
  certi; il resto resta `UNCERTAIN`.
- **Stage 2B** — classificatori pattern-based (e, dove serve, una seconda
  opinione LLM) che risolvono gli `UNCERTAIN`.

Il codice di post-processing per ogni tool vive in
[`0_tool_<tool>/postprocessing/`](../mcp_guard/postprocessing/) (`pipeline_*.py`,
`filter_*.py`, `_classify_*.py`).

> **Nota sui dati**: nella repository sono presenti gli **script** di
> post-processing e la **documentazione**, non i JSON di output (decine di GB).
> I dati grezzi e gli output finali (`vp.json`/`fp.json`/`audit.json`) sono
> archiviati a parte; per ri-eseguire i `pipeline_*.py` vanno ripristinati.

## 5. Consenso cross-framework

I VP di tutti i tool sono aggregati per server da
[`cross_framework/cross_framework_consensus.py`](../cross_framework/cross_framework_consensus.py)
e classificati in tier di confidenza:

| Tier | Criterio | Confidenza |
|------|----------|------------|
| Tier 1 | ≥ 4 framework concordi sullo stesso server | super-alta |
| Tier 2 | 2–3 framework | alta |
| Tier 3 | 1 solo framework | da verificare |

Il consenso compensa il limite intrinseco dello SAST regex-only (FP residui):
quando più strumenti indipendenti concordano, la confidenza nel VP è alta.

## 6. Validazione manuale

Oltre alla pipeline automatica, i VP delle 17 categorie sono stati validati
**manualmente contro il codice sorgente reale** dei repository (vedere
[MANUAL_AUDIT_REPORT.md](MANUAL_AUDIT_REPORT.md)). La classificazione usa quattro
livelli: **VP-C** (confermato sfruttabile), **VP-L** (latente/by-design),
**VP-D** (debole/bassa severità), **FP** (falso positivo).

## 7. Come ripartire

1. Verificare il dataset unico `0.0. All servers unified (69104).xlsx`.
2. Esecuzione distribuita: usare [`deploy.py`](../deploy.py) per deploy/launch
   sulle 9 VM (vedere i `commands.md` dentro ogni `0_tool_*/`).
3. Post-processing: gli script in `0_tool_<tool>/postprocessing/` rigenerano
   `vp.json`/`fp.json`/`audit.json` (richiede il ripristino dei dati grezzi).
4. Aggregazione finale: `cross_framework/cross_framework_consensus.py`.
