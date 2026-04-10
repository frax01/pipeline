# Pipeline - Security Analysis di MCP Servers

## Cosa fa questo progetto

Pipeline distribuita che analizza la sicurezza di **60.205 MCP server** (Model Context Protocol) raccolti da GitHub. L'analisi viene eseguita in parallelo su **9 VM remote** con **7 tool di analisi**. Ogni tool gira su tutte le 9 VM, ognuna processa il suo chunk di server.

## Architettura

### Input
- File Excel: `0.0. All servers without duplicates, .git, _, hash and ERRORE (60205).xlsx`
- Contiene 60.205 URL di repository GitHub con implementazioni di MCP server

### I 9 Tool di Analisi

| Tool | VM | IP | Directory | Script | Cosa analizza |
|------|-----|------|-----------|--------|---------------|
| **mcp-guard** | VM1 | 10.79.6.132 | `0_tool_mcp_guard/` | `run_guard.py` | Path traversal, command injection, fuzzing dinamico |
| **mcp-watch** | VM2 | 10.79.6.133 | `0_tool_mcp_watch/` | `run_watch.py` | Credenziali hardcoded, ANSI injection, data exfiltration |
| **fuzzing** | VM3 | 10.79.6.134 | `analysis/0_tool_fuzzing/` | `run_fuzzing.py` | Input malformati, crash, eccezioni runtime |
| **mcp-scan** | VM4 | 10.79.6.136 | `0_tool_mcp_scan/` | `run_scan.py` | Prompt injection, tool shadowing, toxic flows (Snyk) |
| **mcp-shield** | VM5 | 10.79.6.137 | `0_tool_mcp_shield/` | `run_shield.py` | Hidden instructions nelle tool description (analisi semantica con Claude API) |
| **mcp-security-scan** | VM6 | 10.79.6.138 | `0_tool_mcp_security_scan/` | `run_security_scan.py` | Dangerous capabilities, rug pull, path traversal, remote access |
| **mcp-check** | VM7 | 10.79.6.139 | `0_tool_mcp_check/` | `run_check.py` | Validazione compliance configurazione MCP |

### Sharding
I 60.205 server sono divisi in chunk da ~6.689 ciascuno (CHUNK = 60205 // 9). Ogni VM processa il suo range.

### VM Remote
- User: `tecnico`
- Path remoto: `/home/tecnico/Desktop/Pipeline`
- Frameworks: `/home/tecnico/Desktop/Frameworks`
- Connessione: SSH con chiave

## Struttura directory

```
pipeline/
├── deploy.py              # Orchestratore: deploy, launch, pull, tail, status sulle VM
├── launch.py              # Launcher locale per i tool
├── vmcheck.py             # Monitor stato di tutte le 9 VM (tabella colorata)
├── main.py / mainParallel.py  # Runner principale analisi
├── pull_partial_results.sh    # Aggregazione risultati da tutte le VM
│
├── 0_tool_mcp_guard/      # Tool + risultati per ogni framework
├── 0_tool_mcp_watch/
├── 0_tool_mcp_scan/
├── 0_tool_mcp_shield/
├── 0_tool_mcp_security_scan/
├── 0_tool_mcp_check/
├── tool_scanorama/
├── tool_mcp_validator/
├── analysis/              # Risultati aggregati, chart, 0_tool_fuzzing/
│
├── frameworks/            # Wrapper Python per ogni tool (mcpGuard.py, mcpScan.py, ecc.)
│   └── NewProxy/          # Proxy LLM-based per analisi avanzata (TypeScript)
│
├── functions/             # Utility condivise
│   ├── config.py          # Configurazione centrale (path, comandi, categorie)
│   ├── helper.py          # Helper vari
│   ├── stats.py           # Aggregazione statistiche
│   └── buildConfig.py     # Costruzione config MCP (detect linguaggio, entrypoint)
│
├── monitorVM/             # Utility di monitoring VM
└── data/                  # Script setup analisi
```

## Comandi principali

### Deploy e gestione remota (`deploy.py`)
```bash
python deploy.py --status                    # Stato di tutti i tool su tutte le VM
python deploy.py --launch guard              # Deploy + avvia guard da zero
python deploy.py --launch fuzzing --resume   # Deploy + riprendi fuzzing
python deploy.py --pull scan                 # Scarica risultati di scan
python deploy.py --pull-guard                # Scarica guard da TUTTE le 9 VM
python deploy.py --merge-guard               # Merge risultati guard scaricati
python deploy.py --tail scan                 # Ultime 30 righe del log di scan
python deploy.py --tail-all                  # Ultime 10 righe di TUTTI i log
python deploy.py --full-deploy fuzzing       # Sync intero progetto su VM3
python deploy.py --deploy-fuzzing-all        # Copia fuzzing su TUTTE le VM
```

### Launcher locale (`launch.py`)
```bash
python launch.py scan              # Lancia mcp-scan da zero
python launch.py fuzzing --resume  # Riprendi fuzzing
python launch.py --status          # Stato locale di tutti i tool
python launch.py --kill            # Kill tutti i processi run_*.py
```

### Monitor VM (`vmcheck.py`)
```bash
python vmcheck.py              # Tabella completa con stato processi
python vmcheck.py --no-proc    # Senza check processi (piu' veloce)
```

## Come funziona il tracking del progresso

Ogni tool salva due file JSON nella sua directory:

### `*_stats.json` - Statistiche di progresso
```json
{
  "last_index": 342,        // Ultimo indice processato
  "total": 342,             // Totale server processati
  "range_start": 0,         // Inizio range assegnato
  "range_end": 6689,        // Fine range assegnato
  "remaining": 6347,        // Server rimanenti
  "languages": { ... },     // Conteggio per linguaggio
  "<tool-name>": {
    "total": 240,
    "percentage": 70.0,
    "vulnerabilities": { ... }
  }
}
```

### `*_servers.json` - Log per server
Mappa URL -> risultato/errore per ogni server processato.

### Meccanismo di resume
- `--start 0`: reset stats e riparte da zero
- `--start -1` o `--resume`: carica `last_index` da stats.json e riprende
- `--start N`: salta all'indice N

## Categorie di vulnerabilita trovate

- **Path traversal** (R-01): Accesso a file arbitrari
- **Command injection**: Esecuzione comandi arbitrari
- **Prompt injection** (P-02, P-03): Manipolazione del modello LLM
- **Credential leak** (A-03): Credenziali hardcoded
- **Data exfiltration**: Esfiltrazione conversazioni/dati
- **Tool shadowing**: Tool che si mascherano da altri
- **Dangerous capabilities** (X-01): Capabilities pericolose
- **Rug pull** (X-03): Comportamento che cambia dopo l'installazione
- **Toxic flows** (TF001-TF002): Kill-chain di vulnerabilita combinate

## Linguaggio e convenzioni

- **Python** per tutta la pipeline e i wrapper dei framework
- **TypeScript/Node.js** per il proxy LLM e alcuni tool
- I commenti e i log sono in **italiano**
- Path separator: usare `/` (anche su Windows, dato che lo shell e' bash)
- Le VM usano **Linux** (Ubuntu), la macchina locale e' **Windows 11**
