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

## Gestione RAM sulle VM

### Controllare la RAM
```bash
# Da locale, su una VM specifica (es. VM1)
ssh tecnico@10.79.6.132 "free -h"

# Su tutte le VM in un colpo
for ip in 10.79.6.132 10.79.6.133 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139; do
  echo "=== $ip ==="
  ssh tecnico@$ip "free -h" 2>/dev/null
done

# Vedere quali processi consumano piu' RAM (top 10)
ssh tecnico@10.79.6.132 "ps aux --sort=-%mem | head -15"

# Vedere RAM + processi di analisi attivi
ssh tecnico@10.79.6.132 "free -h && echo '---' && ps aux | grep 'run_\|python\|node\|npx' | grep -v grep"
```

### Liberare RAM senza killare i processi di analisi
```bash
# 1. Pulire le cache del kernel (sicuro, non killa niente)
ssh tecnico@10.79.6.132 "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'"

# 2. Killare processi orfani di analisi precedenti (node/python zombie)
#    PRIMA controllare cosa c'e':
ssh tecnico@10.79.6.132 "ps aux | grep -E 'node|python|npx' | grep -v -E 'run_guard|run_watch|run_scan|run_shield|run_security_scan|run_check|run_fuzzing|grep'"
#    POI killare solo quelli orfani (NB: verificare i PID prima!)
ssh tecnico@10.79.6.132 "ps aux | grep -E 'node|python|npx' | grep -v -E 'run_guard|run_watch|run_scan|run_shield|run_security_scan|run_check|run_fuzzing|grep' | awk '{print \$2}' | xargs -r kill"

# 3. Pulire le directory di clone temporanee (i repo clonati occupano disco e cache)
ssh tecnico@10.79.6.132 "rm -rf /tmp/mcp-* /tmp/repo-* /home/tecnico/Desktop/Pipeline/cloned_repos/*"

# 4. Killare container Docker rimasti appesi
ssh tecnico@10.79.6.132 "docker container prune -f 2>/dev/null; docker image prune -f 2>/dev/null"
```

### Processi da NON killare
I processi di analisi attivi hanno questi nomi:
- `run_guard.py`, `run_watch.py`, `run_scan.py`, `run_shield.py`
- `run_security_scan.py`, `run_check.py`, `run_fuzzing.py`

Se un processo `node` o `python` non contiene uno di questi nomi, e' probabilmente un processo orfano di un'analisi precedente (un repo che e' stato clonato e avviato ma mai terminato).

### Script rapido per tutte le VM
```bash
# Controllare RAM su tutte le VM
for ip in 10.79.6.132 10.79.6.133 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139; do
  echo "=== $ip ==="
  ssh tecnico@$ip "free -h | grep Mem" 2>/dev/null
done

# Pulire cache su tutte le VM
for ip in 10.79.6.132 10.79.6.133 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139; do
  echo "=== $ip ==="
  ssh tecnico@$ip "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches' && free -h | grep Mem" 2>/dev/null
done
```

## Linguaggio e convenzioni

- **Python** per tutta la pipeline e i wrapper dei framework
- **TypeScript/Node.js** per il proxy LLM e alcuni tool
- I commenti e i log sono in **italiano**
- Path separator: usare `/` (anche su Windows, dato che lo shell e' bash)
- Le VM usano **Linux** (Ubuntu), la macchina locale e' **Windows 11**

---

## Post-processing mcp-watch: Analisi LLM dei finding

### Contesto

mcp-watch genera milioni di finding grezzi. L'obiettivo e' ridurli a veri positivi (VP) azionabili, eliminando i falsi positivi (FP). Il processo si articola in 3 stadi:

```
Stage 1  (automatico):  regex generiche del framework      milioni → centinaia (−99.9%)
Stage 2A (automatico):  regole HC di dominio               centinaia → HC-FP + HC-VP + UNCERTAIN
Stage 2B (LLM Ollama):  giudizio semantico automatico      UNCERTAIN → VP o FP
```

**Come funziona nella pratica:**
- Stage 1 e Stage 2A sono completamente automatici (`pipeline_mcp_watch.py --hc-only`)
- Stage 2B usa **Ollama + llama3** in locale — lo script invia ogni finding UNCERTAIN al modello e ottiene un verdetto VP/FP
- L'analisi manuale in-chat (es. con Claude Sonnet) viene usata per **validare e raffinare** le regole HC prima di automatizzarle; non fa parte del flusso standard documentato qui

### Script principale

```
analysisAllData/0_tool_mcp_watch/pipeline_mcp_watch.py
```

Script unificato che contiene:
- Le regole HC (Stage 2A) per tutte le categorie analizzate
- Il chiamante Ollama (Stage 2B) via `urllib` — nessuna dipendenza esterna
- Il merge finale: HC-VP + HC-FP + verdetti Ollama → `vp.json` / `fp.json` / `audit.json`

Ogni sezione per categoria e' marcata con un commento:
```python
# FRAMEWORK: mcp-watch | CATEGORIA: <nome>
```

### Directory di lavoro

```
analysisAllData/0_tool_mcp_watch/
├── pipeline_mcp_watch.py            ← script principale (Stage 2A + 2B + merge)
├── credential-leak/
│   └── filtered/
│       ├── credential_leak_filtered.json      ← output Stage 1
│       └── llm_analysis/
│           ├── hc_fp.json     ← FP certi (regole HC)
│           ├── hc_vp.json     ← VP certi (regole HC)
│           ├── uncertain.json ← finding da analizzare con Ollama
│           ├── vp.json        ← VP finali (merge hc_vp + ollama VP)
│           ├── fp.json        ← FP finali (merge hc_fp + ollama FP)
│           ├── audit.json     ← log completo di tutti i finding
│           └── _llm_api_cache.json  ← cache chiamate Ollama (auto-generata)
├── data-exfiltration/
│   └── filtered/
│       ├── data_exfiltration_filtered.json
│       └── llm_analysis/
│           ├── hc_fp.json / hc_vp.json / uncertain.json
│           ├── vp.json / fp.json / audit.json
│           └── _llm_api_cache.json
└── input-validation/
    └── filtered/
        ├── input_validation_filtered.json
        └── llm_analysis/
            ├── hc_fp.json / hc_vp.json / uncertain.json
            ├── vp.json / fp.json / audit.json
            └── _llm_api_cache.json
```

### Risultati per categoria

| Categoria              | Originali  | Dopo filtro | HC-VP            | HC-FP            | UNCERTAIN        | VP finali | FP finali |
|------------------------|-----------|-------------|------------------|------------------|------------------|-----------|-----------|
| credential-leak        | 646.447   | 784         | 547 (69.8%)      | 135 (17.2%)      | 102 (13.0%)      | 619       | 165       |
| data-exfiltration      | 24.566    | 86          | 2 (2.3%)         | 79 (91.9%)       | 5 (5.8%)         | 2         | 84        |
| input-validation       | —         | 225         | 123 (54.7%)      | 91 (40.4%)       | 11 (4.9%)        | TBD       | TBD       |
| steganographic-attack  | 16.570    | 360         | 3 (0.8%)         | 311 (86.4%)      | 46 (12.8%)       | 3         | 357       |

> input-validation: Stage 2B (Ollama) non ancora eseguito. Eseguire `pipeline_mcp_watch.py --category input-validation --merge`.

### Comandi principali

```bash
# Prerequisito: Ollama installato e modello scaricato
ollama pull llama3

# Stage 2A only (produce hc_fp.json, hc_vp.json, uncertain.json):
python -X utf8 pipeline_mcp_watch.py --category credential-leak --hc-only
python -X utf8 pipeline_mcp_watch.py --category data-exfiltration --hc-only
python -X utf8 pipeline_mcp_watch.py --category input-validation --hc-only

# Stage 2A + 2B + merge completo (produce anche vp.json, fp.json, audit.json):
python -X utf8 pipeline_mcp_watch.py --category credential-leak --merge
python -X utf8 pipeline_mcp_watch.py --category all --merge

# Opzioni utili:
#   --model llama3.1        modello Ollama alternativo
#   --ollama-url http://... URL Ollama custom (default: localhost:11434)
#   --no-cache              ignora la cache e riclassifica tutto
#   --dry-run               mostra i prompt senza chiamare Ollama
```

### Come riprendere l'analisi (nuovo account / nuova sessione)

1. Leggere questo file `CLAUDE.md` per il contesto generale
2. Eseguire `--hc-only` per la categoria di interesse (produce i 3 bucket)
3. Avviare Ollama: `ollama serve` (in un terminale separato)
4. Eseguire il pipeline completo: `python -X utf8 pipeline_mcp_watch.py --category <cat> --merge`
5. Verificare i risultati in `<cat>/filtered/llm_analysis/`

Per raffinare le regole HC prima di eseguire Ollama:
- Esaminare `uncertain.json` per capire quali pattern sfuggono alle regole
- Aggiungere nuove regole HC nella funzione `hc_rules_<categoria>()` in `pipeline_mcp_watch.py`
- Ri-eseguire `--hc-only` e verificare che l'UNCERTAIN si riduca

### Come aggiungere una nuova categoria

1. Eseguire Stage 1 del framework (produce `<cat>_filtered.json` in `<cat>/filtered/`)
2. Aprire `pipeline_mcp_watch.py` e aggiungere:
   - Una nuova funzione `hc_rules_<categoria>(f: dict) -> tuple[str, str]` con le regole HC
   - La categoria alla lista `CATEGORIES`
   - La mappatura in `HC_RULES = {..., "<categoria>": hc_rules_<categoria>}`
3. Prefissare la sezione con il commento:
   ```python
   # FRAMEWORK: mcp-watch | CATEGORIA: <nome>
   ```
4. Eseguire `--hc-only` e analizzare il risultato per affinare le regole
5. Eseguire il pipeline completo con `--merge`

### Struttura del file filtered.json

```json
{
  "category": "credential-leak",
  "original_total": 646447,
  "kept_total": 784,
  "findings": [
    {
      "server_name": "nome-del-server",
      "github_url": "https://github.com/...",
      "language": "nodejs",
      "id": "HARDCODED_CREDENTIALS",
      "category": "credential-leak",
      "file": "src/config.js",
      "line": 42,
      "evidence": "const API_KEY = 'sk-abc...'",
      "filter_confidence": "provider:OpenAI Legacy Key"
    }
  ]
}
```

### ID di vulnerabilita per categoria

**credential-leak:**
- `HARDCODED_CREDENTIALS` — chiave/token hardcoded nel codice
- `PLAINTEXT_STORAGE` — credenziali scritte su disco/log
- `INSECURE_CREDENTIAL_PERMISSIONS` — permessi file errati (chmod)

**data-exfiltration:**
- `DATA_EXFILTRATION` — payload HTTP con dati sensibili verso server esterno
- `MAGIC_PARAMETER_INJECTION` — parametro magico nell'inputSchema di un tool MCP
- `UNUSED_SENSITIVE_PARAMETER` — parametro sensibile non usato nel tool schema
- `CONVERSATION_EXFILTRATION_TRIGGER` — tool description che istruisce l'LLM a esfiltrare la conversazione

**input-validation:**
- `SSRF` — Server-Side Request Forgery: URL controllato dall'utente passato a fetch/axios/got
- `COMMAND_INJECTION` — exec/spawn con argomento controllato dall'utente (concat, template literal, diretto)
- `PATH_TRAVERSAL` — path.join con argomenti spread da input utente

### Regole HC principali (credential-leak)

**HC-FP (alta confidenza Falso Positivo):**
- JWT con `role: "anon"` → Supabase anon key (pubblica per design)
- Server honeypot/vuln intenzionale: `malicious_mcp`, `vulnerable-notes-mcp`, `vertice-cyber`
- Codice commentato (`#`, `//`, `*` all'inizio della riga)
- Pattern streaming LLM: `process.stdout.write(token)`, `sys.stdout.write(token)`
- `PLAINTEXT_STORAGE` su file `.json`/`.yaml` (dati, non config)
- `INSECURE_CREDENTIAL_PERMISSIONS` su `package.json` (script di build)
- `INSECURE_CREDENTIAL_PERMISSIONS` con `chmod 600/644/400` (permessi sicuri)

**HC-VP (alta confidenza Vero Positivo):**
- JWT con `role: "service_role"` → Supabase secret key
- `HARDCODED_CREDENTIALS` in file `.env` (non sample/example)
- Provider specifici: GitHub PAT, Docker PAT, OpenAI `sk-`, AWS `AKIA`, Stripe live, MongoDB URI, ecc.
- `PLAINTEXT_STORAGE` con `writeFileSync` o `creds.to_json()` + file non .json

### Regole HC principali (data-exfiltration)

**HC-FP:**
- `UNUSED_SENSITIVE_PARAMETER` → tutti FP (parametri Python interni, non MCP schema)
- `MAGIC_PARAMETER_INJECTION:tools_list` → tutti FP (funzione di registrazione tool)
- Pattern Ollama/embedding: `json={"model": EMBED_MODEL, "prompt": text}`
- ComfyUI: `127.0.0.1:8188` o `json={"prompt": workflow}`
- mcp-gateway plugin hooks: `async def prompt_pre_fetch(...)` ecc.
- Bundle/minified JS (webpack, rollup)
- Codice commentato, seed data, test trace

**HC-VP:**
- `CONVERSATION_EXFILTRATION_TRIGGER` con "ENTIRE conversation" nella description
- `DATA_EXFILTRATION` con hook `UserPromptSubmit` che invia `CLAUDE_SESSION_ID` a backend esterno

### Regole HC principali (input-validation)

**HC-FP:**
- SSRF con `this.something.fetch(path)` → metodo SDK con base URL pre-configurata (non globale)
- SSRF su pattern interni noti: `scheduledEvents.fetch`, `.graphqlClient.request`, `transport.request`
- Command injection su `.exec()` regex (pattern `/regex/.exec(str)`)
- Command injection su ORM exec: `session.exec(select(...))`, `clickhouse.exec({...})`
- Bundle/minified JS (webpack, rollup, Svelte compiled)
- File demo/test intenzionali: `vulnerable_`, `demo_`, `security_reminder`, `sink_detector`
- Codice commentato

**HC-VP:**
- SSRF con `fetch(params.url)` / `fetch(input.url)` globale (URL controllato dall'attaccante)
- SSRF con `axios.get(params.url)` / `got.get(input.url)` diretto
- Command injection: `exec("cmd " + params.arg)` (concatenazione stringa)
- Command injection: `` exec(`cmd ${params.arg}`) `` (template literal)
- Command injection: `exec(params.command)` / `spawn(params.command)` diretto
- Path traversal: `path.join(...args.paths)` (spread di input utente)

### Regole HC principali (steganographic-attack)

**ID rilevati:**
- `ANSI_ESCAPE_INJECTION` — codici escape ANSI nella sorgente (clear screen, cursor, colori)
- `WHITESPACE_INJECTION` — riga con numero anomalo di whitespace characters

**HC-FP:**
- `ANSI_ESCAPE_INJECTION` → tutti FP: sono tutti codice CLI/terminale legittimo (progress bar, spinner, clear screen, keyboard shortcuts, costanti ANSI). Nessuno inietta ANSI in tool output MCP.
- `WHITESPACE_INJECTION` con `whitespace_in_tool_definition` → FP (deep nesting in codice compliance)
- `WHITESPACE_INJECTION` in file `*_commented*` → FP (documentazione AI-generata)
- `WHITESPACE_INJECTION` con whitespace count < 300 → FP (indentazione profonda ma plausibile)

**HC-VP:**
- `WHITESPACE_INJECTION` con whitespace count ≥ 1000 → VP (impossibile come indentazione → steganografia confermata)
- Caso reale: exa-mcp-server `src/tools/*.ts` con 1152, 2304, 86016 whitespace su `}` nei file di tool definition

**UNCERTAIN → FP (verdetti in-chat):**
- Spek-template (ws 304-336): compliance code Python con annidamento abnorme ma legittimo
- mcp_sofia_voice- (ws 552): config.py con artefatto di formattazione, non tool description
- mcp-mesh/mcp-garmin (ws 302-399): FastAPI server infrastructure, non tool definition MCP

**Soglia chiave:** 1000 chars di whitespace su una singola riga è il discriminante VP/FP — impossibile come indentazione reale in qualsiasi linguaggio.

### Note tecniche

- **Encoding Windows**: usare sempre `python -X utf8` o `io.open(..., encoding='utf-8')`
- **JWT decode**: `base64.urlsafe_b64decode(payload + "=" * (-len % 4))`
- **Cache Ollama**: `_llm_api_cache.json` nella cartella `llm_analysis/` — evita di richiamare il modello per finding gia' classificati; usare `--no-cache` per azzerare
- **Temperatura**: `temperature=0` per riproducibilita'
- **Modello raccomandato**: `llama3` o `llama3.1` (gira in locale, nessun costo)
- **Nessuna dipendenza esterna**: `pipeline_mcp_watch.py` usa solo `urllib` della stdlib Python (no pip install)
- **SSRF VP vs FP**: `fetch(params.url)` globale = VP; `this.client.fetch(path)` metodo SDK = FP
- **Command injection VP vs FP**: `exec(str + params.x)` concat = VP; `/regex/.exec(str)` = FP; `session.exec(select(...))` ORM = FP
