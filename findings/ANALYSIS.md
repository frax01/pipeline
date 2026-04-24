# ANALYSIS.md — Metodologia di analisi dei finding

Questo documento descrive il **processo** di post-processing dei finding generati
dai framework di security analysis sui 60.205 MCP server. È pensato come
riferimento operativo: quando si aggiunge un nuovo framework (es. `mcp-guard`),
questo file spiega esattamente cosa fare, passo per passo.

**Non descrive i risultati** (che stanno in `findings/summary.md` e nei file
`findings/<framework>/<categoria>.md`), ma la **metodologia**.

---

## 1. Obiettivo

Ogni framework genera da migliaia a milioni di finding grezzi, con un rapporto
segnale/rumore bassissimo (spesso < 0.01%). L'obiettivo è ridurli a un insieme
azionabile di **Veri Positivi (VP)** ed eliminare i **Falsi Positivi (FP)** con:

- **Riproducibilità**: stessa classificazione a ogni esecuzione.
- **Auditabilità**: ogni verdetto è documentato con motivo.
- **Costo zero di inferenza esterna**: nessun costo API in produzione.

---

## 2. Architettura a 3 stadi

```
Stage 1   (Python regex, automatico)     milioni → centinaia
Stage 2A  (regole HC di dominio, auto)   centinaia → HC-VP + HC-FP + UNCERTAIN
Stage 2B  (LLM, automatico DOCUMENTATO)  UNCERTAIN → VP o FP
```

### Stage 1 — Filtro regex

Script Python dedicato (`filter_<framework>.py` o `filter_remaining_categories.py`)
che applica regole euristiche veloci:
- scarta test/spec, bundle minificati, third-party (`node_modules`, `site-packages`)
- scarta codice commentato, documentazione, cataloghi LLM, seed data
- scarta server honeypot noti (`vulnicheck`, `mcp-scanner`, `malicious_mcp`, ecc.)
- **whitelist** per categorie ad altissimo rumore: accetta **solo** righe che
  matchano pattern ad altissimo valore (approccio usato per `access-control`:
  428.443 → 17)

Input: JSON con tutti i finding grezzi del framework.
Output: `<categoria>/filtered/<categoria>_filtered.json` con il sottoinsieme
tenuto e campo `filter_confidence` che spiega perché.

### Stage 2A — Regole HC (High Confidence)

Funzione Python `hc_rules_<categoria>(f: dict) -> tuple[str, str]` che ritorna:
- `("HC-VP", "motivo")` → vero positivo certo
- `("HC-FP", "motivo")` → falso positivo certo
- `("UNCERTAIN", "motivo")` → servirà Stage 2B

Le regole sono **pattern regex compilati** specifici del dominio. Ogni regola
ha un nome parlante (es. `_TP_PYDANTIC_OVERRIDE`, `_AC_AWS_PENTEST_EXPLOIT`).

Esempio della forma:

```python
_TP_PYDANTIC_OVERRIDE = re.compile(r'^\s*(overrides|admins)\s*:\s*(Optional\[)?List\[')

def hc_rules_tool_poisoning(f: dict) -> tuple[str, str]:
    ev = f.get("evidence", "") or ""
    if _TP_PYDANTIC_OVERRIDE.search(ev):
        return "HC-FP", "pydantic_field_overrides_or_admins"
    # ... altre regole ...
    return "UNCERTAIN", "no_rule_matched"
```

Output della Stage 2A (tre file nella cartella `<categoria>/filtered/llm_analysis/`):
- `hc_vp.json` — finding con verdetto HC-VP
- `hc_fp.json` — finding con verdetto HC-FP
- `uncertain.json` — finding che richiedono Stage 2B

#### Stage 1 regex vs HC — cosa cambia

Entrambi usano regex Python, ma scopi, forma e tolleranza all'errore sono diversi:

| Aspetto | Stage 1 (filtro) | Stage 2A (HC) |
|---------|------------------|---------------|
| Scopo | tagliare rumore in massa | verdetto finale sui sopravvissuti |
| Volume target | milioni → centinaia (99%+ taglio) | centinaia → VP/FP/UNCERTAIN |
| Verdetto | binario (keep / discard) | ternario (HC-VP / HC-FP / UNCERTAIN) |
| Errore tollerato | sì (può scartare qualche VP se il segnale/rumore migliora) | no, quasi zero — 1 errore → regola declassata |
| Pattern | ampi, grossolani | stretti, dominio-specifici |
| Segnali usati | 1-2 (es. evidence + file path) | triangolazione 3-4 (evidence + language + llm_risk + server) |
| Fonte della regola | standard pubblici (API key format, honeypot list, file path convention) | **ispezione empirica** dei finding residui |
| Google aiuta? | sì (pattern standard noti) | quasi mai — pattern emergono dai dati |

#### Come nascono le regole HC

**Non esistono a priori**. Emergono da un ciclo di lettura dei dati → clustering → codifica → verifica. Tre fonti possibili:

1. **Standard documentato** (raro ma solido):
   - Formato chiavi provider (OpenAI `sk-[A-Za-z0-9]{48,}`, AWS `AKIA[A-Z0-9]{16}`)
   - Claim JWT noti (Supabase `role: "anon"` pubblico, `role: "service_role"` segreto)
   - Regole derivate da spec pubbliche che non richiedono ispezione

2. **Pattern empirico** (caso principale — ~80% delle regole):
   - Nasce leggendo `uncertain.json` e raggruppando finding simili
   - Es. `_TP_PYDANTIC_OVERRIDE`: ispezionando 7 UNCERTAIN di tool-poisoning si scopre che 6 sono campi Pydantic `overrides: List[...]` — non istruzioni di override ma dichiarazioni di schema. Si scrive regex che cattura quel contesto sintattico.

3. **Triangolazione di segnali**:
   - Combina campi del finding (evidence + llm_risk + path + server)
   - Es. `llm_risk=HIGH` + trigger `<IMPORTANT>` + assenza di `<usecase>` → HC-VP; `llm_risk=HIGH` da solo produce FP

#### Workflow operativo (step-by-step)

Questo è il loop concreto per generare le regole HC. Ogni iterazione riduce UNCERTAIN e/o corregge errori.

##### Step 0 — prerequisito: Stage 1 finito

File `<cat>/filtered/<cat>_filtered.json` con N finding residui (es. credential-leak: 784).

```json
{
  "category": "credential-leak",
  "original_total": 646447,
  "kept_total": 784,
  "findings": [
    {"server_name": "...", "evidence": "...", "file": "...", "id": "...", ...}
  ]
}
```

##### Step 1 — prima esecuzione con 0 regole HC

Funzione `hc_rules_<cat>` iniziale:
```python
def hc_rules_credential_leak(f):
    return "UNCERTAIN", "no_rule_matched"  # placeholder
```

Esegui:
```bash
py -X utf8 pipeline_mcp_watch.py --category credential-leak --hc-only
```

Output:
- `hc_vp.json` → 0
- `hc_fp.json` → 0
- `uncertain.json` → **784 finding**

##### Step 2 — campionamento di `uncertain.json`

Non leggi tutti 784. Campione rappresentativo (30-50).

```bash
# Primi N
jq '.findings[0:50]' uncertain.json > sample.json

# Random sampling (meglio — evita bias di ordine)
jq '.findings' uncertain.json | jq 'to_entries | map(.value) | .[0:50]'
```

Oppure in chat: *"Leggi `uncertain.json`, campiona 50 finding rappresentativi, elencali."*

##### Step 3 — lettura 1-per-1 + tagging

Per ogni finding del sample:
1. Leggi `evidence`
2. Guardi `file`, `server_name`, `id`, `language`
3. Assegni verdetto mentale: VP / FP / DUBBIO
4. Scrivi motivo breve

Esempio concreto:
```
Finding 1:
  evidence: "const API_KEY = 'sk-proj-abc123...48chars'"
  file: src/client.js
  → VP: OpenAI project key reale

Finding 2:
  evidence: "// const SECRET = 'hunter2'"
  file: examples/old_client.js
  → FP: commento

Finding 3:
  evidence: "SUPABASE_KEY = 'eyJhbG...role:anon...'"
  → FP: anon key Supabase (pubblica by design)

Finding 4:
  evidence: "SUPABASE_KEY = 'eyJhbG...role:service_role...'"
  file: .env
  → VP: service_role key (segreta)

Finding 5:
  evidence: "const API_KEY = process.env.OPENAI_KEY"
  → FP: lettura da env var (non hardcoded)
```

##### Step 4 — clustering per pattern

Leggi i 50 tag e raggruppi in **pattern catturabili da regex o logica**. Produci una tabella:

| Gruppo | Verdetto | Pattern sintattico |
|--------|----------|-------------------|
| JWT role=anon | FP | JWT decode + `payload.role == "anon"` |
| JWT role=service_role | VP | JWT decode + `payload.role == "service_role"` |
| Commento | FP | `evidence.lstrip().startswith(("//","#","*"))` |
| Env var read | FP | `evidence.match(r"process\.env\.\w+")` |
| Provider key OpenAI | VP | `evidence.match(r"sk-[A-Za-z0-9]{48,}")` |
| Provider key AWS | VP | `evidence.match(r"AKIA[A-Z0-9]{16}")` |
| File `.env` non sample | VP | `file.endswith(".env") and "sample" not in file` |
| Honeypot server | FP | `server_name in _HONEYPOT_SET` |

Alcuni gruppi sono **generalizzazioni** (1 finding → regola per 50 simili). Altri sono **uno-a-uno** (es. honeypot specifici).

Questo step è il **design**.

##### Step 5 — codifica delle regole HC

Traduci la tabella di Step 4 in codice Python. Questo step è l'**implementazione** — mappatura 1:1 con la tabella.

Ordine dei branch: più specifici prima (evita che una regola generica mangi casi che dovevano essere catturati da una regola più stretta).

```python
import re, json, base64

# Pattern compilati una volta (compile-once, match-many)
_COMMENT = re.compile(r'^\s*(#|//|\*|>>>|\.\.)\s')
_OPENAI = re.compile(r'sk-[A-Za-z0-9]{48,}')
_AWS_KEY = re.compile(r'AKIA[A-Z0-9]{16}')
_ENV_READ = re.compile(r'process\.env\.\w+|os\.environ\[')

_HONEYPOT = {"malicious_mcp", "vulnerable-notes-mcp", "IMCP"}

def _decode_jwt_role(ev: str) -> str | None:
    try:
        m = re.search(r'eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.', ev)
        if not m: return None
        payload = m.group(1)
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        return json.loads(decoded).get("role")
    except Exception:
        return None

def hc_rules_credential_leak(f: dict) -> tuple[str, str]:
    ev = f.get("evidence", "") or ""
    file = f.get("file", "") or ""
    server = f.get("server_name", "") or ""

    # Check più specifici prima
    if server in _HONEYPOT:
        return "HC-FP", "honeypot_server"

    if _COMMENT.match(ev):
        return "HC-FP", "commented_code"

    if _ENV_READ.search(ev):
        return "HC-FP", "env_var_read_not_hardcoded"

    role = _decode_jwt_role(ev)
    if role == "anon":
        return "HC-FP", "supabase_anon_public_key"
    if role == "service_role":
        return "HC-VP", "supabase_service_role_secret"

    if _OPENAI.search(ev):
        return "HC-VP", "openai_provider_key"
    if _AWS_KEY.search(ev):
        return "HC-VP", "aws_access_key"

    if file.endswith(".env") and "sample" not in file and "example" not in file:
        return "HC-VP", "real_env_file"

    return "UNCERTAIN", "no_rule_matched"
```

##### Step 6 — ri-esecuzione e misura

```bash
py -X utf8 pipeline_mcp_watch.py --category credential-leak --hc-only
```

Conta risultati:
```
hc_vp.json:     547 (69.8%)
hc_fp.json:     135 (17.2%)
uncertain.json: 102 (13.0%)
```

UNCERTAIN sceso da 784 → 102.

**Check di correttezza**: campiona 10-20 record da `hc_vp.json` e `hc_fp.json`. Se trovi anche **1 errore** (HC-VP che è in realtà FP, o viceversa), la regola è sbagliata. Due opzioni:

1. **Raffinare** la regex per escludere il caso errato:
   ```python
   # sk- matcha anche "sk-XXXXX" placeholder di documentazione
   _OPENAI_REAL = re.compile(r'sk-[A-Za-z0-9]{48,}')
   _OPENAI_PLACEHOLDER = re.compile(r'sk-(XXX+|YOUR|AAAA+|test|demo|example)', re.I)

   if _OPENAI_REAL.search(ev) and not _OPENAI_PLACEHOLDER.search(ev):
       return "HC-VP", "openai_provider_key"
   ```

2. **Declassare** a UNCERTAIN (se la regola non è salvabile) — meglio un UNCERTAIN che un verdetto sbagliato.

##### Step 7 — itera sui residui UNCERTAIN

Prendi i 102 rimasti, ripeti Step 2-6:
1. Leggili (più piccoli → spesso leggibili tutti)
2. Raggruppa i pattern sfuggiti alla prima passata
3. Aggiungi regole HC nuove
4. Ri-esegui

Iterazioni tipiche:
- Iter 1: 784 → 102
- Iter 2: 102 → 28
- Iter 3: 28 → 5
- Iter 4: 5 → 0 (o residuo irriducibile)

##### Step 8 — stop criterion

Fermi quando:
1. **UNCERTAIN = 0** — regole coprono tutto il dataset
2. **UNCERTAIN < 5% del totale** — residuo accettabile, passa a Stage 2B (Ollama o in-chat) per i pochi rimasti
3. **Pattern irriducibile a regex** — finding che richiedono giudizio semantico (es. "questa tool description è injection?"), non più regex → Stage 2B

##### Step 9 — validazione finale

Prima di chiudere la categoria:
1. Apri `hc_vp.json` → spot check 20 random → tutti davvero VP?
2. Apri `hc_fp.json` → spot check 20 random → tutti davvero FP?
3. Se errore: torna a Step 5, raffina.

##### Strumenti pratici in chat

Prompt tipici che accelerano il workflow con Sonnet:
- *"Apri `uncertain.json`, campiona 30, elencali con file/evidence/id"*
- *"Raggruppa per pattern ricorrente, proponi 5 regole HC candidate con stima di copertura"*
- *"Per ogni regola dimmi quanti finding cattura e se c'è rischio di FP incrociato"*
- *"Scrivi la funzione Python con regex compilate, ordine specifico-prima-generico"*
- *"Ri-esegui --hc-only e riporta conteggi hc_vp / hc_fp / uncertain"*
- *"Campiona 20 HC-VP per validazione, elenca finding con evidence"*

Il loop è: **dati → lettura → ipotesi → codifica → verifica → raffino**.

### Stage 2B — Classificazione LLM

**Questo è il punto più importante da capire.**

Lo script (`pipeline_<framework>.py`) è **scritto** per chiamare **Ollama con
modello `llama3`** via `urllib`, con temperatura 0 e cache JSON. La struttura
del codice è autonoma: nessuna dipendenza esterna, funziona offline.

**Ma nella pratica l'analisi non viene fatta da Ollama.**

L'analisi dei finding UNCERTAIN viene fatta **in chat con Claude Sonnet** (cioè
dal modello che sta leggendo questo file). Sonnet ispeziona ogni finding,
decide VP/FP con motivazione, e **il verdetto viene scritto direttamente nel
file `_llm_api_cache.json`**.

Quando poi si esegue `pipeline_<framework>.py --merge` (o `--cache-only`), lo
script:
1. Legge la cache
2. Trova ogni finding già cachato → usa il verdetto dalla cache
3. Solo per i finding NON in cache chiamerebbe Ollama

In pratica: **pre-popoliamo la cache in chat con Sonnet**, poi lo script legge
quella cache e produce i file finali. Ollama non viene mai realmente
interrogato (o viene interrogato solo per eventuali residui).

**Perché questo setup ibrido:**
- Lo script **documenta** una pipeline completa e autonoma (qualcuno può
  eseguirla con solo Ollama se vuole, senza dipendere da Claude).
- La qualità della classificazione Sonnet è nettamente superiore su pattern
  sottili (injection, offensive tools, business logic).
- La cache JSON è il contratto: chi legge `_llm_api_cache.json` non vede
  differenza tra verdetti scritti da Sonnet e da Ollama.

### Merge finale

Lo script applica la formula:
```
VP  = HC-VP ∪ { f ∈ UNCERTAIN | cache[f].verdict == "VP" }
FP  = HC-FP ∪ { f ∈ UNCERTAIN | cache[f].verdict == "FP" }
```

Output (nella stessa `llm_analysis/`):
- `vp.json` — veri positivi finali
- `fp.json` — falsi positivi finali
- `audit.json` — log completo di tutti i finding con stadio e motivo
- `_llm_api_cache.json` — cache della classificazione Stage 2B (persistente)

---

## 3. Struttura delle cartelle

Ogni framework ha una cartella dedicata con la stessa struttura:

```
analysisAllData/0_tool_<framework>/
├── pipeline_<framework>.py              ← script unificato Stage 2A + 2B + merge
├── filter_<framework>.py                ← Stage 1 (o filter_*_categories.py)
├── <categoria_1>/
│   └── filtered/
│       ├── <categoria_1>_filtered.json  ← output Stage 1
│       └── llm_analysis/
│           ├── hc_vp.json               ← Stage 2A VP
│           ├── hc_fp.json               ← Stage 2A FP
│           ├── uncertain.json           ← Stage 2A da classificare
│           ├── _llm_api_cache.json      ← verdetti Stage 2B (pre-popolata in chat)
│           ├── vp.json                  ← merge finale
│           ├── fp.json                  ← merge finale
│           └── audit.json               ← log completo
├── <categoria_2>/...
└── <categoria_N>/...
```

I risultati finali per ogni framework sono anche riepilogati in
`findings/<framework>/<categoria>.md` (descrizione narrativa) e aggregati in
`findings/summary.md` (tabelle comparative).

---

## 4. Struttura del finding

I finding arrivano da framework diversi in formati diversi, ma tutti
convergono a uno schema comune. I campi minimi richiesti da Stage 2A:

### Finding line-level (mcp-watch)
```json
{
  "server_name": "nome-server",
  "github_url": "https://github.com/autore/repo",
  "language": "nodejs",
  "id": "HARDCODED_CREDENTIALS",
  "category": "credential-leak",
  "file": "src/config.js",
  "line": 42,
  "evidence": "const API_KEY = 'sk-abc...'",
  "filter_confidence": "provider:OpenAI Legacy Key"
}
```

### Finding tool-level (mcp-shield, mcp-scan E001/W001)
```json
{
  "server_url": "https://github.com/autore/repo",
  "server_name": "nome-server",
  "tool_name": "nome_tool",
  "tool_description": "testo della description MCP",
  "category": "hidden-instructions",
  "risk": "HIGH",
  "llm_risk": "HIGH",
  "llm_analysis": "..."
}
```

### Finding server-level (mcp-scan W015/W016, mcp-security-scan)
```json
{
  "server_url": "https://github.com/autore/repo",
  "id": "X-01",
  "severity": "high",
  "details": "..."
}
```

---

## 5. Cache key convention

Il formato della cache key varia per framework a seconda della granularità:

| Framework / granularità | Formato cache key |
|---|---|
| line-level (mcp-watch) | `{server_name}/{file}/{line}/{id}` |
| tool-level (mcp-shield, mcp-scan E001/W001) | `{autore/repo}\|{tool_name}` |
| server-level (mcp-scan W015/W016) | `{autore/repo}` |
| server-level (mcp-security-scan) | `{autore/repo}` |
| multi-fase (mcp-check) | `{autore/repo}\|{fase/categoria}` |

La funzione `_cache_key(f, kind)` nello script è il **punto di verità**: se
serve cambiare la granularità (es. aggiungere tool_name a una chiave
server-level), va fatto solo lì.

La cache ha formato:
```json
{
  "autore/repo|tool_name": {"verdict": "VP", "reason": "offensive tool: DCSync"},
  "autore/repo|altro_tool": {"verdict": "FP", "reason": "SDK wrapper read-only"}
}
```

---

## 6. Workflow per aggiungere un nuovo framework

Supponiamo di voler analizzare i finding di un nuovo framework `mcp-guard`:

### Step 1 — Capire i dati
Aprire 1-2 file JSON grezzi del framework, identificare:
- Lo schema del finding (campi chiave, granularità: line/tool/server)
- Le categorie / id di vulnerabilità
- Volumi per categoria
- Pattern di rumore dominanti (campionando ~30-50 finding)

### Step 2 — Stage 1 filtro
Scrivere `filter_<framework>.py` (o estendere `filter_remaining_categories.py`):
- Una funzione per categoria che ritorna `True` se il finding va tenuto
- Regole di esclusione standard: test, commenti, node_modules, honeypot noti,
  bundle minificati
- Per categorie ad altissimo volume (> 100k finding): usare **whitelist di
  pattern di altissimo valore**, non blacklist

Output: file `*_filtered.json` in `<categoria>/filtered/`.

### Step 3 — Stage 2A regole HC
In `pipeline_<framework>.py`:

1. Compilare pattern regex specifici per il dominio del framework
2. Scrivere `hc_rules_<categoria>(f) -> (verdict, reason)` per ogni categoria
3. Aggiungere la categoria a `CATEGORIES` e mappare in `HC_RULES`
4. Prefissare con commento:
   ```python
   # FRAMEWORK: mcp-guard | CATEGORIA: <nome>
   ```

Eseguire `--hc-only` e analizzare `uncertain.json` per raffinare le regole.
Iterare finché UNCERTAIN ≤ 5% del totale (o a 0 se ragionevole).

### Step 4 — Stage 2B classificazione in chat

**Se UNCERTAIN > 0**: in chat con Sonnet, ispezionare ogni finding UNCERTAIN
e scrivere il verdetto direttamente nel `_llm_api_cache.json`:

```json
{
  "<cache_key_1>": {"verdict": "VP", "reason": "breve motivazione"},
  "<cache_key_2>": {"verdict": "FP", "reason": "breve motivazione"}
}
```

Lo script è **documentato** per chiamare Ollama/llama3, ma in pratica la cache
è pre-popolata in chat. Se si vuole usare davvero Ollama:
```bash
ollama serve       # in un terminale separato
ollama pull llama3
py -X utf8 pipeline_mcp_guard.py --category <cat> --merge
```

### Step 5 — Merge finale
```bash
py -X utf8 pipeline_mcp_guard.py --category <cat> --cache-only
# oppure per tutte:
py -X utf8 pipeline_mcp_guard.py --category all --cache-only
```

Produce `vp.json`, `fp.json`, `audit.json`.

### Step 6 — Documentazione
1. Scrivere `findings/mcp-guard/<categoria>.md` per ogni categoria: volumi
   per stadio, VP con evidence, FP con motivazione raggruppata per pattern
2. Aggiornare `findings/summary.md`:
   - Tabella per framework con totali per stadio
   - Nuove righe nella tabella "Dettaglio buckets pipeline"
   - Aggiornare "Totale generale"
3. Aggiornare `CLAUDE.md` con:
   - Sezione "Post-processing mcp-guard"
   - Tabella risultati per categoria
   - Sezione "Regole HC principali" per ogni categoria
   - ID di vulnerabilità mappate

---

## 7. Principi guida

### Triangolazione dei segnali
Nessun singolo segnale è sufficiente. Combinare:
- Pattern sintattico (regex su evidence)
- Contesto file (path, linguaggio)
- Verdetto LLM del framework sorgente (se presente, es. `llm_risk` di mcp-shield)
- Classificazione esterna (whitelist server noti, lista honeypot)

### Whitelist vs blacklist
Per categorie sotto il 5% di rumore: blacklist delle esclusioni note.
Per categorie oltre il 95% di rumore: **whitelist** dei pattern di altissimo
valore (es. `GRANT ALL`, `"Action":"*"`) — non provare a enumerare il rumore.

### Regole HC stabili
Una regola HC deve avere tasso d'errore quasi zero sul suo campione. Se una
regola HC produce anche solo 1 VP classificato come FP (o viceversa), va
resa più specifica o declassata a UNCERTAIN. Le regole HC sono il motore
della riproducibilità.

### Honeypot e scanner
Server intenzionalmente vulnerabili (nomi come `vulnerable-`, `malicious_`,
`mcp-scanner`, `agent-security-scanner-mcp`) producono sistematicamente FP
in quasi tutte le categorie. Mantenere una `_SECURITY_SCANNER_SERVERS` set e
escluderli in Stage 1 o in Stage 2A.

### Offensive tool dichiarati
Server che sono **per design** tool offensivi (`sec-mimikatz-mcp`,
`sec-rubeus-mcp`, `aws-pentest-mcp`) → VP. Anche se il codice è pulito, la
description/functionality dichiara capacità di attacco (DCSync, Kerberoast,
IAM privilege escalation). La classificazione è coerente cross-framework.

### Evitare l'over-engineering dello script
Lo script `pipeline_<framework>.py` deve essere un **singolo file** con:
- Regole HC in cima (compile-once)
- Funzioni `hc_rules_<cat>` separate per categoria
- Dispatcher `HC_RULES` dict
- Chiamante Ollama via `urllib` (no dipendenze)
- CLI con `--hc-only`, `--merge`, `--cache-only`, `--dry-run`, `--no-cache`

Nessun framework Python, nessun ORM, nessun async. Le regole HC sono il
contenuto, il resto è boilerplate minimo.

---

## 8. Note tecniche ricorrenti

- **Encoding Windows**: usare sempre `py -X utf8` (o `python -X utf8`).
  Impostare `sys.stdout.reconfigure(encoding='utf-8')` all'avvio dello script.
- **Temperatura Ollama**: `temperature=0` per riproducibilità.
- **Modello Ollama raccomandato**: `llama3` o `llama3.1`.
- **Nessuna pip install**: lo script usa solo stdlib (`urllib`, `re`, `json`,
  `pathlib`, `argparse`).
- **Cache key stabile**: non cambiarla dopo aver pre-popolato la cache — perderesti
  tutti i verdetti.
- **`--no-cache`** per riclassificare tutto ignorando la cache (test di
  regressione delle regole HC).
- **`--dry-run`** per vedere i prompt che andrebbero a Ollama senza chiamarlo.

---

## 9. Esempio concreto (mcp-watch)

Il framework mcp-watch è il più completo esempio di questa metodologia. Vedere:
- `pipeline_mcp_watch.py` per l'organizzazione del codice
- `filter_remaining_categories.py` per pattern di filtro Stage 1
- Cartelle `credential-leak`, `tool-poisoning`, `access-control`, ecc. per la
  struttura output
- `findings/mcp-watch/*.md` per la forma della documentazione narrativa

Esempi notevoli di pattern risolti da questo flusso:
- **credential-leak**: 646.447 → 784 (Stage 1) → 619 VP / 165 FP (finale)
- **access-control**: 428.443 → 17 (Stage 1 con whitelist aggressiva) → 7 VP / 10 FP
- **tool-mutation**: 18.856 → 2.577 → 0 VP / 2.577 FP (pattern di registration,
  non rug-pull)

---

## 10. Quando consultare questo file

- **Nuovo framework da analizzare** (es. mcp-guard): leggere §6 e seguire gli
  step.
- **Nuova categoria in framework esistente**: leggere §2 + §3 per la struttura,
  poi seguire step 3-6 di §6.
- **Dubbio su cache key**: §5.
- **Decidere whitelist vs blacklist**: §7.
- **Spiegare a un collaboratore cosa stiamo facendo**: §1 + §2.

## 11. Alcuni esempi di server falsi positivi

Questi server sono fatti apposta per essere vulnerabili, quindi i finding che derivano da loro sono falsi positivi.

1. https://github.com/nav33n25/IMCP
2. https://github.com/bishnubista/vulnerable-notes-mcp
3. https://github.com/AlchemicalChef/MCPServer