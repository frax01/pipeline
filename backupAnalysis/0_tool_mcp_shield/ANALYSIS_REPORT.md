# Resoconto tecnico — analisi dei risultati MCP-Shield

**Dataset:** 60.203 server MCP scansionati (9 VM × ~6.689 chunks)
**Framework:** [mcp-shield](https://github.com/riseandignite/mcp-shield) — static analysis su tool description + input schema, con LLM di supporto.
**Scope del report:** capire *come* mcp-shield decide cosa è vulnerabile, valutare la qualità dei risultati, stimare il rumore (falsi positivi) e isolare i dati realmente interessanti.

---

## 1. Come funziona mcp-shield internamente

Il framework è scritto in TypeScript e vive in `frameworks/mcp-shield/src/`. Lo scanner principale (`scanner.ts`) per ogni server MCP:

1. Si connette al server e recupera la lista dei **tool** tramite `listTools()`.
2. Per ogni tool applica 4 analyzer regex-based definiti in `analyzers/tool-analyzer.ts`.
3. Solo se l'analisi statica rileva qualcosa (e solo per certe categorie) invoca opzionalmente **Claude** per una seconda opinione tramite `analyzers/claude-analyzer.ts`.
4. Assegna severity con questa regola secca (`scanner.ts:133`):
   ```ts
   severity = hasShadowing || accessesSensitiveFiles ? 'HIGH' : 'MEDIUM'
   ```
   Non c'è nessuna gradazione: **basta una sola regex match di "sensitive file access" o "shadowing" per far scattare HIGH**, indipendentemente dal contesto.

### I 4 analyzer statici

Tutti e quattro sono **pattern matching puro** su stringhe — nessuna semantica, nessuna analisi di flusso, nessun NLP.

| Categoria | Input analizzato | Meccanismo |
|---|---|---|
| `hidden-instructions` | `tool.description` | ~13 regex per tag HTML-like (`<instructions>`, `<system>`), frasi come "do not tell", "instead of", "always do" |
| `potential-exfiltration` | `tool.inputSchema.properties` | Whitelist di 13 parameter name "sospetti": `note`, `notes`, `feedback`, `details`, `extra`, `additional`, `metadata`, `debug`, `sidenote`, `context`, `annotation`, `reasoning`, `remark` |
| `shadowing-detected` | `tool.description` | ~11 regex su frasi come "before using other tool", "override the behavior of", "this is VERY important" |
| `sensitive-file-access` | `tool.description` | ~19 regex keyword: `~/.ssh`, `.env`, `id_rsa`, **`\bpassword\b`**, **`\btoken\b`**, **`\bsecret\b`**, **`\bcredentials\b`**, **`\bapi[ -_]?key\b`**, `\.\./`, ecc. |

### Il ruolo della LLM (Claude)

In `scanner.ts:166-177` la LLM viene invocata **solo** se:

```ts
if (claudeApiKey &&
    (hasHiddenInstructions || hasShadowing || accessesSensitiveFiles) &&
    tool.description) {
  claudeAnalysis = await analyzeWithClaude(tool.description, claudeApiKey)
}
```

⚠️ **I tool con solo `potential-exfiltration` non vengono mai analizzati dalla LLM**. Questo spiega il gap 5918 (vulnerable) − 4269 (LOW+MED+HIGH+failures) = **1649 tool valutati solo dall'analisi statica**, corrispondenti grosso modo ai 1707 findings di `potential-exfiltration`.

Il prompt di Claude (`claude-analyzer.ts:22-42`) è molto semplice: chiede YES/NO per 5 categorie e un overall risk LOW/MEDIUM/HIGH. Il parsing del risk è altrettanto naive:

```ts
const overallRisk = response.content[0].text.includes('HIGH') ? 'HIGH' :
                    response.content[0].text.includes('MEDIUM') ? 'MEDIUM' :
                    response.content[0].text.includes('LOW') ? 'LOW' : null
```

Basta che "HIGH" compaia nel testo della risposta (es. "this is NOT HIGH risk") per alzare il rating.

### Come la pipeline (wrapper `mcpShield.py`) parsa l'output

Il wrapper non consuma JSON strutturato: prende l'output testuale umano di `npx mcp-shield` e lo parsa a regex (`frameworks/mcpShield.py:55-68`):

```python
m = re.match(r"[\u2013\-]\s*(.+?):\s*(.+)", line)
if m and current_tool:
    raw_issue = m.group(1).lower().replace(" ", "-")
    ...
    tools[current_tool]["category"][raw_issue][idx] = {"description": m.group(2)}
```

Questo è il motivo per cui compaiono le categorie spurie `"text"-(default)`, `"raw"`, `"annotations"`, `png`, `svg`: il regex `r"- (.+?): (.+)"` ha **falsato il match** su righe che non erano issue di vulnerabilità ma metadati descrittivi del tool — vedi §4.3.

---

## 2. Numeri complessivi

| Metrica | Valore |
|---|---|
| Server totali analizzati | 60.203 |
| Server in cui mcp-shield è eseguito con successo | **9.842 (16,35%)** |
| Tool totali osservati | 80.993 |
| Tool ritenuti `safe` | 75.075 (92,69%) |
| Tool ritenuti `vulnerable` | **5.918 (7,31%)** |
| Media tool vulnerabili per server | 0,60 |

**Nota sulla copertura del 16,35%:** significa che su ~83% dei server scansionati mcp-shield non ha prodotto output (server non avviabili, MCP non validi, timeout, errori di connessione). Questo *non* è una debolezza di mcp-shield in sé — è il dataset che contiene molti server malformati o non installabili. Tuttavia il numero va tenuto presente prima di fare affermazioni sulla popolazione totale.

### Distribuzione findings per categoria (stats counter)

| Categoria | Count | % sul totale vulnerabilità |
|---|---:|---:|
| sensitive-file-access | **4.352** | 66,47% |
| potential-exfiltration | **1.707** | 26,07% |
| hidden-instructions | 448 | 6,84% |
| shadowing-detected | 35 | 0,53% |
| png / svg / "text"/"raw"/"annotations" | 5 | 0,09% |

> Nota: i counter `categories` (instance-level) non coincidono con il numero di entry nei file JSON (tool-level). Discrepanza già analizzata — un tool con N pattern match nella stessa categoria produce 1 entry con `descriptions=[...N...]` ma incrementa il counter di N. Non è un bug, è granularità diversa.

### Distribuzione LLM risk

| LLM overallRisk | Count | % dei tool analizzati dalla LLM |
|---|---:|---:|
| LOW | 1.703 | 54,1% |
| MEDIUM | 1.422 | 45,2% |
| HIGH | **22** | **0,7%** |
| failures | 1.122 | — |

Su **4.269 tool sottoposti a LLM** (esclusi gli exfiltration-only), la LLM ha confermato solo **22 HIGH**. Questo è probabilmente il segnale più forte di qualità del dataset: lo **0,5% circa** dei finding statici mantiene un alto rischio dopo seconda opinion.

I **1.122 failures** non sono un bug di mcp-shield ma dell'integrazione: 1.118 sono semplici "failed" (response parsing fallito o API error) e 4 sono timeout. Sono da considerare "analisi non conclusiva".

---

## 3. Valutazione qualitativa — analisi dei primi 2 record per file

Ho estratto le prime 2 entry da ogni file JSON in ogni sottocartella categoria. Riportata qui sotto una lettura per ognuna.

### 3.1 `sensitive-file-access/sensitive_file_access_HIGH.json` (3.956 entry)

**Esempi:**
```json
{ "tool_name": "create_database",
  "descriptions": ["password (Password access)"], "risk": "HIGH", "llm_risk": "LOW" }
{ "tool_name": "get_business_centers_tool",
  "descriptions": ["token (Token access)"], "risk": "HIGH", "llm_risk": "LOW" }
```

**Verdetto: falso positivo sistemico e massiccio.**

La regex `\bpassword\b` / `\btoken\b` / `\bsecret\b` / `\bcredentials\b` matcha **qualsiasi** tool che nella description menziona queste parole. Un endpoint database che accetta `password` come parametro di connessione, un'API che usa `token` di autenticazione OAuth, un servizio che ha `credentials` → tutti **HIGH risk sensitive file access**.

Guardando la distribuzione interna della categoria (da `descriptions` nello stats):
- `token (Token access)`: **1.581** (36%)
- `.. (Path traversal attempt)`: **1.064** (24%) ← il pattern `\.\./i` matcha QUALSIASI doppio punto (es. frasi come "See section 1..2", versioni "v1..v2", ecc.)
- `credentials (Credentials access)`: 411
- `API key (API key access)`: 295
- `password (Password access)`: 251
- `secret (Secret access)`: 133 + `Secret`: 25 + `SECRET`: 17

Solo una piccola minoranza (~10-50 findings) riguarda pattern effettivamente pericolosi come `~/.ssh` (10), `id_rsa` (4), `/etc/passwd` (1), `.env` (54) — e anche qui servirebbe contesto per distinguere un tool legittimo di gestione configurazione da uno malevolo.

**Conferma dalla LLM:** entrambi gli esempi mostrati sopra sono stati rivalutati come `LOW` dalla LLM. Guardando l'aggregato, la stragrande maggioranza dei findings `sensitive-file-access` (che confluiscono nei 1.703 LOW LLM) sono proprio questi.

**Cifre utili:**
- `.. (Path traversal)` + `token` + `password` + `credentials` + `api key` + `secret` ≈ **3.900 su 4.352** → >89% della categoria è riconducibile a 6 regex keyword che generano falsi positivi nella pratica.

### 3.2 `potential-exfiltration/potential_exfiltration_HIGH.json` (75) e `_MEDIUM.json` (1.609)

**Esempi:**
```json
{ "tool_name": "api_haystack_execute_swap",
  "descriptions": ["note (string)"], "risk": "HIGH", "llm_risk": "LOW" }
{ "tool_name": "21st_magic_component_refiner",
  "descriptions": ["context (string)"], "risk": "MEDIUM", "llm_risk": "LOW" }
```

**Verdetto: falso positivo di design.**

La logica (`tool-analyzer.ts:104`) confronta i nomi dei parametri con una whitelist fissa di 13 parole. Problemi:

1. `note` su uno swap blockchain è un **memo di transazione** standard (es. tag Algorand, memo Solana). Niente di sospetto.
2. `debug` è un flag binario comune in API REST.
3. `context` è uno dei nomi più banali in assoluto ("context window", "scraping context", "generation context", ...).
4. `metadata` è quasi un pattern architetturale.
5. `details`, `feedback`, `notes`, `reasoning`, `annotation` hanno usi leciti in mille tool.

Distribuzione interna (da stats):
- `context (string)`: **592** (~35%)
- `notes (string)`: 240
- `metadata (object)`: 213
- `note (string)`: 129
- `debug (boolean)`: 97
- `context (object)`: 93

**Che cos'è un vero exfiltration channel?** Un parametro che consente al tool di trasmettere dati arbitrari fuori dal controllo dell'utente. Per essere dannoso deve essere:
- opzionale (non viene riempito dall'utente)
- di tipo testuale/oggetto libero
- accompagnato da istruzioni nascoste che dicono al LLM di metterci dentro dati sensibili.

**Il detector cattura solo la condizione 1 (parzialmente)** e ignora completamente 2 e 3. È quindi un filtro grossolano che richiede verifica umana.

**⚠️ Bug di severity:** le 75 entry HIGH di `potential-exfiltration` NON esistono perché la exfiltration in sé sia HIGH. Esistono perché il severity è a **livello tool**, non a livello finding: se un tool ha **sia** exfiltration **sia** sensitive-file-access, tutti i suoi findings (inclusi quelli di exfiltration) ereditano HIGH. Questo è coerente con il parsing in `mcpShield.py`: il risk viene assegnato alla riga `Risk Level: HIGH` del tool e replicato su tutti gli issue successivi.

### 3.3 `hidden-instructions/hidden_instructions_HIGH.json` (93) e `_MEDIUM.json` (349)

**Esempi:**
```json
{ "tool_name": "generate_envelope_report",
  "descriptions": ["instead of"], "risk": "HIGH", "llm_risk": "LOW" }
{ "tool_name": "arango_search_tools",
  "descriptions": ["instead of"], "risk": "MEDIUM", "llm_risk": "LOW" }
```

**Verdetto: falso positivo massiccio su "instead of".**

Distribuzione interna:
- `"instead of"` + `"Instead of"` + `"INSTEAD of"` + `"INSTEAD OF"`: **368 + 20 + 5 + 5 = 398 su 448** → **89% dei findings di questa categoria è la locuzione "instead of"**.

La regex è `/\binstead (do|of|you should)\b/i`, pensata per matchare frasi come "instead of using X, always do Y" (pattern di instruction override). Ma "instead of" compare in *qualsiasi* description che dica ad esempio "use this instead of the legacy endpoint". **Zero valore discriminante.**

Il resto (~50 findings) è più interessante:
- `<instructions>` (6), `<IMPORTANT>` (3) → tag di istruzioni annidate, **questo è il pattern dichiaratamente pericoloso dall'analisi di Invariant Labs**.
- `Ignore all instructions` (1) → classico prompt injection marker.
- `Do not mention`, `Never show`, `hide this`, `not visible`, `DO NOT tell` → frasi di concealment.
- `ALWAYS include/do/add` → forced action.

**Questi ~50 sono il vero segnale della categoria** e varrebbe la pena guardarli uno per uno.

### 3.4 `shadowing-detected/shadowing_detected_HIGH.json` (34)

**Esempi:**
```json
{ "tool_name": "start_google_auth",
  "descriptions": ["before using other tool"], "risk": "HIGH", "llm_risk": "NOT_COMPLETED" }
{ "tool_name": "scrape",
  "descriptions": ["before using other tool"], "risk": "HIGH", "llm_risk": "NOT_COMPLETED" }
```

**Verdetto: falso positivo ma categoria rumorosa con qualche segnale.**

Distribuzione:
- `"before using other tool"`: **24/35 (69%)** ← locuzione tipica delle auth flow ("call this before using other tools") che NON è shadowing
- `"instead of using"`: 6 ← pattern ambiguo
- `"When this tool is available"` (1), `"This is VERY VERY"` (1), `"Prioritize this"` (2), `"after using the tool"` (1) → sono i **veri shadowing pattern** descritti nel README di mcp-shield come esempio di attacco

I 2 esempi mostrati (`start_google_auth`, `scrape`) hanno entrambi `llm_risk = NOT_COMPLETED` → **la LLM non è stata invocata per il loro caso**. Curioso: lo shadowing *è* uno dei trigger per la LLM. Il `NOT_COMPLETED` indica che probabilmente la chiamata API ha fallito o è andata in errore per questi specifici record (rientrano nei 1.118 `failed`).

**Da controllare a mano:** i 5-6 finding con pattern `"prioritize this"`, `"When this tool is available"`, `"This is VERY VERY"`. Sono i più vicini ai test case ufficiali del framework.

### 3.5 `png/png_MEDIUM.json` e `svg/svg_MEDIUM.json` (1 cadauna)

```json
{ "tool_name": "remarkable_image", "category": "png",
  "descriptions": ["Returned as BlobResourceContents with base64-encoded data"] }
{ "tool_name": "remarkable_image", "category": "svg",
  "descriptions": ["Returned as TextResourceContents with SVG markup"] }
```

**Verdetto: bug di parsing.**

Nessuna regex di mcp-shield produce `png` o `svg` come pattern name. Queste categorie **non esistono** nel framework. Vengono dal parser wrapper `mcpShield.py:55` che usa regex `r"- (.+?): (.+)"`. L'output testuale di mcp-shield per questo specifico tool conteneva righe come:

```
- png: Returned as BlobResourceContents with base64-encoded data
- svg: Returned as TextResourceContents with SVG markup
```

Queste **non erano sezioni issue**, erano righe descrittive del formato di output del tool `remarkable_image`. Il parser non distingue e le cattura come findings. Stesso motivo per `"text"-(default)`, `"raw"`, `"annotations"` (tutti relativi a un tool PDF/EPUB su VM5): mcp-shield ha stampato una tabella di opzioni output che sembrava "- key: desc".

**Impatto:** 5 finding spurious su ~5.918. Trascurabile in volume, ma segnala che il parser testuale di `mcpShield.py` andrebbe reso più strict — per esempio catturando solo le righe dentro il blocco `Issues:` del tool corrente.

---

## 4. Giudizio sintetico

### 4.1 L'analisi è fatta bene?

**Dal punto di vista del framework (mcp-shield):** è un buon tool *diagnostico di superficie*. Fa esattamente quello che dichiara: **pattern matching ingenuo** su description e inputSchema, pensato per dare un primo segnale a un security engineer che poi deve leggere i findings. Non è, né vuole essere, un tool di classificazione automatica.

Il fatto che il README dichiari esplicitamente esempi come "calculateSum con `<instructions>` che legge `~/.ssh/id_rsa`" conferma che la progettazione punta ai casi più espliciti e plateali di tool poisoning. Quei casi li prende bene.

**Dal punto di vista dell'applicazione a un dataset di 60k server "in the wild":** l'assenza di qualsiasi filtro di contesto rende il 90%+ dei findings falsi positivi. Il dataset che ne risulta **non è consumabile come lista di vulnerabilità** — serve un secondo layer di triage, che nel nostro caso è la LLM, ma:
- non copre gli exfiltration-only (~1.700 finding);
- ha 1.122 failures non recuperati;
- il parser del risk è fragile (`text.includes('HIGH')`).

### 4.2 Quanti falsi positivi?

Stima cauta basata sull'intersezione stats + LLM:

| Categoria | Count | % falso positivo stimato | Segnale residuo (stima) |
|---|---:|---:|---:|
| sensitive-file-access | 4.352 | ~95% (dominato da `token`, `..`, `password`, `credentials`) | ~100-200 (ssh, id_rsa, /etc/passwd, .env con contesto sospetto) |
| potential-exfiltration | 1.707 | ~98% (parameter name whitelist senza contesto) | ~20-50 (da validare caso per caso, probabilmente <10 reali) |
| hidden-instructions | 448 | ~89% (dominato da "instead of") | **~50 finding genuini** (`<instructions>`, `<IMPORTANT>`, `Ignore all`, `Do not mention`, `Never show`) |
| shadowing-detected | 35 | ~85% (dominato da "before using other tool") | **~5-6 finding genuini** (prioritize this, When this tool is available, This is VERY VERY) |
| png/svg/"..." | 5 | 100% (bug parser) | 0 |
| **Totale** | **~6.547** | ~94-96% | **~180-280** |

In controluce, la LLM conferma la stima: **22 HIGH su ~4.269 tool analizzati** è coerente con un segnale residuo di poche centinaia di tool realmente sospetti.

### 4.3 Cosa c'è di davvero interessante nel dataset?

I dati potenzialmente di valore, da guardare a mano:

1. **I ~50 finding `hidden-instructions` non-"instead of"** — in particolare quelli con tag `<instructions>`, `<IMPORTANT>`, `<system>`, `<secret>`, e le frasi di concealment (`Do not mention`, `Never show`, `hide this`, `not visible`, `DO NOT tell`, `Ignore all instructions`). Questi sono esattamente il pattern attacco descritto dalla ricerca di Invariant Labs e sono plausibilmente veri positivi.

2. **I ~6 finding `shadowing-detected` con pattern non triviali** — `When this tool is available`, `This is VERY VERY`, `Prioritize this`, `after using the tool`. Volumi piccolissimi, perfetti per verifica manuale.

3. **I 22 HIGH confermati dalla LLM.** Questo è il dataset più concentrato di segnale: tool dove sia l'analisi statica sia la LLM sono concordi su rischio alto. **Va estratta questa lista separatamente** — al momento non esiste un file dedicato, si può ricavare filtrando `mcp_shield_servers.json` o i findings per `llm_risk == "HIGH"`.

4. **I ~10 finding `~/.ssh`, 4 finding `id_rsa`, 1 finding `/etc/passwd`, 54 finding `.env`** — anche in assenza di contesto sono da esaminare uno per uno. Un tool legittimo ha pochissimi motivi di menzionare questi path nella description.

5. **Le statistiche aggregate sui descriptor** (`descriptions` nello stats file) sono di per sé interessanti come **mappa epidemiologica** del dataset: che tipo di tool sono stati rilasciati, quali parameter name sono più comuni, che rapporto c'è tra tool con `token/password` vs tool con `ssh-key/id_rsa`. Utili per caratterizzare la popolazione di server MCP pubblicata, meno per la security triage.

### 4.4 Problemi noti e suggerimenti

| Problema | Dove | Fix suggerito |
|---|---|---|
| Severity a livello tool replicata su tutti gli issue | `mcpShield.py` parser | Assegnare severity per singolo finding in base alla categoria |
| Parser testuale cattura righe non-issue (png/svg/raw/...) | `mcpShield.py:55` | Limitare match alle sole righe dentro il blocco `Issues:` del tool corrente |
| LLM non invocata per exfiltration-only | `scanner.ts:166` | Patch upstream oppure secondo pass custom |
| LLM risk parsing fragile (`includes('HIGH')`) | `claude-analyzer.ts:50` | Chiedere alla LLM risposta JSON strutturata |
| 1.118 `failed` senza retry | integrazione LLM | Retry con exponential backoff |
| Regex `\.\./i` genera 1.064 falsi positivi da `..` | `tool-analyzer.ts:220` | Rafforzare a `\.\./[\w/]` per richiedere un path component dopo |
| Regex "instead of" genera ~400 falsi positivi | `tool-analyzer.ts:88` | Rimuovere `of` dal pattern o richiedere vicinanza a verbi imperativi |

---

## 5. Bug di attribuzione upstream ⚠️ (scoperta successiva)

Nel corso dell'analisi di un singolo record è emerso un **bug sistemico** che invalida l'attribuzione di una parte significativa dei findings Python. Merita una sezione a sé perché **non è un falso positivo di mcp-shield**: è un difetto della pipeline che fa sì che mcp-shield analizzi **un pacchetto diverso da quello presente nel repo clonato**.

### 5.1 Il caso che lo ha rivelato

Record nel dataset:
```json
{
  "server_url": "https://github.com/nkeat12/supabase-mcp-server",
  "tool_name": "retrieve_logs",
  "category": "hidden-instructions",
  "descriptions": ["instead of"],
  "risk": "HIGH",
  "llm_risk": "HIGH",
  "llm_analysis": "...custom query parameter allows users to execute arbitrary SQL queries..."
}
```

Clonando `nkeat12/supabase-mcp-server` a mano: il tool `retrieve_logs` **non esiste**. Il repo è un fork stale di `alexander-zuev/supabase-mcp-server` con solo 8 tool (`get_db_schemas`, `get_tables`, `get_table_schema`, `execute_sql_query`, `send_management_api_request`, `live_dangerously`, `get_management_api_spec`, `get_management_api_safety_rules`). Nessun `retrieve_logs`.

Clonando l'upstream `alexander-zuev/supabase-mcp-server`: `retrieve_logs` c'è, ed è definito in:
- `supabase_mcp/tools/descriptions/logs_and_analytics_tools.yaml` — **la description flaggata**, dove appare la locuzione `"custom_query: Complete custom SQL query to execute instead of the pre-built queries"` → match letterale del pattern `\binstead (do|of|you should)\b`
- `supabase_mcp/tools/registry.py:168` — dichiarazione `@mcp.tool(...)` del tool
- `supabase_mcp/core/feature_manager.py:220` — wrapper di dispatch
- `supabase_mcp/services/api/api_manager.py:295` — implementazione effettiva

### 5.2 Root cause: `detect_python_runner` + uvx

Il bug vive in `functions/buildConfig.py:86-105`:

```python
def detect_python_runner(repo_path: Path):
    pyproject = repo_path / "pyproject.toml"
    ...
    if pyproject.exists():
        content = pyproject.read_text(...)
        match = re.search(r'^name\s*=\s*"([^"]+)"', content, re.MULTILINE)
        if match:
            name = match.group(1)

        if "[project.scripts]" in content:
            return ("uvx", name)   # ← sceglie uvx come runner
```

E poi in `build_mcp_config` (riga 324-327):

```python
if runner == "uvx":
    result["command"] = "uvx"
    result["main"] = [f"{name}@latest"]   # ← uvx <name>@latest
    return result
```

Quando il repo ha `[project.scripts]` nel `pyproject.toml`, la pipeline **ignora il codice clonato** e lancia `uvx <package-name>@latest`, che:

1. Risolve `<package-name>` contro il **registro pubblico PyPI**
2. Scarica l'ultima versione pubblicata (non quella del fork)
3. La esegue
4. mcp-shield si connette a quel processo e scansiona i tool della versione PyPI

Il fork `nkeat12` ha mantenuto `name = "supabase-mcp-server"` in pyproject.toml → identico al pacchetto upstream pubblicato da alexander-zuev → `uvx supabase-mcp-server@latest` pesca la versione 0.3.x dell'upstream, che contiene `retrieve_logs`.

I finding vengono poi salvati con il `server_url` del ciclo corrente (`run_shield.py:445` → `update_output_files(server_url, ...)`), cioè `nkeat12/...`. **L'attribuzione del finding al repo è quindi scorretta**: la vulnerabilità descritta appartiene al codice upstream di alexander-zuev, non al fork.

### 5.3 Ampiezza del problema

Questo bug colpisce **tutti i repo Python con `[project.scripts]` in pyproject.toml** che condividono il `name` con un pacchetto già pubblicato su PyPI. Casi tipici:

- Fork stale che non rinominano il pacchetto (la maggioranza dei fork)
- Repo mirror (`MCP-Mirror/*`, molto presenti nel dataset)
- Repo template/esempio che riusano il nome di un pacchetto community
- Fork legittimi con modifiche locali, ma che non sono stati pubblicati su PyPI

Il sottoinsieme colpito va stimato dal `mcp_shield_servers.json` incrociando i server Python `completed` con la presenza di `[project.scripts]` nel pyproject.toml — non è ricavabile dai soli stats attuali. Su 2.187 server Python completati, ragionevole stimarne una frazione non trascurabile.

### 5.4 Implicazioni per il dataset

- Il subset di findings "Python con uvx" **non misura** vulnerabilità del repo: misura vulnerabilità dell'upstream PyPI.
- Un fork benigno può ereditare i findings di un upstream compromesso, e viceversa un fork maligno può sfuggire se l'upstream PyPI è pulito (il clone non viene mai davvero scansionato).
- I 22 HIGH confermati dalla LLM sono **probabilmente anch'essi affetti** in parte: vanno verificati uno per uno capendo quale strategia di runner è stata scelta.
- Il conteggio delle categorie resta corretto in totale, ma la distribuzione per `server_url` è inaffidabile per i record colpiti.

### 5.5 Fix proposti

In ordine di preferenza:

1. **Preferire sempre l'esecuzione locale in `detect_python_runner`**. Cercare prima un entry point locale (`main.py`, `src/server.py`, `__main__.py`, `server/main.py`, ecc.) e usare `uv run` / `python` puntando al codice clonato. Cadere su `uvx` solo se non c'è alcun entry point locale e il pacchetto è effettivamente pubblicato. Questa è la fix corretta: uno scanner di codice deve analizzare *il codice che vede*.

2. **Install editable**. `uv pip install -e .` (o `pip install -e .`) nel repo clonato prima di lanciare lo script, così il pacchetto "installato" è fisicamente quello locale. Richiede un passaggio aggiuntivo ma è corretto dal punto di vista semantico.

3. **Flaggare i repo "pyPI-overlap"**. Minimo intervento: quando si sceglie la strategia `uvx`, registrare nel log del server un marker tipo `source=pypi:<version>` invece di `source=repo`. Non risolve il problema ma permette di escludere o ri-analizzare quel subset a posteriori.

### 5.6 Cosa fare adesso sul dataset esistente

- Aggiungere al `mcp_shield_servers.json` (o a un file parallelo) il flag che indica la strategia di runner usata, retroattivamente se possibile analizzando i pyproject.toml.
- Ri-eseguire mcp-shield solo sui server Python con `[project.scripts]` usando `uv pip install -e .` in un'ambiente isolato, prima di lanciare il tool. È l'unico modo di ottenere findings davvero attribuibili al fork.
- Non trarre conclusioni sulle vulnerabilità "per repo" dal subset Python finché il fix non è stato applicato e ri-eseguito.

---

## 6. TL;DR

- **Il framework è onesto**: fa pattern matching ingenuo e lo dichiara. Funziona bene per trovare i tool poisoning plateali; non funziona come classificatore automatico su dataset grandi.
- **~94-96% dei 5.918 findings sono falsi positivi**, dominati da 6 regex keyword (`token`, `..`, `password`, `credentials`, `context`, `instead of`) e dalla whitelist ingenua dei parameter name sospetti.
- **Il segnale residuo è di ~150-280 findings interessanti**, concentrati in: (a) 22 HIGH confermati dalla LLM, (b) ~50 hidden-instructions con tag/concealment reali, (c) ~6 shadowing non triviali, (d) ~70 sensitive-file-access con path effettivamente sensibili (.ssh, id_rsa, .env con contesto).
- **Due bug collaterali**: parser testuale troppo permissivo (5 categorie spurie png/svg/...) e severity a livello tool invece che a livello finding.
- **LLM come fallback secondario** è utile ma parziale: non copre 1.700 tool, ha 1.122 failures senza retry, parsing del risk fragile.
- **Il dato più actionable è la lista di 22 HIGH confermati LLM** — va estratta come file a parte e verificata a mano.
