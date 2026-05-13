# Checklist di verifica manuale per categoria

**Scopo**: documentare, per ciascuna delle 17 categorie di vulnerabilità, i check espliciti che eseguo a mano sul codice sorgente reale (fetchato da GitHub) per decidere il verdetto `VP-C` / `VP-L` / `VP-D` / `FP`.

**Convenzioni**:

| Sigla | Significato |
|-------|-------------|
| **VP-C** | Vero Positivo Confermato — vulnerabilità sfruttabile sul codice attuale |
| **VP-L** | Vero Positivo Latente / by-design — capability dichiarata del server |
| **VP-D** | Vero Positivo Debole — pattern reale ma blast radius limitato |
| **FP**   | Falso Positivo — pattern matchato ma codice benigno |

Per ogni categoria riporto: **(1) entry point** (cosa apre il check), **(2) sequenza di check** (in ordine logico), **(3) decision rule** (cosa decide il verdetto).

---

## 1. sql-injection (mcp-guard)

**Entry point**: f-string SQL del tipo `cursor.execute(f"... {var} ...")` o `text(f"...")`.

**Check**:
1. **Origine della variabile interpolata** (`{table}`, `{db}`, `{column}`):
   - costante hardcoded / da `sqlite_master` / loop su lista interna → benigno
   - da `params.X` / `args.X` / URI MCP / tool input → tainted
2. **Sanitizer a monte**: cerco `validate_*`, regex whitelist `^[a-zA-Z_]+$`, escape espliciti
3. **Server espone già `execute_sql` arbitrario?** (grep `execute_sql` / `query` tool nel server)
4. **DBMS supporta stacked queries** (MSSQL, PostgreSQL → sì; SQLite → no)
5. **Tipo di interpolazione**: identifier (table/column) vs value/string

**Decision**:
- Sanitizer presente → **FP**
- Tainted + DB con stacking + no sanitizer → **VP-C**
- Tainted ma server espone già SQL arbitrario by design → **VP-L**
- Identifier da config server-fissato → **VP-L**
- Identifier metadata (es. Teradata QUERY_BAND) → **VP-D**

---

## 2. dangerous-capabilities (mcp-security-scan)

**Entry point**: lista di tool MCP con description che contiene keyword sensibili (`execute`, `run`, `delete`, `install`).

**Check**:
1. **Verbo della description**: read vs write/exec
2. **Server type**: wrapper di servizio noto (Docker / k8s / SSH / DB) vs app generica
3. **Match HC del framework**: corrisponde al testo reale?
   - es. HC `real_install` su `pip install dep` in nota dipendenza → match errato
4. **Intent offensivo esplicito**: terminologia MITRE / pentest nei tool name

**Decision**:
- Server è wrapper di servizio (Docker/k8s/SSH/DB) → **VP-L** (by design)
- Read-only (search, list, get) flaggato → **FP**
- Offensive tool (mimikatz, etc.) → **VP-L**
- Esecuzione generica senza contesto → **VP-C** (raro)

---

## 3. credential-leak (mcp-watch)

**Entry point**: stringa che matcha pattern provider (`sk-`, `AIzaSy`, `ghp_`, `AKIA`, `xoxb-`).

**Check**:
1. **Formato chiave**: prefix valido + lunghezza canonica del provider
2. **Entropia stringa**: random vs sequenza alfabetica/placeholder
3. **Filename**: `.env` vs `.env.example` vs `docs/` vs `test/`
4. **Commento esplicito**: `// public key`, `// intentionally exposed`
5. **Contesto di assegnazione**: `process.env.X || 'real_key'` (fallback) vs solo env
6. **Varname-value match**: `apiKey: 'apiKey'`, `TOKEN: 'token'` → self-describing → fake

**Decision**:
- Formato + entropia reali + in `.env` committato → **VP-C**
- Commento "public/intentional" → **FP**
- Sequenza alfabetica (`A1bC2dE3...`) o placeholder (`YOUR_KEY`) → **FP**
- In `.env.example` / `docs/` → **FP**
- Fallback hardcoded reale dopo `||` → **VP-C**

---

## 4. ssrf (mcp-guard)

**Entry point**: `fetch(...)`, `axios.get(...)`, `requests.get(...)` con interpolazione di variabili.

**Check**:
1. **Cosa controlla l'attaccante?**
   - intera URL (`fetch(params.url)`) → full SSRF
   - solo path/query (`fetch(\`${BASE}/${params.x}\`)`) → no SSRF
   - nulla (URL completamente statica) → no SSRF
2. **BASE/host**: hardcoded, da env, o da params?
3. **Sanitizer**: `URLSearchParams` auto-escape, `encodeURIComponent`
4. **Tipo di chiamata**: SDK method (`this.client.get(path)`) vs raw `fetch`

**Decision**:
- `params.url` intera URL controllata → **VP-C**
- Host fisso (hardcoded o env), path/query da utente → **VP-D**
- SDK method con base bound + auto-escape → **FP**
- URL completamente statica → **FP**

---

## 5. untrusted-content (mcp-scan W015)

**Entry point**: server con tool che fetch da fonti esterne.

**Check**:
1. **La fonte è pubblicamente scrivibile senza privilegi?** (GitHub free, YouTube, blog, Salesforce web-to-lead, Telegram public, ecc.)
2. **Il contenuto è passato al LLM senza isolamento?**
3. **Il server ha disclaimer / sandbox?**

**Decision**:
- Fonte pubblicamente scrivibile + contenuto al LLM raw → **VP-C**
- Fonte autenticata privata → **FP**
- Fonte pubblica ma sanitizer attivo → **VP-D**

---

## 6. path-traversal-static (mcp-guard)

**Entry point**: `os.path.join(...)`, `filepath.Join(...)`, `path.join(...)` con variabili.

**Check**:
1. **Origine della variabile path**: MCP tool input vs CLI args vs costanti interne
2. **Sanitizer**: `path.resolve` + check inside base, rejection di `..`
3. **Operazione finale**: read (`open(...)`) vs write (`open(.., 'w')`) vs check (`os.path.exists`)
4. **Base dir hardcoded** assoluto vs configurabile

**Decision**:
- MCP input + write + no sanitizer → **VP-C**
- MCP input + read + no sanitizer → **VP-C** (severità minore)
- CLI args (local user) → **VP-D**
- Costanti interne / scanner code che VERIFICA traversal → **VP-L** o **FP**
- Sanitizer attivo → **FP**

---

## 7. command-injection-static (mcp-guard)

**Entry point**: `exec.Command(...)`, `subprocess.run(...)`, `spawn(...)`, `execSync(\`...\`)`.

**Check**:
1. **Linguaggio + funzione**: Go `exec.Command` no-shell vs `sh -c`, Node `spawn` vs `shell:true`, Python `shell=True`
2. **Pattern di obfuscation** (trojan detection):
   - string concat per spezzare keyword (`"/bi"+"n/s"+"h"`)
   - array index char lookup (`UC[32]+UC[38]`)
   - base64 decode + exec
   - wget/curl verso domini sospetti (`.icu`, `.xyz`, IP raw)
3. **Origine arg**: `params.X` (MCP) vs `args[i]` (CLI) vs costanti
4. **Server intent**: esplicito CLI/shell runner by design?

**Decision**:
- Obfuscation pattern + C2 download → **VP-C trojan**
- `sh -c "${user_input}"` o template literal con user var → **VP-C**
- Go/Node exec senza shell + args separati → **FP**
- CLI input only → **VP-D**
- Server esplicito shell runner → **VP-L**

---

## 8. code-injection-static (mcp-guard) — `eval()`

**Entry point**: `eval(...)`, `Function(...)`, `eng.eval(...)`, `nvim.eval(...)`.

**Check**:
1. **Cosa viene eval()?**
   - user input diretto → tainted
   - var da workspace controllato (es. MATLAB var name = identifier validato) → constrained
   - loop var da stringa hardcoded → safe
2. **Sanitizer**: whitelist `[a-z]`, escape di quote
3. **Engine scope**: JS global vs MATLAB engine (constrained by identifier rules) vs Vim eval (può chiamare `system()`)

**Decision**:
- JS `eval(user_input)` globale → **VP-C**
- MATLAB `eng.eval(f"...{var}...")` con var = identifier validato → **VP-D**
- Vim eval `system()` esplicitamente esposto come tool → **VP-L**
- Loop var da stringa statica → **FP**

---

## 9. input-validation (mcp-watch)

**Entry point**: stesso schema di cat 7 + cat 4 (combo: SSRF + command/code injection + path traversal aggregati).

**Check**: deriva da cat 4/6/7/8 in base al sink rilevato.

---

## 10. protocol-violation (mcp-watch) — `INSECURE_TRANSPORT`, `SESSION_ID_IN_URL`

**Entry point**: URL `http://` o `?sid={}` nella query string.

**Check**:
1. **Host nell'URL**:
   - IP esterno pubblico via `http://` → cleartext reale
   - `localhost`, `127.0.0.1`, `192.168.x.x` → dev/LAN
   - `example.com`, dominio in commento/docs → docs
2. **Contenuto inviato via HTTP**: file, API key in header, body sensibile
3. **SESSION_ID_IN_URL**:
   - auth session reale (Pi-hole, Synology) → exfil
   - MCP SSE protocol `?session_id=` → protocollo (no auth)
   - Stripe `CHECKOUT_SESSION_ID` → non secret

**Decision**:
- HTTP esterno + sensitive data → **VP-C**
- HTTP esterno + public data → **VP-D**
- HTTP localhost / docs / example → **FP**
- Auth session in URL reale → **VP-C**
- MCP protocol session in URL → **FP**

---

## 11. prompt-injection (mcp-scan E001 tool-level)

**Entry point**: tool description con linguaggio imperativo verso il modello.

**Check**:
1. **Istruzioni LLM-targeted esplicite**:
   - "Ignore previous instructions" / "Disregard system" → injection
   - "Silently remember", "Don't tell user" → hidden exfil
   - "PROACTIVELY", "MUST IMMEDIATELY" → behavior override
2. **Tag XML di injection**: `<IMPORTANT>`, `<system>`, `<cmd>` (vs `<usecase>` strutturale che è benigno)
3. **Forced tool chaining**: "After this returns, call X with..."
4. **Typo deliberato**: `sliently` (intentional obfuscation marker)

**Decision**:
- Tag injection esplicito (`<IMPORTANT>` con istruzioni nascoste) → **VP-C**
- Hidden exfil ("silently remember", "don't mention") → **VP-C**
- Forced tool chaining cross-tool → **VP-C**
- Imperative behavior change senza occultamento → **VP-D**
- Linguaggio imperativo normale (`MUST`, `ALWAYS`) per workflow → **FP**

---

## 12. insecure-deserialization (mcp-guard) — `pickle`

**Entry point**: `pickle.loads(...)`, `pickle.load(...)`, `yaml.load(...)`.

**Check**:
1. **Origine del payload**:
   - `pickle.loads(args.data)` da MCP tool → tainted diretto
   - `pickle.loads(row[0])` da DB scritto dal server stesso → trust depending on persistence
   - `pickle.load(open(const_path, 'rb'))` → trusted local
2. **Path file attaccante-controllato?** (se è `pickle.load(open(...))`)
3. **Cross-session/multi-user persistence?**

**Decision**:
- Payload da MCP tool diretto → **VP-C**
- DB SQLite scritto dal server, cross-session → **VP-D**
- Path hardcoded → **FP**
- Cache propria di security scanner stesso → **FP**

---

## 13. sensitive-file-access (mcp-shield)

**Entry point**: tool description che menziona file/credential sensibili.

**Check**:
1. **Linguaggio MITRE ATT&CK**: DCSync, LSASS, Kerberoast, mimikatz, sekurlsa
2. **Server name pattern**: `sec-*`, `red-*`, `attack-*`, `offensive-*`

**Decision**:
- Linguaggio MITRE + server `sec-*` → **VP-L** (offensive by design)
- Linguaggio MITRE su tool non offensive → **VP-C** (rare)
- Read di file di config legittima → **FP**

---

## 14. sensitive-info-disclosure (multi-source)

**Entry point**: response del server che il framework matcha contro pattern di leak.

**Check**:
1. **Cosa è realmente nella response?**
   - contenuto reale di `/etc/passwd` (`root:x:0:0:`) → leak reale
   - echo del payload (URI fornita dall'utente riemessa) → no leak
   - Python traceback con path interni → debug info
   - Stack trace con secret/session_id → critical leak
2. **Error message granularity**: generico vs implementation detail

**Decision**:
- Contenuto reale di file sistema in response → **VP-C**
- Stack trace con credenziali / session ID → **VP-C**
- Python traceback con path interni / echo payload → **VP-D**
- Echo del payload utente con keyword matchata → **FP**

---

## 15. access-control (mcp-watch) — `EXCESSIVE_PERMISSIONS`

**Entry point**: pattern di permission grant largo (`GRANT ALL`, IAM `"*":"*"`).

**Check**:
1. **Scope del grant**:
   - `*.*` (tutti DB / risorse) → globale
   - DB / role dedicato → limitato
2. **Server intent**: AWS pentest tool documenta IAM privesc vs app server crea admin user
3. **Contesto runtime**: setup one-time vs runtime privilege escalation

**Decision**:
- Pentest tool con tecniche IAM documentate → **VP-L** (offensive by design)
- App che crea user con grant ampio → **VP-D** (se DB dedicato) o **VP-C** (se `*.*`)

---

## 16. data-exfiltration (mcp-watch)

**Entry point**: hook installation, tool schema che richiede conversation context.

**Check**:
1. **Hook content**: cosa viene inviato e dove?
   - `UserPromptSubmit` → backend esterno → conversation exfil
   - Tool schema "extracted from ENTIRE conversation" → LLM viene istruito a inviare tutto
2. **Destination**: server backend dichiarato vs hidden endpoint
3. **User awareness**: l'utente che installa è informato del flusso dati?

**Decision**:
- Hook che invia UserPromptSubmit a backend esterno → **VP-C**
- Tool schema esplicita richiesta di conversation context → **VP-C**
- Telemetry interna documentata → **VP-D**

---

## 17. tool-shadowing (mcp-shield)

**Entry point**: tool description che menziona o altera comportamento di altro tool.

**Check**:
1. **Menzione cross-tool**: "When this tool is available, X tool must..."
2. **Indirizzo malevolo**: `attacker@pwnd.com`, `attacker.com`, raw IP esterno
3. **Linguaggio di overriding**: "ALWAYS use X instead", "NEVER use Y"

**Decision**:
- Override esplicito + endpoint malevolo → **VP-C**
- "Use this together with X" (workflow legittimo) → **FP**

---

## Sintesi: pattern trasversali

Indipendentemente dalla categoria, ho 4 macro-check ricorrenti:

1. **Tracing data source** — la variabile interpolata da dove viene? MCP input / CLI / config / costante / iteratore interno
2. **Sanitizer presence** — c'è validazione/escape prima del sink? Quanto è completa?
3. **By-design vs unintended** — il pattern è la feature dichiarata del server o un'esposizione accidentale?
4. **Blast radius** — sfruttando il finding, l'attaccante ottiene RCE remoto, file read locale, denial of service, o nulla di concreto?

Il verdetto è una combinazione: 

- **VP-C** = data source tainted + no sanitizer + unintended + blast radius alto
- **VP-L** = pattern reale ma è la feature del server (by-design)
- **VP-D** = pattern reale, unintended, ma blast radius basso (host fisso, no shell, identifier constraint, ecc.)
- **FP** = sanitizer attivo, sorgente costante, pattern matchato per coincidenza testuale
