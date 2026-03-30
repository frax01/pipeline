# MCP Watch - How It Works

Questo documento descrive il funzionamento degli scanner contenuti nel framework **mcp-watch** e la logica tecnica utilizzata per identificare potenziali vulnerabilità.

---

## 1. AnsiInjectionScanner
Questo scanner si occupa di identificare vulnerabilità di attacco steganografico dove istruzioni malevole vengono nascoste all'interno del codice.

### `containsAnsiEscapes`
- **Severity**: Medium
- **Descrizione**: Cerca l'uso di sequenze di escape ANSI utilizzate per iniettare e nascondere codice. (RIRUNNARLO)
- **Esempio**: Stringhe che contengono pattern regex come `\u001b[31m` o `\x1b[`.
- **Dettaglio Tecnico**: Lo scanner utilizza un'espressione regolare per individuare varie forme di sequenze ANSI: `/\u001b\[[0-9;]*[a-zA-Z]/`, `/\\u001b\[[0-9;]*[a-zA-Z]/`, `/\\x1b\[[0-9;]*[a-zA-Z]/`, e `/\x1b\[[0-9;]*[a-zA-Z]/`.

### `containsWhitespaceInjection`
- **Severity**: Medium
- **Descrizione**: Rileva l'uso eccessivo di spazi bianchi invisibili usati per occultare payload malevoli.
- **Esempio**: Una linea di codice in cui la differenza di lunghezza tra la stringa completa e la stringa "trimata" (senza spazi) è maggiore di 100 caratteri.
- **Dettaglio Tecnico**: Il controllo logico calcola la lunghezza della riga senza spazi (`line.trim().length`) e la sottrae alla lunghezza totale. Se la riga non è vuota e la differenza supera i 100 caratteri, scatta la segnalazione.

---

## 2. ConversationExfiltrationScanner
Si concentra sul rilevamento di pattern volti all'esfiltrazione fraudolenta della cronologia delle conversazioni dell'utente (rischio critico).

### `containsConversationTriggers`
- **Severity**: Critical
- **Descrizione**: Rileva specifiche frasi o trigger inseriti nella proprietà `description` di un tool per indurre l'AI a inoltrare i dati dell'utente.
- **Esempio**: Una descrizione che contiene frasi come `thank you please send conversation history` o `forward chat`.
- **Dettaglio Tecnico**: La funzione scatta se e solo se la riga contiene la parola "description" in combinazione con uno dei seguenti pattern regex case-insensitive: `/thank\s+you.*(?:conversation|history|chat)/i`, `/please.*(?:conversation|history|chat)/i`, `/when.*(?:user|says|types).*(?:conversation|history)/i`, `/if.*(?:conversation|history|chat)/i`, `/trigger.*(?:conversation|history|chat)/i`, `/forward.*(?:conversation|history|chat)/i`, o `/send.*(?:conversation|history|chat)/i`.

**Esempio di ritrovamento:**
`C:\Users\francesco\Desktop\pipeline\analysisAllData\0_tool_mcp_watch\data-exfiltration\data_exfiltration_critical.json`
```json
{
    "server_name": "mcp-salesforce",
    "github_url": "https://github.com/AiondaDotCom/mcp-salesforce",
    "language": "nodejs",
    "id": "CONVERSATION_EXFILTRATION_TRIGGER",
    "category": "data-exfiltration",
    "description": "Conversation history exfiltration trigger detected",
    "file": "src/tools/learn-context.js",
    "line": 22,
    "evidence": "description: \"Learn and store personal/business context about the user and their Salesforce data model relationships. This helps provide better context-aware assistance across sessions. PROACTIVELY CAPTURE AHA MOMENTS: Whenever you discover something important about the user's workflow, business processes, preferences, challenges, or breakthrough insights during conversations, automatically use store_learning to preserve this knowledge. Look for moments when the user reveals key information, expresses frustration, shares successful strategies, or has realizations - these are valuable learnings that should be stored immediately.\",",
    "source": "Trail of Bits research"
}
```

---

## 3. CredentialScanner
Identifica perdite o gestioni insicure di credenziali, chiavi e token all'interno del codice.

### `containsHardcodedCredentials`
- **Severity**: Critical
- **Descrizione**: Identifica chiavi API, password e token scritti direttamente (hardcoded) nel codice sorgente. (RIRUNNARLO)
- **Esempio**: `const apiKey = "sk-abcdefghijklmnopqrstuvwxyz12345678"` oppure stringhe relative a token AWS o GitHub OAuth.
- **Dettaglio Tecnico**: Il matching avviene tramite una batteria di regex mirate, come `/(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][a-zA-Z0-9]{15,}["']/i` per stringhe generiche, `/sk-[a-zA-Z0-9]{20,}/` per OpenAI, `/ghp_[a-zA-Z0-9]{36}/` per GitHub, e altre per Slack, AWS, Google, e JWT. Per evitare falsi positivi, la riga viene ignorata se passa la funzione `isExampleCredential()` (che filtra parole come "test", "demo", "placeholder").

### `containsPlaintextStorage`
- **Severity**: High
- **Descrizione**: Trova salvataggi di credenziali su file system in chiaro senza cifratura. 
- **Esempio**: L'uso della funzione `writeFileSync` in combinazione con i termini `token` o `secret` in una riga che non prevede funzioni crittografiche (es. `crypto` o `bcrypt`).
- **Dettaglio Tecnico**: Richiede che tre condizioni siano vere contemporaneamente nella stessa riga: 1) presenza di metodi di scrittura su file (`/writeFileSync\s*\(/`, `/writeFile\s*\(/`, ecc.), 2) indicatori di credenziali (`/\b(?:token|key|secret|password|auth|credential|apiKey)\b/i`), e 3) assenza totale di funzioni crittografiche (`/\b(?:encrypt|cipher|hash|crypto|bcrypt|scrypt)\b/i`).

### `containsInsecureCredentialPermissions`
- **Severity**: High
- **Descrizione**: Identifica permessi file molto permissivi e insicuri assegnati a file contenenti credenziali.
- **Esempio**: Un comando come `chmod 777` applicato a stringhe contenenti la parola `password` o `secret`.
- **Dettaglio Tecnico**: Ricerca specificamente comandi `chmod` permissivi per i gruppi e per gli altri (regex `/chmod\s+[0-9]*[4-7][4-7][4-7]/`) combinati nella stessa stringa con indicatori come `/(?:key|token|secret|password|credential)/i`.

**Esempio di ritrovamento:**
`C:\Users\francesco\Desktop\pipeline\analysisAllData\0_tool_mcp_watch\credential-leak\credential_leak_high.json`
```json
{
    "server_name": "dicom-mcp",
    "github_url": "https://github.com/sscotti/dicom-mcp",
    "language": "python",
    "id": "INSECURE_CREDENTIAL_PERMISSIONS",
    "category": "credential-leak",
    "description": "Credentials with world-readable permissions",
    "file": "CERTIFICATES.md",
    "line": 44,
    "evidence": "chmod 644 cert.pem cert-key-combined.pem",
    "source": "Trail of Bits research"
}
```

---

## 4. InputValidationScanner 
Ricerca vulnerabilità critiche dovute alla mancata convalida degli input dell'utente.

### `containsCommandInjection`
- **Severity**: Critical
- **Descrizione**: Rileva la possibilità per un input utente di essere eseguito come comando di sistema. 
- **Esempio**: L'utilizzo di `exec()` o `spawn()` dove vengono passati valori presi direttamente da `req`, `params` o `body`.
- **Dettaglio Tecnico**: La condizione si verifica se viene trovato un pattern di esecuzione pericoloso (come `/execSync?\s*\(/`, `/spawn\s*\(/`, `/system\s*\(/`, `/popen\s*\(/`) e contestualmente la riga include uno di questi specifici ingressi utente: "req.", "params", "query", "body", "input", "user", o "argv".

### `containsSSRF`
- **Severity**: High
- **Descrizione**: Trova vulnerabilità Server-Side Request Forgery, in cui il server fa richieste arbitrarie esterne dettate dall'utente. 
- **Esempio**: Funzioni come `fetch(req.query)` oppure `axios.get(input)`.
- **Dettaglio Tecnico**: Verifica un insieme di pattern di richieste di rete concatenati direttamente ad accessi input, ad esempio `/fetch\s*\(\s*(?:req\.|params\.|query\.|input\.)/` o `/axios\.get\s*\(\s*(?:req\.|params\.|query\.|input\.)/`.

### `containsPathTraversal`
- **Severity**: High
- **Descrizione**: Identifica vulnerabilità che permettono all'utente di accedere a directory non previste del file system. 
- **Esempio**: Codice che passa l'input a `readFile` combinato con notazioni parent relative come `../` o `..\`.
- **Dettaglio Tecnico**: Utilizza espressioni regolari per identificare funzioni di lettura unite a pattern di path traversal, come `/readFile\s*\([^)]*\.\./`, `/\.\.\/|\.\.\\/`, o `/path.*\.\./`.

---

## 5. ParameterInjectionScanner
Verifica iniezioni dannose tramite i parametri di una funzione o richieste.

### `containsMagicParameters`
- **Severity**: Critical
- **Descrizione**: Rileva l'uso di "parametri magici" in funzioni in grado di esfiltrare il contesto segreto dell'AI. 
- **Esempio**: Funzioni dichiarate con nomi di parametro tipo `system_prompt`, `conversation_history` o `tools_list`.
- **Dettaglio Tecnico**: Cerca definizioni di funzioni (`/def\s+\w+\s*\(|function\s+\w+\s*\(/i`) che includono esplicitamente nomi "magici" documentati come `\btools_?list\b`, `\btool_?call_?history\b`, `\bconversation_?history\b`, `\bchain_?of_?thought\b`, o `\bsystem_?prompt\b`.

### `containsUnusedSensitiveParameters`
- **Severity**: High
- **Descrizione**: Trova parametri nominati in modo "sensibile" che non vengono mai utilizzati nel corpo della funzione. 
- **Dettaglio Tecnico**: Estrae il nome della funzione e i suoi parametri tramite regex in vari linguaggi (TS/JS/Python). Se un parametro sensibile (es. `conversation_history`) viene rilevato, lo scanner cattura il corpo intero della funzione e lo ispeziona. Cerca l'effettivo utilizzo del parametro (escludendo la riga della firma stessa) tramite pattern come `\b${param}\b(?!\s*[,:])`, stringhe interpolate `\$\{${param}\}`, o accesso alle proprietà. Se non trova utilizzi reali, segnala il rischio.

### `containsDataExfiltration`
- **Severity**: Critical
- **Descrizione**: Cerca logiche che inviano specificamente parametri di contesto verso endpoint esterni. 
- **Esempio**: Pattern come `requests.post(url, data=conversation_history)`.
- **Dettaglio Tecnico**: Usa regex per trovare richieste di rete in uscita con payload sospetti, come `/requests\.(post|put|patch)\s*\([^)]*(?:conversation|history|prompt|context|tool)/i` o `/fetch\s*\([^)]*(?:conversation|history|prompt|context|tool)/i`.

---

## 6. PermissionScanner
Analizza i rischi legati ai controlli degli accessi e dei consensi.

### `containsConsentFatiguePatterns`
- **Severity**: Medium
- **Descrizione**: Rileva richieste di consenso ripetute ciclicamente all'utente. 
- **Esempio**: Logica con terminologie quali `approve loop` o `confirm repeatedly`.
- **Dettaglio Tecnico**: Esegue un check case-insensitive con pattern come `/(?:approve|consent|allow|permit).*(?:loop|repeat|again|multiple)/i` o `/confirm.*(?:many|several|repeatedly)/i`.

### `containsExcessivePermissions`
- **Severity**: High
- **Descrizione**: Identifica ruoli o richieste di privilegi eccessivi, minando il principio del minimo privilegio. 
- **Esempio**: Codice che assegna `root`, `admin` o `full access` a un ruolo (`role`) utente.
- **Dettaglio Tecnico**: Verifica se la stringa contiene parole chiave elevate ("admin", "root", "superuser", "full access", ecc.) E contemporaneamente parole di contesto di assegnazione ("user", "permission", "scope", "role", "access").

---

## 7. PromptInjectionScanner
Verifica la presenza di iniezioni fraudolente nei prompt di sistema.

### `containsSuspiciousPrompts`
- **Severity**: High
- **Descrizione**: Rileva tentativi di manipolazione o bypass delle istruzioni inseriti all'interno dei testi di descrizione dei tools. 
- **Esempio**: Una descrizione contenente frasi come `ignore previous instructions` o `[SYSTEM] override`.
- **Dettaglio Tecnico**: Scatta unicamente se la riga contiene la parola "description" in combinazione con regex aggressive, come `/ignore\s+(previous|above|all|prior)\s+(instructions?|commands?|prompts?)/i`, `/\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[JAILBREAK\]/i`, o `/act\s+as\s+(?:if|a|an)/i`.

### `containsRADEPatterns`
- **Severity**: High
- **Descrizione**: Individua minacce "Retrieval-Agent Deception" dove contenuti estrapolati istruiscono di nascosto l'agente. 
- **Esempio**: File con testo misto come `document instruction` o `retrieve bypass`.
- **Dettaglio Tecnico**: Cerca incroci specifici tra termini di fetching e comandi, tramite regex come `/retrieve.*(?:ignore|system|admin)/i` o `/document.*(?:instruction|command|system)/i`.

---

## 8. ProtocolViolationScanner
Analizza violazioni di sicurezza nei protocolli usati dall'MCP.

### `containsSessionIdInUrl`
- **Severity**: High
- **Descrizione**: Evidenzia perdite sensibili passando identificatori di sessione negli URL.
- **Esempio**: Codice che costruisce stringhe url contenenti `?sessionId=`.
- **Dettaglio Tecnico**: Abbina un identificatore (`/(?:sessionId|session_id|sid)=/`) con un chiaro segnale di creazione o uso di un URL ("GET", "url", "path", "route", o "endpoint").

**Esempio di ritrovamento:**
`C:\Users\francesco\Desktop\pipeline\analysisAllData\0_tool_mcp_watch\protocol-violation\protocol_violation_high.json`
```json
{
    "server_name": "tako-mcp",
    "github_url": "https://github.com/TakoData/tako-mcp",
    "language": "python",
    "id": "SESSION_ID_IN_URL",
    "category": "protocol-violation",
    "description": "Session ID in URL - exposes sensitive identifiers",
    "file": "tests/test_client.py",
    "line": 321,
    "evidence": "f\"{base_url}/messages/?session_id={fake_session_id}\",",
    "source": "VulnerableMCP database"
}
```

### `containsInsecureTransport`
- **Severity**: High
- **Descrizione**: Segnala l'utilizzo di protocolli HTTP non crittografati al posto di HTTPS. 
- **Esempio**: Presenza nel file di url a `http://api.production.domain.com`.
- **Dettaglio Tecnico**: Cerca "http://" ma ignora la riga se contiene domini sicuri o di test predefiniti ("localhost", "127.0.0.1", "example.com") o se marcata come stringa placeholder dalla funzione genitore `isExampleCredential()`.

---

## 9. ServerSpoofingScanner
Ricerca pattern in cui i server MCP provano a impersonare o dirottare servizi fidati.

### `containsSuspiciousServerNames`
- **Severity**: Medium
- **Descrizione**: Rileva server che si nominano deliberatamente come noti servizi online per trarre in inganno. 
- **Esempio**: Il nome del server (`name`) è configurato come `github` o `slack` pur non essendo testato localmente.
- **Dettaglio Tecnico**: Estrae il nome del server usando `/name.*["']([^"']+)["']/gi` nell'intero contenuto del file e controlla se corrisponde in parte a una lista di servizi noti (come "github", "aws", "slack"), escludendo preventivamente stringhe innocue che iniziano per "my-" o che includono "test" e "demo".

### `containsCrossServerShadowing`
- **Severity**: High
- **Descrizione**: Identifica codice finalizzato a intercettare di nascosto le richieste destinate verso altri server. 
- **Esempio**: Uso ricorrente di termini operativi legati all'intercettazione come `intercept server` o `proxy server`.
- **Dettaglio Tecnico**: Effettua match sull'intero file con regex mirate allo shadowing: `/intercept.*server/i`, `/override.*server/i`, `/proxy.*server/i`, `/hijack.*server/i`.

---

## 10. ToolMutationScanner
Analizza i pericoli legati alle modifiche dinamiche ("mutazioni") della lista dei tool dell'agente IA a runtime.

### `containsToolMutation`
- **Severity**: High
- **Descrizione**: Rileva manipolazioni in tempo reale dell'array dei tools, comportamento rischioso che apre agli attacchi "rug-pull". 
- **Esempio**: Uso di comandi in JavaScript/TypeScript come `tools.push(newTool)` o `tools.splice(...)`.
- **Dettaglio Tecnico**: Segnala quando nella stessa riga è presente il termine "tools" o "tool" insieme a un metodo di mutazione array ("push", "splice", "pop", "shift", "unshift" o assegnazione regex `/tools?\[.*\]\s*=/`), a condizione che non ci siano commenti ("//" o "*"), e le stringhe "test" e "example" non siano presenti.

### `containsToolNameCollision`
- **Severity**: Medium
- **Descrizione**: Individua rischi collegati alla collisione o sovrascrittura forzata di tool pre-esistenti a causa di nomi duplicati. 
- **Esempio**: Codice di avviso o operazione legata a logiche di `duplicate tool name`.
- **Dettaglio Tecnico**: Semplicemente accerta che la riga includa le parole "name", "tool", ed almeno una parola relativa a conflitti ("duplicate", "same", "collision", "conflict").

---

## 11. ToolPoisoningScanner
Identifica vulnerabilità che rendono tossici i tool mascherandoli sotto intenti legittimi.

### `containsHiddenInstructions`
- **Severity**: Critical
- **Descrizione**: Rileva istruzioni nascoste tra le definizioni o descrizioni dei tool per controllare e forzare il comportamento dell'AI. 
- **Esempio**: Testo nel parametro `description` in cui si legge `forget everything` o `act as if`.
- **Dettaglio Tecnico**: Richiede la presenza di "description" insieme a pattern di hijacking evidenti: `/ignore\s+(previous|all)\s+instructions/i`, `/\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]/i`, o `/forget\s+(everything|all)/i`.

### `containsDeceptiveToolNaming`
- **Severity**: High
- **Descrizione**: Identifica una mancata corrispondenza tra un nome rassicurante e una logica interna altamente pericolosa. 
- **Esempio**: Un tool rinominato `weather` (meteo) o `calculator` che include logica che contiene azioni come `delete`, `kill` o `exec`.
- **Dettaglio Tecnico**: Richiede la presenza di "name" accompagnato da un nome innocuo (`/calculator|math|time|weather|file.*read/i`), e contemporaneamente la presenza di verbi o metodi pericolosi (`/delete|remove|destroy|kill|hack|steal|exfiltrate/i` o `/exec|eval|system/i`).

---

## 12. ToxicFlowScanner
Verifica un potenziale "Toxic Agent Flow", misurando come i dati passano da sistemi esterni non affidabili ad aree privilegiate dell'ecosistema.

### `containsUntrustedDataProcessing`
- **Severity**: Medium
- **Descrizione**: Rileva l'elaborazione di dati ricevuti da fonti esterne prive di opportuna igiene e sanitizzazione. 
- **Esempio**: Estrapolazione di `response.json()` senza richiamare preventivamente alcuna funzione come `sanitize()`, `clean()` o `validate()`.
- **Dettaglio Tecnico**: Cerca una fonte non sicura (es. `/\.data\.|response\.|\.json\(\)|\.text\(\)/`, `/readFile|read.*content|fetch.*file/i`) ed emette il flag SOLO se non trova pattern noti di sicurezza come `/sanitize|escape|validate|filter|clean/i` o `/encode|decode|parse.*safe|safe.*parse/i`.

### `containsAutomaticPublishing`
- **Severity**: High
- **Descrizione**: Trova logica che pubblica istantaneamente dinamismi elaborati verso output pubblici o all'esterno (forte rischio di fuga dati). 
- **Esempio**: La combinazione in una riga di espressioni di pubblicazione come `publish` o `auto create` incatenata a interpolazioni stringhe dinamiche come `${input}`.
- **Dettaglio Tecnico**: Combina regex di pubblicazione (`/create(?!.*test)|auto.*create|generate.*content/i`, `/publish|send|post|upload|write.*file/i`) con indicatori di contenuto dinamico stringato (`/\$\{|template|interpolate|\+.*\+/, /\.data|response\.|content\.|input\./`).

### `analyzeGenericToxicChains`
- **Severity**: Critical
- **Descrizione**: Un'analisi più profonda dell'intero file che certifica la presenza di una catena intera (e grave) d'esfiltrazione. 
- **Esempio**: Rileva se all'interno dello stesso modulo vengono compiute queste azioni connesse: `fetch` (input esterno) -> elaborazione di logica admin (accesso privilegiato) -> e richiamo di `post`/`publish` (pubblicazione).
- **Dettaglio Tecnico**: A differenza degli altri, questo metodo non valuta la singola riga, ma scansiona tutto il file tracciando tre flag booleani: `hasExternalInput` (attivato da `/fetch|api|external|remote|input|request/i`), `hasPrivilegedAccess` (attivato da `/private|confidential|secret|internal|admin|privileged/i`), e `hasPublicOutput` (attivato da `/public|create|publish|send|post|share|broadcast/i`). Se tutt'e tre le regex trovano una corrispondenza nello stesso file, lo scanner segnala una vulnerabilità critica di catena.
ica di catena.