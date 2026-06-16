# MCP Shield - How It Works

**Mcp-shield** si concentra sull'analisi delle descrizioni (`description`) e degli schemi di input (`inputSchema`) dei tool esposti all'LLM.

---

## 1. `detectHiddenInstructions`
Questo scanner cerca direttive progettate per essere nascoste all'utente finale o istruzioni che cercano di forzare/ignorare il comportamento standard dell'AI.

- **Severity**: Medium (impostata di default per questo tipo di issue nello scanner principale).
- **Cosa fa**: Analizza la stringa di descrizione del tool cercando pattern regex legati a occultamento, tag XML sospetti o override di istruzioni.
- **Esempio**: Rileva frasi come `do not tell`, `user must not see`, `ignore previous instructions`, `never reveal`, oppure l'uso di tag come `<secret>...</secret>` o `<system>...</system>`.

---

## 2. `detectExfiltrationChannels`
Identifica la presenza di parametri sospetti nello schema di input del tool che potrebbero essere sfruttati dall'LLM per esfiltrare segretamente dati o contesto.

- **Severity**: Medium.
- **Cosa fa**: Analizza i nomi delle proprietà all'interno di `toolInputSchema.properties` e li confronta con una lista di parametri noti per essere usati come canali secondari di esfiltrazione.
- **Esempio**: Rileva parametri chiamati `note`, `feedback`, `metadata`, `debug`, `context` o `reasoning`.

---

## 3. `detectToolShadowing`
Si concentra sul rilevamento di descrizioni che cercano di alterare, sostituire o intercettare il comportamento di altri tool o dell'agente stesso.

- **Severity**: High (se rilevato, lo scanner innalza automaticamente la criticità a High).
- **Cosa fa**: Utilizza espressioni regolari per trovare intenti di override esplicito o hook di esecuzione pre/post utilizzo.
- **Esempio**: Rileva frasi all'interno della descrizione come `override the behavior of`, `instead of using`, `before using any tool`, `replace the function`, o `modify the agent`.

---

## 4. `detectSensitiveFileAccess`
Identifica tentativi dichiarati di accedere a file di sistema critici, credenziali o tentativi di path traversal.

- **Severity**: High (la presenza di questa vulnerabilità porta la criticità a High).
- **Cosa fa**: Cerca riferimenti espliciti a file chiave, directory di configurazione, terminologia di sicurezza o tentativi di navigazione tra le cartelle nella descrizione del tool.
- **Esempio**: Match su percorsi come `~/.ssh`, `.env`, `/etc/passwd`, file come `id_rsa`, o concetti legati a password, api key, e traversal come `../`.

---

## 5. `detectCrossOriginViolations`
Verifica se un tool tenta di manipolare o fare riferimento esplicito ad altri server MCP (cross-origin), violando l'isolamento dei server.

- **Severity**: Medium.
- **Cosa fa**: Confronta le parole usate nella descrizione del tool con i nomi degli altri server installati (presi dalla configurazione) o con una lista di server MCP popolari noti (come whatsapp, slack, github, gitlab, gdrive) escludendo il server stesso.
- **Esempio**: Se stai scansionando un server custom e la sua descrizione contiene la parola "slack" (che fa parte della lista dei server popolari) per impartire ordini su come l'LLM dovrebbe usare Slack, viene segnalato come violazione cross-origin.

---

## 6. `analyzeWithClaude` (Claude Analyzer)
Un modulo opzionale che esegue un'analisi semantica e contestuale avanzata sfruttando un LLM (Claude 3.7 Sonnet).

- **Severity**: Dinamica (LOW, MEDIUM, HIGH) in base all'output restituito dall'intelligenza artificiale.
- **Cosa fa**: Invia l'intera descrizione del tool alle API di Anthropic, chiedendo a Claude di comportarsi come un "esperto di sicurezza informatica" e di valutare 5 categorie specifiche: istruzioni nascoste, file sensibili, shadowing, esfiltrazione e override.
- **Esempio**: Se i controlli regex classici sollevano un flag (es. per istruzioni nascoste o shadowing), viene attivato Claude Analyzer che restituisce un'analisi YES/NO dettagliata e un livello di rischio complessivo contestualizzato al reale intento della frase.