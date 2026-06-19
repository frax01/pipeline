# MCP Security Scanner: How It Works

Questo scanner utilizza un approccio modulare diviso in due macro-categorie: **controlli agnostici** (indipendenti dal trasporto, eseguiti direttamente sulle funzionalità del server) e **controlli HTTP-specifici**.

> [!NOTE]
> In questo tool, la **Severity** (Critical, High, Medium, Low, Info) viene iniettata dinamicamente tramite oggetti di configurazione (*SpecCheck*), ma ogni controllo è mappato su una sigla specifica che ne indica la categoria:
> - **A**: Authentication
> - **X**: Exploit / Execution
> - **R**: Resources
> - **P**: Prompt / Injection
> - **T**: Transport / Network

---

## 1. Controlli Agnostici (Logica di Sicurezza)

Questi controlli operano sulla logica applicativa del server, indipendentemente dal protocollo di trasporto utilizzato.

### Unauthenticated Access `[A-01]`
* **Cos'è**: Verifica se i tool del server sono esposti pubblicamente senza richiedere un'autenticazione valida.
* **Esempio di Match**: Il server restituisce un array pieno di tool (`len(tools) > 0`) anche se lo scanner non ha inviato alcun token/credenziale.
* **Dettaglio Tecnico**: La funzione riceve la lista dei tool estratti a monte. Il controllo passa se la lista è vuota (`passed = not bool(tools)`). Nell'implementazione HTTP, lo scanner invia una richiesta POST di tipo JSON-RPC method: `"tools/list"` senza header di autenticazione, e si aspetta di ricevere uno status HTTP 401 o 403.

### Dangerous Capabilities `[X-01]`
* **Cos'è**: Rileva tool che possiedono funzionalità altamente pericolose ma che mancano di vincoli di validazione nel loro schema JSON, permettendo all'LLM di abusarne liberamente.
* **Esempio di Match**: Un tool chiamato `exec`, `write_file`, o `chmod` in cui lo schema di input accetta stringhe generiche senza regex o whitelist.
* **Dettaglio Tecnico**: Lo scanner itera sulle proprietà di `inputSchema.properties` di ogni tool. Cerca parole chiave pericolose nel nome o descrizione (es. `exec`, `shell`, `delete`, `eval`, `admin`). Se ne trova una, analizza le proprietà JSON Schema cercando chiavi di vincolo come `"enum"`, `"pattern"`, `"minimum"`, `"maximum"`, `"minLength"`, `"maxLength"`. Se non ci sono vincoli (`not has_constraints`), il tool viene contrassegnato come rischioso.

### Prompt Injection Heuristics `[P-02]`
* **Cos'è**: Cerca tramite euristiche testuali dei tentativi di prompt injection direttamente nelle descrizioni dei tool esposti.
* **Esempio di Match**: Descrizioni che contengono frasi manipolatorie come *"ignore any safety rules"*, *"override other tools"*, o *"hidden instruction"*.
* **Dettaglio Tecnico**: Trasforma il campo `description` di ciascun tool in minuscolo (`.lower()`) e controlla la presenza come sottostringa di una hardcoded blacklist di frasi malevole.

### Tool Stability (Rug-Pull Protection) `[X-03]`
* **Cos'è**: Protegge contro gli attacchi "rug-pull". Verifica che le firme e le descrizioni dei tool non mutino improvvisamente e dinamicamente nel tempo.
* **Esempio di Match**: Lo scanner chiede la lista dei tool due volte; se tra la prima e la seconda volta un tool cambia descrizione per diventare malevolo, la scansione fallisce.
* **Dettaglio Tecnico**: La funzione riceve due liste di tool (`tools_first` e `tools_second`) ottenute chiamando `tools/list` a distanza di tempo. Converte gli array in un Set in Python contenente tuple di `(name, description)`. Applica poi l'operatore di differenza simmetrica `set1.symmetric_difference(set2)`: se emergono elementi, significa che l'array è stato mutato a runtime.

### Resource Traversal & Access Control `[R-01 / R-02]`
* **Cos'è**: Effettua test attivi di sicurezza provando a far leggere al server file di sistema fuori dal suo scope.
* **Esempio di Match**: Il server accetta e restituisce il contenuto alla richiesta di lettura della risorsa `file:///../../etc/hosts` (**R-01**) o `file:///etc/passwd` (**R-02**).
* **Dettaglio Tecnico**: Sfrutta la dependency injection del trasporto inviando una vera chiamata JSON-RPC con metodo `resources/read` e passando i parametri `{"uri": "file:///../../etc/hosts"}` o `{"uri": "file:///etc/passwd"}`. Se l'oggetto di risposta JSON contiene un campo `result` valido (di tipo dict), il test fallisce in quanto significa che il server non ha bloccato il traversal o l'accesso privilegiato.

### Sensitive Resource Exposure `[R-03]`
* **Cos'è**: Cerca esposizioni di segreti nelle risorse dell'agente. Controlla sia i nomi/URI delle risorse, sia il contenuto stesso leggendole.
* **Esempio di Match**: Una risorsa chiamata "credentials" il cui contenuto mostra termini come `sk-`, `api key` o stringhe di connessione a DB `postgresql://`.
* **Dettaglio Tecnico**: In una prima fase ricerca parole sospette (es. *credential*, *token*) nei parametri `name` e `uri` usando `any(keyword in name or keyword in uri)`. Quando individua un target potenziale, lancia proattivamente una chiamata RPC `resources/read` usando il suo URI, formatta la risposta grezza in stringa JSON (`json.dumps(resp).lower()`) e fa uno scan testuale su di essa per le firme di credenziali esposte.

### Injection Fuzzing (RCE) `[X-02]`
* **Cos'è**: Esegue un vero e proprio fuzzing. Identifica tool che accettano stringhe e inietta payload dannosi, verificando se il server esegue comandi arbitrari o svela l'output.
* **Esempio di Match**: Invia `$(whoami)` o `../../../../etc/passwd` come argomento di un tool. Se la risposta del server contiene `root:x:` o `uid=`, il test fallisce perché c'è una RCE (*Remote Code Execution*) in corso.
* **Dettaglio Tecnico**: Per ogni tool, analizza l'albero delle proprietà `inputSchema.properties` per trovare il primo parametro di tipo `"string"`. Trovato il nome del parametro, invia chiamate RPC `tools/call` con payload del tipo `{"name": nome_tool, "arguments": {str_param: payload}}`. Subito dopo, fa il parsing stringa della risposta e cerca evidenze di compromissione (`uid=`, `linux`, `root:x:`, ecc.).

### Indirect Prompt Injection `[P-03]`
* **Cos'è**: Testa flussi di Indirect Prompt Injection. Cerca risorse esterne (HTTP/HTTPS) e controlla se i tool ne eseguono ciecamente le direttive malevole.
* **Esempio di Match**: Una risorsa `external://...` contiene *"exfiltrate"*, lo scanner chiama un tool di riassunto su quella risorsa, e la risposta svela la vulnerabilità ripetendo la frase o trapelando segreti.
* **Dettaglio Tecnico**: Trova le risorse (`resources/list`) con prefisso URI `external://`, `http://` o `https://`. Legge la risorsa per accertarsi che contenga del payload da injection. Poi cerca un tool di tipo "summarize". Se lo trova, chiama attivamente `tools/call` passando l'URI della risorsa incriminata e ispeziona l'output prodotto per accertarsi che l'AI non sia stata alterata ("exploited").

### Remote Access Control Exposure `[RC-01]`
* **Cos'è**: Ricerca e testa tool che potrebbero aprire porte locali o abilitare accessi remoti inavvertitamente.
* **Esempio di Match**: Identifica un tool chiamato `remote_access` o `bind`, prova a chiamarlo passando `port: 8080` e fallisce se il server risponde *"listening"* o *"server started"*.
* **Dettaglio Tecnico**: Trova i tool tramite keyword (remote, bind, expose). Poi lancia una RPC `tools/call` con l'argomento predefinito `{"port": 8080}`. Se la chiamata va a buon fine, cerca stringhe di successo nel dump JSON (come `remote_access_enabled:true` o `listening`).

---

## 2. Controlli HTTP e Protocollo (Network Layer)

Questi test sono eseguiti unicamente sulle connessioni **HTTP** e **SSE**.

### TLS Enforcement `[T-02]`
* **Cos'è/Match**: Verifica semplicemente che il server venga contattato in `https://` invece che in testo in chiaro.
* **Dettaglio Tecnico**: Analizza l'endpoint URL passato allo scanner usando il metodo Python `base_url.lower().startswith("https://")`.

### Origin Validation (DNS-Rebind) `[T-01]`
* **Cos'è/Match**: Tenta di effettuare una connessione all'endpoint falsificando l'header HTTP. Se il server lo accetta, è vulnerabile agli attacchi di dirottamento.
* **Dettaglio Tecnico**: Lo scanner effettua una richiesta forzando un header malevolo `{"Origin": "http://evil.tld"}`. Se la risposta restituisce uno `status_code < 400`, significa che il server non implementa policy CORS/Origin restrittive.

### Session Tampering `[T-03]`
* **Cos'è/Match**: Verifica l'isolamento delle sessioni modificando arbitrariamente l'header e facendo richieste; un server sicuro deve rigettare la richiesta.
* **Dettaglio Tecnico**: Prende una sessione legittima e esegue una richiesta `POST` sovrascrivendo l'header `Mcp-Session-Id` con il valore `"tampered-session"`. Il test fallisce se lo status HTTP non è un codice d'errore (401, 403, 400).

### Prompt Argument Validation `[P-01]`
* **Cos'è/Match**: Prova a rompere l'API dei "Prompt" omettendo parametri obbligatori o inviando tipi di dato errati.
* **Dettaglio Tecnico**: Lancia una chiamata RPC `prompts/get` con payload `"arguments": {}` (vuoto) e verifica che ritorni un errore. Successivamente muta il tipo delle variabili (es. passa un intero a una stringa) per testare l'integrità del type checking.

### Template Fuzzing `[R-04]`
* **Cos'è/Match**: Se ci sono URI Template, invia delle probe di manipolazione per vedere se forzando il template vengono svelati contenuti ad accesso limitato.
* **Dettaglio Tecnico**: Esegue lo slicing dei `uriTemplate` iniettando parametri non autorizzati (es. `notes://admin`). Se ottiene una risposta valida dal server (es. presenza di testo *"Notes for"*), il template viene riportato come vulnerabile.
à il template come vulnerabile.