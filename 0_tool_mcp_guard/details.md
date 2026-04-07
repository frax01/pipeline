# 1 (le prime 4 vulnerabilità)

{
    "total": 4,
    "vulnerabilities": [
        {
            "server_url": "https://github.com/0xshariq/github-mcp-server",
            "server_name": "github-mcp-server",
            "language": "nodejs",
            "severity": "critical",
            "file": "dist/index.js",
            "description": "Security vulnerability detected during runtime analysis. Method tested: tools/call. Issues found: Path traversal payload returned sensitive file content or path info",
            "payload": "{'jsonrpc': '2.0', 'id': 40, 'method': 'tools/call', 'params': {'name': 'git_remove', 'arguments': {'file': '....//....//etc/shadow'}}}",
            "response": "{'result': {'content': [{'type': 'text', 'text': '{\"content\":[{\"type\":\"text\",\"text\":\"âœ… Successfully removed file from staging area: ....//....//etc/shadow\\\\nFile unstaged successfully.\"}],\"isError\":false,\"metadata\":{\"operation\":\"git-remove\",\"duration\":281,\"timestamp\":\"2026-04-07T19:57:22.537Z\",\"workingDirectory\":\"C:\\\\\\\\Users\\\\\\\\francesco\\\\\\\\Desktop\\\\\\\\pipeline\\\\\\\\github-mcp-server\"}}'}]}, 'jsonrpc': '2.0', 'id': 40}",
            "remediation": "Implement proper input validation and sanitization for file paths. Use allowlists for permitted paths."
        },
        {
            "server_url": "https://github.com/0xshariq/github-mcp-server",
            "server_name": "github-mcp-server",
            "language": "nodejs",
            "severity": "critical",
            "file": "dist/index.js",
            "description": "Security vulnerability detected during runtime analysis. Method tested: tools/call. Issues found: Path traversal payload returned sensitive file content or path info",
            "payload": "{'jsonrpc': '2.0', 'id': 43, 'method': 'tools/call', 'params': {'name': 'git_remove', 'arguments': {'file': 'whoami; cat /etc/passwd'}}}",
            "response": "{'result': {'content': [{'type': 'text', 'text': '{\"content\":[{\"type\":\"text\",\"text\":\"âœ… Successfully removed file from staging area: whoami; cat /etc/passwd\\\\nFile unstaged successfully.\"}],\"isError\":false,\"metadata\":{\"operation\":\"git-remove\",\"duration\":252,\"timestamp\":\"2026-04-07T19:57:23.499Z\",\"workingDirectory\":\"C:\\\\\\\\Users\\\\\\\\francesco\\\\\\\\Desktop\\\\\\\\pipeline\\\\\\\\github-mcp-server\"}}'}]}, 'jsonrpc': '2.0', 'id': 43}",
            "remediation": "Implement proper input validation and sanitization for file paths. Use allowlists for permitted paths."
        },
        {
            "server_url": "https://github.com/0xshariq/github-mcp-server",
            "server_name": "github-mcp-server",
            "language": "nodejs",
            "severity": "critical",
            "file": "dist/index.js",
            "description": "Security vulnerability detected during runtime analysis. Method tested: tools/call. Issues found: Path traversal payload returned sensitive file content or path info",
            "payload": "{'jsonrpc': '2.0', 'id': 45, 'method': 'tools/call', 'params': {'name': 'git_remove', 'arguments': {'file': '`cat /etc/passwd`'}}}",
            "response": "{'result': {'content': [{'type': 'text', 'text': '{\"content\":[{\"type\":\"text\",\"text\":\"âœ… Successfully removed file from staging area: `cat /etc/passwd`\\\\nFile unstaged successfully.\"}],\"isError\":false,\"metadata\":{\"operation\":\"git-remove\",\"duration\":355,\"timestamp\":\"2026-04-07T19:57:24.462Z\",\"workingDirectory\":\"C:\\\\\\\\Users\\\\\\\\francesco\\\\\\\\Desktop\\\\\\\\pipeline\\\\\\\\github-mcp-server\"}}'}]}, 'jsonrpc': '2.0', 'id': 45}",
            "remediation": "Implement proper input validation and sanitization for file paths. Use allowlists for permitted paths."
        },
        {
            "server_url": "https://github.com/0xshariq/github-mcp-server",
            "server_name": "github-mcp-server",
            "language": "nodejs",
            "severity": "critical",
            "file": "dist/index.js",
            "description": "Security vulnerability detected during runtime analysis. Method tested: tools/call. Issues found: Path traversal payload returned sensitive file content or path info",
            "payload": "{'jsonrpc': '2.0', 'id': 56, 'method': 'tools/call', 'params': {'name': 'git_remove', 'arguments': {'file': 'file:///etc/passwd'}}}",
            "response": "{'result': {'content': [{'type': 'text', 'text': '{\"content\":[{\"type\":\"text\",\"text\":\"âœ… Successfully removed file from staging area: file:///etc/passwd\\\\nFile unstaged successfully.\"}],\"isError\":false,\"metadata\":{\"operation\":\"git-remove\",\"duration\":192,\"timestamp\":\"2026-04-07T19:57:27.401Z\",\"workingDirectory\":\"C:\\\\\\\\Users\\\\\\\\francesco\\\\\\\\Desktop\\\\\\\\pipeline\\\\\\\\github-mcp-server\"}}'}]}, 'jsonrpc': '2.0', 'id': 56}",
            "remediation": "Implement proper input validation and sanitization for file paths. Use allowlists for permitted paths."
        }
    ]
}

## Le 4 vulnerabilità trovate su `git_remove`

Tutte e 4 riguardano lo stesso tool (`git_remove`) e lo stesso problema di fondo: **il server non valida l'input** prima di passarlo al comando `git reset HEAD "<input>"`.

---

### Cosa fa `git_remove` normalmente

Il tool dovrebbe rimuovere un file dalla staging area di git. L'utente passa un nome file, e il server esegue:
```bash
git reset HEAD "file.txt"
```

### Cosa succede con i payload malevoli

Il server risponde `"Successfully removed file from staging area"` per **tutti** i payload, senza controllare se il path è valido o pericoloso:

| # | Payload | Tipo di attacco | Cosa significa |
|---|---------|----------------|----------------|
| 1 | `....//....//etc/shadow` | **Path traversal** | Tenta di raggiungere `/etc/shadow` (file con hash delle password Linux) uscendo dalla directory del repo |
| 2 | `whoami; cat /etc/passwd` | **Command injection** | Il `;` tenta di concatenare un secondo comando shell per leggere `/etc/passwd` |
| 3 | `` `cat /etc/passwd` `` | **Command injection (backtick)** | I backtick tentano una command substitution — eseguire `cat /etc/passwd` e usare l'output come argomento |
| 4 | `file:///etc/passwd` | **Path traversal (URI scheme)** | Usa lo schema `file://` per tentare l'accesso diretto a un file di sistema |

### Perché sono veri positivi

In questo caso specifico, `git reset HEAD` non è pericoloso di per sé — non legge né espone il contenuto dei file. Quindi l'**impatto reale è basso**. Però il fatto che il server:

1. **Non valida l'input** — accetta qualsiasi stringa senza sanitizzazione
2. **Non limita i path** — non verifica che il file sia dentro il repository
3. **Risponde con successo** — non segnala errore per path palesemente malevoli

...è un **difetto di design** che indica che probabilmente anche gli **altri 34 tool** del server hanno lo stesso problema. Se un tool diverso (es. `git_clone`, `git_checkout`) avesse lo stesso difetto, l'impatto sarebbe molto più grave — ad esempio un `git clone` con un URL malevolo potrebbe esfiltrare dati o eseguire codice.

### In sintesi

La vulnerabilità reale non è tanto "git_remove fa cose pericolose" ma piuttosto: **questo server MCP non ha nessun layer di input validation**. È un pattern che si ripete su tutti i tool — `git_remove` è semplicemente quello dove il server non ritorna errore, rendendo la vulnerabilità rilevabile.

Inoltre, guardando il codice che abbiamo appena modificato, la detection funziona così:

### Step 1: Il fuzzer invia i payload

`_perform_live_fuzzing` scopre i 35 tool del server tramite `tools/list`, poi genera payload mirati per ogni parametro di tipo stringa. Per il tool `git_remove` che ha un parametro `file`, genera varianti con:
- Path traversal: `../../../etc/passwd`, `....//....//etc/shadow`, `/etc/passwd`, `file:///etc/passwd`
- Command injection: `whoami; cat /etc/passwd`, `` `cat /etc/passwd` ``

### Step 2: Il server risponde

Per ognuno dei 654 payload, il fuzzer legge la risposta JSON-RPC. Per `git_remove`:

- Con `../../../etc/passwd` → `"isError": true`, `"is outside repository"` → **errore, git ha bloccato**
- Con `....//....//etc/shadow` → `"isError": false`, `"Successfully removed"` → **successo, git non ha bloccato**

### Step 3: `_analyze_real_response` decide

Questo è il codice chiave (dopo il nostro fix):

```
1. Parsa la risposta e controlla isError
2. Se isError è true  → server_reported_error = True → SKIP (non è una vuln)
3. Se isError è false → controlla gli indicator nel testo della risposta
```

Gli indicator che hanno matchato per le 4 finding:

| Payload | Indicator matchato | Lista di detection |
|---------|-------------------|-------------------|
| `....//....//etc/shadow` | `/etc/shadow` | `path_traversal_indicators` |
| `whoami; cat /etc/passwd` | `/etc/passwd` | `path_traversal_indicators` |
| `` `cat /etc/passwd` `` | `/etc/passwd` | `path_traversal_indicators` |
| `file:///etc/passwd` | `/etc/passwd` | `path_traversal_indicators` |

La logica è: se il server risponde **con successo** (non errore) e nella risposta compaiono path di file sensibili, allora il payload è passato — il server l'ha processato senza rifiutarlo.

### Perché le altre ~27 finding simili sono state filtrate

Stesso payload (es. `../../../etc/passwd`) mandato a `git_add_all`, `git_add`, `git_status`, `git_remove_all` → il server risponde con `"isError": true` → il nostro check su `server_reported_error` li scarta. La stringa `/etc/passwd` appare nella risposta solo perché viene riecheggiata nel campo `workingDirectory` del messaggio di errore, non perché il file è stato effettivamente acceduto.

