# 🛡️ MCP Guard: How It Works

Questo strumento adotta un approccio universale (**"UniversalMCPScanner"**) per analizzare la sicurezza dei server MCP. Supporta **Python**, **Node.js**, **Go** e sistemi basati su **Docker**. A differenza dei tool precedenti, combina l'analisi del codice statico con il fuzzing dinamico attivo, avviando il server in locale e bombardandolo di richieste.

Ecco la spiegazione dettagliata delle fasi di scansione e delle funzioni rilevate in `mcp_scanner.py`, senza alcuna sintesi del contenuto originale.

---

## 🔍 1. Static Analysis Engine (Analisi Statica del Codice)
Questa componente ricerca vulnerabilità ispezionando i file sorgenti del repository scaricato senza eseguirli.

### 🧩 Pattern Based Detection `[Severity: High - Medium]`
* **Cos'è**: Ricerca configurazioni insicure e segreti hardcodati tramite l'analisi di pattern (espressioni regolari) all'interno dei file del server MCP.
* **Esempio di Match**: Rileva stringhe come chiavi API scritte in chiaro (es. chiavi di sessione) o impostazioni di default insicure esposte nel codice.
* **Dettaglio Tecnico**: Lo scanner legge i file di testo riga per riga, applicando regole di pattern-matching (sfruttando il modulo nativo `re`) su una libreria di regex note. Quando trova un match, solleva una vulnerabilità statica etichettata con lo scoring CVSS/AIVSS.

### 📦 Dependency Scanning `[Severity: Critical - Info]`
* **Cos'è**: Analizza i file di manifesto per identificare pacchetti o librerie obsolete note per avere vulnerabilità pubbliche (CVE).
* **Esempio di Match**: Trova un `requirements.txt` o un `package.json` che richiede una versione di un pacchetto obsoleta e soggetta ad attacchi noti.
* **Dettaglio Tecnico**: Lo scanner fa il parsing dei file (utilizzando `yaml`, `tomllib` o `json`) estraendo i nomi e le versioni delle dipendenze. Questi vengono poi confrontati con un database di vulnerabilità note per associarne la gravità corrispondente.

---

## ⚡ 2. Dynamic Analysis & Intelligent Fuzzing (Fuzzing Dinamico)
Questa è la parte più avanzata di **mcp-guard**. Avvia il server live e inietta payload per osservarne il comportamento, eventuali bypass di sicurezza o crash.

### 💣 Test Dynamic Fuzzing `[Severity: Critical]`
* **Cos'è**: Il core del fuzzing dinamico. Lancia il server MCP in un ambiente isolato e prova a comprometterlo inviando input malformati o estremi verso i suoi tool.
* **Esempio di Match**: Il test cattura un crash (es. un *Denial of Service*) o un `"BrokenPipeError"` quando il server MCP riceve un payload inaspettato e si chiude improvvisamente.
* **Dettaglio Tecnico**: Utilizza il modulo `subprocess` per avviare il server. Implementa un'architettura concorrente (tramite `threading`, `queue` e `asyncio`) per inviare ripetutamente stringhe anomale, sia tramite lo stream standard (stdio) che via rete (websockets). Se il processo figlio muore restituendo errori di I/O o pipe rotte, lo scanner cattura il segnale (es. impostando `signal.SIG_IGN` su `SIGPIPE` su sistemi Linux per non morire a sua volta) e scrive un log diagnostico nel file `mcp_guard_crash.log`.

### 🛡️ Check Protocol Validation `[Severity: Critical - Medium]`
* **Cos'è**: Interroga il server live per verificare se convalida rigorosamente gli argomenti secondo il protocollo MCP e se previene vulnerabilità strutturali (come *Command Injection* o *Path Traversal*).
* **Esempio di Match**: Prova a effettuare un *"Path Traversal"* inserendo percorsi di sistema. Se il server accetta il parametro alterato e restituisce l'output al posto di un errore di validazione, il test fallisce.
* **Dettaglio Tecnico**: Sfrutta la libreria HTTP `requests` o l'interfaccia `stdio` per lanciare chiamate RPC reali verso il server (es. invocando i tool listati). Valuta quindi il pacchetto JSON di risposta per determinare se il server è riuscito a mitigare dinamicamente l'attacco.

---

## 🏗️ 3. Gestione e Isolamento (Safety e Sandboxing)
Non sono veri e propri exploit test, ma meccanismi di sicurezza fondamentali dello scanner stesso durante l'operatività.

### 📁 Repository Handler `[Severity: Info]`
* **Cos'è**: Scarica e processa il server bersaglio in un ambiente sandbox sicuro prima di testarlo.
* **Dettaglio Tecnico**: Lo scanner effettua download HTTPS con protezione sui timeout. Appoggia l'analisi in cartelle effimere gestite dai moduli `tempfile` e `shutil` per pulire i residui al termine. Inoltre, applica limiti di risorse (CPU e RAM) per impedire che il server sotto test blocchi la macchina di host a causa di cicli infiniti.