# MCP Scan (Snyk / Invariant Labs) — Spiegazione dei grafici

**MCP Scan** (Snyk Agent Scan) e un client Python che avvia ogni server MCP, enumera i tool esposti e invia name, description e inputSchema al backend Snyk/Invariant Labs. Il backend esegue 3 analisi: (A) Prompt Injection Check — check statico per tag `<IMPORTANT>` e parole trigger + check LLM via GPT-4o-mini; (B) Untrusted Content Analysis — un LLM valuta se i tool possono processare contenuto controllato da un attaccante; (C) Tool Labeling — assegna score float per is_public_sink, destructive, untrusted_content, private_data.

Server analizzati: **10.710** su 60.205 (17.79%)
Tool totali enumerati: **132.009** (media 12.33 per server)
Vulnerabilita totali: **5.352** (media 0.5 per server)

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi dei 10.710 server che MCP Scan e riuscito ad avviare e di cui ha enumerato i tool.

**Interpretazione**: La copertura bassa (17.79%) e dovuta al fatto che il tool deve avviare il server, stabilire la connessione MCP e completare l'enumerazione dei tool — pipeline fragile che fallisce su server con dipendenze mancanti, configurazioni complesse o servizi esterni richiesti. Node.js (7.566) domina, seguito da Python (2.493).

---

## 02_severity.png — Distribuzione delle severity

**Cosa mostra**: Vulnerabilita per livello di severity.

- **Low (4.319, 80.7%)**: La grande maggioranza — include W001 (dangerous words: 2.051) e W016 (potential untrusted content: 2.268). I W001 sono parole trigger come "important", "critical", "override" trovate nelle descrizioni dei tool. I W016 sono valutazioni LLM a bassa confidenza
- **Medium (924, 17.3%)**: W015 (untrusted content) — l'LLM del backend ha determinato con confidenza media che il server puo processare contenuto da fonti esterne non fidate
- **Critical (109, 2.0%)**: E001 (prompt injection) — l'LLM ha identificato prompt injection nelle descrizioni dei tool. Questi sono i finding piu affidabili

**La piramide e corretta**: Molti low, pochi critical — distribuzione realistica per uno scanner di sicurezza.

---

## 03_server_vs_tool.png — Vulnerabilita server-level vs tool-level

**Cosa mostra**: Due torte affiancate che separano le vulnerabilita in due categorie strutturalmente diverse.

**Server-level (3.192 finding)**:
- **Potential Untrusted Content / W016 (71.05%)**: L'LLM valuta che il server POTREBBE processare contenuto esterno, ma con bassa confidenza. Esempio: un server che fa fetch di URL potrebbe ricevere contenuto malevolo
- **Untrusted Content / W015 (28.95%)**: Confidenza media. Esempio: mcp-devcontainers che esegue container da repository esterni

**Tool-level (2.160 finding)**:
- **Dangerous Words / W001 (94.95%)**: Parole trigger nelle descrizioni. Alto tasso di falsi positivi — "critical vulnerability" in una descrizione di security scanner non e prompt injection
- **Prompt Injection / E001 (5.05%)**: L'LLM ha confermato prompt injection nella descrizione del tool. Questi 109 finding sono i piu affidabili dell'intero dataset

**Perche la distinzione importa**: I W015/W016 sono rischi architetturali (il server nel suo complesso), mentre E001/W001 sono problemi specifici di un singolo tool.

---

## 04_trigger_words.png — Distribuzione delle parole trigger W001

**Cosa mostra**: Quali parole hanno generato i 2.051 warning W001 (dangerous words).

**Le parole e il loro contesto**:
- **important (643)**: La piu frequente. Spesso usata legittimamente: "Important: provide the full path". Falso positivo nella maggior parte dei casi
- **override (536)**: Usata in contesti di configurazione ("override default settings"). Puo indicare prompt injection ("override previous instructions") ma raramente lo e
- **ignore (482)**: Ambigua — "ignore empty results" e legittimo, "ignore previous instructions" e injection
- **critical (354)**: Spesso in contesti di sicurezza ("critical vulnerabilities"). Quasi sempre falso positivo
- **bypass (112)**: Piu sospetta — "bypass authentication" potrebbe essere injection. Confidenza media
- **urgent (45)**, **vital (34)**, **crucial (14)**: Parole di enfasi usate raramente in prompt injection reale

**Punto chiave per la tesi**: Il check statico basato su parole trigger ha un altissimo tasso di falsi positivi. Solo "bypass" e "ignore" hanno una probabilita ragionevole di indicare injection reale.

---

## 05_tools_safe_vulnerable.png — Tool sicuri vs vulnerabili

**Cosa mostra**: Dei 132.009 tool enumerati, quanti sono stati classificati come sicuri vs vulnerabili.

- **Safe (129.889, 98.39%)**: Nessun finding di sicurezza
- **Vulnerable (2.120, 1.61%)**: Almeno un finding (W001, E001, o label sospetto)

**L'1.61% e realistico**: E coerente con l'aspettativa che la grande maggioranza dei tool MCP sia benigna. Questo numero e il piu credibile tra tutti i tool di analisi.

---

## 06_issue_codes.png — Distribuzione dei codici di finding

**Cosa mostra**: Conteggio per codice di finding specifico.

- **W016 (2.268)**: Potential untrusted content (server-level, low severity)
- **W001 (2.051)**: Dangerous words (tool-level, low severity) — parole trigger nelle descrizioni
- **W015 (924)**: Untrusted content confermato (server-level, medium severity)
- **E001 (109)**: Prompt injection confermata via LLM (tool-level, critical severity)

**La gerarchia e chiara**: W016 > W001 > W015 > E001, con severity crescente e volume decrescente. Questo indica che il sistema di classificazione di Snyk e ben calibrato — piu un finding e grave, piu e raro.
