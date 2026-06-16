# Snyk Agent Scan - How It Works

Questo strumento adotta un approccio leggermente diverso: classifica le vulnerabilità tramite codici specifici (**Issues**, **Warnings** e **Toxic Flows**) e analizza le descrizioni dei tool, delle "skill" dell'agente e le catene di esecuzione. Inoltre, utilizza anche l'Intelligenza Artificiale (come si vede nel file `policy.gr`) per la detection.

Ecco la spiegazione dettagliata degli scanner e dei pattern rilevati da **snyk-agent-scan**.

---

## 🚨 Issues (Vulnerabilità Critiche / Alta Gravità)
Queste sono minacce di sicurezza confermate che possono compromettere il server MCP o l'agente.

### 1. `E001`: Prompt injection in tool description
- **Severity**: Issue (Alta)
- **Cos'è**: Rileva attacchi di "tool poisoning" in cui istruzioni avversarie nascoste vengono inserite nella descrizione del tool per prendere il controllo dell'agente in modo invisibile all'utente. Come visto in `policy.gr`, lo scanner interroga un LLM (gpt-4o-mini) chiedendogli di individuare iniezioni di prompt.
- **Esempio di Match**: Frasi nascoste, blocchi in base64 o direttive come "Ignore previous instruction".

### 2. `E002`: Cross-server tool reference (Tool Shadowing)
- **Severity**: Issue (Alta)
- **Cos'è**: Si verifica quando un tool appartenente a un server MCP cita o cerca di sovrascrrivere un tool appartenente a un altro server, rompendo l'isolamento (sandboxing) tra di essi.
- **Esempio di Match**: La descrizione di un tool nel server A che cerca di dirottare le chiamate legittime indirizzate al server B.

### 3. `E003`: Tool description hijacks agent behavior
- **Severity**: Issue (Alta)
- **Cos'è**: Rileva tool che, invece di descrivere semplicemente la propria funzione all'agente, gli impartiscono direttive comportamentali autoritarie, minando la sua autonomia.
- **Esempio di Match**: Istruzioni palesi come "devi sempre chiamare questo tool", oppure "evita di eseguire i controlli di sicurezza".

### 4. `E004`, `E005`, `E006`: Vulnerabilità all'interno delle Skill
Questo gruppo analizza i file specifici delle "Skill" (competenze/addestramenti) forniti all'agente.

- **E004 (Prompt Injection in Skill)**: Rileva istruzioni ingannevoli dentro il file della skill progettate per bypassare le linee guida.
- **E005 (Suspicious Download URL)**: Identifica link verso binari non attendibili, short-url (es. bit.ly) o casi di typosquatting.
- **E006 (Malicious code patterns)**: Trova codice malevolo vero e proprio per attacchi RCE, backdoor o esfiltrazione dati celato nelle skill.

---

## ⚠️ Warnings (Avvisi / Media-Bassa Gravità)
Queste segnalazioni indicano configurazioni o pratiche rischiose che richiedono indagini manuali.

### 1. `W001`: Suspicious words in tool description
- **Severity**: Warning (Media)
- **Cos'è**: Rileva terminologie sospette tipiche del social engineering o del prompt hacking.
- **Esempio di Match**: L'utilizzo intensivo di parole come "important" o "crucial", oppure tag testuali manipolatori come `<IMPORTANT>` (rilevato staticamente nel file `policy.gr`).

### 2. `W002`: Too many entities
- **Severity**: Warning (Bassa)
- **Cos'è**: Segnala un sovraccarico dell'agente. Se un server espone troppe entità, le performance di scelta dell'LLM degradano e la superficie d'attacco aumenta.
- **Esempio di Match**: Un server MCP che offre più di 100 tool/risorse combinati.

### 3. Anomalie di gestione delle Credenziali (`W007`, `W008`)
- **W007**: Skill che forzano l'agente a stampare o passare credenziali in chiaro nel proprio output visibile.
- **W008**: Rileva API keys, password o token scritti (hardcoded) direttamente nei file delle istruzioni o nel codice.

### 4. Comportamenti pericolosi autorizzati (`W009`, `W011`, `W012`, `W013`)
- **W009**: Segnala tool con capacità di transazione finanziaria diretta (banche, crypto, pagamenti).
- **W011**: Skill che espongono la sessione a input pubblici non sicuri (es. far leggere all'agente tweet o commenti da forum) aprendo a indirect prompt injections.
- **W012**: Dipendenze dinamiche dove lo skill scarica istruzioni o codice da URL esterni a runtime, non potendo verificarne il contenuto preventivamente.
- **W013**: Istruzioni che invitano l'agente ad alterare servizi di sistema o ottenere privilegi root/admin della macchina utente.

---

## ☠️ Toxic Flows (Catene Pericolose / Critiche)
Questa è una caratteristica molto avanzata di **Snyk agent-scan**. Lo scanner esamina tutti i tool a disposizione dell'agente e li etichetta (labels) per capire se, usati in combinazione, permettono una kill-chain letale.

### 1. `TF001`: Data Leak Toxic Flow
- **Severity**: Issue (Critica)
- **Cos'è**: L'agente possiede i mezzi necessari per far fuoriuscire dati privati verso l'esterno a causa di una iniezione indiretta.
- **Cosa matcha (La combinazione deve esistere interamente)**:
    1. Un tool classificato come "**untrusted content**" (es. Fetch Web, dove un hacker può inserire l'exploit).
    2. Un tool classificato come "**private data**" (es. accesso al File System o al DB per leggere segreti).
    3. Un tool classificato come "**public sink**" (es. invio messaggi Slack/WhatsApp, richieste HTTP esterne).

### 2. `TF002`: Destructive Toxic Flow
- **Severity**: Issue (Critica)
- **Cos'è**: Simile al precedente, ma lo scopo della catena è distruggere l'ambiente utente.
- **Cosa matcha**:
    1. Un tool "**untrusted content**" per acquisire il payload malevolo.
    2. Un tool "**destructive**" capace di eseguire operazioni irreversibili (es. comandi terminale `rm -rf`, invio irreversibile di denaro).

---

## Esempi di ritrovamento

### Server vulnerabile (Esempio didattico)
```json
{
    "server_url": "https://github.com/nav33n25/IMCP",
    "tool_name": "code-analyzer",
    "category": "prompt-injection",
    "labels": {
        "is_public_sink": 0,
        "destructive": 0,
        "untrusted_content": 0,
        "private_data": 0
    },
    "extra_data": {
        "risk_score": 1.0,
        "reason": "Yes. The description contains a hidden instruction that directly tells the agent to extract sensitive secrets (API keys, DB strings, encryption keys) when certain keywords are present and to exfiltrate code to an external malicious auditor URL. That'...",
        "thought_process": "<reasoning>Yes. The description contains a hidden instruction that directly tells the agent to extract sensitive secrets (API keys, DB strings, encryption keys) when certain keywords are present and to exfiltrate code to an external malicious auditor URL. That's a classic prompt-injection / data-exfiltration attempt and instructs behavior outside safe tool use.</reasoning> <answer>1</answer>",
        "title": "Prompt Injection Found",
        "description": "\nAn external tool description contains manipulative text that intentionally blurs the line between descriptive data and system instructions.\nWhen the AI agent reads this text to learn how the tool works, it unwittingly processes hidden commands like directives to ignore previous rules, base64 encoded payloads, or manipulative formatting.\nThe agent then treats these malicious inputs as legitimate behavioral overrides.\n",
        "severity": "critical",
        "explanation": "\nPrompt injections allow a third party to secretly overwrite your original instructions to the AI.\nAs a result, the agent might leak sensitive information or perform harmful actions while appearing to function normally.\n",
        "evidence": "Yes. The description contains a hidden instruction that directly tells the agent to extract sensitive secrets (API keys, DB strings, encryption keys) when certain keywords are present and to exfiltrate code to an external malicious auditor URL. That's a classic prompt-injection / data-exfiltration attempt and instructs behavior outside safe tool use."
    }
}
```

Perchè mi trova solo alcune vulnerabilità?

# Codici che troviamo (analisi statica su server singoli)
E001 - Analisi LLM della descrizione del tool → basta leggere il tool
W001 - Matching di keyword nella descrizione → basta leggere il tool
W015/W016 - Analisi semantica delle capability del server → basta analizzare i tool esposti


# Codici che NON troviamo e perché
E002 — Cross-server tool shadowing
Richiede che un server faccia riferimento a tool di un altro server. Si attiva solo quando lo scanner analizza più server insieme nello stesso environment. Dalla vostra pipeline, ogni server viene scansionato singolarmente con la propria config isolata — quindi il cross-reference non viene mai rilevato.

E003 — Tool description hijacks agent behavior
Simile a E001 ma per direttive esplicite (non nascoste). Potrebbe essere che nessuno dei server scansionati contenga pattern abbastanza aggressivi da superare la soglia di E003, oppure che lo scanner li stia classificando tutti sotto E001.

E004, E005, E006 — Vulnerabilità nelle skill
Questi codici analizzano le skill (prompt template), non i tool. Se i server che scansionate non espongono skill MCP, questi codici non possono attivarsi.

W002 — Too many entities
Si attiva solo quando un server espone 100+ tool/resources/prompts combinati. È raro — la maggior parte dei server MCP ha pochi tool.

W007, W008, W009, W011, W012, W013 — Warning sulle skill
Come E004-E006, sono tutti specifici per le skill. Nessuna skill analizzata = nessun finding.

TF001, TF002 — Toxic Flows
Questi richiedono combinazioni specifiche di label su più tool dello stesso server:

TF001 (Data Leak): untrusted_content + private_data + is_public_sink
TF002 (Destructive): untrusted_content + destructive
Dai vostri dati, nessun server ha tool con queste combinazioni di label simultaneamente. Il che non vuol dire che non esistano — vuol dire che nei ~60k server scansionati nessuno ha triggerato queste condizioni (o che lo scanner è conservativo nell'assegnare label combinate).

W003, W004, W005, W006, X001, X002 — Codici di sistema
Questi non sono vulnerabilità ma errori operativi dello scanner (server non trovato, non nel registry, impossibile avviarlo). Probabilmente li avete nel log ma non li state raccogliendo nei JSON dei risultati perché non sono finding di sicurezza.