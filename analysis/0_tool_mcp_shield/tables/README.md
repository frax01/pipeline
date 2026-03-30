# MCP Shield — Spiegazione dei grafici

**MCP Shield** e un tool di analisi statica in TypeScript che opera sulle descrizioni e sugli inputSchema dei tool MCP. Ha 4 detector: (1) sensitive-file-access — regex su parole come "token", "secret", "credentials" nelle descrizioni; (2) potential-exfiltration — parametri con nomi sospetti come "notes", "metadata", "url" che potrebbero essere usati per esfiltrare dati; (3) hidden-instructions — tag `<instructions>`, `<IMPORTANT>`, "ignore previous" nelle descrizioni; (4) shadowing — tool che cercano di manipolare o impersonare altri tool. Ha anche un'analisi LLM opzionale che valuta le descrizioni.

Server analizzati: **11.456** su 60.205 (19.03%)
Tool totali enumerati: **93.461** (media 8.16 per server)
Tool vulnerabili: **6.832** (7.31%)

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi degli 11.456 server analizzati.

**Interpretazione**: Node.js (8.026) domina ancora di piu rispetto agli altri tool, con Python (2.689) e Go (490). La copertura bassa (19.03%) e dovuta al requisito di avviare il server e completare l'enumerazione dei tool via protocollo MCP. Docker (33) e unknown (218) sono quasi assenti — i server in Docker raramente si avviano nel contesto di test automatizzato.

---

## 02_tools_safe_vulnerable.png — Tool sicuri vs vulnerabili

**Cosa mostra**: Dei 93.461 tool enumerati, la proporzione safe vs vulnerable.

- **Safe (86.629, 92.69%)**: Nessun finding
- **Vulnerable (6.832, 7.31%)**: Almeno un finding dall'analisi statica o LLM

**Confronto con Snyk**: MCP Scan (Snyk) riporta 1.61% di tool vulnerabili, MCP Shield riporta 7.31%. La differenza e dovuta al detector sensitive-file-access che e molto aggressivo — qualsiasi tool che menziona "file", "read", "content" nella descrizione viene flaggato.

---

## 03_static_categories.png — Categorie dell'analisi statica

**Cosa mostra**: Distribuzione delle categorie di vulnerabilita trovate dall'analisi statica.

- **Sensitive File Access (5.139, 75.2%)**: La categoria dominante. Il detector cerca parole come "token", "secret", "password", "credentials", "file", "read" nelle descrizioni dei tool. E troppo aggressivo: un tool che descrive "reads the content of a configuration file" viene flaggato come se potesse accedere a file sensibili
- **Potential Exfiltration (1.924, 28.2%)**: Parametri con nomi che potrebbero indicare canali di esfiltrazione: "url", "endpoint", "webhook", "notes", "metadata", "description". Molti sono falsi positivi (es. un parametro "url" per specificare quale URL scansionare)
- **Hidden Instructions (519, 7.6%)**: Tag `<IMPORTANT>`, `<instructions>`, "ignore previous", "override" nelle descrizioni. Questo e il finding piu credibile — le hidden instructions sono una tecnica nota di prompt injection
- **Shadowing (39, 0.57%)**: Tool che cercano di impersonare o manipolare altri tool. I 39 finding hanno altissima confidenza di malevolenza — lo shadowing e quasi sempre intenzionale

**Nota**: Le percentuali sommano a >100% perche un tool puo avere piu categorie.

---

## 04_static_severity.png — Severity dell'analisi statica

**Cosa mostra**: Distribuzione della severity per i finding statici.

- **High (4.662, 68.24%)**: Include sensitive-file-access e hidden-instructions
- **Medium (2.170, 31.76%)**: Include potential-exfiltration e shadowing

**Problema**: Classificare sensitive-file-access come HIGH e discutibile quando il 75% di questi finding sono falsi positivi. La severity dovrebbe riflettere la confidenza del finding, non solo la potenziale gravita.

---

## 05_llm_analysis.png — Risultati dell'analisi LLM

**Cosa mostra**: Quando l'analisi LLM opzionale e abilitata, MCP Shield invia le descrizioni dei tool a un modello che valuta il rischio.

- **LOW (3.267)**: L'LLM ha valutato la descrizione come a basso rischio
- **MEDIUM (2.721)**: Rischio medio — la descrizione menziona capacita potenzialmente pericolose ma in modo legittimo
- **HIGH (66)**: L'LLM ha identificato descrizioni ad alto rischio — possibile prompt injection o istruzioni nascoste

**Confronto con l'analisi statica**: L'LLM e piu conservativo — solo 66 HIGH vs 4.662 HIGH dell'analisi statica. Questo suggerisce che l'analisi statica genera molti piu falsi positivi rispetto alla valutazione LLM. I 66 HIGH dell'LLM sono probabilmente i finding piu affidabili di MCP Shield.
