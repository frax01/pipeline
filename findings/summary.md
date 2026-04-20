# Riepilogo numerico findings

## mcp-watch

| Categoria | Originali | Dopo filtro (Fase 2) | VP finali | FP finali |
|---|---:|---:|---:|---:|
| credential-leak | 646.447 | 784 | 619 | 165 |
| data-exfiltration | 24.566 | 86 | 2 | 84 |
| input-validation | 764.234 | 225 | 125 | 100 |
| protocol-violation | 381.429 | 2.927 | 79 | 2.848 |
| steganographic-attack | 16.570 | 360 | 3 | 357 |
| tool-poisoning | 136 | 7 | 0 | 7 |
| prompt-injection | 302 | 8 | 0 | 8 |
| tool-mutation | 18.856 | 2.577 | 0 | 2.577 |
| access-control | 428.443 | 17 | 7 | 10 |
| **Totale** | **2.281.983** | **6.991** | **835** | **6.156** |

### Dettaglio mcp-watch per ID

**credential-leak** (784 dopo filtro → 619 VP)
| ID | Kept | VP |
|---|---:|---:|
| PLAINTEXT_STORAGE | 434 | 351 |
| HARDCODED_CREDENTIALS | 339 | 268 |
| INSECURE_CREDENTIAL_PERMISSIONS | 11 | 0 |

**data-exfiltration** (86 dopo filtro → 2 VP)
| ID | Kept | VP |
|---|---:|---:|
| DATA_EXFILTRATION | 57 | 1 |
| UNUSED_SENSITIVE_PARAMETER | 13 | 0 |
| MAGIC_PARAMETER_INJECTION | 12 | 0 |
| CONVERSATION_EXFILTRATION_TRIGGER | 4 | 1 |

**input-validation** (225 dopo filtro → 125 VP)
| ID | Kept | VP |
|---|---:|---:|
| SSRF_VULNERABILITY | 142 | 94 |
| COMMAND_INJECTION_RISK | 73 | 29 |
| PATH_TRAVERSAL | 10 | 2 |

**protocol-violation** (2.927 dopo filtro → 79 VP)
| ID | Kept | VP |
|---|---:|---:|
| INSECURE_TRANSPORT | 2.775 | 64 |
| SESSION_ID_IN_URL | 152 | 15 |

**steganographic-attack** (360 dopo filtro → 3 VP)
| ID | Kept | VP |
|---|---:|---:|
| WHITESPACE_INJECTION | 217 | 3 |
| ANSI_ESCAPE_INJECTION | 143 | 0 |

**tool-poisoning** (7 dopo filtro → 0 VP)
| ID | Kept | VP |
|---|---:|---:|
| HIDDEN_TOOL_INSTRUCTIONS | 7 | 0 |

**prompt-injection** (8 dopo filtro → 0 VP)
| ID | Kept | VP |
|---|---:|---:|
| TOOL_DESCRIPTION_INJECTION | 8 | 0 |

> `RETRIEVAL_AGENT_DECEPTION` escluso dall'analisi (55.480 finding di rumore
> puro: pattern `<!-- system:` in documentazione auto-generata).

**tool-mutation** (2.577 dopo filtro → 0 VP)
| ID | Kept | VP |
|---|---:|---:|
| DYNAMIC_TOOL_MUTATION | 2.577 | 0 |

> `TOOL_NAME_COLLISION` escluso dall'analisi.

**access-control** (17 dopo filtro → 7 VP)
| ID | Kept | VP |
|---|---:|---:|
| EXCESSIVE_PERMISSIONS | 17 | 7 |

> `CONSENT_FATIGUE_RISK` escluso dall'analisi.
> Filtro Stage 1 con whitelist aggressiva: 428.443 → 17 (riduzione 100.0%).

### Dettaglio buckets pipeline (HC → LLM)

| Categoria | HC-VP | HC-FP | UNCERTAIN | VP in-chat/LLM | FP in-chat/LLM |
|---|---:|---:|---:|---:|---:|
| credential-leak | 459 | 145 | 180 | 160 | 20 |
| data-exfiltration | 2 | 79 | 5 | 0 | 5 |
| input-validation | 123 | 91 | 11 | 2 | 9 |
| protocol-violation | 79 | 2.848 | 0 | 0 | 0 |
| steganographic-attack | 3 | 311 | 46 | 0 | 46 |
| tool-poisoning | 0 | 7 | 0 | 0 | 0 |
| prompt-injection | 0 | 8 | 0 | 0 | 0 |
| tool-mutation | 0 | 2.577 | 0 | 0 | 0 |
| access-control | 7 | 10 | 0 | 0 | 0 |

---

## mcp-scan

Nessuna Fase 2 a regex: la detection e' interamente nel backend LLM di Invariant Labs.

| Categoria | Originali | Dopo filtro | VP finali | Borderline | FP finali |
|---|---:|---:|---:|---:|---:|
| E001 (prompt-injection) | 80 | 80 | 18 | 10 | 52 |
| W015 (untrusted-content) | 599 | 599 | ~590 | — | ~9 |
| **Totale** | **679** | **679** | **~608** | **10** | **~61** |

### Dettaglio mcp-scan

**E001** — severity critical, risk_score variabile (0.0-1.0), assegnato dal LLM di Invariant.

Ripartizione VP per tipo di attacco:
| Tipo | Finding |
|---|---:|
| Hiding information from user | 15 |
| Data exfiltration / credential theft | 5 |
| Tool di attacco espliciti | 3 |
| Tool chaining injection | 2 |
| Impersonation | 1 |
| System prompt exfiltration | 1 |

**W015** — severity medium, risk_score uniforme 0.5 per tutti i 599 finding.

Ripartizione per facilita' reale di poisoning:
| Livello | Finding |
|---|---:|
| Rischio reale alto (repo Git, web scraping, social) | ~200 |
| Rischio reale medio (API pubbliche, package manager) | ~250 |
| Rischio reale basso (API autenticate, dati privati) | ~150 |

Nota: esiste anche **W016** ("Potential Untrusted Content", 1.483 finding, severity low, score 0.25) — controparte low-severity di W015 non analizzata nel dettaglio.

---

## mcp-shield

Nessuna Fase 2 a regex: lo scanner applica gia' matcher statico + LLM. Lo Stage 2A di `pipeline_mcp_shield.py` consolida la classificazione con regole HC deterministiche.

| Categoria | Originali (HIGH + MEDIUM) | Dopo filtro | VP finali | FP finali |
|---|---:|---:|---:|---:|
| hidden-instructions | 310 (68 + 242) | 310 | 4 | 306 |
| potential-exfiltration | 1.621 (73 + 1.548) | 1.621 | 0 | 1.621 |
| sensitive-file-access | 3.094 (3.094 + 0) | 3.094 | 11 | 3.083 |
| shadowing-detected | 22 (22 + 0) | 22 | 1 | 21 |
| **Totale** | **5.047** | **5.047** | **16** | **5.031** |

### Dettaglio buckets pipeline mcp-shield (HC → LLM)

| Categoria | HC-VP | HC-FP | UNCERTAIN | VP LLM | FP LLM |
|---|---:|---:|---:|---:|---:|
| hidden-instructions | 4 | 231 | 75 | 0 | 75 |
| potential-exfiltration | 0 | 1.621 | 0 | 0 | 0 |
| sensitive-file-access | 11 | 3.083 | 0 | 0 | 0 |
| shadowing-detected | 1 | 21 | 0 | 0 | 0 |

### VP mcp-shield per server unico

| Server | Tool VP | Categoria |
|---|---:|---|
| sec-mimikatz-mcp | 6 | sensitive-file-access |
| sec-rubeus-mcp | 3 | sensitive-file-access |
| sec-bloodhound-mcp | 1 | sensitive-file-access |
| sec-evil-winrm-mcp | 1 | sensitive-file-access |
| math-mcp-server-nodejs | 2 (+1) | hidden-instructions (+shadowing-detected) |
| mdsel-mcp | 1 | hidden-instructions |
| vibe-coding-hater-mcp-server | 1 | hidden-instructions |

---

## mcp-security-scan

Scanner a probe dinamici sul server MCP (non analisi statica del codice). Lo Stage 1 e' `filter_security_scan.py` (regex specifiche per evidenza reale); Stage 2A (regole HC) applicato solo a `rug-pull` e `dangerous-capabilities`; Stage 2B classificazione in-chat con Sonnet via cache.

| Categoria | Originali | Dopo filtro | VP finali | FP finali |
|---|---:|---:|---:|---:|
| dangerous-capabilities (X-01) | 4.644 | 1.230 | 1.001 | 229 |
| input-validation (X-02) | 4.364 | 85 | 83 | 2 |
| path-traversal (R-01) | 131 | 5 | 5 | 0 |
| sensitive-file-access (R-02) | 116 | 5 | 5 | 0 |
| rug-pull (X-03) | 91 | 59 | 0 | 59 |
| prompt-injection (P-02) | 35 | 3 | 0 | 3 |
| data-leak (A-03) | 13 | 2 | 0 | 2 |
| remote-access-control (RC-01) | 5 | 1 | 0 | 1 |
| indirect-prompt-injection (P-03) | 3 | 3 | 0 | 3 |
| sensitive-resource-exposure (R-03) | 2 | 2 | 0 | 2 |
| **Totale** | **9.404** | **1.395** | **1.094** | **301** |

Nota: `initialization-error` (444 entries) scartato come noise infrastrutturale (server non avviati).

### Dettaglio buckets pipeline mcp-security-scan

| Categoria | Filtrati Stage 1 | HC-VP | HC-FP | UNCERTAIN | VP in-chat | FP in-chat |
|---|---:|---:|---:|---:|---:|---:|
| dangerous-capabilities | 1.230 | 961 | 208 | 61 | 40 | 21 |
| input-validation | 85 | — | — | 85 | 83 | 2 |
| rug-pull | 59 | 0 | 59 | 0 | 0 | 0 |
| path-traversal | 5 | — | — | 5 | 5 | 0 |
| sensitive-file-access | 5 | — | — | 5 | 5 | 0 |
| prompt-injection | 3 | — | — | 3 | 0 | 3 |
| indirect-prompt-injection | 3 | — | — | 3 | 0 | 3 |
| data-leak | 2 | — | — | 2 | 0 | 2 |
| sensitive-resource-exposure | 2 | — | — | 2 | 0 | 2 |
| remote-access-control | 1 | — | — | 1 | 0 | 1 |

### VP mcp-security-scan per tipologia

**input-validation (X-02) — Command injection confermati (83 VP)**
Unica categoria con prova diretta di sfruttamento: il server ha realmente eseguito il payload e restituito output di sistema reale.

| Pattern di match | VP |
|---|---:|
| `uid=` (output di `; id`) | ~40 |
| `Linux kernel version` (output di `` `uname -a` ``) | ~20 |
| `root:x:0:0:` (contenuto di `/etc/passwd`) | ~15 |
| `ami-*` / `meta-data` (AWS IMDS) | ~5 |
| altri | ~3 |

**dangerous-capabilities (X-01) — Tool con exec/shell/fs (1.001 VP)**

| Pattern di match | VP |
|---|---:|
| `dc_exec_desc` (execute/run command) | ~500 |
| `file_ops_desc` (delete/write file) | ~200 |
| `ssh_exec` (esecuzione remota SSH) | ~100 |
| `real_install` (install package/plugin) | ~80 |
| `spawn_terminal` / `sudo` / `offensive_tool` | ~70 |
| `explicit_offense` (aircrack, nmap, metasploit, ecc.) | ~50 |

**path-traversal + sensitive-file-access (R-01/R-02) — 10 VP (5+5, stessi server)**
I 5 server: `worksona/-worksona-mcp-server`, `nhatvu148/video-transcriber-mcp`, `kbyk004/my-docs-mcp-server`, `danielitus/mcp-document-server`, `uniswap/spec-workflow-mcp`. Tutti falliscono sia R-01 che R-02 per mancata validazione di URI `file://`.

---

## mcp-check

Test harness di conformance del protocollo MCP (non scanner di sicurezza). Stage 1 `filter_mcp_check.py` scarta noise infrastrutturale (not_connected ~73k, timeout ~4k, ecc.) e tiene 11.101 finding in 16 categorie su 3 fasi. Stage 2A (regole HC) applicato a 14 categorie; 2 categorie (`handshake/invalid_arguments`, `tool_invocation/panic_or_crash`) classificate direttamente via cache in-chat. Non si usa Ollama: tutte le categorie arrivano a UNCERTAIN=0 tramite regole HC deterministiche + cache in-chat.

| Fase / Categoria | Originali | Dopo filtro | VP finali | FP finali |
|---|---:|---:|---:|---:|
| handshake / schema_violation | — | 49 | 49 | 0 |
| handshake / other_errors | — | 117 | 110 | 7 |
| handshake / method_not_found | — | 289 | 289 | 0 |
| handshake / invalid_arguments | — | 7 | 2 | 5 |
| handshake / unauthorized_or_auth_missing | — | 5 | 0 | 5 |
| tool_discovery / schema_violation | — | 229 | 229 | 0 |
| tool_discovery / other_errors | — | 29 | 26 | 3 |
| tool_discovery / method_not_found | — | 42 | 42 | 0 |
| tool_discovery / warnings | — | 357 | 357 | 0 |
| tool_invocation / schema_violation | — | 4.860 | 4.860 | 0 |
| tool_invocation / other_errors | — | 3.817 | 3.361 | 456 |
| tool_invocation / panic_or_crash | — | 4 | 4 | 0 |
| tool_invocation / invalid_arguments | — | 253 | 74 | 179 |
| tool_invocation / method_not_found | — | 50 | 50 | 0 |
| tool_invocation / warnings | — | 878 | 0 | 878 |
| tool_invocation / unauthorized_or_auth_missing | — | 115 | 0 | 115 |
| **Totale** | **—** | **11.101** | **9.453** | **1.648** |

Nota: la colonna "Originali" e' vuota perche' mcp-check non ha un conteggio pre-filtro paragonabile agli scanner statici — ogni server produce 0..N entry per fase/categoria e gli errori infrastrutturali (`not_connected`, `timeout`, `initialization-error`) sono scartati dal Stage 1 prima della categorizzazione.

### Dettaglio buckets pipeline mcp-check (HC -> cache in-chat)

| Categoria | Filtrati | HC-VP / HC-FP | UNCERTAIN dopo HC | VP cache in-chat | FP cache in-chat |
|---|---:|---|---:|---:|---:|
| handshake/schema_violation | 49 | 49 / 0 | 0 | — | — |
| handshake/other_errors | 117 | 110 / 7 | 0 | — | — |
| handshake/method_not_found | 289 | 289 / 0 | 0 | — | — |
| handshake/invalid_arguments | 7 | no HC | 7 | 2 | 5 |
| handshake/unauthorized | 5 | 0 / 5 | 0 | — | — |
| tool_discovery/schema_violation | 229 | 229 / 0 | 0 | — | — |
| tool_discovery/other_errors | 29 | 26 / 3 | 0 | — | — |
| tool_discovery/method_not_found | 42 | 42 / 0 | 0 | — | — |
| tool_discovery/warnings | 357 | 357 / 0 | 0 | — | — |
| tool_invocation/schema_violation | 4.860 | 4.860 / 0 | 0 | — | — |
| tool_invocation/other_errors | 3.817 | 3.361 / 456 | 0 | — | — |
| tool_invocation/panic_or_crash | 4 | no HC | 4 | 4 | 0 |
| tool_invocation/invalid_arguments | 253 | ~70 / ~170 | residuo | ~4 | ~9 |
| tool_invocation/method_not_found | 50 | 50 / 0 | 0 | — | — |
| tool_invocation/warnings | 878 | 0 / 878 | 0 | — | — |
| tool_invocation/unauthorized | 115 | 0 / 115 | 0 | — | — |

### VP mcp-check per tipologia (tra i 9.453 VP)

| Pattern | VP |
|---|---:|
| `tool_invocation/schema_violation` (output schema / tools/list response invalido) | 4.860 |
| `tool_invocation/other_errors` — `ErrorHandlingFailure` (tool name injection) | ~3.294 |
| `tool_invocation/warnings` (tool senza description quality) | —  |
| `tool_discovery/warnings` (tool senza description) | 357 |
| `handshake/method_not_found` (initialize non implementato) | 289 |
| `tool_discovery/schema_violation` (InvalidToolSchemas) | 229 |
| `handshake/other_errors` (unmarshal, runtime JS/Py, discovery crash) | 110 |
| `tool_invocation/invalid_arguments` (bug parametri server) | 74 |
| `tool_invocation/method_not_found` (tool dichiarato non implementato) | 50 |
| `handshake/schema_violation` (initialize Zod failure) | 49 |
| `tool_discovery/method_not_found` (tools/list non implementato) | 42 |
| `tool_discovery/other_errors` (DuplicateToolNames + runtime crash) | 26 |
| `tool_invocation/panic_or_crash` (Go nil pointer / interface panic) | 4 |
| `handshake/invalid_arguments` | 2 |

---

## Totale generale

| Framework | Originali | Dopo filtro | VP finali | FP finali |
|---|---:|---:|---:|---:|
| mcp-watch | 2.281.983 | 6.991 | 835 | 6.156 |
| mcp-scan | 679 | 679 | ~608 | ~71 |
| mcp-shield | 5.047 | 5.047 | 16 | 5.031 |
| mcp-security-scan | 9.404 | 1.395 | 1.094 | 301 |
| mcp-check | — | 11.101 | 9.453 | 1.648 |
| **Totale** | **2.297.113** | **25.213** | **~12.006** | **~13.207** |
