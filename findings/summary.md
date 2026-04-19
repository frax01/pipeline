# Riepilogo numerico findings

## mcp-watch

| Categoria | Originali | Dopo filtro (Fase 2) | VP finali | FP finali |
|---|---:|---:|---:|---:|
| credential-leak | 646.447 | 784 | 619 | 165 |
| data-exfiltration | 24.566 | 86 | 2 | 84 |
| input-validation | 764.234 | 225 | 125 | 100 |
| protocol-violation | 381.429 | 2.927 | 79 | 2.848 |
| steganographic-attack | 16.570 | 360 | 3 | 357 |
| **Totale** | **1.833.246** | **4.382** | **828** | **3.554** |

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

### Dettaglio buckets pipeline (HC → LLM)

| Categoria | HC-VP | HC-FP | UNCERTAIN | VP in-chat/LLM | FP in-chat/LLM |
|---|---:|---:|---:|---:|---:|
| credential-leak | 459 | 145 | 180 | 160 | 20 |
| data-exfiltration | 2 | 79 | 5 | 0 | 5 |
| input-validation | 123 | 91 | 11 | 2 | 9 |
| protocol-violation | 79 | 2.848 | 0 | 0 | 0 |
| steganographic-attack | 3 | 311 | 46 | 0 | 46 |

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

## Totale generale

| Framework | Originali | Dopo filtro | VP finali | FP finali |
|---|---:|---:|---:|---:|
| mcp-watch | 1.833.246 | 4.382 | 828 | 3.554 |
| mcp-scan | 679 | 679 | ~608 | ~71 |
| mcp-shield | 5.047 | 5.047 | 16 | 5.031 |
| mcp-security-scan | 9.404 | 1.395 | 1.094 | 301 |
| **Totale** | **1.848.376** | **11.503** | **~2.546** | **~8.957** |
