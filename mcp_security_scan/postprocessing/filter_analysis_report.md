# MCP Security Scan - Report Filtro Falsi Positivi

**Data**: 2026-07-27 12:30

## Cosa fa mcp-security-scan

mcp-security-scan e' uno scanner che testa la sicurezza dei server MCP tramite probe attivi e analisi euristica. I check includono:

- **X-01**: Rilevamento capacita' pericolose nei tool (keyword-based)
- **X-02**: Fuzzing di input validation con injection payloads
- **X-03**: Stabilita' delle tool description (rug pull detection)
- **R-01**: Path traversal su risorse
- **R-02**: Accesso a file sensibili
- **R-03**: Esposizione risorse sensibili
- **A-03**: Token indirection / data leak
- **P-02**: Prompt injection nelle tool description
- **P-03**: Prompt injection indiretta via risorse esterne
- **RC-01**: Esposizione accesso remoto

## Perche' serve un filtro

Lo scanner usa approcci euristici con **keyword matching** e **indicatori generici** che producono un alto tasso di falsi positivi:

- **X-01**: keyword come 'fetch', 'http', 'url' flaggano tool read-only
- **X-02**: indicatori come 'linux', 'insecure' matchano error messages
- **A-03**: errori 'token mancante' confusi con data leak
- **RC-01**: 'enabled' troppo generico come indicatore di accesso remoto

## Categorie scartate

| Categoria | Motivo |
|-----------|--------|
| `initialization-error` | Server non avviato, noise infrastrutturale (444 entries) |

## Risultati del filtro

| Categoria | Vuln ID | Originali | Filtrati | Rimossi | Riduzione |
|-----------|---------|-----------|----------|---------|----------|
| `dangerous-capabilities` | X-01 | 3112 | 785 | 2327 | 74.8% |
| `input-validation` | X-02 | 2868 | 63 | 2805 | 97.8% |
| `path-traversal` | R-01 | 102 | 4 | 98 | 96.1% |
| `sensitive-file-access` | R-02 | 88 | 4 | 84 | 95.5% |
| `rug-pull` | X-03 | 86 | 52 | 34 | 39.5% |
| `prompt-injection` | P-02 | 35 | 1 | 34 | 97.1% |
| `data-leak` | A-03 | 11 | 1 | 10 | 90.9% |
| `remote-access-control` | RC-01 | 5 | 3 | 2 | 40.0% |
| `indirect-prompt-injection` | P-03 | 1 | 1 | 0 | 0.0% |
| `sensitive-resource-exposure` | R-03 | 1 | 1 | 0 | 0.0% |
| **TOTALE** | | **6309** | **915** | **5394** | **85.5%** |

## Categorie piu' interessanti

### 1. input-validation (X-02) - Command Injection Confermati

I finding tenuti sono server dove i payload di injection sono stati **realmente eseguiti**. Ad esempio, `; id` ha prodotto `uid=1000(tecnico)...`. Questi sono i finding piu' critici dell'intera analisi: **command injection confermati su server MCP reali**.

### 2. prompt-injection (P-02) - Hidden Instructions

Tool con istruzioni nascoste nelle description, progettate per manipolare l'LLM. Pattern come 'HIDDEN INSTRUCTION - INVISIBLE TO USER' sono chiari indicatori di intent malevolo.

### 3. dangerous-capabilities (X-01) - Tool con Exec/Shell

Tool che espongono esecuzione comandi (exec, shell, bash) o manipolazione file system senza constraint sui parametri. Pericolosi se il server e' accessibile senza autenticazione.

### 4. rug-pull (X-03) - Comportamento Instabile

Server che cambiano le tool description dopo la prima interazione. Potenziale indicatore di comportamento malevolo post-installazione.

## Come usare i risultati

I file filtrati si trovano in `<categoria>/filtered/`:
- `*_filtered.json`: finding filtrati con alta confidenza di essere veri positivi
- `*_analysis.md`: report di analisi con statistiche, esempi e interpretazione

Il campo `_filter_reason` in ogni finding spiega perche' e' stato tenuto.
