# MCP-Check Filter - Report Analisi

**Data**: 2026-07-27 12:30

## Cosa è mcp-check

mcp-check è un **test harness di conformance** per il protocollo MCP. NON è uno scanner di sicurezza. Testa:

1. **Handshake**: connessione, initialize, capability negotiation
2. **Tool Discovery**: enumerazione tool, validazione schema JSON
3. **Tool Invocation**: esecuzione tool con input validi e invalidi

## Categorie scartate (noise)

| Categoria | Motivo |
|-----------|--------|
| `not_connected` | Server non avviato (dipendenze, Docker, config) |
| `connection_refused` | Connessione TCP rifiutata |
| `timeout` | Timeout connessione/risposta |
| `file_not_found` | File/comando non trovato |
| `docker_missing` | Docker non installato sulla VM |
| `macos_specific_failed` | Test macOS su VM Linux |

## Categorie filtrate

| Fase | Categoria | Originali | Filtrati | Rimossi | Riduzione |
|------|-----------|-----------|----------|---------|----------|
| handshake | `invalid_arguments` | 16 | 16 | 0 | 0.0% |
| handshake | `method_not_found` | 327 | 327 | 0 | 0.0% |
| handshake | `other_errors` | 504 | 101 | 403 | 80.0% |
| handshake | `schema_violation` | 51 | 51 | 0 | 0.0% |
| handshake | `unauthorized_or_auth_missing` | 10 | 10 | 0 | 0.0% |
| tool_discovery | `invalid_arguments` | 9 | 9 | 0 | 0.0% |
| tool_discovery | `method_not_found` | 54 | 54 | 0 | 0.0% |
| tool_discovery | `other_errors` | 70 | 49 | 21 | 30.0% |
| tool_discovery | `schema_violation` | 275 | 275 | 0 | 0.0% |
| tool_discovery | `unauthorized_or_auth_missing` | 3 | 3 | 0 | 0.0% |
| tool_discovery | `warnings` | 435 | 435 | 0 | 0.0% |
| tool_invocation | `invalid_arguments` | 260 | 260 | 0 | 0.0% |
| tool_invocation | `method_not_found` | 70 | 70 | 0 | 0.0% |
| tool_invocation | `other_errors` | 4518 | 4248 | 270 | 6.0% |
| tool_invocation | `panic_or_crash` | 5 | 5 | 0 | 0.0% |
| tool_invocation | `schema_violation` | 5413 | 5413 | 0 | 0.0% |
| tool_invocation | `unauthorized_or_auth_missing` | 134 | 134 | 0 | 0.0% |
| tool_invocation | `warnings` | 938 | 938 | 0 | 0.0% |
| **TOTALE** | | **13092** | **12398** | **694** | **5.3%** |

## Categorie più interessanti

### 1. `panic_or_crash`
I crash/panic sono i finding più critici. Indicano bug reali nel server che potrebbero essere sfruttati per DoS. Tutti i server Go con panic recovered mostrano type assertion failure su input mancanti.

### 2. `schema_violation`
Schema JSON non validi nelle tool definition. Impattano l'interoperabilità con client MCP e possono causare comportamenti inattesi nell'LLM.

### 3. `invalid_arguments`
Server che non gestiscono correttamente input invalidi. Possono indicare mancanza di input validation.

### 4. `unauthorized_or_auth_missing`
Server con layer di autenticazione. Informativi per capire quali server proteggono le loro API.

### 5. `warnings`
Issue di qualità: tool senza descrizione, naming inconsistente. Impattano l'usabilità da parte dell'LLM.

## Come usare i risultati

I file filtrati si trovano in `<fase>/<categoria>/filtered/`:
- `*_filtered.json`: finding filtrati in formato JSON
- `*_analysis.md`: report di analisi con esempi e interpretazione
