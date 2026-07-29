# tool_discovery/unauthorized_or_auth_missing - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 3 |
| Finding filtrati | 3 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 3 |

## Finding per tipo di test

### `tool-enumeration` (3 finding)

**1. [wpcom-mcp-bundle](https://github.com/Automattic/wpcom-mcp-bundle)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: No authentication method available. Please configure JWT_TOKEN, OAuth, Basic Auth (WP_API_USERNAME+WP_API_PASSWORD), or CUSTOM_HEADERS.`

**2. [mcp-proxy-hub](https://github.com/naotaka3/mcp-proxy-hub)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**3. [apis-mcp](https://github.com/Synergy-Shock/apis-mcp)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

## Interpretazione

Gli errori di **auth** indicano server che richiedono autenticazione per funzionare. Non sono vulnerabilità in sé, ma sono informativi: mostrano quali server hanno un layer di auth attivo.

