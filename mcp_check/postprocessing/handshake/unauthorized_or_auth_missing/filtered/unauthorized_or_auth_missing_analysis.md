# handshake/unauthorized_or_auth_missing - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 10 |
| Finding filtrati | 10 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 8 |
| python | 1 |
| go | 1 |

## Finding per tipo di test

### `resource-discovery` (8 finding)

**1. [drive-mcp](https://github.com/rishipradeep-think41/drive-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

**2. [mcp-gdrive](https://github.com/konashevich/mcp-gdrive)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

**3. [mcp-disaster-preparedness-proj-2](https://github.com/myusegtr/mcp-disaster-preparedness-proj-2)** (python)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

**4. [mcp-gdrive](https://github.com/General-Intelligence-Labs/mcp-gdrive)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

**5. [combine-mcp](https://github.com/nazar256/combine-mcp)** (go)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico...`

**6. [google-drive-mcp](https://github.com/piotr-agier/google-drive-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico...`

**7. [gyazo-mcp-server](https://github.com/nota/gyazo-mcp-server)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Failed to list resources: GYAZO_ACCESS_TOKEN environment variable is required`

**8. [wpcom-mcp-bundle](https://github.com/Automattic/wpcom-mcp-bundle)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: No authentication method available. Please configure JWT_TOKEN, OAuth, Basic Auth (WP_API_USERNAME+WP_API_PASSWORD), or CUSTOM_HEADERS.`

### `tool-discovery` (3 finding)

**1. [wpcom-mcp-bundle](https://github.com/Automattic/wpcom-mcp-bundle)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: No authentication method available. Please configure JWT_TOKEN, OAuth, Basic Auth (WP_API_USERNAME+WP_API_PASSWORD), or CUSTOM_HEADERS.`

**2. [mcp-proxy-hub](https://github.com/naotaka3/mcp-proxy-hub)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**3. [apis-mcp](https://github.com/Synergy-Shock/apis-mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `prompt-discovery` (1 finding)

**1. [wpcom-mcp-bundle](https://github.com/Automattic/wpcom-mcp-bundle)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: No authentication method available. Please configure JWT_TOKEN, OAuth, Basic Auth (WP_API_USERNAME+WP_API_PASSWORD), or CUSTOM_HEADERS.`

## Interpretazione

Gli errori di **auth** indicano server che richiedono autenticazione per funzionare. Non sono vulnerabilità in sé, ma sono informativi: mostrano quali server hanno un layer di auth attivo.

