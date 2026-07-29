# handshake/invalid_arguments - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 16 |
| Finding filtrati | 16 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 10 |
| go | 4 |
| python | 2 |

## Finding per tipo di test

### `tool-discovery` (9 finding)

**1. [302_basic_mcp](https://github.com/302ai/302_basic_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**2. [302_sandbox_mcp](https://github.com/302ai/302_sandbox_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**3. [302_browser_use_mcp](https://github.com/302ai/302_browser_use_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**4. [302_custom_mcp](https://github.com/302ai/302_custom_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**5. [302_file_parser_mcp](https://github.com/302ai/302_file_parser_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**6. [302_image_mcp](https://github.com/302ai/302_image_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**7. [302_web_search_mcp](https://github.com/302ai/302_web_search_mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**8. [mcp-gateway](https://github.com/common-creation/mcp-gateway)** (go)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: MCP error -32602: API key is required to call the tool`

**9. [mcp-http-stdio](https://github.com/Kiennh/mcp-http-stdio)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32602: Missing sessionId`

### `connection-establishment` (7 finding)

**1. [mcp-origin](https://github.com/dstotijn/mcp-origin)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid params`

**2. [mcp-cbs-cijfers-open-data](https://github.com/dstotijn/mcp-cbs-cijfers-open-data)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid params`

**3. [mcp-developer-overheid-api-register](https://github.com/dstotijn/mcp-developer-overheid-api-register)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid params`

**4. [talebook-mcp](https://github.com/HorkyChen/talebook-mcp)** (python)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid request parameters`

**5. [omni-api-mcp](https://github.com/debojyotig/omni-api-mcp)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid params`

**6. [inspector-jake](https://github.com/inspectorjake/inspector-jake)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid request parameters`

**7. [prayer-times-mcp-server](https://github.com/mustafamjumaah/prayer-times-mcp-server)** (python)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32602: Invalid request parameters`

### `resource-discovery` (1 finding)

**1. [mcp-http-stdio](https://github.com/Kiennh/mcp-http-stdio)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32602: Missing sessionId`

### `prompt-discovery` (1 finding)

**1. [mcp-http-stdio](https://github.com/Kiennh/mcp-http-stdio)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32602: Missing sessionId`

## Interpretazione

Gli **invalid_arguments** indicano server che non gestiscono correttamente argomenti non validi o mancanti. Possono indicare input validation insufficiente.

