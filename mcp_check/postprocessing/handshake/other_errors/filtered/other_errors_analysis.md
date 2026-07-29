# handshake/other_errors - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 504 |
| Finding filtrati | 101 |
| Rimossi | 403 (80.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 70 |
| go | 21 |
| python | 10 |

## Finding per tipo di test

### `ping-test` (46 finding)

**1. [talk-with-figma-claude](https://github.com/gaganmanku96/talk-with-figma-claude)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: MCP error -32002: WebSocket connection is not available. Attempting to reconnect...`

**2. [yapi-mcp-server](https://github.com/KO-Good-code/yapi-mcp-server)** (go)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "content"
    ],
    "path": [],
    "message": "Unrecognized key: \"content\""
  }
]`

**3. [mcp-server](https://github.com/Diegoval-Dev/mcp-server)** (python)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "ok"
    ],
    "path": [],
    "message": "Unrecognized key: \"ok\""
  }
]`

**4. [DotnetMCPServer](https://github.com/kasirajan22/DotnetMCPServer)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: MCP error -32603: Internal error`

**5. [zapmail-mcp](https://github.com/dsouzaalan/zapmail-mcp)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "ok"
    ],
    "path": [],
    "message": "Unrecognized key: \"ok\""
  }
]`

**6. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: MCP error -32603: Request failed: Not Found`

**7. [logic-thinking](https://github.com/quanticsoul4772/logic-thinking)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "status"
    ],
    "path": [],
    "message": "Unrecognized key: \"status\""
  }
]`

**8. [ai_collaboration_mcp_server](https://github.com/atsuki-sakai/ai_collaboration_mcp_server)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "status",
      "timestamp"
    ],
    "path": [],
    "message": "Unrecognized keys: \"status\", \"timestamp\""
  }
]`

**9. [react-devtools-mcp](https://github.com/skylarbarrera/react-devtools-mcp)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "message",
      "server",
      "status"
    ],
    "path": [],
    "message": "Unrecognized keys: \"message\", \"server\", \"status\""
  }
]`

**10. [llm-mcp-bridge](https://github.com/ramgeart/llm-mcp-bridge)** (nodejs)
- Type: `PingError`
- Message: `Ping failed: [
  {
    "code": "unrecognized_keys",
    "keys": [
      "message",
      "server",
      "status"
    ],
    "path": [],
    "message": "Unrecognized keys: \"message\", \"server\", \"status\""
  }
]`

*... e altri 36 finding simili*

### `resource-discovery` (28 finding)

**1. [mssql-mcp-node](https://github.com/mihai-dulgheru/mssql-mcp-node)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: [config] No valid database configuration found. Set MSSQL_* for single mode or MSSQL_<NAME>_* for multi mode.`

**2. [mcp-server-flomo](https://github.com/GolderBrother/mcp-server-flomo)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Cannot destructure property 'name' of 'request.params' as it is undefined.`

**3. [code-explorer-mcp](https://github.com/jordankamto/code-explorer-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: MCP error -32603: Failed to list resources`

**4. [keitaro-mcp](https://github.com/GodzillaDancer/keitaro-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: template.resourceTemplate.listCallback is not a function`

**5. [pocketbase-mcp](https://github.com/fadlee/pocketbase-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: HTTP error 404`

**6. [postgis-mcp](https://github.com/receptopalak/postgis-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Veritabanı bağlantısı bulunamadı. .env içine DB_URL_1, DB_URL_2 ... veya legacy DB_* değişkenleri ekleyin.`

**7. [mcp-selenium-extended](https://github.com/sapangupta63/mcp-selenium-extended)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Cannot read properties of undefined (reading 'list')`

**8. [DotnetMCPServer](https://github.com/kasirajan22/DotnetMCPServer)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Failed to get resources`

**9. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Request failed: Not Found`

**10. [mcp-server](https://github.com/HookbaseApp/mcp-server)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: MCP error -32603: Config not initialized. Call initConfig() first.`

*... e altri 18 finding simili*

### `tool-discovery` (21 finding)

**1. [mcp-jetbrains](https://github.com/JetBrains/mcp-jetbrains)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: No working IDE endpoint available.`

**2. [mcp-proxy-sidecar](https://github.com/dortegau/mcp-proxy-sidecar)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: No working IDE endpoint available.`

**3. [mcp-assistant](https://github.com/nodlab/mcp-assistant)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: The "path" argument must be of type string or an instance of Buffer or URL. Received undefined`

**4. [DotnetMCPServer](https://github.com/kasirajan22/DotnetMCPServer)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: Failed to get tools`

**5. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: Request failed: Not Found`

**6. [notemd-mcp](https://github.com/Jacobinwwey/notemd-mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: Failed to parse URL from /tools`

**7. [azure-pricing-mcp](https://github.com/charris-msft/azure-pricing-mcp)** (python)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error 0: name 'true' is not defined`

**8. [mcp-server-gravatar](https://github.com/Automattic/mcp-server-gravatar)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: can't resolve reference #/components/schemas/VerifiedAccount from id #`

**9. [handsai-bridge](https://github.com/Vrivaans/handsai-bridge)** (go)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: HTTP 401`

**10. [follow-plan-mcp](https://github.com/vibeclasses/follow-plan-mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: MCP error -32603: MCP error -32603: Failed to connect to backend: MCP error -32603: Backend error: Not Found - <!doctype html><meta charset="utf-8"><title>Not found</title>
<body style="font:16px/1.6 system-ui;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center;color:#333">
<h1 style="font-size:2rem">No site here yet</h1>
<p>This address isn't live. If this is your business, we may be building a preview for you.</p></body>`

*... e altri 11 finding simili*

### `connection-establishment` (8 finding)

**1. [mcpterm](https://github.com/dwrtz/mcpterm)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: client protocol version 2025-11-25 not supported`

**2. [wordpress-mcp-server](https://github.com/stefans71/wordpress-mcp-server)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32000: WordPress credentials not provided in environment variables or request parameters`

**3. [woocommerce-mcp-server](https://github.com/techspawn/woocommerce-mcp-server)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32000: WordPress site URL not provided in environment variables or request parameters`

**4. [notion-knowledge-mcp](https://github.com/YuHuanHsu/notion-knowledge-mcp)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**5. [mcp2](https://github.com/martin-1103/mcp2)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: Unsupported protocol version: 2025-11-25`

**6. [bazi-mcp](https://github.com/justinwongcn/bazi-mcp)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: protocol version not supported, supported lastest version is 2025-03-26`

**7. [mcp-server](https://github.com/luffy050596/mcp-server)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**8. [querymind](https://github.com/rduffyuk/querymind)** (python)
- Type: `ConnectionError`
- Message: `Failed to establish connection: MCP error -32603: Unsupported protocol version: 2025-11-25`

### `prompt-discovery` (7 finding)

**1. [mcp-server-clash-of-clans](https://github.com/Saunved/mcp-server-clash-of-clans)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: field.isOptional is not a function`

**2. [mcp-server-mlflow](https://github.com/B-Step62/mcp-server-mlflow)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: Failed to list prompts`

**3. [depot-mcp](https://github.com/MAKaminski/depot-mcp)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: Request failed: Error: Unknown method: prompts/list`

**4. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: Request failed: Not Found`

**5. [mcp-server](https://github.com/AfryDario/mcp-server)** (python)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: Internal error: 'MCPServer' object has no attribute '_handle_prompts_list'`

**6. [youtube-analytics-mcp](https://github.com/dogfrogfog/youtube-analytics-mcp)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: field.isOptional is not a function`

**7. [mcpd-proxy](https://github.com/mozilla-ai/mcpd-proxy)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: MCP error -32603: Request failed: Not Found`

## Interpretazione

Gli **other_errors** filtrati sono errori runtime che non rientrano nelle altre categorie. Dopo aver rimosso errori di setup/infrastruttura, rimangono errori applicativi potenzialmente interessanti.

