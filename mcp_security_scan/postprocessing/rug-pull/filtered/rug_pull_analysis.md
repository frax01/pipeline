# rug-pull (X-03) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Instabilita' delle tool description tra due chiamate successive (T1 vs T2). Indica che il server cambia comportamento dopo la prima chiamata. Basso tasso di FP (diff deterministico), filtro leggero.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 86 |
| Finding filtrati (tenuti) | 52 |
| Rimossi | 34 |
| Tasso di riduzione | 39.5% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `KEPT:kept` | 52 |
| `REJECTED:server_crashed` | 34 |

## Server unici con vulnerabilita' reali: 52

## Esempi di finding tenuti (max 15)

### 1. [touchdesigner-mcp](https://github.com/8beeeaaat/touchdesigner-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "get_td_info", "description": "Get server information from TouchDesigner", "inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"detailLevel": {"type": "string", "enum": ["minimal", "summary", "detailed"], "description": "Response detail level for tool output (minimal, summary, or detailed)"}, "responseFormat": {"type": "string", "enum": ["json", "yaml", "markdown"], "description": "Structured output format for formatted responses"}}}, "execution": {"taskSupport": "forbidden"}}]}, {"before": [], "after": [{"name": "update_td_node_parameters", "description": "Update parameters of a specific node in TouchDesigner", "inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "prope... [troncato]```

### 2. [nutrient-dws-mcp-server](https://github.com/PSPDFKit/nutrient-dws-mcp-server)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "check_credits", "description": "Check your Nutrient DWS API credit balance and usage for the current billing period.\n\nThis is a read-only account lookup. It does not upload any document content.\n\nReturns: subscription type, total credits, used credits, and remaining credits.", "inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {}}, "annotations": {"title": "Nutrient Credit Balance", "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true}, "execution": {"taskSupport": "forbidden"}}]}, {"before": [], "after": [{"name": "document_signer", "description": "Digitally sign PDF files using the Nutrient Sign API. Reads input files from the local file system or sandbox (i... [troncato]```

### 3. [DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [{"name": "set_config_value", "description": "\n                        Set a specific configuration value by key.\n                        \n                        WARNING: Should be used in a separate chat from file operations and \n                        command execution to prevent security issues.\n                        \n                        Config keys include:\n                        - blockedCommands (array)\n                        - defaultShell (string)\n                        - allowedDirectories (array of paths)\n                        - fileReadLineLimit (number, max lines for read_file)\n                        - fileWriteLineLimit (number, max lines per write_file call)\n                        - telemetryEnabled (boolean)\n                        \n ... [troncato]```

### 4. [it-tools-mcp](https://github.com/wrenchpilot/it-tools-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "calculate_ipv4_subnet", "description": "Calculate IPv4 subnet information", "inputSchema": {"type": "object", "properties": {"cidr": {"type": "string", "description": "IPv4 CIDR notation (e.g., 192.168.1.0/24)"}}, "required": ["cidr"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "annotations": {"title": "Ipv4-subnet-calc", "readOnlyHint": false}, "execution": {"taskSupport": "forbidden"}}]}, {"before": [], "after": [{"name": "parse_url", "description": "Parse URL into components", "inputSchema": {"type": "object", "properties": {"url": {"type": "string", "description": "URL to parse"}}, "required": ["url"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "annotations": {"titl... [troncato]```

### 5. [ai-agent-with-mcp](https://github.com/moises-paschoalick/ai-agent-with-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"uri": "api://textract", "name": "Textract Tool", "description": "Sends an image to the Textract API for analysis", "inputSchema": {"type": "object", "properties": {"filePath": {"type": "string", "description": "The local path to the image file to be uploaded"}}, "required": ["filePath"]}}]}, {"before": [], "after": [{"uri": "api://users", "name": "Users Tool", "description": "Fetches a list of users from an external API", "inputSchema": {"type": "object", "properties": {}}}]}, {"before": [], "after": [{"uri": "hello://world", "name": "Hello Tool", "description": "Responds with a hello world message", "inputSchema": {"type": "object", "properties": {}}}]}]```

### 6. [godoc-mcp-server](https://github.com/yikakia/godoc-mcp-server)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"description": "provide a golang package name,get package consts,types,functions,variables,subpackages and how to use it. If return is null then means cannot find the package by the given name", "inputSchema": {"type": "object", "properties": {"pkgName": {"type": "string", "description": "the package name user search"}, "needURL": {"type": "boolean", "description": "if user need the link to the definition"}}, "required": ["pkgName", "needURL"], "additionalProperties": false}, "name": "getPackageInfo", "outputSchema": {"type": "object", "properties": {"Overview": {"type": "string"}, "Consts": {"type": ["null", "array"], "items": {"type": "object", "properties": {"SourceURL": {"type": "string"}, "Definition": {"type": "string"}, "Comment": {"type": "string"}}, "req... [troncato]```

### 7. [mcp-openapi](https://github.com/ReAPI-com/mcp-openapi)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [{"name": "search-api-schemas", "description": "Search for schemas across specifications", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "specId": {"type": "string"}}, "required": ["query"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}}], "after": []}, {"before": [{"name": "load-api-operation-by-operationId", "description": "Load an operation by operationId", "inputSchema": {"type": "object", "properties": {"specId": {"type": "string"}, "operationId": {"type": "string"}}, "required": ["specId", "operationId"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}}], "after": []}, {"before": [{"name": "get-api-catalog", "description": "Get the API catalog, the catalog contains ... [troncato]```

### 8. [google-workspace-mcp](https://github.com/orvice/google-workspace-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"description": "Read data from a specific range in a spreadsheet", "inputSchema": {"type": "object", "required": ["email", "spreadsheetId", "range"], "properties": {"email": {"type": "string", "description": "Email address to access Sheets"}, "range": {"type": "string", "description": "A1 notation range (e.g. Sheet1!A1:B10)"}, "spreadsheetId": {"type": "string", "description": "Spreadsheet ID"}}, "additionalProperties": false}, "name": "read_sheet_range", "outputSchema": {"type": "object", "required": ["data"], "properties": {"data": {"type": "string", "description": "Cell data in table format"}}, "additionalProperties": false}}]}, {"before": [], "after": [{"description": "Suspend or restore a user account", "inputSchema": {"type": "object", "required": ["userKey... [troncato]```

### 9. [zoom-mcp-server](https://github.com/JavaProgrammerLB/zoom-mcp-server)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "get_a_meeting_details", "description": "Retrieve the meeting's details with a given ID", "inputSchema": {"type": "object", "properties": {"id": {"type": "number", "description": "The ID of the meeting."}}, "required": ["id"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}}]}, {"before": [], "after": [{"name": "delete_a_meeting", "description": "Delete a meeting with a given ID", "inputSchema": {"type": "object", "properties": {"id": {"type": "number", "description": "The ID of the meeting to delete."}}, "required": ["id"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}}]}, {"before": [], "after": [{"name": "list_meetings", "description": "List scheduled meetings", "inputSchema": ... [troncato]```

### 10. [MCP-TMDB](https://github.com/ShubhanshuSondhiya/MCP-TMDB)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "get-trending", "description": "Get trending movies", "inputSchema": {"type": "object", "properties": {"timeWindow": {"type": "string", "enum": ["day", "week"], "description": "Time window for trending movies"}}, "required": []}}]}, {"before": [], "after": [{"name": "get-movie-details", "description": "Get detailed information about a specific movie", "inputSchema": {"type": "object", "properties": {"movieId": {"type": "string", "description": "ID of the movie to get details for"}}, "required": ["movieId"]}}]}, {"before": [], "after": [{"name": "get-similar", "description": "Get similar movies to a given movie", "inputSchema": {"type": "object", "properties": {"movieId": {"type": "string", "description": "ID of the movie to find similar movies for"}}, "re... [troncato]```

### 11. [digitalocean-mcp](https://github.com/digitalocean/digitalocean-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "update_database_firewall_rules", "description": "Update the firewall (trusted sources) rules for a specific database cluster.", "inputSchema": {"type": "object", "properties": {"path": {"type": "object", "properties": {"database_cluster_uuid": {"type": "string"}}, "required": ["database_cluster_uuid"], "additionalProperties": false}, "body": {"type": "object", "properties": {"rules": {"type": "array", "items": {"type": "object", "properties": {"uuid": {"anyOf": [{"type": "string"}, {"not": {}}]}, "cluster_uuid": {"anyOf": [{"type": "string"}, {"not": {}}]}, "type": {"type": "string", "enum": ["droplet", "k8s", "ip_addr", "tag", "app"]}, "value": {"type": "string"}, "created_at": {"anyOf": [{"type": "string"}, {"not": {}}]}}, "required": ["type", "value"]... [troncato]```

### 12. [coding-db-mcp](https://github.com/xuejike/coding-db-mcp)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "query_loki", "description": "执行 Loki 日志查询（只读模式），支持 LogQL 查询表达式", "inputSchema": {"type": "object", "properties": {"alias": {"type": "string", "description": "日志平台连接别名（可选，指定后其他连接参数可省略）"}, "baseUrl": {"type": "string", "description": "Loki 服务地址"}, "user": {"type": "string", "description": "认证用户名"}, "pwd": {"type": "string", "description": "认证密码/Token"}, "query": {"type": "string", "description": "LogQL 查询表达式"}, "start": {"type": "string", "description": "起始时间（ISO 8601 或相对时间如 '1h', '30m', '7d'）"}, "end": {"type": "string", "description": "结束时间（默认 'now'）"}, "limit": {"type": "integer", "description": "返回行数限制（默认 100，最大 1000）"}, "direction": {"type": "string", "enum": ["forward", "backward"], "description": "排序方向（默认 backward）"}}, "required": ["query"]}, "annot... [troncato]```

### 13. [npm-search-mcp-server](https://github.com/btwiuse/npm-search-mcp-server)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "search_npm_packages", "description": "Search for npm packages using the npm search command", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query to find npm packages"}}, "required": ["query"]}}]}]```

### 14. [mcpLocalHelper](https://github.com/rodhayl/mcpLocalHelper)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "analyze_test_gaps", "description": "Estimate missing tests from source/test patterns (requires root). Supports relative-path globs; defaults include TS/JS/PY. Guidance only.", "inputSchema": {"type": "object", "properties": {"root": {"type": "string", "description": "Root directory to analyze"}, "testPatterns": {"type": "array", "items": {"type": "string"}, "description": "Glob patterns for test files (matched against relative paths and file names)"}, "sourcePatterns": {"type": "array", "items": {"type": "string"}, "description": "Glob patterns for source files (matched against relative paths and file names)"}}, "required": ["root"]}}]}, {"before": [], "after": [{"name": "generate_agents_md", "description": "Generate AGENTS.md from project structure. use... [troncato]```

### 15. [hr-mcp-server](https://github.com/gabrielrojasnyc/hr-mcp-server)

- **ID**: `X-03`
- **Severity**: `medium`
- **Filter reason**: `kept`
- **Details**: ```[{"before": [], "after": [{"name": "request_global_leave", "inputSchema": {"type": "object", "properties": {"employee_id": {"type": "string", "description": "The ID of the employee requesting leave"}, "start_date": {"type": "string", "description": "Start date of the leave (YYYY-MM-DD)"}, "end_date": {"type": "string", "description": "End date of the leave (YYYY-MM-DD)"}, "reason": {"type": "string", "description": "Reason for the leave request"}, "countries": {"type": "array", "items": {"type": "string"}, "description": "Countries for which leave is being requested (e.g., [\"USA\", \"UK\"])"}, "contact_info": {"type": "object", "properties": {"email": {"type": "string", "description": "Contact email during leave"}, "phone": {"type": "string", "description": "Contact phone during leave"}, ... [troncato]```


*... e altri 37 finding*

## Interpretazione

I finding tenuti indicano server dove le tool description sono cambiate tra la prima e la seconda chiamata. Questo potrebbe indicare un server che modifica il proprio comportamento dopo l'installazione.

## Lista completa server vulnerabili

- https://github.com/8beeeaaat/touchdesigner-mcp
- https://github.com/Alirezawmoradi/github-follower-manager-mcp
- https://github.com/BMSoft1024/Common_MCP_Gateway
- https://github.com/ITSpecialist111/Agent365-Bridge
- https://github.com/JavaProgrammerLB/zoom-mcp-server
- https://github.com/Jeremy-Min-Yang/minecraft-mcp-server-pixel
- https://github.com/LupinLin1/wechatlog-mcp-server
- https://github.com/Olanetsoft/midnight-mcp
- https://github.com/PSPDFKit/nutrient-dws-mcp-server
- https://github.com/RachidChabane/mcp-secrets-vault
- https://github.com/ReAPI-com/mcp-openapi
- https://github.com/ShubhanshuSondhiya/MCP-TMDB
- https://github.com/abhirockzz/mcp_cosmosdb_go
- https://github.com/alucardeht/isis-mcp
- https://github.com/askme765cs/open-docs-mcp
- https://github.com/basin-ai/basin-mcp
- https://github.com/bsmi021/mcp-file-context-server
- https://github.com/btwiuse/npm-search-mcp-server
- https://github.com/cablate/mcp-google-gmail
- https://github.com/datum-cloud/datum-mcp
- https://github.com/digitalocean/digitalocean-mcp
- https://github.com/dsflon/floncss-mcp
- https://github.com/fastmcp-me/nutrient-dws-mcp-server
- https://github.com/gabrielrojasnyc/hr-mcp-server
- https://github.com/hibukki/minecraft-mcp-server
- https://github.com/hongkongkiwi/medium-scraper-mcp
- https://github.com/kevinwatt/shell-mcp
- https://github.com/khalideidoo/gcloud-go-mcp
- https://github.com/kmwebnet/MCP-Server-for-sensor-device
- https://github.com/koltyakov/godot-mcp
- https://github.com/lambdasawa/oob-probe-mcp-server
- https://github.com/lkendrickd/mcp-server
- https://github.com/mettamatt/code-reasoning
- https://github.com/moises-paschoalick/ai-agent-with-mcp
- https://github.com/omd0/srt-mcp
- https://github.com/orvice/google-workspace-mcp
- https://github.com/p-c-mo/another-pg-mcp
- https://github.com/pjy998/cmmi-specs-agent
- https://github.com/rodhayl/mcpLocalHelper
- https://github.com/shelajev/developer-events-mcp
- https://github.com/taigrr/obsidian-mcp
- https://github.com/tan-yong-sheng/ai-vision-mcp
- https://github.com/thesammykins/notifyme_mcp
- https://github.com/tofunori/mcp-jupyter-complete
- https://github.com/umputun/local-docs-mcp
- https://github.com/wishmaster127/writing-tools-mcp
- https://github.com/wonderwhy-er/DesktopCommanderMCP
- https://github.com/worldnine/textwell-mcp
- https://github.com/wrenchpilot/it-tools-mcp
- https://github.com/xuejike/coding-db-mcp
- https://github.com/yikakia/godoc-mcp-server
- https://github.com/yokingma/one-search-mcp
