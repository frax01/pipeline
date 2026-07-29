# dangerous-capabilities (X-01) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Tool con capacita' pericolose (esecuzione comandi, scrittura/cancellazione file, modifica permessi). Lo scanner usa keyword generiche ('fetch', 'http', 'url', 'admin') che generano moltissimi FP su tool read-only. Il filtro tiene solo tool che REALMENTE eseguono comandi, scrivono/cancellano file, o hanno parametri pericolosi senza constraint.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 3112 |
| Finding filtrati (tenuti) | 785 |
| Rimossi | 2327 |
| Tasso di riduzione | 74.8% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `REJECTED:all_tools_safe` | 2293 |
| `KEPT:kept_1_of_1` | 233 |
| `KEPT:kept_1_of_2` | 143 |
| `KEPT:kept_1_of_3` | 61 |
| `KEPT:kept_1_of_4` | 43 |
| `KEPT:kept_2_of_2` | 38 |
| `REJECTED:details_not_parseable` | 34 |
| `KEPT:kept_2_of_3` | 29 |
| `KEPT:kept_1_of_5` | 28 |
| `KEPT:kept_2_of_4` | 17 |
| `KEPT:kept_1_of_7` | 15 |
| `KEPT:kept_2_of_5` | 13 |
| `KEPT:kept_1_of_8` | 11 |
| `KEPT:kept_3_of_3` | 10 |
| `KEPT:kept_2_of_6` | 10 |
| `KEPT:kept_2_of_7` | 9 |
| `KEPT:kept_1_of_6` | 9 |
| `KEPT:kept_1_of_9` | 8 |
| `KEPT:kept_3_of_5` | 6 |
| `KEPT:kept_3_of_7` | 6 |
| `KEPT:kept_1_of_12` | 5 |
| `KEPT:kept_1_of_10` | 5 |
| `KEPT:kept_2_of_13` | 5 |
| `KEPT:kept_1_of_11` | 5 |
| `KEPT:kept_2_of_10` | 4 |
| `KEPT:kept_1_of_13` | 4 |
| `KEPT:kept_4_of_5` | 4 |
| `KEPT:kept_2_of_11` | 3 |
| `KEPT:kept_4_of_12` | 3 |
| `KEPT:kept_3_of_4` | 3 |
| `KEPT:kept_2_of_9` | 3 |
| `KEPT:kept_3_of_10` | 3 |
| `KEPT:kept_4_of_4` | 2 |
| `KEPT:kept_3_of_12` | 2 |
| `KEPT:kept_1_of_23` | 2 |
| `KEPT:kept_3_of_6` | 2 |
| `KEPT:kept_1_of_40` | 2 |
| `KEPT:kept_1_of_14` | 2 |
| `KEPT:kept_6_of_6` | 2 |
| `KEPT:kept_1_of_37` | 1 |
| `KEPT:kept_5_of_21` | 1 |
| `KEPT:kept_2_of_25` | 1 |
| `KEPT:kept_1_of_19` | 1 |
| `KEPT:kept_3_of_66` | 1 |
| `KEPT:kept_5_of_5` | 1 |
| `KEPT:kept_4_of_8` | 1 |
| `KEPT:kept_5_of_23` | 1 |
| `KEPT:kept_15_of_15` | 1 |
| `KEPT:kept_4_of_21` | 1 |
| `KEPT:kept_2_of_15` | 1 |
| `KEPT:kept_5_of_10` | 1 |
| `KEPT:kept_5_of_9` | 1 |
| `KEPT:kept_9_of_44` | 1 |
| `KEPT:kept_3_of_9` | 1 |
| `KEPT:kept_5_of_106` | 1 |
| `KEPT:kept_1_of_15` | 1 |
| `KEPT:kept_2_of_16` | 1 |
| `KEPT:kept_3_of_21` | 1 |
| `KEPT:kept_2_of_21` | 1 |
| `KEPT:kept_6_of_8` | 1 |
| `KEPT:kept_4_of_15` | 1 |
| `KEPT:kept_2_of_14` | 1 |
| `KEPT:kept_1_of_75` | 1 |
| `KEPT:kept_4_of_17` | 1 |
| `KEPT:kept_3_of_42` | 1 |
| `KEPT:kept_3_of_11` | 1 |
| `KEPT:kept_2_of_8` | 1 |
| `KEPT:kept_1_of_18` | 1 |
| `KEPT:kept_4_of_45` | 1 |
| `KEPT:kept_1_of_16` | 1 |
| `KEPT:kept_6_of_73` | 1 |
| `KEPT:kept_4_of_50` | 1 |
| `KEPT:kept_5_of_8` | 1 |
| `KEPT:kept_7_of_25` | 1 |

## Server unici con vulnerabilita' reali: 785

## Esempi di finding tenuti (max 15)

### 1. [docker-mcp-server](https://github.com/0xshariq/docker-mcp-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_2_of_3`
- **Details**: ```[{"name": "docker-compose", "description": "Run Docker Compose commands", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "Docker Compose command to run (e.g., 'up', 'down')"}, "filePath": {"type": "string", "description": "Path to the Docker Compose file"}, "projectName": {"type": "string", "description": "Project name for Docker Compose"}}, "required": ["command"]}, "_filter_reason": "dangerous_desc:\\b(docker.*(exec\|run\|compose))"}, {"name": "docker-exec", "description": "Execute a command in a running Docker container", "inputSchema": {"type": "object", "properties": {"containerId": {"type": "string", "description": "ID of the Docker container"}, "command": {"type": "string", "description": "Command to execute inside the container"}, "inter... [troncato]```

### 2. [mcp-1panel](https://github.com/1Panel-dev/mcp-1panel)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"description": "install openresty, if not set name, default is openresty, if not set http_port, default is 80, if not set https_port, default is 443", "inputSchema": {"type": "object", "properties": {"name": {"type": "string", "description": "openresty name"}, "http_port": {"type": "number", "description": "openresty http port"}, "https_port": {"type": "number", "description": "openresty https port"}}, "additionalProperties": false}, "name": "install_openresty", "_filter_reason": "dangerous_desc:\\b(install\|uninstall)\\s+"}]```

### 3. [mcp-devcontainers](https://github.com/AI-QL/mcp-devcontainers)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_5`
- **Details**: ```[{"name": "devcontainer_exec", "description": "Runs a custom shell command inside the devcontainer for the specified workspace. Useful for executing arbitrary commands or scripts within the devcontainer environment.", "inputSchema": {"type": "object", "properties": {"workspaceFolder": {"type": "string", "description": "Path to the workspace folder (string)"}, "stdioFilePath": {"type": "string", "description": "Path for output logs (string), default is /dev/null"}, "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Command to execute (array of string)"}}, "required": ["workspaceFolder", "command"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "_filter_reason": "unconstrained_param:command"}]```

### 4. [mcp-salesforce](https://github.com/AiondaDotCom/mcp-salesforce)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_5`
- **Details**: ```[{"name": "salesforce_query", "description": "Execute SOQL queries against any Salesforce object. Supports SELECT, WHERE, ORDER BY, LIMIT, and other SOQL features.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "SOQL query string (e.g., 'SELECT Id, Name FROM Account WHERE Industry = \\'Technology\\' LIMIT 10'). Use proper SOQL syntax with single quotes for string literals."}}, "required": ["query"]}, "_filter_reason": "unconstrained_param:query"}]```

### 5. [hyperbolic-mcp](https://github.com/HyperbolicLabs/hyperbolic-mcp)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"name": "remote-shell", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "Command to execute on the remote server"}}, "required": ["command"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "_filter_reason": "dangerous_name:\\b(exec\|execute\|run_command\|run_shell\|shell\|bash\|terminal\|subprocess)\\b"}]```

### 6. [memos-api-mcp](https://github.com/MemTensor/memos-api-mcp)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_7`
- **Details**: ```[{"name": "search_memory", "description": "\n  Trigger: MUST be auto-invoked by the client before generating every answer (including greetings like \"hello\"). Do not wait for the user to request memory/MCP/tool usage.\n  Purpose: MemOS retrieval API. Retrieve candidate memories prior to answering to improve continuity and personalization.\n  ## 👤 Identity Query Rule\n  - If the user asks \"Who am I?\", \"What is my profile?\", or asks for a summary of what you know about them/their identity/habits:\n    1. Call this tool (`search_memory`) to find recent context.\n    2. **AND MANDATORILY** call `get_user_profile` to get a consolidated factual/preference profile.\n    - Semantic search alone is insufficient for a holistic identity summary.\n  Usage requirements:\n    - Always call this too... [troncato]```

### 7. [mcp-neovim-server](https://github.com/bigcodegen/mcp-neovim-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"name": "vim_command", "description": "Execute Vim commands with optional shell command support", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "Vim command to execute (use ! prefix for shell commands if enabled)"}}, "required": ["command"], "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "_filter_reason": "unconstrained_param:command"}]```

### 8. [iterm-mcp](https://github.com/ferrislucas/iterm-mcp)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_3`
- **Details**: ```[{"name": "write_to_terminal", "description": "Writes text to the active iTerm terminal - often used to run a command in the terminal", "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "description": "The command to run or text to write to the terminal"}}, "required": ["command"]}, "_filter_reason": "dangerous_desc:\\b(run\\s+(a\\s+)?(shell\|command\|script\|bash))"}]```

### 9. [graphlit-mcp-server](https://github.com/graphlit/graphlit-mcp-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_37`
- **Details**: ```[{"name": "ingestTwitterSearch", "description": "Searches for recent posts from Twitter/X, and ingests them into Graphlit knowledge base.\n    Accepts search query, and an optional read limit for the number of posts to ingest.\n    Requires environment variable to be configured: TWITTER_TOKEN.\n    Executes asynchronously, creates Twitter feed, and returns the feed identifier. Optionally creates a recurring feed that checks for new content every 15 minutes when 'recurring' is set to true.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query"}, "readLimit": {"type": "number", "description": "Number of posts to ingest, optional. Defaults to 100."}, "recurring": {"type": "boolean", "default": false, "description": "Whether to create a rec... [troncato]```

### 10. [consul-mcp-server](https://github.com/kocierik/consul-mcp-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_4`
- **Details**: ```[{"name": "execute-prepared-query", "description": "Execute a prepared query", "inputSchema": {"type": "object", "properties": {"id": {"type": "string", "default": "", "description": "ID of the prepared query"}}, "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}, "_filter_reason": "dangerous_name:\\b(exec\|execute\|run_command\|run_shell\|shell\|bash\|terminal\|subprocess)\\b"}]```

### 11. [mcp-compass](https://github.com/liuyoshio/mcp-compass)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_1`
- **Details**: ```[{"name": "recommend-mcp-servers", "description": "\n          Use this tool when there is a need to findn external MCP tools.\n          It explores and recommends existing MCP servers from the \n          internet, based on the description of the MCP Server \n          needed. It returns a list of MCP servers with their IDs, \n          descriptions, GitHub URLs, and similarity scores.\n          ", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "\n                Description for the MCP Server needed. \n                It should be specific and actionable, e.g.:\n                GOOD:\n                - 'MCP Server for AWS Lambda Python3.9 deployment'\n                - 'MCP Server for United Airlines booking API'\n                - 'MCP Serv... [troncato]```

### 12. [glean-mcp-server](https://github.com/longyi1207/glean-mcp-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_1`
- **Details**: ```[{"name": "search", "description": "Tool to perform search queries using Glean API", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "The query to perform retrieval on"}}, "required": ["query"]}, "_filter_reason": "unconstrained_param:query"}]```

### 13. [clarity-mcp-server](https://github.com/microsoft/clarity-mcp-server)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_1_of_1`
- **Details**: ```[{"name": "query-analytics-dashboard", "description": "Fetch Microsoft Clarity analytics data using a simplified natural language search query. The query should be focused on one specific data retrieval or aggregation task. Avoid complex multi-purpose queries. Time ranges should be explicitly specified when possible. If no time range is provided, prompt the user to specify one.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "A natural language search query string for filtering and shaping analytics data. The query should be specific and include temporal constraints when available. (e.g., 'Top browsers last 3 days', 'The active time duration for mobile devices in United States last week'). Time ranges should be explicitly specified when possibl... [troncato]```

### 14. [adobe-commerce-dev-mcp](https://github.com/rafaelstz/adobe-commerce-dev-mcp)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_2_of_2`
- **Details**: ```[{"name": "introspect_admin_graphql_schema", "description": "This tool introspects and returns the portion of the Adobe Commerce GraphQL schema relevant to the user prompt. Only use this for the Adobe Commerce API. Uses Adobe Commerce version 2.4.8.\n\n    It takes two arguments: query and filter. The query argument is the string search term to filter schema elements by name. The filter argument is an array of strings to filter results to show specific sections.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Search term to filter schema elements by name. Only pass simple terms like 'product', 'category', etc."}, "filter": {"type": "array", "items": {"type": "string", "enum": ["all", "types", "queries", "mutations"]}, "default": ["all"], "desc... [troncato]```

### 15. [github-projects-mcp](https://github.com/redducklabs/github-projects-mcp)

- **ID**: `X-01`
- **Severity**: `high`
- **Filter reason**: `kept_2_of_11`
- **Details**: ```[{"name": "execute_custom_project_query", "description": "Execute a custom GraphQL query for maximum flexibility\n\n    SECURITY: This tool validates queries to prevent mutations and schema introspection.\n    Only 'query' operations are allowed, not 'mutation' or 'subscription'.\n\n    PAGINATION: Server limits pagination to 25 items per request for performance.\n    Use 'first: 25' and cursor-based pagination for large datasets.\n\n    EFFICIENCY: Select only needed fields to reduce response size. Full project item\n    data can exceed 25KB for just 20 items.\n\n    CRITICAL: For counting, you MUST paginate through ALL results if hasNextPage=true.\n\n    Args:\n        query: Complete GraphQL query string (queries only, no mutations)\n        variables: JSON string of query variables (op... [troncato]```


*... e altri 770 finding*

## Interpretazione

I finding tenuti sono tool che **realmente** eseguono comandi di sistema, scrivono/cancellano file, o hanno parametri di tipo 'command'/'shell' senza constraint (enum, pattern, maxLength). Questi tool rappresentano un rischio reale se accessibili senza autenticazione.

I finding scartati sono tool flaggati per keyword generiche come 'fetch', 'http', 'url', 'admin' che in realta' sono read-only o data fetching.

## Lista completa server vulnerabili

- https://github.com/0brym/mcp
- https://github.com/0xshariq/docker-mcp-server
- https://github.com/1999AZZAR/project-guardian-mcp-server
- https://github.com/1Panel-dev/mcp-1panel
- https://github.com/2black0/enhanced-iterm-mcp-server
- https://github.com/3dean/blender_mcp_server
- https://github.com/4bd4ll4h/mcp-devtools-browser
- https://github.com/9olidity/MCP-Server-Pentest
- https://github.com/AI-QL/mcp-devcontainers
- https://github.com/AbdurRaahimm/mcp-git-terminal-server
- https://github.com/Abinesh0206/kube-mcp
- https://github.com/Adnanrizvi0242/mcp-orchestration
- https://github.com/AeaZer/mcp-elasticsearch
- https://github.com/AerialByte/mcp-netcoredbg
- https://github.com/Agencia-Tecnologica-Multiverse-Limitada/UX-UI-MCP
- https://github.com/AiondaDotCom/mcp-salesforce
- https://github.com/AkibaAT/ddev-mcp
- https://github.com/Akira-Papa/macOS-GUI-Control-MCP
- https://github.com/AlemzhanJ/strayl-mcp
- https://github.com/AlexGladkov/claude-in-mobile
- https://github.com/Amana03/universal-mcp-server
- https://github.com/Anansitrading/sprite-mcp-server
- https://github.com/Anarkh-Lee/universal-db-mcp
- https://github.com/AreAArseth/tmux-mcp
- https://github.com/ArvidSU/contractor
- https://github.com/AshwathDAzur/mcp-localdata-ai-bridge
- https://github.com/Atomzzm/mcp-mysql-server
- https://github.com/Automata-Labs-team/MCP-Server-Playwright
- https://github.com/Avinier/replit-mcp
- https://github.com/Beledarian/mcp-local-memory
- https://github.com/BessColeridge/newline
- https://github.com/Beyond-Network-AI/beyond-mcp-server
- https://github.com/BradA1878/mcp-wave
- https://github.com/BrawlerXull/System-Monitoring-MCP
- https://github.com/BridgerB/metabase-mcp
- https://github.com/Cam10001110101/mcp-server-obsidian-jsoncanvas
- https://github.com/CharlieKerfoot/code-execution-mcp
- https://github.com/ChrisL108/electron-ui-mcp
- https://github.com/ChristianSch/openrouter-websearch-mcp
- https://github.com/Cocoon-AI/mcp-perforce
- https://github.com/Countly/countly-mcp-server
- https://github.com/Crypto-Goatz/rocket-plus-mcp
- https://github.com/Curzibn/mcp-bisheng
- https://github.com/Cyronius/claude-database-tools
- https://github.com/DanNsk/multi-memory-mcp
- https://github.com/DavidCho1999/Canada-AEC-Code-MCP
- https://github.com/DavidOsherdiagnostica/cost-plus-drugs
- https://github.com/DeepaRajareddy/redshift_mcp_server
- https://github.com/DevAdalat/colab-mcp
- https://github.com/Digital-Defiance/mcp-debugger-server
- https://github.com/Dynamic-Mockups/mcp
- https://github.com/ESnark/blowback
- https://github.com/Ebop14/slander_mcp
- https://github.com/EmersonGarrido/mcp-project-context
- https://github.com/Entropy-Is-Software-Development/zed-shell-mcp-server
- https://github.com/Esty8321/git-mcp-server
- https://github.com/Eutectico/mcp-kali-server
- https://github.com/EvalVis/webreadmcp
- https://github.com/EveryInc/sparkle-mcp-server
- https://github.com/ExpertVagabond/raycast-mcp-server
- https://github.com/FYZAFH/mcp-codex-dev
- https://github.com/Ferreyrajp/MCP-Filesystem-Server---Python
- https://github.com/FloSch62/clab-mcp-server
- https://github.com/FreddyE1982/mcp2term
- https://github.com/FrontMage/ssh-mcp-go
- https://github.com/GILSMON/mcpServer_as_gatekeeper
- https://github.com/GalSened/mcp-filesystem-server
- https://github.com/GaloisHLee/mcp-server-sagemath
- https://github.com/Garoth/wolframalpha-llm-mcp
- https://github.com/Ghostwillower/Pc-MCP
- https://github.com/GitJuhb/zellij-mcp-server
- https://github.com/Gmacem/mcp-ssh-ops
- https://github.com/Gopenux/Siigo-MCP
- https://github.com/Gorav22/TerminusAI
- https://github.com/GuDaStudio/GrokSearch
- https://github.com/GuangYiDing/mysql-mcp-server
- https://github.com/Hadar301/mcp-openshift-installer-checker
- https://github.com/Hanny658/browser-mcp-demo
- https://github.com/HarleyVader/llm-toolshed-mcp-server
- https://github.com/HatriGt/hana-mcp-server
- https://github.com/Helms-AI/openclaw-mcp-server
- https://github.com/Hor1zonZzz/terminal-mcp
- https://github.com/HowardQin/fastmcp-opengauss
- https://github.com/HyperbolicLabs/hyperbolic-mcp
- https://github.com/IQAIcom/defillama-mcp
- https://github.com/InstalabsAI/instagit
- https://github.com/Ipiano/gdb-mcp
- https://github.com/Isydoria/mcp-workflow-analyse-cv
- https://github.com/IzumiSy/mcp-universal-db-client
- https://github.com/JackRiebel/network-rag-mcp
- https://github.com/JeremyProffitt/go-mcp-commander
- https://github.com/JesseObrien/mcp-debug-server
- https://github.com/Jing-yilin/twitterapi-mcp-server
- https://github.com/JohanCodinha/nrepl-mcp-server
- https://github.com/Juand4rck12/mcp-pos-server
- https://github.com/KevinRabun/GDPRShiftLeftMCP
- https://github.com/KinoThe-Kafkaesque/ssh-mcp-server
- https://github.com/Kishore-MK/ai42-mcp
- https://github.com/KotoriK/browserslist-mcp
- https://github.com/Kranthithota/codedev-mcp
- https://github.com/Krelborn/docker-compose-mcp
- https://github.com/LokiMCPUniverse/zoho-crm-mcp-server
- https://github.com/LukeL99/enhanced-filesystem-mcp
- https://github.com/Lyonk71/joplin-mcp
- https://github.com/MOHCentral/opm-mcp-server
- https://github.com/MadeByTokens/browser-mcp-server
- https://github.com/MagnusJohansson/siglent-sds-mcp
- https://github.com/MaraBank/mcp-ssh-server
- https://github.com/MarcoLooy/pega-dx-mcp
- https://github.com/MausRundung/mcp-explorer
- https://github.com/MaxSmithy/FordMCP
- https://github.com/MaykolMedrano/mcp_bcrp
- https://github.com/MemTensor/memos-api-mcp
- https://github.com/MerzoukeMansouri/adeo-mozaic-mcp
- https://github.com/MiguelMartinezCV/chatvolt-mcp
- https://github.com/MikeyBeez/mcp-reasoning-tools
- https://github.com/MissionSquad/mcp-helper-tools
- https://github.com/Mming-Lab/minecraft-bedrock-mcp-server
- https://github.com/MobAI-App/mobai-mcp
- https://github.com/MoebiusSt/indesign-scripting-mcp
- https://github.com/MrFixit96/go-dev-mcp
- https://github.com/MrGNSS/ClaudeDesktopCommander
- https://github.com/MyPrototypeWhat/mcp-auto-install
- https://github.com/NOVA-3951/Replit-MCP
- https://github.com/Nam088/mcp-database-server
- https://github.com/Nexlab-One/python-vlang-mcp
- https://github.com/NickSmet/mcp-local-memory
- https://github.com/Nicolas-Gong/mysql-crud-mcp-server
- https://github.com/NightTrek/Ollama-mcp
- https://github.com/Nipurn123/duckduckgo-mcp
- https://github.com/Nonetss/none.api
- https://github.com/PDurgaJayaRam/Web-MCP-Server
- https://github.com/PasinduSupushmika/kali-docker-vapt
- https://github.com/PedroaHosing/mcp-grafana
- https://github.com/Pharbi/mcp-impresario
- https://github.com/PleasePrompto/google-ai-mode-mcp
- https://github.com/PonClick/marktplaats-mcp
- https://github.com/Priyonuj/mcp-file-navigator
- https://github.com/QianChenglong/obsidian-cdp-mcp
- https://github.com/Quentinchampenois/shell-history-mcp-server
- https://github.com/Qvakk/terraform-registry-mcp-server
- https://github.com/REMnux/remnux-mcp-server
- https://github.com/Radek44/mcp-tauri-automation
- https://github.com/RestDB/codehooks-mcp-server
- https://github.com/RinardNick/mcp-terminal
- https://github.com/Robbie1977/VFB3-MCP
- https://github.com/RonaldDegsa/server-everything
- https://github.com/RuneLind/mcp-maven-test-runner
- https://github.com/RuoJi6/fofa_quake_hunter_mcp
- https://github.com/SJMakin/even-better-playwright-mcp
- https://github.com/SabirAliyev/mcp-pro
- https://github.com/Sai-Adarsh/coyote-mcp-server
- https://github.com/SaintDoresh/Weather-MCP-ClaudeDesktop
- https://github.com/SalesforceDiariesBySanket/salesforce-docs-mcp
- https://github.com/SamMorrowDrums/remarkable-mcp
- https://github.com/SayreBlades/mcp-web-tools
- https://github.com/Sceat/sui-graphql-mcp
- https://github.com/Sergiolm17/mcp-shalom
- https://github.com/Sharmaz/phoenixd-mcp-server
- https://github.com/ShayYeffet/mcp_server
- https://github.com/StarJumper-ElevenLabs/starjumper-demo-mcp
- https://github.com/StealthBadger747/mcp-omnienv-nix
- https://github.com/Step-by-Step-technology/pocketbase-mcp
- https://github.com/StrawHatAI/claude-dev-tools
- https://github.com/Streen9/terminal-mcp
- https://github.com/Sunwood-ai-labs/command-executor-mcp-server
- https://github.com/Sunwood-ai-labs/duckduckgo-web-search
- https://github.com/Swartdraak/Docker-MCP
- https://github.com/Syncause/mcp-server
- https://github.com/Szowesgad/automator-mcp
- https://github.com/T1Trit/yandex-browser-mcp
- https://github.com/TNTisdial/persistent-shell-mcp
- https://github.com/TaichiHo/k8s-interactive-mcp
- https://github.com/TauqeerAhmad5201/docker-mcp-extension
- https://github.com/TechnicalRhino/cubeapm-mcp
- https://github.com/Teja-sudo/postgres-mcp-server
- https://github.com/TeodorTrotea/mcptest
- https://github.com/TheDarkSkyXD/debug-electron-mcp
- https://github.com/Timtech4u/deno-mcp-server
- https://github.com/TrentBrown/iterm-mcp
- https://github.com/UjjwalSk/tempo-mcp-server
- https://github.com/VAST-AI-Research/tripo-mcp
- https://github.com/Vijaydaswani/openai-mcp-demo
- https://github.com/Vivusk/mcp-ssh-persistent
- https://github.com/WeiWeicode/20250923MCPtest
- https://github.com/WilliamCloudQi/matlab-mcp-server
- https://github.com/Winds-AI/MSSQL_MCP_Server-custom-fork-
- https://github.com/Wladastic/AutoProbeMCP
- https://github.com/XiaoLuoTian189/ezbt-mcp
- https://github.com/XunMInt/cisco-cli-mcp
- https://github.com/Xuzan9396/xz_mcp
- https://github.com/YUChoe/sqlite-mcp
- https://github.com/YanivGabay/AirConditionMcp
- https://github.com/Yukendiran2002/browser_mcp
- https://github.com/Zaptimist/mcp-proxmox
- https://github.com/Zetrix-Chain/zetrix-mcp-server
- https://github.com/Zhwt/go-mcp-mysql
- https://github.com/a13-team/filesystem-mcp-ignore
- https://github.com/aakash231217/mcp_server_assignment
- https://github.com/abbasnosrat/MCPServerAgent
- https://github.com/abhirockzz/mcp_kusto
- https://github.com/abhishekcbanaj/mcp-filesystem-server
- https://github.com/ablagodarenko/crash_mcp
- https://github.com/achuajays/latest-news-fetcher-mcp
- https://github.com/acro5piano/mcp-auto-browser
- https://github.com/adamdude828/mcp-server-docker
- https://github.com/adamteece/pendo-mcp-code-exec
- https://github.com/admin-skooler/nota-mcp-test
- https://github.com/afreakk/qutebrowser-mcp
- https://github.com/afshawnlotfi/mcp-configurable-puppeteer
- https://github.com/agent3-666/agent3-mcp-registry
- https://github.com/ahmedrowaihi/mcp-server-playwright-headless
- https://github.com/ahmetbarut/mcp-database-server
- https://github.com/aiforhumans/local-utils-mcp
- https://github.com/akkytech0617/letta-cloud-mcp
- https://github.com/alc0der/mergestat-mcp
- https://github.com/aledlie/doppler-mcp
- https://github.com/alephtex/perplexity-mcp-server
- https://github.com/alexmeckes/godot-mcp
- https://github.com/algae514/terminal-mcp-server
- https://github.com/allegiant/MQScript_MCP
- https://github.com/allenyzh/mcp-server-commandline
- https://github.com/alphatheory-ccarneiro/document-edit-mcp
- https://github.com/alxspiker/Windows-Command-Line-MCP-Server
- https://github.com/amafjarkasi/electron-mcp-server
- https://github.com/amankale376/calculator-mcp-server
- https://github.com/amarodeabreu/sensei-mcp
- https://github.com/amotivv/soulver-mcp-server
- https://github.com/amusphere/mcp-db
- https://github.com/anand-kamble/mcp-instagram
- https://github.com/ananya5151/pok-mon-battle-simulation
- https://github.com/anchore/grype-mcp
- https://github.com/andrelip/paginate-mcp
- https://github.com/andresthor/cmd-line-mcp
- https://github.com/andrewgazelka/arc-mcp
- https://github.com/angiejones/mcp-selenium
- https://github.com/animalang/mcp-llvm
- https://github.com/anton-107/server-run-commands
- https://github.com/antonorlov/mcp-postgres-server
- https://github.com/antonpme/auralis-commander
- https://github.com/anyrxo/proton-drive-mcp
- https://github.com/aplavin/julia-mcp
- https://github.com/appknox/appknox-mcp
- https://github.com/apvlv/davinci-resolve-mcp
- https://github.com/arielolin/apiiro-mongo-mcp
- https://github.com/aroshak/cisco-ssh-mcp
- https://github.com/ashellearl123/mysql_mcp
- https://github.com/ashenud/mcp-mysql-server
- https://github.com/ashok9315-cmyk/mcp-server-google-bigquery
- https://github.com/asoluka/antigravity-pdf-mcp
- https://github.com/aswinsuryan/gcp-openshift-mcp-server
- https://github.com/athapong/aio-mcp
- https://github.com/atlcomgit/mcp-ssh
- https://github.com/auchenberg/claude-code-mcp
- https://github.com/audreyui/components-build-mcp
- https://github.com/availsthlm/chrome-devtools-mcp-server
- https://github.com/avi892nash/purescript-mcp-tools
- https://github.com/avisangle/calculator-server
- https://github.com/azcoigreach/screeps-mcp
- https://github.com/azza39925/kali-mcp-server
- https://github.com/bacarrdy/mcp-ssh-server
- https://github.com/badchars/mcp-browser
- https://github.com/badchars/mcp-browser-injection-extented
- https://github.com/bbdaniels/kobo-mcp
- https://github.com/bbssppllvv/apple-docs-mcp-server
- https://github.com/bdwyertech/mcp-atlassian-server
- https://github.com/benbobenbo/mcp-server
- https://github.com/bendichter/dandi-query-mcp
- https://github.com/benoute/calibre-mcp
- https://github.com/benoute/grokipedia
- https://github.com/bensonfx/mcp-liner
- https://github.com/bgbruno/bg-server-mcp-shell
- https://github.com/bgreene2/wolfram-alpha-mcp-server
- https://github.com/bharathRathod23/ORACLE-MCP-SERVER
- https://github.com/bigcodegen/mcp-neovim-server
- https://github.com/billallison/brsearch-mcp-server
- https://github.com/bleugreen/cli-bridge
- https://github.com/blink-new/browser-mcp
- https://github.com/boazFridenberg/mcp-AppsFlyer-sdk
- https://github.com/bobbyhiddn/Sympathy-MCP
- https://github.com/brkhrdt/pty-mcp
- https://github.com/brownrl/eco_mcp
- https://github.com/bryantanderson/kubernetes-mcp-server
- https://github.com/bsmi021/mcp-file-operations-server
- https://github.com/bsmi021/mcp-python-executor
- https://github.com/bypawel/tachibot-mcp
- https://github.com/c3ptv3/simple-tempo-mcp-server
- https://github.com/callnirajgupta/mcp-playwright-server
- https://github.com/cameronking4/mcp-azure-cloudshell
- https://github.com/cameronking4/orchestrator-mcp
- https://github.com/captainChaozi/search-intent-mcp
- https://github.com/carpathiansalt/MCP-Flutter-Livekit-Team
- https://github.com/ceciliomichael/mcp-filesystem
- https://github.com/cfdude/mac-shell-mcp
- https://github.com/cfdude/super-shell-mcp
- https://github.com/chaitanyaiscoding/MCP_Database_Tools-
- https://github.com/chenz4027/postgres-mcp
- https://github.com/chittyos/chittymcp
- https://github.com/chrishayuk/chuk-mcp-solver
- https://github.com/ciborro/jina-light-mcp
- https://github.com/cicarulez/mcp-build-verifier
- https://github.com/circuitry-dev/circuitry-mcp-server
- https://github.com/clarifyhealth/cms-datagov-mcp-server
- https://github.com/claudiotx/coding-cloud-mcp
- https://github.com/cloudbring/newrelic-mcp
- https://github.com/cloudsmithy/easysearch-mcp-server
- https://github.com/cloudwarriors-ai/mcp-docs
- https://github.com/cmiretf/pattern-police-mcp
- https://github.com/code-alchemist01/project-managment-mcp-Server
- https://github.com/code-craka/puppeteer-mcp
- https://github.com/codenjoyme/mcpyrex-javascript
- https://github.com/codingsasi/ddev-mcp
- https://github.com/conorluddy/xc-mcp
- https://github.com/cookchen233/mycli-dms-mcp
- https://github.com/coolbit-in/docker-mcp
- https://github.com/craverath/postgres_mcp_cra
- https://github.com/credentum/ao-mcp-server
- https://github.com/crexative/colombia-mcp-server
- https://github.com/cupkappu/mcp-obsidian-server
- https://github.com/cvrt-jh/wordpress-mcp
- https://github.com/dadepo/whois-mcp
- https://github.com/dalager/obsidian-mcp
- https://github.com/danielsimonjr/math-mcp
- https://github.com/dannwaneri/mcp-knowledge-base-server
- https://github.com/dannwaneri/vectorize-mcp-server
- https://github.com/dattm283/mcp-server-incident-pilot
- https://github.com/davejohnson/infraprint
- https://github.com/davisdane2/mssql-mcp-vscode-extratools
- https://github.com/deadraid/mcp-postgresql
- https://github.com/deepkl/mcp-searxng
- https://github.com/deepsuthar496/Remote-Command-MCP
- https://github.com/democratize-technology/claude-code-mcp
- https://github.com/dharmit01/postgres-mcp
- https://github.com/dheersingh1973/mcp-mysql
- https://github.com/dillip285/mcp-terminal
- https://github.com/dimitar-grigorov/mcp-file-tools
- https://github.com/dims/kubectl-mcp
- https://github.com/disnet/flint-note-mcp
- https://github.com/dmmulroy/opensrc-mcp
- https://github.com/dockergiant/rolldev-mcp-server
- https://github.com/donnel666/uart-mcp
- https://github.com/doppelgangersai/context-mcp-server
- https://github.com/dorhaimovich/coralogix-mcp-server
- https://github.com/drn74/mcp-ffmpeg-server
- https://github.com/drx-1877/dev-tools
- https://github.com/dsinghbailey/dependency-context
- https://github.com/dvillegastech/flutter_mcp_2
- https://github.com/dwmkerr/shellwright-mcp-server
- https://github.com/earthlingai/command
- https://github.com/ebeloded/bun-mcp
- https://github.com/eddevfront/mysql-mcp-server
- https://github.com/eddie-rembrandt/MCP-CodeV
- https://github.com/eddykuhan/postgres-mcp
- https://github.com/egoist/shell-command-mcp
- https://github.com/el95149/baloosearch-mcp
- https://github.com/elber-code/database-tools
- https://github.com/elcamino666/kali-mcp
- https://github.com/ememni/mcp
- https://github.com/endgame-hq/mcp
- https://github.com/enemyrr/mcp-mysql-server
- https://github.com/enigma522/secure-python-mcp-server
- https://github.com/eramitmittal/file_tools_mcp
- https://github.com/erhansiraci/ue-mcp
- https://github.com/eshvargb/MCP_ClaudeAI
- https://github.com/eugener/jarvis-mcp
- https://github.com/f2cmb/firefox-dev-tools-mcp
- https://github.com/fabiothiroki/mcp-local-analyst
- https://github.com/fabiovige/mcp-mysql-simple
- https://github.com/fastmcp-me/mcp-modus
- https://github.com/fastmcp-me/mcp-mysql
- https://github.com/fastmcp-me/playwright-mcp
- https://github.com/fellanH/klar-mcp
- https://github.com/ferrislucas/iterm-mcp
- https://github.com/fgulen/homemade-playwright-mcp-server
- https://github.com/flrngel/fuzzy-memory-mcp
- https://github.com/flyingwebie/withmoxie-mcp-server
- https://github.com/fr0ster/mcp-abap-adt
- https://github.com/fractaloutlook/spacetimedb-mcp-server
- https://github.com/franHR11/pcpro-mcp-mysql
- https://github.com/fryjustinc/ssh-mcp-sessions
- https://github.com/fzvincent/dbeaver-mcp-server
- https://github.com/g0t4/mcp-server-memory-file
- https://github.com/gabrielmaialva33/mcp-filesystem
- https://github.com/gcorroto/mcp-oracle-db
- https://github.com/gdbelvin/rlang-mcp-server
- https://github.com/gesslar/lpc-mud-bridge-mcp
- https://github.com/gfffrtt/go-mcp-servers
- https://github.com/giannisalinetti/python-mcp-server
- https://github.com/girishsahu008/mcpshellserver
- https://github.com/github-hewei/mcp-android-adb-server
- https://github.com/gmo-internet/conoha_vps_mcp
- https://github.com/grahamjenkins/ssh-utils-mcp
- https://github.com/graphlit/graphlit-mcp-server
- https://github.com/gunjanjp/linuxshell-mcp
- https://github.com/gvishnoi/mysql-server-mcp
- https://github.com/halilural/electron-mcp-server
- https://github.com/hazzel-cn/node-terminal-mcp
- https://github.com/heffrey78/shell-mcp-server
- https://github.com/hidenorigoto/sacloud-mcp
- https://github.com/hiraishikentaro/wezterm-mcp
- https://github.com/hirakinii/osf-api-mcp
- https://github.com/hiroto0706/practice-mcp-server
- https://github.com/hitakaha/mcp-server-nso
- https://github.com/hoklims/stacksfinder-mcp
- https://github.com/hosseinnnazari/mssql-mcp-local-sql-auth
- https://github.com/houtini-ai/lm
- https://github.com/hrmeetsingh/mcp-browser-automation
- https://github.com/hughescr/persistent-shell-mcp
- https://github.com/hyzhak/ollama-mcp-server
- https://github.com/ianhi/jupyterlab-claude-code
- https://github.com/iclaudiumihaila/mcp-safari-server
- https://github.com/idletoaster/ssh-mcp-server
- https://github.com/igorviniciusavanci/postgres-mcp-server
- https://github.com/ikari-pl/fibaro-mcp
- https://github.com/ikeyu0806/my-mcp-server
- https://github.com/imprvhub/mcp-status-observer
- https://github.com/imran31415/codemode-sqlite-mcp
- https://github.com/inteligencianegociosmmx/vegaLite_mcp_server
- https://github.com/iris-networks/terminal_mcp
- https://github.com/ishayoyo/excel-mcp
- https://github.com/ishumilin/schwaizer-opendata-mcp
- https://github.com/ivan-katkov/scopus-mcp
- https://github.com/j0KZ/mcp_pure_data
- https://github.com/jackyxhb/InferMCPServer
- https://github.com/jagadeesh52423/mongo-mcp
- https://github.com/jakubbuskiewicz/mcp-test
- https://github.com/jasondsmith72/claude-ssh-server
- https://github.com/jatingodnani/mcp-server
- https://github.com/javapanda30/db_query_mcp_server
- https://github.com/jaystarz1/playwright-smart-mcp
- https://github.com/jhanglim/mattermost-mcp-server
- https://github.com/jiawei686/wechat-dev-mcp
- https://github.com/jikime/py-mcp-naver-search
- https://github.com/jl-codes/platformio-mcp
- https://github.com/joaomj/openrouter-search-server
- https://github.com/joemccann/xai-mcp-server
- https://github.com/johan-perso/mcp-shop-server
- https://github.com/johngrimes/mcp-js-debugger
- https://github.com/johnhenry/vimble-mcp
- https://github.com/johnib/kusto-mcp
- https://github.com/jojojs-lab/mcp-server-starter
- https://github.com/joseb33w/google-docs-mcp-server
- https://github.com/joshrutkowski/applescript-mcp
- https://github.com/jparkerweb/mcp-sqlite
- https://github.com/jramalho/avd-mcp
- https://github.com/jrame/mcp-process
- https://github.com/jrandolf/par5-mcp
- https://github.com/jtalk22/slack-mcp-server
- https://github.com/jwaldor/mcp-scrape-copilot
- https://github.com/k4zuki0539/-rpgmaker-mz-mcp
- https://github.com/k5tuck/binelek-mcp-server
- https://github.com/k65miyazakiy/mcp-server-spanner
- https://github.com/k8ika0s/mcp-tmux
- https://github.com/kalivaraprasad-gonapa/react-mcp
- https://github.com/kanniganfan/terminal-mcp
- https://github.com/kaushald/talk-ai-perf-k6-mcp-server
- https://github.com/kaznak/shell-command-mcp
- https://github.com/kazuph/mcp-tmux
- https://github.com/kbjorklid/docs-mcp
- https://github.com/kcpatt27/memvid-mcp
- https://github.com/keegancsmith/emacs-mcp-server
- https://github.com/kelleyblackmore/jarvis-mcp
- https://github.com/kevinbin/mcp-mysql-server
- https://github.com/kevinwatt/mysql-mcp
- https://github.com/keywaysh/keyway-mcp
- https://github.com/kgatilin/gsuite-mcp-go
- https://github.com/khizar-anjum/risky-business-mcp
- https://github.com/kirby44/terminals
- https://github.com/kml93/gemini-design-mcp
- https://github.com/knight0zh/mssql-mcp-server
- https://github.com/knutkirkhorn/docker-mcp-server
- https://github.com/kocierik/consul-mcp-server
- https://github.com/koh-yoshimoto/mysql-mcp-server
- https://github.com/koopatroopa787/first_mcp
- https://github.com/koorchik/ssh-mcp-server
- https://github.com/kousunh/Excel-mcp-server
- https://github.com/kshayk/avibase-mcp
- https://github.com/kylegrahammatzen/tambo-mcp-server
- https://github.com/laelhalawani/remote_hosts_client
- https://github.com/latiftplgu/Spotify-OAuth-MCP-server
- https://github.com/lazy-dinosaur/ccxt-mcp
- https://github.com/lbrichards/mcp-file-surgeon
- https://github.com/ldroguetti/saturn-mcp-server
- https://github.com/lekt9/openreplay-mcp
- https://github.com/lerlerchan/rstudio-mcp-server
- https://github.com/letoribo/mcp-graphql-enhanced
- https://github.com/letuhao/chrome-mcp
- https://github.com/lexfrei/mcp-loki
- https://github.com/lihongjie0209/console-mcp
- https://github.com/liliang-cn/mcp-sqlite-server
- https://github.com/liliangshan/mcp-server-mysql
- https://github.com/linagora/llng-mcp
- https://github.com/lisyoen/mcp-fileops
- https://github.com/lite/iterm-mcp
- https://github.com/liuyoshio/mcp-compass
- https://github.com/lizthedeveloper/terminal-mcp-idk
- https://github.com/lkpkkk123/sqlite_mcp
- https://github.com/longyi1207/glean-mcp-server
- https://github.com/lox/tmux-mcp-server
- https://github.com/lucastl/mcp-agentic-jvl
- https://github.com/lucdesign/indesign-mcp-server
- https://github.com/luoxixuan/photoshop-mcp-server
- https://github.com/m-siles/branch-thinking
- https://github.com/madhukarkumar/singlestore-mcp-server
- https://github.com/mahathirmuh/mcp-ssh-server
- https://github.com/mamprimauto/mcp
- https://github.com/manganate006/playwright-spa-mcp
- https://github.com/manju07/file-system-mcp-server
- https://github.com/manvkaur/azure-functions-templates-mcp-server
- https://github.com/maoxiaoke/mcp-media-processor
- https://github.com/marcinwyszynski/pylon-mcp
- https://github.com/marcostalder85/mcp-mysql-server
- https://github.com/marian-craciunescu/ssh-mcp-server-secured
- https://github.com/maricoxu/remote-terminal-mcp
- https://github.com/mario-andreschak/mcp-puppeteer-browser
- https://github.com/mark3labs/codebench-mcp
- https://github.com/markolive1501/MCP
- https://github.com/martindai/linux-mcp-server-go
- https://github.com/martymarkenson/Postgres-Connector-MCP
- https://github.com/matlab/matlab-mcp-core-server
- https://github.com/matula/godot-mcp-server
- https://github.com/mauricio-cantu/brasil-api-mcp-server
- https://github.com/maxforgan/clinicaltrials-mcp
- https://github.com/mckinleymedia/mcflow-mcp
- https://github.com/mcollina/perm-shell-mcp
- https://github.com/mcpland/testing-mcp
- https://github.com/meesvandongen/sqlite-mcp
- https://github.com/meinzeug/the-android-mcp
- https://github.com/melihbirim/pg-mcp
- https://github.com/memextech/headless-terminal-mcp
- https://github.com/merajmehrabi/puppeteer-mcp-server
- https://github.com/mertcankaraoglu/local-mcp-ssh
- https://github.com/mertcankaraoglu/ssh-mcp
- https://github.com/mfangtao/mcp-ssh-server
- https://github.com/mgandhi82/splunk-cypress-mcp
- https://github.com/mhyrr/sketchup-mcp
- https://github.com/michael7736/mysql-mcp-server
- https://github.com/microsoft/clarity-mcp-server
- https://github.com/mikechao/artic-mcp
- https://github.com/mikedaley/appleii-agent
- https://github.com/mitsuhiko/playwrightess-mcp
- https://github.com/mjrestivo16/mcp-kubernetes
- https://github.com/mofumofu3n/mcp-gemini-web-search
- https://github.com/mohammadrehan1992/mssql-server-mcp
- https://github.com/mondragon-developer/MCP-googleDocs
- https://github.com/moradelboca/dossin__mcp
- https://github.com/moyu6027/deepseek-MCP-server
- https://github.com/mpx-ecology/mcp-server-rag
- https://github.com/mr-wolf-gb/smart-shell-mcp
- https://github.com/mrsions/imagesearch-mcp
- https://github.com/msawayda/unified-browser-mcp
- https://github.com/msilverblatt/basic-mcp
- https://github.com/mundume/gmail-mcp
- https://github.com/mymanish9-code11/QuantConnect-mcp-server
- https://github.com/nagypeterjob/brew-mcp
- https://github.com/namle-teq/puppeteer-mcp-server
- https://github.com/namtran/diskcleankit-mcp
- https://github.com/nanoseil/mcp-bgtask
- https://github.com/naya-cat-1/mcp-ssh-sftp-server
- https://github.com/nayantarasundarraj-hue/Databricks-cursor-mcp
- https://github.com/nbardy/mcp-iterm
- https://github.com/nfodor/mcp-chromium-arm64
- https://github.com/ngc-shj/searxng-mcp-server
- https://github.com/nguyenvanduocit/script-mcp
- https://github.com/nibesh0/NetSecmcp
- https://github.com/nicholmikey/chrome-tools-MCP
- https://github.com/nickgnd/tmux-mcp
- https://github.com/nicolas-costa/mysql-control-bridge
- https://github.com/nikhgupta/mindsdb-mysql-mcp
- https://github.com/nikhilpawar9/oracle-mcp-server
- https://github.com/nilsir/mcp-server-mysql
- https://github.com/nizarius/mcp-rnw-browser
- https://github.com/nkaewam/adk-mcp
- https://github.com/noisysocks/autoconsent-mcp
- https://github.com/noriyuki-shimizu/a11y-test-mcp
- https://github.com/nqkdev/mcp-macos-automation
- https://github.com/nschoonbroodt/mcp-tauri
- https://github.com/nurvx/ref-tools-mcp
- https://github.com/o0x1024/mcp-playwright-security
- https://github.com/ohqay/math-tools
- https://github.com/ojacques/mkdocs-mcp
- https://github.com/okooo5km/memory-mcp-server-go
- https://github.com/omattsson/terragrunt-mcp-server
- https://github.com/omkarkharade/mysql-mcp
- https://github.com/openSVM/zig-mcp-server
- https://github.com/optimisticdur/go-mcp-mysql
- https://github.com/optistar/mcp-server-filesystem
- https://github.com/oregpt/Agenticledger_MCP_ZeekeeGitBook
- https://github.com/osherai/bullhorn-mcp-python
- https://github.com/pahar0/mcp-server-splunk
- https://github.com/palolxx/pollinations-think-mcp
- https://github.com/panxiande/RSSHub-MCP
- https://github.com/paolino/mcp-memory-server
- https://github.com/parfaitBashombe/mcp-server
- https://github.com/parikshitBoxtalk/boxtalk-data-mcp
- https://github.com/pashpashpash/iterm-mcp
- https://github.com/patrickkabwe/rn-mcp
- https://github.com/pengcunfu/go-mcp-exec-command
- https://github.com/pengcunfu/go-mcp-mysql
- https://github.com/pfmartin/golang-mcp-server
- https://github.com/phinaliumz/jira-mcp
- https://github.com/piexl/CAD-MCP
- https://github.com/pirumar/nestjsmcp
- https://github.com/platformatic/mcp-node
- https://github.com/pleaodev/pedro-leao-mcp-mysql-server
- https://github.com/posidron/mcp-powershell
- https://github.com/pradeeppai/mcp-grafana
- https://github.com/prismeai/prismeai-mcp
- https://github.com/protocol-lattice/memory-bank-mcp
- https://github.com/ptbsare/terminal-mcp-server
- https://github.com/puneet8800/claude-auto-documenter-v2
- https://github.com/qckfx/node-debugger-mcp
- https://github.com/qosha1/docker-reader-mcp
- https://github.com/qpd-v/mcp-delete
- https://github.com/quantmew/agent-browser-mcp
- https://github.com/quillopy/quillopy-mcp
- https://github.com/rafaelstz/adobe-commerce-dev-mcp
- https://github.com/raghuchandrasekaran/devspace-mcp-server
- https://github.com/rangta10/kali-mcp-server
- https://github.com/rclone-ui/rclone-mcp
- https://github.com/rdwj/mcp-test-mcp
- https://github.com/redducklabs/github-projects-mcp
- https://github.com/ref-tools/ref-tools-mcp
- https://github.com/reposit-bot/reposit-mcp
- https://github.com/resilientbeast/grid-esports-mcp
- https://github.com/richard0913/adb-mcp
- https://github.com/richardwhiteii/rlm
- https://github.com/ricleedo/Knowledge-EmbeddingAPI-MCP
- https://github.com/rikhoffbauer/shell-mcp-server
- https://github.com/rishabkoul/iTerm-MCP-Server
- https://github.com/rjsalgado/mariadb-mcp-server
- https://github.com/rlaksana/mcp-cli-gemini
- https://github.com/rnd-pro/browser-x-mcp
- https://github.com/rnd-pro/terminal-x-mcp
- https://github.com/rsathish29/mcp-server-poc
- https://github.com/rspeciale0519/wincalcmcp
- https://github.com/rt0120-Ramco/mcp-py
- https://github.com/run-as-root/warden-mcp-server
- https://github.com/runreal/unreal-mcp
- https://github.com/rvmey/triggercmd-mcp-stdio
- https://github.com/rwh85/zarf-docs-mcp
- https://github.com/sachindesai2213/weather-mcp-server
- https://github.com/saihgupr/keyboard-maestro-mcp
- https://github.com/sajithrw/mcp-mysql
- https://github.com/sam2332/mcp-quick-sqlite3
- https://github.com/samber/go-playground-mcp
- https://github.com/sammcj/mcp-aws-kb
- https://github.com/samscarrow/oracle-mcp-server
- https://github.com/sanchorelaxo/opensim-mcp
- https://github.com/santosh07401/redshift-mcp-server
- https://github.com/saravmani-kmu/learn_vscode_mcp_sse
- https://github.com/sarptandoven/python-sdk-to-mcp-converter
- https://github.com/sassyrog/node-mssql-mcp-fork
- https://github.com/saturnino-adrales/mysql-mcp
- https://github.com/schwarztim/bambu-mcp
- https://github.com/schwarztim/sec-aircrack-ng-mcp
- https://github.com/schwarztim/sec-bloodhound-mcp
- https://github.com/schwarztim/sec-crackmapexec-mcp
- https://github.com/schwarztim/sec-dirb-mcp
- https://github.com/schwarztim/sec-evil-winrm-mcp
- https://github.com/schwarztim/sec-gobuster-mcp
- https://github.com/schwarztim/sec-ligolo-ng-mcp
- https://github.com/schwarztim/sec-netexec-mcp
- https://github.com/schwarztim/sec-nuclei-mcp
- https://github.com/schwarztim/sec-powershell-empire-mcp
- https://github.com/schwarztim/sec-proxychains-mcp
- https://github.com/schwarztim/sec-sqlmap-mcp
- https://github.com/schwarztim/sec-wireshark-mcp
- https://github.com/scooby359/chroma-mcp
- https://github.com/scrapybara/scrapybara-mcp
- https://github.com/seongeon-kim/morphik-mcp-dify
- https://github.com/sergio-deras/mcp-shellserver
- https://github.com/sethdford/vibe-coder-mcp
- https://github.com/sfz009900/kalilinuxmcp
- https://github.com/shadcnspace/shadcnspace-mcp
- https://github.com/shaunmacfullstack/claude-perplexity-mcp
- https://github.com/shiiman/multi-agent-mcp
- https://github.com/shuji-bonji/epsg-mcp
- https://github.com/shuji-bonji/rxjs-mcp-server
- https://github.com/signal-slot/mcp-gdb
- https://github.com/signal-slot/mcp-remotetouch
- https://github.com/skillhub-club/mcp-server
- https://github.com/slauzinho/vivado-mcp
- https://github.com/snahrup/microsoft-fabric-mcp
- https://github.com/snoglobe/prolog_mcp
- https://github.com/solon07/mcp-devops-assistant
- https://github.com/sonirico/mcp-stockfish
- https://github.com/spences10/mcp-wsl-exec
- https://github.com/srmorete/adb-mcp
- https://github.com/srthkdev/dbeaver-mcp-server
- https://github.com/ssdeanx/branch-thinking
- https://github.com/ssdeanx/branch-thinking-mcp
- https://github.com/standardbeagle/dart-query
- https://github.com/starlink-awaken/mcp-openclaw
- https://github.com/stat-guy/terminal
- https://github.com/steevenmentech/MCP-SQl-SERVER
- https://github.com/stepanowon/local-fs-mcp-server
- https://github.com/stilllovee/run-command-mcp
- https://github.com/stishkin/cdb-mcp
- https://github.com/storypixel/mcp-taskwarrior-ai
- https://github.com/surkoff-v/postgresql-mcp-server-n8n
- https://github.com/suvidhay/File_RWLE
- https://github.com/tacticlaunch/mcp-telegram
- https://github.com/tairqaldy/codearchitect-mcp
- https://github.com/talentedmrweb/local-dev-bridge-mcp
- https://github.com/tamirsida/overleaf_mcp
- https://github.com/tanevanwifferen/mcp-inception
- https://github.com/termau/ssh-mcp
- https://github.com/tesla0225/mcp-create
- https://github.com/tetsuo-ai/grok-api-mcp
- https://github.com/thabiso-m-absa/opensearch-mcp-server
- https://github.com/theSharque/mcp-architect
- https://github.com/thejusdutt/google-research-mcp
- https://github.com/thejusdutt/kiro-research-mcp
- https://github.com/thekaranpargaie/kube-mcp
- https://github.com/thirdstrandstudio/mcp-xpath
- https://github.com/thoughtpunch/claude_project_mcp
- https://github.com/tiendung2k03/mcp-adb
- https://github.com/timbotgpt/sqlite-mcp
- https://github.com/timtech4u/python-mcp-server
- https://github.com/tinywind/bash-mcp
- https://github.com/titan213/oracle-db-mcp
- https://github.com/tlkc888-Jenkins/autropicai-mcp
- https://github.com/tofunori/claude-mcp-data-explorer
- https://github.com/tomgutt/azure-ai-search-mcp
- https://github.com/tomo1833/private-desk-mcp-server
- https://github.com/tonybentley/signalk-mcp-server
- https://github.com/topherbc/python-run-mcp
- https://github.com/trickv/claude-squared-code
- https://github.com/trupti79916/mcp-multiple-db-toolbox
- https://github.com/tsoernes/mcp-registry
- https://github.com/tsuyoshi-otake/otak-mcp-shell
- https://github.com/ttpears/gitlab-mcp
- https://github.com/tugcantopaloglu/godot-mcp
- https://github.com/tulasi-das/MCP-FileSytem-Server
- https://github.com/turbot/steampipe-mcp
- https://github.com/tyler-technologies-oss/forge-mcp
- https://github.com/uetuluk/claude-dj-mcp
- https://github.com/universal-tool-calling-protocol/go-utcp-mcp-bridge
- https://github.com/ushakrishnan/Vaali_MCP_Server
- https://github.com/v0idpwn/hexdocs-mcp
- https://github.com/vaukalak/prismjs-mcp
- https://github.com/vdesabou/kafka-docker-playground-mcp-server
- https://github.com/veithly/ssh-client-mcp
- https://github.com/vespo92/OPNSenseMCP
- https://github.com/vicagbasi/mssql-mcp
- https://github.com/vilasone455/vscode-context-mcp
- https://github.com/volkan-m/vnc-mcp-server
- https://github.com/vv-vivek/browser-agent-mcp
- https://github.com/wagonbomb/megaraptor-mcp
- https://github.com/wahyurudiyan/go-mcp-docker
- https://github.com/waldzellai/exa-mcp-server-websets
- https://github.com/wangzhaobo168/dm-mcp-server
- https://github.com/washyu/ansible-mcp-server
- https://github.com/weetime/prometheus-mcp-server
- https://github.com/wei/hn-mcp-server
- https://github.com/weidwonder/terminal-mcp-server
- https://github.com/wendehals/bricks-mcp
- https://github.com/wfqdreamcity/linux-server-mcp-server
- https://github.com/wgthomas/rlm-mcp-server
- https://github.com/widjis/mcp-ssh
- https://github.com/wilsonbeam/openclaw-adb-mcp
- https://github.com/wllcnm/mcp-mysql
- https://github.com/wolfgangihloff/rechtsinformationen-bund-de-mcp
- https://github.com/woocommerce/qit-mcp
- https://github.com/xhd2015/dlv-mcp
- https://github.com/xhulz/mcp-game-helper
- https://github.com/yanmxa/prometheus-mcp-server
- https://github.com/yanxxcloud/mcp-server-postgresql-rw
- https://github.com/yaoxiaolinglong/mcp-mongodb-mysql-server
- https://github.com/yevlakhov/mysql-mcp
- https://github.com/yhsung/whisper-cli-mcp
- https://github.com/yoda-digital/mcp-cerebra-legal-server
- https://github.com/yoreland/devicefarm-mcp-server
- https://github.com/yuki9541134/mcp-redash
- https://github.com/yusaaztrk/movie-mcp-main
- https://github.com/zhanyiwp/desktopcommandermcp
- https://github.com/zhookteam/zhook-mcp
- https://github.com/ziad-hsn/code-mode-toon
- https://github.com/zibdie/SSH-MCP-Server
- https://github.com/zilbonn/android-mcp-emulator
- https://github.com/zio3/smart-fs-mcp
- https://github.com/zopalz/image-search-mcp
- https://github.com/ztobs/cline-browser-use-mcp
- https://github.com/zudsniper/claude-code-container-mcp
