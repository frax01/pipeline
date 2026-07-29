# tool_invocation/other_errors - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 4518 |
| Finding filtrati | 4248 |
| Rimossi | 270 (6.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 3503 |
| python | 624 |
| go | 104 |
| unknown | 14 |
| docker | 3 |

## Finding per tipo di test

### `error-handling-nonexistent-tool` (3619 finding)

**1. [docker-mcp-server](https://github.com/0xshariq/docker-mcp-server)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**2. [github-mcp-server](https://github.com/0xshariq/github-mcp-server)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**3. [agentops-mcp](https://github.com/AgentOps-AI/agentops-mcp)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**4. [mcp-salesforce](https://github.com/AiondaDotCom/mcp-salesforce)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**5. [mcp-ssh](https://github.com/AiondaDotCom/mcp-ssh)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**6. [starwind-ui-mcp](https://github.com/Boston343/starwind-ui-mcp)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**7. [coinstats-mcp](https://github.com/CoinStatsHQ/coinstats-mcp)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**8. [openai-websearch-mcp](https://github.com/ConechoAI/openai-websearch-mcp)** (python)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**9. [mcp-contrast](https://github.com/Contrast-Security-OSS/mcp-contrast)** (docker)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

**10. [scrapi-mcp](https://github.com/DevEnterpriseSoftware/scrapi-mcp)** (nodejs)
- Type: `ErrorHandlingFailure`
- Message: `Server did not return error for non-existent tool`

*... e altri 3609 finding simili*

### `initialization` (24 finding)

**1. [mcp-jetbrains](https://github.com/JetBrains/mcp-jetbrains)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: No working IDE endpoint available.`

**2. [mcp-proxy-sidecar](https://github.com/dortegau/mcp-proxy-sidecar)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: No working IDE endpoint available.`

**3. [mcp-assistant](https://github.com/nodlab/mcp-assistant)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: The "path" argument must be of type string or an instance of Buffer or URL. Received undefined`

**4. [mcp-wordpress-remote](https://github.com/automattic/mcp-wordpress-remote)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: MCP error -32603: Cannot process tools/list: WordPress connection failed during initialization`

**5. [DotnetMCPServer](https://github.com/kasirajan22/DotnetMCPServer)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Failed to get tools`

**6. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Request failed: Not Found`

**7. [notemd-mcp](https://github.com/Jacobinwwey/notemd-mcp)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Failed to parse URL from /tools`

**8. [azure-pricing-mcp](https://github.com/charris-msft/azure-pricing-mcp)** (python)
- Type: `InitializationError`
- Message: `MCP error 0: name 'true' is not defined`

**9. [mcp-server-gravatar](https://github.com/Automattic/mcp-server-gravatar)** (nodejs)
- Type: `InitializationError`
- Message: `can't resolve reference #/components/schemas/VerifiedAccount from id #`

**10. [handsai-bridge](https://github.com/Vrivaans/handsai-bridge)** (go)
- Type: `InitializationError`
- Message: `MCP error -32603: HTTP 401`

*... e altri 14 finding simili*

### `tool-query-basic-invocation` (13 finding)

**1. [mcp-mongodb-mysql-server](https://github.com/yaoxiaolinglong/mcp-mongodb-mysql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Database configuration not set. Use connect_db tool first.`

**2. [mysql-query-mcp-server](https://github.com/devakone/mysql-query-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Only SELECT, SHOW, DESCRIBE, and DESC queries are allowed`

**3. [mssql-mcp-server](https://github.com/knight0zh/mssql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid query arguments`

**4. [microsoft-planner-mcp](https://github.com/vyente-ruffin/microsoft-planner-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: query error: EOF`

**5. [mysql-mcp-server](https://github.com/koh-yoshimoto/mysql-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: MySQL connection not established`

**6. [codemode-sqlite-mcp](https://github.com/imran31415/codemode-sqlite-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32000: failed to execute query: SQL logic error: near "test": syntax error (1)`

**7. [My-Network-MCP](https://github.com/danielrosehill/My-Network-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Database configuration not set. Use connect_db tool first.`

**8. [mcp_sqlserver_client](https://github.com/ferescobardev/mcp_sqlserver_client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to localhost:1433 - Could not connect (sequence)`

**9. [mcp-postgres](https://github.com/helloscoopa/mcp-postgres)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No database connection available. Database URL should be provided via SSE connection.`

**10. [mongodb-mcp](https://github.com/leorosignoli/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: MONGODB_URI environment variable is required`

*... e altri 3 finding simili*

### `tool-send_control_character-basic-invocation` (5 finding)

**1. [iterm-mcp](https://github.com/ferrislucas/iterm-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid control character letter`

**2. [iterm-mcp](https://github.com/pashpashpash/iterm-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid control character letter`

**3. [skill-valut-mcp-server](https://github.com/AdouaniHoussemKhalil/skill-valut-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid control character letter`

**4. [wezterm-mcp](https://github.com/hiraishikentaro/wezterm-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to send control character: Unknown control character: test`

**5. [iterm-mcp](https://github.com/TrentBrown/iterm-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid control character letter`

### `tool-search-basic-invocation` (5 finding)

**1. [everything-search-server](https://github.com/Alihkhawaher/everything-search-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "query"
    ],
    "message": "Required"
  }
]`

**2. [google-pse-mcp](https://github.com/rendyfebry/google-pse-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API_KEY is not configured`

**3. [everything-search-mcp-server](https://github.com/ananyaakamat/everything-search-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not connect to Everything Search. Make sure the HTTP server is enabled in Everything's settings (Tools > Options > HTTP Server).`

**4. [google-workspace-mcp](https://github.com/dguido/google-workspace-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OAuth credentials file not found at: /home/tecnico/.config/google-workspace-mcp/credentials.json`

**5. [d365fo-mcp-server](https://github.com/dynamics365ninja/d365fo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: database is locked`

### `tool-list_directory-basic-invocation` (5 finding)

**1. [server-everything](https://github.com/RonaldDegsa/server-everything)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: ENOTDIR: not a directory, scandir 'test'`

**2. [code-explorer-mcp](https://github.com/jordankamto/code-explorer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Directory not found: test`

**3. [iconfont-mcp](https://github.com/zys8119/iconfont-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

**4. [mcp-server](https://github.com/centia-io/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: ENOTDIR: not a directory, scandir 'test'`

**5. [smart-fs-mcp](https://github.com/zio3/smart-fs-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

### `tool-fetch_html-basic-invocation` (5 finding)

**1. [mcp-npx-fetch](https://github.com/tokenizin-agency/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [fetch-mcp](https://github.com/goswamig/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**3. [mcp-npx-fetch](https://github.com/tokenizin/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**4. [Mariner5MCP](https://github.com/kHeroBite/Mariner5MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**5. [fetch-mcp](https://github.com/s-h-a-d-o-w/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_format",
    "format": "url",
    "path": [
      "url"
    ],
    "message": "Invalid URL"
  }
]`

### `tool-fetch_markdown-basic-invocation` (5 finding)

**1. [mcp-npx-fetch](https://github.com/tokenizin-agency/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [fetch-mcp](https://github.com/goswamig/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**3. [mcp-npx-fetch](https://github.com/tokenizin/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**4. [Mariner5MCP](https://github.com/kHeroBite/Mariner5MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**5. [fetch-mcp](https://github.com/s-h-a-d-o-w/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_format",
    "format": "url",
    "path": [
      "url"
    ],
    "message": "Invalid URL"
  }
]`

### `tool-fetch_txt-basic-invocation` (5 finding)

**1. [mcp-npx-fetch](https://github.com/tokenizin-agency/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [fetch-mcp](https://github.com/goswamig/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**3. [mcp-npx-fetch](https://github.com/tokenizin/mcp-npx-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**4. [Mariner5MCP](https://github.com/kHeroBite/Mariner5MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**5. [fetch-mcp](https://github.com/s-h-a-d-o-w/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_format",
    "format": "url",
    "path": [
      "url"
    ],
    "message": "Invalid URL"
  }
]`

### `tool-get_build_status-basic-invocation` (5 finding)

**1. [mindsdb-mysql-mcp](https://github.com/nikhgupta/mindsdb-mysql-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**2. [jenkins-mcp-server](https://github.com/ddang-jung/jenkins-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**3. [Jenkins-server-mcp](https://github.com/hekmon8/Jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**4. [jenkins-server-mcp](https://github.com/grysonbaltazar/jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**5. [mcpblox](https://github.com/vivekhaldar/mcpblox)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-analyze_codebase-basic-invocation` (5 finding)

**1. [autonomous-docs-mcp](https://github.com/perryjr1444-ux/autonomous-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: TypeError: fs.readJson is not a function`

**2. [claude-4.5-mcp-tutorial](https://github.com/Njengah/claude-4.5-mcp-tutorial)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "path"
    ],
    "message": "Required"
  }
]`

**3. [CodeAnalysisMCP](https://github.com/AlotfyDev/CodeAnalysisMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: ENOTDIR: not a directory, mkdir 'test/CodeAnalysisReports/analysis_2026-07-14T11-56-57-061Z'`

**4. [smart-docs-mcp](https://github.com/giinie/smart-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: The path test is not a valid directory.`

**5. [frontend-rag](https://github.com/wn01011/frontend-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: ENOTDIR: not a directory, mkdir 'test/CodeAnalysisReports/analysis_2026-07-14T11-56-57-061Z'`

### `tool-puppeteer_navigate-basic-invocation` (5 finding)

**1. [puppeteer-mcp](https://github.com/code-craka/puppeteer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not find Chrome (ver. 131.0.6778.204). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [puppeteer-mcp-server](https://github.com/AnyContext-ai/puppeteer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Protocol error (Page.navigate): Cannot navigate to invalid URL`

**3. [apostrophe-cms-generator](https://github.com/andrewmat32/apostrophe-cms-generator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

**4. [devsolo](https://github.com/slamb2k/devsolo)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Protocol error (Page.navigate): Cannot navigate to invalid URL`

**5. [puppeteer-mcp-server](https://github.com/todoforai/puppeteer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

### `tool-execute_jql-basic-invocation` (4 finding)

**1. [jira-mcp-server](https://github.com/KS-GEN-AI/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**2. [shufersal-mcp](https://github.com/matipojo/shufersal-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**3. [mcp-tools](https://github.com/briandchristian/mcp-tools)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**4. [jira_mcp_server](https://github.com/raghvendra2420/jira_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

### `tool-get_only_ticket_name_and_description-basic-invocation` (4 finding)

**1. [jira-mcp-server](https://github.com/KS-GEN-AI/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**2. [shufersal-mcp](https://github.com/matipojo/shufersal-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**3. [mcp-tools](https://github.com/briandchristian/mcp-tools)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**4. [jira_mcp_server](https://github.com/raghvendra2420/jira_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

### `tool-create_ticket-basic-invocation` (4 finding)

**1. [jira-mcp-server](https://github.com/KS-GEN-AI/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**2. [shufersal-mcp](https://github.com/matipojo/shufersal-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**3. [mcp-tools](https://github.com/briandchristian/mcp-tools)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

**4. [jira_mcp_server](https://github.com/raghvendra2420/jira_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'data')`

### `tool-create_or_update_file-basic-invocation` (4 finding)

**1. [barebones-mcp](https://github.com/DekaCube/barebones-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

**2. [mcp-github](https://github.com/MissionSquad/mcp-github)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

**3. [gh-mcp-server-oauth](https://github.com/hastings2020/gh-mcp-server-oauth)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

**4. [Mcp_client-server](https://github.com/kaustubhdeshmukh11/Mcp_client-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

### `tool-get_weather_forecast-basic-invocation` (4 finding)

**1. [cwa-mcp-server](https://github.com/lincw/cwa-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error: Invalid locationName. Available options: 宜蘭縣, 花蓮縣, 臺東縣, 澎湖縣, 金門縣, 連江縣, 臺北市, 新北市, 桃園市, 臺中市, 臺南市, 高雄市, 基隆市, 新竹縣, 新竹市, 苗栗縣, 彰化縣, 南投縣, 雲林縣, 嘉義縣, 嘉義市, 屏東縣`

**2. [muti-mcps](https://github.com/TaylorChen/muti-mcps)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OPENWEATHER_API_KEY is not configured`

**3. [test-mcp-weather-server](https://github.com/1broseidon/test-mcp-weather-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**4. [christmas-mcp-mariadb](https://github.com/Chr1stm4s/christmas-mcp-mariadb)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-create_repository-basic-invocation` (4 finding)

**1. [mcp-github](https://github.com/MissionSquad/mcp-github)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

**2. [gitee-mcp-server](https://github.com/normal-coder/gitee-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 登录失效，无权限访问该资源`

**3. [Mcp_client-server](https://github.com/kaustubhdeshmukh11/Mcp_client-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

**4. [vibecoding-mcp-servers](https://github.com/mastoica/vibecoding-mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 登录失效，无权限访问该资源`

### `tool-generate_image-basic-invocation` (4 finding)

**1. [mcp-server-amazon-bedrock](https://github.com/zxkane/mcp-server-amazon-bedrock)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: Could not load credentials from any providers`

**2. [mcp-opengauss-server](https://github.com/lianekai/mcp-opengauss-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: Could not load credentials from any providers`

**3. [mcp-image](https://github.com/mako10k/mcp-image)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: AI Image MCP server is not configured correctly. Ensure MODAL_JOB_API_URL (or JOB_API_SERVER_URL/JOBAPI_URL) is set before using this tool.`

**4. [fal-mcp-server-gentou](https://github.com/Sunwood-ai-labs/fal-mcp-server-gentou)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: FAL_KEY environment variable is not set.`

### `tool-take_screenshot-basic-invocation` (4 finding)

**1. [WSLSnapit-MCP](https://github.com/peterparker57/WSLSnapit-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to take screenshot: Failed to generate base64 output from PowerShell`

**2. [snowflake-mcp](https://github.com/peterdonaghey/snowflake-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute take_screenshot: Session test not found`

**3. [mcp_server](https://github.com/tonyreuropa/mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to take screenshot: Failed to generate base64 output from PowerShell`

**4. [webscout-mcp](https://github.com/fastmcp-me/webscout-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute take_screenshot: Session test not found`

### `tool-get_component_demo-basic-invocation` (4 finding)

**1. [neobrutalism-mcp-server](https://github.com/dennisimoo/neobrutalism-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool request failed: Failed to get demo for component "test": Demo for component "test" not found in local examples`

**2. [gluestack-ui-mcp-server](https://github.com/gauravsaini/gluestack-ui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get component demo for "test": Component "test" not found. Available components: `

**3. [shadcn-svelte-mcp-server](https://github.com/mudiageo/shadcn-svelte-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get demo for component "test": Demo for component "test" not found in shadcn-svelte registry`

**4. [templui-mcp-server](https://github.com/tggo/templui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Resource not found: Failed to get demo for component "test": Demo files for component "test" not found`

### `tool-list_documents-basic-invocation` (3 finding)

**1. [cashfree-mcp](https://github.com/cashfree/cashfree-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330124:1330124:0710/112704.448699:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330124:1330124:0710/112704.448754:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

**2. [proton-docs-mcp](https://github.com/anyrxo/proton-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330124:1330124:0710/112704.448699:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330124:1330124:0710/112704.448754:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

**3. [misonote-mcp-client](https://github.com/leeguooooo/misonote-mcp-client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 获取文档列表失败: MCP_API_KEY 环境变量未设置。请在 Cursor 配置中设置此变量。`

### `tool-create_document-basic-invocation` (3 finding)

**1. [cashfree-mcp](https://github.com/cashfree/cashfree-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330165:1330165:0710/112705.585800:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330165:1330165:0710/112705.585852:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

**2. [proton-docs-mcp](https://github.com/anyrxo/proton-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330165:1330165:0710/112705.585800:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330165:1330165:0710/112705.585852:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

**3. [misonote-mcp-client](https://github.com/leeguooooo/misonote-mcp-client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 创建文档失败: MCP_API_KEY 环境变量未设置。请在 Cursor 配置中设置此变量。`

### `tool-create_entities-basic-invocation` (3 finding)

**1. [memento-mcp](https://github.com/gannonh/memento-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

**2. [adobe-commerce-mcp](https://github.com/codexpect/adobe-commerce-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

**3. [mnemosyne-mcp](https://github.com/zhadyz/mnemosyne-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

### `tool-create_relations-basic-invocation` (3 finding)

**1. [memento-mcp](https://github.com/gannonh/memento-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

**2. [adobe-commerce-mcp](https://github.com/codexpect/adobe-commerce-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

**3. [mnemosyne-mcp](https://github.com/zhadyz/mnemosyne-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to connect to server. Please ensure that your database is listening on the correct host and port and that you have compatible encryption settings both on Neo4j server and driver. Note that the default encryption setting has changed in Neo4j 4.0.`

### `tool-show_tables-basic-invocation` (3 finding)

**1. [ai-agent-with-mcp](https://github.com/moises-paschoalick/ai-agent-with-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute show_tables: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

**2. [mysql_mcp](https://github.com/ashellearl123/mysql_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: ❌ 执行失败: MCP error -32600: ❌ 请先使用 connect_database 工具连接到数据库`

**3. [tidb-serverless-mcp](https://github.com/bohnen/tidb-serverless-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute show_tables: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

### `tool-select-profile-basic-invocation` (3 finding)

**1. [aws-mcp](https://github.com/RafalWilinski/aws-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'sso_start_url')`

**2. [AWS-MCP](https://github.com/ihatesea69/AWS-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'sso_start_url')`

**3. [assemblyline-mcp](https://github.com/brandonlhill/assemblyline-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'sso_start_url')`

### `tool-execute_command-basic-invocation` (3 finding)

**1. [jarvis-mcp](https://github.com/eugener/jarvis-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: exit status 1`

**2. [kalilinuxmcp](https://github.com/sfz009900/kalilinuxmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

**3. [mcp](https://github.com/mubeensadiq/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

### `tool-trigger_build-basic-invocation` (3 finding)

**1. [mindsdb-mysql-mcp](https://github.com/nikhgupta/mindsdb-mysql-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**2. [jenkins-mcp-server](https://github.com/ddang-jung/jenkins-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**3. [jenkins-server-mcp](https://github.com/grysonbaltazar/jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-read_file-basic-invocation` (3 finding)

**1. [mcp-software-engineer](https://github.com/Rajawatrajat/mcp-software-engineer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error executing tool read_file: [read_file] Error reading file: fs.stat is not a function`

**2. [iconfont-mcp](https://github.com/zys8119/iconfont-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

**3. [smart-fs-mcp](https://github.com/zio3/smart-fs-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

### `tool-convert_task_markdown-basic-invocation` (3 finding)

**1. [meshseeks](https://github.com/twalichiewicz/meshseeks)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to convert markdown tasks: __dirname is not defined`

**2. [claude-code-mcp-enhanced](https://github.com/grahama1970/claude-code-mcp-enhanced)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to convert markdown tasks: __dirname is not defined`

**3. [BasketBall_-MCP_chatbot](https://github.com/jayanta8509/BasketBall_-MCP_chatbot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to convert markdown tasks: __dirname is not defined`

### `tool-ssh_connect-basic-invocation` (3 finding)

**1. [mcp-ssh](https://github.com/atlcomgit/mcp-ssh)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Не указан host или username в .env.`

**2. [my-appflowy-mcp](https://github.com/18896101294/my-appflowy-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: SSH authentication incomplete. Provide either password or privateKey`

**3. [ssh-mcp-server](https://github.com/koorchik/ssh-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: SSH authentication incomplete. Provide either password or privateKey`

### `tool-execute_js-basic-invocation` (3 finding)

**1. [cline-browser-use-mcp](https://github.com/ztobs/cline-browser-use-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

**2. [js-sandbox-mcp-server](https://github.com/garc33/js-sandbox-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution error: test is not defined`

**3. [arxiv-mcp-server](https://github.com/makspyn/arxiv-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

### `tool-create-basic-invocation` (3 finding)

**1. [Ollama-mcp](https://github.com/NightTrek/Ollama-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create model: Command failed: ollama create test -f test
Error: unexpected EOF
`

**2. [mcflow-mcp](https://github.com/mckinleymedia/mcflow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to create workflow: TypeError: workflow.nodes is not iterable`

**3. [coding-standards-mcp](https://github.com/manasvi-turing/coding-standards-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create model: Command failed: ollama create test -f test
Error: unexpected EOF
`

### `tool-get_weather-basic-invocation` (3 finding)

**1. [weather-mcp-server](https://github.com/shtansky-bikeleasing/weather-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get weather for test: Request failed with status code 404`

**2. [filesystem-mcp-server](https://github.com/johntawfik/filesystem-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OpenWeatherMap APIキーが設定されていません。.envファイルにOPENWEATHER_API_KEYを設定してください。`

**3. [weather-server](https://github.com/duwenji/weather-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OpenWeatherMap APIキーが設定されていません。.envファイルにOPENWEATHER_API_KEYを設定してください。`

### `tool-update_task-basic-invocation` (3 finding)

**1. [mcp-task-manager](https://github.com/blizzy78/mcp-task-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Task not found: test`

**2. [mcp-coordinator](https://github.com/magnus-ffcg/mcp-coordinator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Task not found: test`

**3. [pyrus-mcp](https://github.com/staners2/pyrus-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MCP error -32600: PYRUS_LOGIN environment variable is required`

### `tool-calculate-basic-invocation` (3 finding)

**1. [mcp_quickstart_python](https://github.com/jessicarod7/mcp_quickstart_python)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行错误: Gemini API 密钥未配置或无效，无法初始化客户端。`

**2. [simple-mcp-server](https://github.com/neozhangtcl/simple-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行错误: Gemini API 密钥未配置或无效，无法初始化客户端。`

**3. [enhanced-mcp-server](https://github.com/onesound71/enhanced-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 계산 오류: 허용되지 않는 문자가 포함되어 있습니다`

### `tool-get_product-basic-invocation` (3 finding)

**1. [cscart-mcp](https://github.com/hungryweb/cscart-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing get_product: Invalid URL`

**2. [nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

**3. [sun_ecommerce_mcp](https://github.com/solana8800/sun_ecommerce_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

### `tool-create_product-basic-invocation` (3 finding)

**1. [cscart-mcp](https://github.com/hungryweb/cscart-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing create_product: Invalid URL`

**2. [nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

**3. [sun_ecommerce_mcp](https://github.com/solana8800/sun_ecommerce_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

### `tool-get_current_weather-basic-invocation` (3 finding)

**1. [muti-mcps](https://github.com/TaylorChen/muti-mcps)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OPENWEATHER_API_KEY is not configured`

**2. [test-mcp-weather-server](https://github.com/1broseidon/test-mcp-weather-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**3. [christmas-mcp-mariadb](https://github.com/Chr1stm4s/christmas-mcp-mariadb)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-delete_note-basic-invocation` (3 finding)

**1. [obsidian-mcp](https://github.com/newtype-01/obsidian-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Note not found: test`

**2. [obsidian-mcp](https://github.com/jianruidutong/obsidian-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to delete note: Error: Note not found: test`

**3. [slack-mcp-honc](https://github.com/rishabh510/slack-mcp-honc)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Note not found: test`

### `tool-market_data-basic-invocation` (3 finding)

**1. [tesouro-direto-mcp](https://github.com/AtilioA/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve market data`

**2. [BitbucketMCP1.0](https://github.com/yogeshhrathod/BitbucketMCP1.0)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve market data`

**3. [tesouro-direto-mcp](https://github.com/fastmcp-me/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve market data`

### `tool-bond_data-basic-invocation` (3 finding)

**1. [tesouro-direto-mcp](https://github.com/AtilioA/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve bond data`

**2. [BitbucketMCP1.0](https://github.com/yogeshhrathod/BitbucketMCP1.0)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve bond data`

**3. [tesouro-direto-mcp](https://github.com/fastmcp-me/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to retrieve bond data`

### `tool-search_bonds-basic-invocation` (3 finding)

**1. [tesouro-direto-mcp](https://github.com/AtilioA/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search bonds`

**2. [BitbucketMCP1.0](https://github.com/yogeshhrathod/BitbucketMCP1.0)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search bonds`

**3. [tesouro-direto-mcp](https://github.com/fastmcp-me/tesouro-direto-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search bonds`

### `tool-create_task-basic-invocation` (3 finding)

**1. [mcp-orchestro](https://github.com/khaoss85/mcp-orchestro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env`

**2. [zihtasks-mcp](https://github.com/thiiz/zihtasks-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Projeto test não encontrado`

**3. [pyrus-mcp](https://github.com/staners2/pyrus-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MCP error -32600: PYRUS_LOGIN environment variable is required`

### `tool-aggregate-basic-invocation` (3 finding)

**1. [mongodb-mcp-that-works](https://github.com/sourabhfb/mongodb-mcp-that-works)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

**2. [mongodb-mcp](https://github.com/leorosignoli/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: MONGODB_URI environment variable is required`

**3. [jimeng-web-mcp](https://github.com/LupinLin1/jimeng-web-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

### `tool-schema-basic-invocation` (3 finding)

**1. [mysql-mcp-server](https://github.com/koh-yoshimoto/mysql-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: MySQL connection not established`

**2. [mcp-postgres](https://github.com/helloscoopa/mcp-postgres)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No database connection available. Database URL should be provided via SSE connection.`

**3. [mcp-graphiti](https://github.com/steven0lisa/mcp-graphiti)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MySQL connection not established`

### `tool-searxng_web_search-basic-invocation` (3 finding)

**1. [rs_systems_mcp_health_monitor](https://github.com/00one00/rs_systems_mcp_health_monitor)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: ⚠️ Configuration Issues: SEARXNG_URL not set. Set SEARXNG_URL (e.g., http://localhost:8080 or https://search.example.com)`

**2. [open-mcp](https://github.com/amplify-studio/open-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GATEWAY_URL environment variable is required for web search. Configure it or use image tools only.`

**3. [mcp-searxng](https://github.com/zhy1369800/mcp-searxng)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ⚠️ Configuration Issues: SEARXNG_URL not set. Set SEARXNG_URL (e.g., http://localhost:8080 or https://search.example.com)`

### `tool-web_url_read-basic-invocation` (3 finding)

**1. [rs_systems_mcp_health_monitor](https://github.com/00one00/rs_systems_mcp_health_monitor)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: 🔧 URL Format Error: Invalid URL "test"`

**2. [open-mcp](https://github.com/amplify-studio/open-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GATEWAY_URL environment variable is required for URL reading. Configure it or use image tools only.`

**3. [mcp-searxng](https://github.com/zhy1369800/mcp-searxng)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 🔧 URL Format Error: Invalid URL "test"`

### `tool-get_component-basic-invocation` (3 finding)

**1. [precast-mcp-brutalist-ui](https://github.com/buungroup-packages/precast-mcp-brutalist-ui)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get component: Failed to parse component 'test': [
  {
    "code": "invalid_type",
    "expected": "object",
    "received": "string",
    "path": [],
    "message": "Expected object, received string"
  }
]`

**2. [neobrutalism-mcp-server](https://github.com/dennisimoo/neobrutalism-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool request failed: Failed to get component "test": Component "test" not found in local components`

**3. [gluestack-ui-mcp-server](https://github.com/gauravsaini/gluestack-ui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get component "test": Component "test" not found. Available components: `

### `tool-create-user-basic-invocation` (2 finding)

**1. [keycloak-model-context-protocol](https://github.com/ChristophEnglisch/keycloak-model-context-protocol)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Network response was not OK.`

**2. [keycloak-mcp-server](https://github.com/M0-AR/keycloak-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "validation": "email",
    "code": "invalid_string",
    "message": "Invalid email",
    "path": [
      "email"
    ]
  }
]`

### `tool-delete-user-basic-invocation` (2 finding)

**1. [keycloak-model-context-protocol](https://github.com/ChristophEnglisch/keycloak-model-context-protocol)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Network response was not OK.`

**2. [keycloak-mcp-server](https://github.com/M0-AR/keycloak-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Keycloak server connection failed. The server may be temporarily unavailable or experiencing network issues. Please check server status and try again in a moment.`

### `tool-ssh_execute-basic-invocation` (2 finding)

**1. [win-cli-mcp-server](https://github.com/SimonB97/win-cli-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: SSH support is disabled in configuration`

**2. [super-win-cli-mcp-server](https://github.com/Faucet94/super-win-cli-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: SSH support is disabled in configuration`

### `tool-read_document-basic-invocation` (2 finding)

**1. [cashfree-mcp](https://github.com/cashfree/cashfree-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330144:1330144:0710/112704.991055:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330144:1330144:0710/112704.991115:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

**2. [proton-docs-mcp](https://github.com/anyrxo/proton-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch the browser process! undefined
[1330144:1330144:0710/112704.991055:ERROR:ozone_platform_x11.cc(244)] Missing X server or $DISPLAY
[1330144:1330144:0710/112704.991115:ERROR:env.cc(258)] The platform failed to initialize.  Exiting.


TROUBLESHOOTING: https://pptr.dev/troubleshooting
`

### `tool-search_animations-basic-invocation` (2 finding)

**1. [mcp-server-lottiefiles](https://github.com/junmer/mcp-server-lottiefiles)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search animations: Request failed with status code 403`

**2. [figma-context-mcp](https://github.com/articpenguin/figma-context-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search animations: Request failed with status code 403`

### `tool-get_animation_details-basic-invocation` (2 finding)

**1. [mcp-server-lottiefiles](https://github.com/junmer/mcp-server-lottiefiles)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get animation: Request failed with status code 403`

**2. [figma-context-mcp](https://github.com/articpenguin/figma-context-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get animation: Request failed with status code 403`

### `tool-get_popular_animations-basic-invocation` (2 finding)

**1. [mcp-server-lottiefiles](https://github.com/junmer/mcp-server-lottiefiles)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get popular animations: Request failed with status code 403`

**2. [figma-context-mcp](https://github.com/articpenguin/figma-context-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get popular animations: Request failed with status code 403`

### `tool-get_oauth_url-basic-invocation` (2 finding)

**1. [calendly-mcp-server](https://github.com/meAmitPatil/calendly-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID environment variable is required for OAuth`

**2. [tradewithjarvis](https://github.com/ashutoshrudraksh/tradewithjarvis)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID environment variable is required for OAuth`

### `tool-exchange_code_for_tokens-basic-invocation` (2 finding)

**1. [calendly-mcp-server](https://github.com/meAmitPatil/calendly-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID and CALENDLY_CLIENT_SECRET environment variables are required for OAuth`

**2. [tradewithjarvis](https://github.com/ashutoshrudraksh/tradewithjarvis)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID and CALENDLY_CLIENT_SECRET environment variables are required for OAuth`

### `tool-refresh_access_token-basic-invocation` (2 finding)

**1. [calendly-mcp-server](https://github.com/meAmitPatil/calendly-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID and CALENDLY_CLIENT_SECRET environment variables are required for OAuth`

**2. [tradewithjarvis](https://github.com/ashutoshrudraksh/tradewithjarvis)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Calendly API error: Error: CALENDLY_CLIENT_ID and CALENDLY_CLIENT_SECRET environment variables are required for OAuth`

### `tool-place_order-basic-invocation` (2 finding)

**1. [zerodha-kite-mcp](https://github.com/anshuljain90/zerodha-kite-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Kite Connect not initialized. Check API credentials.`

**2. [testOMSMCP](https://github.com/kushal45/testOMSMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: User not logged in or session expired. Please use the login_user tool first.`

### `tool-get_gcp_asset_history-basic-invocation` (2 finding)

**1. [mcp-server-perplexity](https://github.com/tanigami/mcp-server-perplexity)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create Cloud Asset client: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

**2. [mcp-gcp-asset-inventory](https://github.com/benjaminwestern/mcp-gcp-asset-inventory)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create Cloud Asset client: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

### `tool-get_gcp_effective_iam_policies-basic-invocation` (2 finding)

**1. [mcp-server-perplexity](https://github.com/tanigami/mcp-server-perplexity)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create Cloud Asset client: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

**2. [mcp-gcp-asset-inventory](https://github.com/benjaminwestern/mcp-gcp-asset-inventory)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create Cloud Asset client: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

### `tool-get_book-basic-invocation` (2 finding)

**1. [octomind-mcp](https://github.com/OctoMind-dev/octomind-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 0: validating tool output: validating root: validating /properties/identifiers: type: <invalid reflect.Value> has type "null", want "object"`

**2. [calibre-mcp](https://github.com/benoute/calibre-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error 0: validating tool output: validating root: validating /properties/identifiers: type: <invalid reflect.Value> has type "null", want "object"`

### `tool-create_plugin-basic-invocation` (2 finding)

**1. [framer-plugin-mcp](https://github.com/Sheshiyer/framer-plugin-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create plugin: EEXIST: file already exists, mkdir '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

**2. [thoughtspot-admin-mcp](https://github.com/billdback-ts/thoughtspot-admin-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create plugin: EEXIST: file already exists, mkdir '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

### `tool-build_plugin-basic-invocation` (2 finding)

**1. [framer-plugin-mcp](https://github.com/Sheshiyer/framer-plugin-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to build plugin: require is not defined`

**2. [thoughtspot-admin-mcp](https://github.com/billdback-ts/thoughtspot-admin-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to build plugin: require is not defined`

### `tool-bridge_bridgeAssets-basic-invocation` (2 finding)

**1. [linea-mcp](https://github.com/qvkare/linea-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to bridge assets: Source and destination chains must be different.`

**2. [remote-mcp-server](https://github.com/bjacobso/remote-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to bridge assets: Source and destination chains must be different.`

### `tool-bridge_bridgeStatus-basic-invocation` (2 finding)

**1. [linea-mcp](https://github.com/qvkare/linea-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to check bridge status: HTTP request failed.

Status: 401
URL: https://mainnet.infura.io/v3/YOUR_INFURA_KEY
Request body: {"method":"eth_getTransactionReceipt","params":["test"]}

Details: "invalid project id\n"
Version: viem@2.44.2`

**2. [remote-mcp-server](https://github.com/bjacobso/remote-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to check bridge status: HTTP request failed.

Status: 401
URL: https://mainnet.infura.io/v3/YOUR_INFURA_KEY
Request body: {"method":"eth_getTransactionReceipt","params":["test"]}

Details: "invalid project id\n"
Version: viem@2.44.2`

### `tool-google_search-basic-invocation` (2 finding)

**1. [mcp-integrated-search-server](https://github.com/mako10k/mcp-integrated-search-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Search failed: MCP error -32600: Google Search is not configured. Set GOOGLE_API_KEY and GOOGLE_SEARCH_ENGINE_ID.`

**2. [mcp-mssql-server](https://github.com/blueshiftlabs-ai/mcp-mssql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Search failed: MCP error -32600: Google Search is not configured. Set GOOGLE_API_KEY and GOOGLE_SEARCH_ENGINE_ID.`

### `tool-google_search_images-basic-invocation` (2 finding)

**1. [mcp-integrated-search-server](https://github.com/mako10k/mcp-integrated-search-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image search failed: MCP error -32600: Google Search is not configured. Set GOOGLE_API_KEY and GOOGLE_SEARCH_ENGINE_ID.`

**2. [mcp-mssql-server](https://github.com/blueshiftlabs-ai/mcp-mssql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image search failed: MCP error -32600: Google Search is not configured. Set GOOGLE_API_KEY and GOOGLE_SEARCH_ENGINE_ID.`

### `tool-redmine_list_issues-basic-invocation` (2 finding)

**1. [mcp-integrated-search-server](https://github.com/mako10k/mcp-integrated-search-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to list Redmine issues: No Redmine configuration found. Provide REDMINE_CONFIG_PATH or add a redmine-repositories.json. Alternatively set REDMINE_URL and REDMINE_API_KEY for legacy mode.`

**2. [mcp-mssql-server](https://github.com/blueshiftlabs-ai/mcp-mssql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to list Redmine issues: No Redmine configuration found. Provide REDMINE_CONFIG_PATH or add a redmine-repositories.json. Alternatively set REDMINE_URL and REDMINE_API_KEY for legacy mode.`

### `tool-web_fetch-basic-invocation` (2 finding)

**1. [notion-mcp-server](https://github.com/orbit-logistics/notion-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [bodigi-mcp-server](https://github.com/bobbiedigital2025/bodigi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

### `tool-show_databases-basic-invocation` (2 finding)

**1. [ai-agent-with-mcp](https://github.com/moises-paschoalick/ai-agent-with-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute show_databases: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

**2. [tidb-serverless-mcp](https://github.com/bohnen/tidb-serverless-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute show_databases: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

### `tool-switch_database-basic-invocation` (2 finding)

**1. [ai-agent-with-mcp](https://github.com/moises-paschoalick/ai-agent-with-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute switch_database: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

**2. [tidb-serverless-mcp](https://github.com/bohnen/tidb-serverless-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute switch_database: Missing user name prefix. See https:/***/select-cluster-tier#user-name-prefix`

### `tool-describe_entity-basic-invocation` (2 finding)

**1. [mcpkg](https://github.com/owulveryck/mcpkg)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: unexpected EOF`

**2. [mcp-mysql-server](https://github.com/brenomed/mcp-mysql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: unexpected EOF`

### `tool-find_triples-basic-invocation` (2 finding)

**1. [mcpkg](https://github.com/owulveryck/mcpkg)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: unexpected EOF`

**2. [mcp-mysql-server](https://github.com/brenomed/mcp-mysql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: unexpected EOF`

### `tool-get_diagnostics-basic-invocation` (2 finding)

**1. [flutter-tools](https://github.com/dkpoulsen/flutter-tools)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Flutter SDK not found in PATH. Please ensure Flutter is installed and in your PATH.`

**2. [minimal-godot-mcp](https://github.com/ryanmazzolini/minimal-godot-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: file_path must be a .gd file`

### `tool-cluster_describe-basic-invocation` (2 finding)

**1. [gcp-mcp-server](https://github.com/lreimer/gcp-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

**2. [mcp-server](https://github.com/carlos5456/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

### `tool-clusters_list-basic-invocation` (2 finding)

**1. [gcp-mcp-server](https://github.com/lreimer/gcp-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

**2. [mcp-server](https://github.com/carlos5456/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

### `tool-project_describe-basic-invocation` (2 finding)

**1. [gcp-mcp-server](https://github.com/lreimer/gcp-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

**2. [mcp-server](https://github.com/carlos5456/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: credentials: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc for more information`

### `tool-get_style-basic-invocation` (2 finding)

**1. [mcp-server-newrelic](https://github.com/ulucaydin/mcp-server-newrelic)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid category: test`

**2. [mcp-server-stylepilot](https://github.com/chenyqthu/mcp-server-stylepilot)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid category: test`

### `tool-create_style-basic-invocation` (2 finding)

**1. [mcp-server-newrelic](https://github.com/ulucaydin/mcp-server-newrelic)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid category: test`

**2. [mcp-server-stylepilot](https://github.com/chenyqthu/mcp-server-stylepilot)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid category: test`

### `tool-get_question_by_id-basic-invocation` (2 finding)

**1. [re-stack-mcp](https://github.com/jagreetdg/re-stack-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Question with ID 50 not found`

**2. [tinder-mcp-node](https://github.com/mc422/tinder-mcp-node)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Question with ID 'test' not found`

### `tool-book-search-basic-invocation` (2 finding)

**1. [inori-mcp](https://github.com/liu599/inori-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 未知的书架编号：test，可用的书架编号为：A（科幻）、B（文学）、C（计算机）、D（动漫）`

**2. [markdown-notes-mcp](https://github.com/codeMaestro78/markdown-notes-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: 未知的书架编号：test，可用的书架编号为：A（科幻）、B（文学）、C（计算机）、D（动漫）`

### `tool-web-fetch-basic-invocation` (2 finding)

**1. [fibery-mcp-graphql](https://github.com/greatwitenorth/fibery-mcp-graphql)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid URL: test`

**2. [fetch-web-mcp](https://github.com/conanjunn/fetch-web-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid URL: test`

### `tool-get_details-basic-invocation` (2 finding)

**1. [tagesschau-mcp-server](https://github.com/a2xdeveloper/tagesschau-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Get "test": unsupported protocol scheme ""`

**2. [linux-audio-mcp](https://github.com/creatdevz/linux-audio-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Get "test": unsupported protocol scheme ""`

### `tool-build-basic-invocation` (2 finding)

**1. [mcp-bazel](https://github.com/aaomidi/mcp-bazel)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel build for target "test": bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [build test]
Output:
`

**2. [emistr-mcp](https://github.com/cybersmurf/emistr-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel build for target "test": bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [build test]
Output:
`

### `tool-deps-basic-invocation` (2 finding)

**1. [mcp-bazel](https://github.com/aaomidi/mcp-bazel)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel query for dependencies of target "test" with depth 1: bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [query deps('test', 1) --output label]
Output:
`

**2. [emistr-mcp](https://github.com/cybersmurf/emistr-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel query for dependencies of target "test" with depth 1: bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [query deps('test', 1) --output label]
Output:
`

### `tool-reverse-dependencies-basic-invocation` (2 finding)

**1. [mcp-bazel](https://github.com/aaomidi/mcp-bazel)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel query for target "//:test" (derived from input "test") with depth -1: bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [query rdeps(//..., //:test) --output graph]
Output:
`

**2. [emistr-mcp](https://github.com/cybersmurf/emistr-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute bazel query for target "//:test" (derived from input "test") with depth -1: bazel command failed: exec: "bazel": executable file not found in $PATH
Args: [query rdeps(//..., //:test) --output graph]
Output:
`

### `tool-write_note-basic-invocation` (2 finding)

**1. [mcp-server-flomo](https://github.com/GolderBrother/mcp-server-flomo)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unknown tool`

**2. [mcp-server-bear](https://github.com/ssiswent/mcp-server-bear)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 3: Command failed: open "bear://x-callback-url/create?title=test&text=test"
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'bear://x-callback-url/create?title=test&text=test'
`

### `tool-add_bpmn_element-basic-invocation` (2 finding)

**1. [mcp-mhworld](https://github.com/likweitan/mcp-mhworld)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Diagram not found: test`

**2. [BPMN-MCP](https://github.com/dattmavis/BPMN-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Diagram not found: test`

### `tool-connect_bpmn_elements-basic-invocation` (2 finding)

**1. [mcp-mhworld](https://github.com/likweitan/mcp-mhworld)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Diagram not found: test`

**2. [BPMN-MCP](https://github.com/dattmavis/BPMN-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Diagram not found: test`

### `tool-create_vm-basic-invocation` (2 finding)

**1. [kubevirt-mcp-server](https://github.com/lyarwood/kubevirt-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (post virtualmachines.kubevirt.io)`

**2. [remote-mcp-server](https://github.com/davesbits/remote-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (post virtualmachines.kubevirt.io)`

### `tool-delete_vm-basic-invocation` (2 finding)

**1. [kubevirt-mcp-server](https://github.com/lyarwood/kubevirt-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (delete virtualmachines.kubevirt.io test)`

**2. [remote-mcp-server](https://github.com/davesbits/remote-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (delete virtualmachines.kubevirt.io test)`

### `tool-get_instancetype-basic-invocation` (2 finding)

**1. [kubevirt-mcp-server](https://github.com/lyarwood/kubevirt-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (get virtualmachineclusterinstancetypes.instancetype.kubevirt.io test)`

**2. [remote-mcp-server](https://github.com/davesbits/remote-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: the server could not find the requested resource (get virtualmachineclusterinstancetypes.instancetype.kubevirt.io test)`

### `tool-get_image_info-basic-invocation` (2 finding)

**1. [interactive-feedback-macos-mcp](https://github.com/gmh5225/interactive-feedback-macos-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Get image info failed: unsupported file type: undefined (file: /home/tecnico/Desktop/Frameworks/mcp-check/test)`

**2. [md2docx-mcp-server](https://github.com/ddipass/md2docx-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Get image info failed: unsupported file type: undefined (file: /home/tecnico/Desktop/Frameworks/mcp-check/test)`

### `tool-bluesky-daily-basic-invocation` (2 finding)

**1. [bluesky-daily-mcp](https://github.com/briangershon/bluesky-daily-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: yyyymmdd must be in YYYYMMDD format`

**2. [vscode-extension-and-mcp-together](https://github.com/dealenx/vscode-extension-and-mcp-together)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: yyyymmdd must be in YYYYMMDD format`

### `tool-info-basic-invocation` (2 finding)

**1. [mysql-query-mcp-server](https://github.com/devakone/mysql-query-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No connection pool available for environment: local`

**2. [brew-mcp](https://github.com/nagypeterjob/brew-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: find brew binary :exec: "brew": executable file not found in $PATH`

### `tool-convert_time-basic-invocation` (2 finding)

**1. [time-mcp-server](https://github.com/okooo5km/time-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid source timezone: unknown time zone test`

**2. [mcp-process-manager](https://github.com/dennisonbertram/mcp-process-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid source timezone: unknown time zone test`

### `tool-get_current_time-basic-invocation` (2 finding)

**1. [time-mcp-server](https://github.com/okooo5km/time-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid timezone: unknown time zone test`

**2. [mcp-process-manager](https://github.com/dennisonbertram/mcp-process-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid timezone: unknown time zone test`

### `tool-API-get-input-schema-basic-invocation` (2 finding)

**1. [mcp-server-rss3](https://github.com/RSS3-Network/mcp-server-rss3)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Method undefined not found`

**2. [mcp-whatsms](https://github.com/descomplicar-marketing-e-tecnologia/mcp-whatsms)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Method undefined not found`

### `tool-ollama_chat-basic-invocation` (2 finding)

**1. [Ultrahuman-MCP](https://github.com/Monasterolo21/Ultrahuman-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ollama chat error: model 'test' not found`

**2. [ollama-mcp-server](https://github.com/devdarcom/ollama-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ollama chat error: model 'test' not found`

### `tool-ollama_generate-basic-invocation` (2 finding)

**1. [Ultrahuman-MCP](https://github.com/Monasterolo21/Ultrahuman-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ollama generate error: model 'test' not found`

**2. [ollama-mcp-server](https://github.com/devdarcom/ollama-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ollama generate error: model 'test' not found`

### `tool-speak-basic-invocation` (2 finding)

**1. [say-mcp-server](https://github.com/bmorphism/say-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to speak text: Command failed: say -v "Alex" -r 175 "test"
/bin/sh: 1: say: not found
`

**2. [apple-notifier-mcp](https://github.com/turlockmike/apple-notifier-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unexpected error: Command failed: say "test"
/bin/sh: 1: say: not found
`

### `tool-initialize_project-basic-invocation` (2 finding)

**1. [mcp-servers](https://github.com/Props-Labs/mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, open 'test/.flyway-mcp.json'`

**2. [Flyway-MCP-Server](https://github.com/dmattox-sparkcodelabs/Flyway-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, open 'test/.flyway-mcp.json'`

### `tool-update_migration_path-basic-invocation` (2 finding)

**1. [mcp-servers](https://github.com/Props-Labs/mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No project has been initialized. Please run initialize_project first.

Example: "Initialize Flyway for the project at /path/to/your/project"

This will create a .flyway-mcp.json config file and migrations directory in your project.`

**2. [Flyway-MCP-Server](https://github.com/dmattox-sparkcodelabs/Flyway-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No project has been initialized. Please run initialize_project first.

Example: "Initialize Flyway for the project at /path/to/your/project"

This will create a .flyway-mcp.json config file and migrations directory in your project.`

### `tool-flyway_info-basic-invocation` (2 finding)

**1. [mcp-servers](https://github.com/Props-Labs/mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No project has been initialized. Please run initialize_project first.

Example: "Initialize Flyway for the project at /path/to/your/project"

This will create a .flyway-mcp.json config file and migrations directory in your project.`

**2. [Flyway-MCP-Server](https://github.com/dmattox-sparkcodelabs/Flyway-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No project has been initialized. Please run initialize_project first.

Example: "Initialize Flyway for the project at /path/to/your/project"

This will create a .flyway-mcp.json config file and migrations directory in your project.`

### `tool-wiki_image_info-basic-invocation` (2 finding)

**1. [wikipedia-mcp-image-crawler](https://github.com/dazeb/wikipedia-mcp-image-crawler)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image not found: test`

**2. [mcp-template](https://github.com/duyixian1234/mcp-template)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image not found: test`

### `tool-az_execute-basic-invocation` (2 finding)

**1. [pumpswap-mcp](https://github.com/kukapay/pumpswap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az test
/bin/sh: 1: az: not found
`

**2. [azure-mcp](https://github.com/eddyv73/azure-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az test
/bin/sh: 1: az: not found
`

### `tool-az_login-basic-invocation` (2 finding)

**1. [pumpswap-mcp](https://github.com/kukapay/pumpswap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az login
/bin/sh: 1: az: not found
`

**2. [azure-mcp](https://github.com/eddyv73/azure-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az login
/bin/sh: 1: az: not found
`

### `tool-az_account_set-basic-invocation` (2 finding)

**1. [pumpswap-mcp](https://github.com/kukapay/pumpswap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az account set --subscription "test"
/bin/sh: 1: az: not found
`

**2. [azure-mcp](https://github.com/eddyv73/azure-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Azure CLI error: Command failed: az account set --subscription "test"
/bin/sh: 1: az: not found
`

### `tool-hosting_importWordpressWebsite-basic-invocation` (2 finding)

**1. [api-mcp-server](https://github.com/hostinger/api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid archive format. Supported formats: zip, tar, tar.gz, tgz, 7z, gz, gzip`

**2. [america-hostinger-mcp](https://github.com/alxubuntu/america-hostinger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid archive format. Supported formats: zip, tar, tar.gz, tgz, 7z, gz, gzip`

### `tool-hosting_deployWordpressPlugin-basic-invocation` (2 finding)

**1. [api-mcp-server](https://github.com/hostinger/api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Plugin path is not a directory: test`

**2. [america-hostinger-mcp](https://github.com/alxubuntu/america-hostinger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Plugin path is not a directory: test`

### `tool-hosting_deployWordpressTheme-basic-invocation` (2 finding)

**1. [api-mcp-server](https://github.com/hostinger/api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Theme path is not a directory: test`

**2. [america-hostinger-mcp](https://github.com/alxubuntu/america-hostinger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Theme path is not a directory: test`

### `tool-user_input_dialog-basic-invocation` (2 finding)

**1. [mongodb-mcp-server](https://github.com/mongodb-developer/mongodb-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to get user input: Dialog failed with code 127`

**2. [user-input-mcp](https://github.com/finnmerlett/user-input-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to get user input: Dialog failed with code 127`

### `tool-spacetimedb_connect-basic-invocation` (2 finding)

**1. [mcp-server-calendly](https://github.com/shwetank-dev/mcp-server-calendly)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Connection failed: Failed to parse URL from test/v1/database/test/schema?version=9`

**2. [spacetimedb-mcp-server](https://github.com/fractaloutlook/spacetimedb-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Connection failed: Failed to parse URL from test/v1/database/test/schema?version=9`

### `tool-navigate_to_page-basic-invocation` (2 finding)

**1. [VeniAI-Hukuk-EmsalKarar-MCPServer](https://github.com/bayyyyyuuu/VeniAI-Hukuk-EmsalKarar-MCPServer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing navigate_to_page: MCP error -32603: Failed to navigate: Error: Browser not initialized`

**2. [mcp-scraper-inspect](https://github.com/fuahyo/mcp-scraper-inspect)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing navigate_to_page: MCP error -32603: Failed to navigate: Error: Browser not initialized`

### `tool-ask_feedback-basic-invocation` (2 finding)

**1. [obsidian-local-rest-api-mcp](https://github.com/j-shelfwood/obsidian-local-rest-api-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool ask_feedback failed: An API error occurred: invalid_auth`

**2. [claude-mcp-slack-feedback](https://github.com/gailentech/claude-mcp-slack-feedback)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool ask_feedback failed: An API error occurred: invalid_auth`

### `tool-inform_slack-basic-invocation` (2 finding)

**1. [obsidian-local-rest-api-mcp](https://github.com/j-shelfwood/obsidian-local-rest-api-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool inform_slack failed: An API error occurred: invalid_auth`

**2. [claude-mcp-slack-feedback](https://github.com/gailentech/claude-mcp-slack-feedback)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool inform_slack failed: An API error occurred: invalid_auth`

### `tool-json_to_pptx-basic-invocation` (2 finding)

**1. [tavily-mcp-loadbalancer](https://github.com/yatotm/tavily-mcp-loadbalancer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "object",
    "received": "string",
    "path": [
      "slideshow",
      "slides",
      0,
      "elements",
      0
    ],
    "message": "Expected object, received string"
  }
]`

**2. [slides-mcp](https://github.com/gavanduffy/slides-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "object",
    "received": "string",
    "path": [
      "slideshow",
      "slides",
      0,
      "elements",
      0
    ],
    "message": "Expected object, received string"
  }
]`

### `tool-get_upcoming_talks-basic-invocation` (2 finding)

**1. [nerdearla-agenda-mcp](https://github.com/tecnomanu/nerdearla-agenda-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_upcoming_talks: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [mcp-emtrafesa](https://github.com/georgegiosue/mcp-emtrafesa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_upcoming_talks: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-get_past_talks-basic-invocation` (2 finding)

**1. [nerdearla-agenda-mcp](https://github.com/tecnomanu/nerdearla-agenda-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_past_talks: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [mcp-emtrafesa](https://github.com/georgegiosue/mcp-emtrafesa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_past_talks: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-get_topics_by_tags-basic-invocation` (2 finding)

**1. [nerdearla-agenda-mcp](https://github.com/tecnomanu/nerdearla-agenda-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_topics_by_tags: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [mcp-emtrafesa](https://github.com/georgegiosue/mcp-emtrafesa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error ejecutando get_topics_by_tags: Could not find Chrome (ver. 140.0.7339.185). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-stop_build-basic-invocation` (2 finding)

**1. [mindsdb-mysql-mcp](https://github.com/nikhgupta/mindsdb-mysql-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**2. [jenkins-server-mcp](https://github.com/grysonbaltazar/jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-search_by_error-basic-invocation` (2 finding)

**1. [sellerchamp-mcp](https://github.com/WowWashington/sellerchamp-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

**2. [stackoverflow-mcp](https://github.com/gscalzo/stackoverflow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

### `tool-search_by_tags-basic-invocation` (2 finding)

**1. [sellerchamp-mcp](https://github.com/WowWashington/sellerchamp-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

**2. [stackoverflow-mcp](https://github.com/gscalzo/stackoverflow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

### `tool-analyze_stack_trace-basic-invocation` (2 finding)

**1. [sellerchamp-mcp](https://github.com/WowWashington/sellerchamp-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

**2. [stackoverflow-mcp](https://github.com/gscalzo/stackoverflow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Stack Overflow API error: Invalid filter specified (400)`

### `tool-create_project-basic-invocation` (2 finding)

**1. [mcp-software-engineer](https://github.com/Rajawatrajat/mcp-software-engineer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error executing tool create_project: [create_project] Project must be created within workspace directory`

**2. [mcp-node-omnibus-server](https://github.com/bsmi021/mcp-node-omnibus-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create project: ENOTDIR: not a directory, mkdir 'test/test'`

### `tool-list_repositories-basic-invocation` (2 finding)

**1. [barebones-mcp](https://github.com/DekaCube/barebones-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

**2. [gh-mcp-server-oauth](https://github.com/hastings2020/gh-mcp-server-oauth)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

### `tool-get_file_contents-basic-invocation` (2 finding)

**1. [barebones-mcp](https://github.com/DekaCube/barebones-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

**2. [gh-mcp-server-oauth](https://github.com/hastings2020/gh-mcp-server-oauth)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Configuration file not found. Please create mcp-config.json. See mcp-config.example.json for template.`

### `tool-fetch-basic-invocation` (2 finding)

**1. [calibre-mcp-nodejs](https://github.com/ispyridis/calibre-mcp-nodejs)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid epub URL format`

**2. [fetch-mcp](https://github.com/h16rkim/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid url: must be a valid URL`

### `tool-ticktick_get_projects-basic-invocation` (2 finding)

**1. [ticktick-mcp-server](https://github.com/liadgez/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

**2. [Cookidoo-MCP-Server](https://github.com/hnizdiljan/Cookidoo-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

### `tool-ticktick_create_project-basic-invocation` (2 finding)

**1. [ticktick-mcp-server](https://github.com/liadgez/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

**2. [Cookidoo-MCP-Server](https://github.com/hnizdiljan/Cookidoo-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

### `tool-ticktick_get_task_details-basic-invocation` (2 finding)

**1. [ticktick-mcp-server](https://github.com/liadgez/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

**2. [Cookidoo-MCP-Server](https://github.com/hnizdiljan/Cookidoo-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: TickTick credentials not properly configured`

### `tool-status-basic-invocation` (2 finding)

**1. [mcp-status-observer](https://github.com/imprvhub/mcp-status-observer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unknown command: test. Available commands: list, --all, or platform with -- prefix like --openrouter, --openai, --github`

**2. [My-Agent-Airbnb-s-MCP-Server-Google-ADK-](https://github.com/jayakumarpujar/My-Agent-Airbnb-s-MCP-Server-Google-ADK-)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Unknown command: test. Available commands: list, --all, or platform with -- prefix like --openrouter, --openai, --github`

### `tool-fork_parity_auto_triage_commits-basic-invocation` (2 finding)

**1. [fork-parity-mcp](https://github.com/moikas-code/fork-parity-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_auto_triage_commits: Repository not initialized. Run fork_parity_sync_and_analyze first.`

**2. [printify-mcp-server](https://github.com/jeffkimble/printify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_auto_triage_commits: Repository not initialized. Run fork_parity_sync_and_analyze first.`

### `tool-fork_parity_get_detailed_status-basic-invocation` (2 finding)

**1. [fork-parity-mcp](https://github.com/moikas-code/fork-parity-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_get_detailed_status: Repository not initialized`

**2. [printify-mcp-server](https://github.com/jeffkimble/printify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_get_detailed_status: Repository not initialized`

### `tool-fork_parity_generate_dashboard-basic-invocation` (2 finding)

**1. [fork-parity-mcp](https://github.com/moikas-code/fork-parity-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_generate_dashboard: Repository not initialized`

**2. [printify-mcp-server](https://github.com/jeffkimble/printify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing fork_parity_generate_dashboard: Repository not initialized`

### `tool-create_test_folder-basic-invocation` (2 finding)

**1. [Android-Debug-Bridge-MCP](https://github.com/TiagoDanin/Android-Debug-Bridge-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: mkdir -p "/home/tecnico/Desktop/Frameworks/mcp-check/test"
mkdir: cannot create directory '/home/tecnico/Desktop/Frameworks/mcp-check/test': File exists
`

**2. [chrome-mcp-client-rpa](https://github.com/jiabai/chrome-mcp-client-rpa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: mkdir -p "/home/tecnico/Desktop/Frameworks/mcp-check/test"
mkdir: cannot create directory '/home/tecnico/Desktop/Frameworks/mcp-check/test': File exists
`

### `tool-list_apps-basic-invocation` (2 finding)

**1. [Android-Debug-Bridge-MCP](https://github.com/TiagoDanin/Android-Debug-Bridge-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: adb shell pm list packages | grep "test"
/bin/sh: 1: adb: not found
`

**2. [chrome-mcp-client-rpa](https://github.com/jiabai/chrome-mcp-client-rpa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: adb shell pm list packages | grep "test"
/bin/sh: 1: adb: not found
`

### `tool-open_app-basic-invocation` (2 finding)

**1. [Android-Debug-Bridge-MCP](https://github.com/TiagoDanin/Android-Debug-Bridge-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: adb shell monkey -p test 1
/bin/sh: 1: adb: not found
`

**2. [chrome-mcp-client-rpa](https://github.com/jiabai/chrome-mcp-client-rpa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Command failed: adb shell monkey -p test 1
/bin/sh: 1: adb: not found
`

### `tool-getData-basic-invocation` (2 finding)

**1. [mcp-postgres](https://github.com/a21071/mcp-postgres)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 
Invalid `prisma.user.findMany()` invocation:


error: Environment variable not found: DATABASE_URL.
  -->  schema.prisma:13
   | 
12 |   provider = "postgresql"
13 |   url      = env("DATABASE_URL")
   | 

Validation Error Count: 1`

**2. [sql-context](https://github.com/johnhnguyen97/sql-context)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 
Invalid `prisma.user.findMany()` invocation:


error: Environment variable not found: DATABASE_URL.
  -->  schema.prisma:13
   | 
12 |   provider = "postgresql"
13 |   url      = env("DATABASE_URL")
   | 

Validation Error Count: 1`

### `tool-addUserData-basic-invocation` (2 finding)

**1. [mcp-postgres](https://github.com/a21071/mcp-postgres)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "email",
    "code": "invalid_string",
    "message": "Invalid email",
    "path": [
      "email"
    ]
  }
]`

**2. [sql-context](https://github.com/johnhnguyen97/sql-context)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "email",
    "code": "invalid_string",
    "message": "Invalid email",
    "path": [
      "email"
    ]
  }
]`

### `tool-deleteUserData-basic-invocation` (2 finding)

**1. [mcp-postgres](https://github.com/a21071/mcp-postgres)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 
Invalid `prisma.user.deleteMany()` invocation:


error: Environment variable not found: DATABASE_URL.
  -->  schema.prisma:13
   | 
12 |   provider = "postgresql"
13 |   url      = env("DATABASE_URL")
   | 

Validation Error Count: 1`

**2. [sql-context](https://github.com/johnhnguyen97/sql-context)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 
Invalid `prisma.user.deleteMany()` invocation:


error: Environment variable not found: DATABASE_URL.
  -->  schema.prisma:13
   | 
12 |   provider = "postgresql"
13 |   url      = env("DATABASE_URL")
   | 

Validation Error Count: 1`

### `tool-memory.create-basic-invocation` (2 finding)

**1. [mcp-memory](https://github.com/sdimitrov/mcp-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

**2. [trademark-mcp-server](https://github.com/jordanburke/trademark-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

### `tool-memory.search-basic-invocation` (2 finding)

**1. [mcp-memory](https://github.com/sdimitrov/mcp-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

**2. [trademark-mcp-server](https://github.com/jordanburke/trademark-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

### `tool-memory.list-basic-invocation` (2 finding)

**1. [mcp-memory](https://github.com/sdimitrov/mcp-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

**2. [trademark-mcp-server](https://github.com/jordanburke/trademark-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: `

### `tool-get_hn_post_formatted_comments-basic-invocation` (2 finding)

**1. [hn-companion-mcp](https://github.com/georgeck/hn-companion-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid post URL`

**2. [Google-MCP-Tools-Access](https://github.com/joseb33w/Google-MCP-Tools-Access)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid post URL`

### `tool-dry_run_query-basic-invocation` (2 finding)

**1. [bigquery-analysis-mcp-server](https://github.com/gotalab/bigquery-analysis-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**2. [coolify-mcp](https://github.com/jovert94/coolify-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-run_query_with_validation-basic-invocation` (2 finding)

**1. [bigquery-analysis-mcp-server](https://github.com/gotalab/bigquery-analysis-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**2. [coolify-mcp](https://github.com/jovert94/coolify-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-gsheets_update_cell-basic-invocation` (2 finding)

**1. [drive-mcp](https://github.com/rishipradeep-think41/drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to authenticate`

**2. [mcp-gdrive](https://github.com/General-Intelligence-Labs/mcp-gdrive)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 401: Login Required.`

### `tool-get_all_content-basic-invocation` (2 finding)

**1. [playwright-mcp-server](https://github.com/Kotelberg/playwright-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No active browser context. Please navigate to a page first.`

**2. [malicious_mcp](https://github.com/k1msum1n/malicious_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No active browser context. Please navigate to a page first.`

### `tool-list_pipelines-basic-invocation` (2 finding)

**1. [mcp-codepipeline-server](https://github.com/cuongdev/mcp-codepipeline-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

**2. [mcp-test-scenarios-server](https://github.com/kasturinarra/mcp-test-scenarios-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

### `tool-get_pipeline_state-basic-invocation` (2 finding)

**1. [mcp-codepipeline-server](https://github.com/cuongdev/mcp-codepipeline-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

**2. [mcp-test-scenarios-server](https://github.com/kasturinarra/mcp-test-scenarios-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

### `tool-list_pipeline_executions-basic-invocation` (2 finding)

**1. [mcp-codepipeline-server](https://github.com/cuongdev/mcp-codepipeline-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

**2. [mcp-test-scenarios-server](https://github.com/kasturinarra/mcp-test-scenarios-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: CredentialsError: Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1`

### `tool-search_repositories-basic-invocation` (2 finding)

**1. [mcp-github](https://github.com/MissionSquad/mcp-github)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

**2. [Mcp_client-server](https://github.com/kaustubhdeshmukh11/Mcp_client-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: GitHub PAT is required`

### `tool-create_deployment-basic-invocation` (2 finding)

**1. [mcp-fastapi](https://github.com/iamkhanwasim/mcp-fastapi)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: HttpError: HTTP request failed`

**2. [mcp-server-kubernetes](https://github.com/kmathur/mcp-server-kubernetes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: HttpError: HTTP request failed`

### `tool-create_namespace-basic-invocation` (2 finding)

**1. [mcp-fastapi](https://github.com/iamkhanwasim/mcp-fastapi)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: HttpError: HTTP request failed`

**2. [mcp-server-kubernetes](https://github.com/kmathur/mcp-server-kubernetes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: HttpError: HTTP request failed`

### `tool-get_collection_detail-basic-invocation` (2 finding)

**1. [mcp-insomnia](https://github.com/anggasct/mcp-insomnia)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Collection with ID test not found`

**2. [mcp-safesql](https://github.com/lakshjethani/mcp-safesql)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Collection with ID test not found`

### `tool-get_crate_doc-basic-invocation` (2 finding)

**1. [cargo-doc-mcp](https://github.com/spacemeowx2/cargo-doc-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

**2. [mcp-database-query](https://github.com/linlaz/mcp-database-query)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

### `tool-list_symbols-basic-invocation` (2 finding)

**1. [cargo-doc-mcp](https://github.com/spacemeowx2/cargo-doc-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

**2. [mcp-database-query](https://github.com/linlaz/mcp-database-query)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

### `tool-search_doc-basic-invocation` (2 finding)

**1. [cargo-doc-mcp](https://github.com/spacemeowx2/cargo-doc-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

**2. [mcp-database-query](https://github.com/linlaz/mcp-database-query)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Invalid project path: test. Cargo.toml not found.`

### `tool-adb_connect_wifi-basic-invocation` (2 finding)

**1. [adb-mcp](https://github.com/desamtralized/adb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb connect test:5555
/bin/sh: 1: adb: not found
`

**2. [simple-agent-and-mcp-server](https://github.com/linsun/simple-agent-and-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb connect test:5555
/bin/sh: 1: adb: not found
`

### `tool-adb_screenshot-basic-invocation` (2 finding)

**1. [adb-mcp](https://github.com/desamtralized/adb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb  shell screencap -p /sdcard/screenshot.png
/bin/sh: 1: adb: not found
`

**2. [simple-agent-and-mcp-server](https://github.com/linsun/simple-agent-and-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb  shell screencap -p /sdcard/screenshot.png
/bin/sh: 1: adb: not found
`

### `tool-adb_list_devices-basic-invocation` (2 finding)

**1. [adb-mcp](https://github.com/desamtralized/adb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb devices
/bin/sh: 1: adb: not found
`

**2. [simple-agent-and-mcp-server](https://github.com/linsun/simple-agent-and-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Command failed: adb devices
/bin/sh: 1: adb: not found
`

### `tool-search_fhir-basic-invocation` (2 finding)

**1. [flux-mcp](https://github.com/tehw0lf/flux-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search FHIR resources: Request failed with status code 404`

**2. [chat-with-fhir-mcp-server](https://github.com/llucbrell/chat-with-fhir-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to search FHIR resources: Request failed with status code 404`

### `tool-read_fhir-basic-invocation` (2 finding)

**1. [flux-mcp](https://github.com/tehw0lf/flux-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

**2. [chat-with-fhir-mcp-server](https://github.com/llucbrell/chat-with-fhir-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-get_honeybadger_fault-basic-invocation` (2 finding)

**1. [honeybadger-mcp](https://github.com/vishalzambre/honeybadger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

**2. [mcp-iso8859-writer](https://github.com/lmendezz/mcp-iso8859-writer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

### `tool-get_honeybadger_notices-basic-invocation` (2 finding)

**1. [honeybadger-mcp](https://github.com/vishalzambre/honeybadger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

**2. [mcp-iso8859-writer](https://github.com/lmendezz/mcp-iso8859-writer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

### `tool-list_honeybadger_faults-basic-invocation` (2 finding)

**1. [honeybadger-mcp](https://github.com/vishalzambre/honeybadger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

**2. [mcp-iso8859-writer](https://github.com/lmendezz/mcp-iso8859-writer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Project ID is required`

### `tool-get_command_info-basic-invocation` (2 finding)

**1. [drupal-tools-mcp](https://github.com/Cleversoft-IT/drupal-tools-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch command info: Request failed with status code 404`

**2. [nardocs](https://github.com/loganrenz/nardocs)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch command info: Request failed with status code 404`

### `tool-extract-html-fragment-basic-invocation` (2 finding)

**1. [mcp-node-fetch](https://github.com/mcollina/mcp-node-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [maat_mcp_server](https://github.com/loplat/maat_mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

### `tool-fetch-url-basic-invocation` (2 finding)

**1. [mcp-node-fetch](https://github.com/mcollina/mcp-node-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [maat_mcp_server](https://github.com/loplat/maat_mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

### `tool-check-status-basic-invocation` (2 finding)

**1. [mcp-node-fetch](https://github.com/mcollina/mcp-node-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [maat_mcp_server](https://github.com/loplat/maat_mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

### `tool-write-text-basic-invocation` (2 finding)

**1. [textwell-mcp](https://github.com/worldnine/textwell-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Textwell write failed: MCP error -32603: URL scheme execution failed: Command failed: open "textwell:///replace?text=test"
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'textwell:///replace?text=test'
`

**2. [freecad-mcp-server](https://github.com/lucygoodchild/freecad-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Textwell write failed: MCP error -32603: URL scheme execution failed: Command failed: open "textwell:///replace?text=test"
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'textwell:///replace?text=test'
`

### `tool-configure_round_robin-basic-invocation` (2 finding)

**1. [mcp-decent-sampler-drums](https://github.com/dandeliongold/mcp-decent-sampler-drums)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to configure round robin: Sample file not found: test`

**2. [best-practices-mcp](https://github.com/m-de-graaff/best-practices-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to configure round robin: Sample file not found: test`

### `tool-analyze_wav_samples-basic-invocation` (2 finding)

**1. [mcp-decent-sampler-drums](https://github.com/dandeliongold/mcp-decent-sampler-drums)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: File too small to be a valid WAV file`

**2. [best-practices-mcp](https://github.com/m-de-graaff/best-practices-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: File too small to be a valid WAV file`

### `tool-mysql_list_databases-basic-invocation` (2 finding)

**1. [mysql-mcp](https://github.com/pickstar-2002/mysql-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 执行工具 mysql_list_databases 时发生错误: 数据库未连接，请先调用 connect() 方法`

**2. [mcp-mysql-server](https://github.com/ashenud/mcp-mysql-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to list databases: `

### `tool-screenshot-basic-invocation` (2 finding)

**1. [cline-browser-use-mcp](https://github.com/ztobs/cline-browser-use-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

**2. [arxiv-mcp-server](https://github.com/makspyn/arxiv-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

### `tool-get_html-basic-invocation` (2 finding)

**1. [cline-browser-use-mcp](https://github.com/ztobs/cline-browser-use-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

**2. [arxiv-mcp-server](https://github.com/makspyn/arxiv-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Browser operation failed: Python script failed with code 127: `

### `tool-read_note-basic-invocation` (2 finding)

**1. [obsidian-mcp](https://github.com/quinny1187/obsidian-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute read_note: Invalid vault path: test`

**2. [obsidian-mcp](https://github.com/jianruidutong/obsidian-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to read note: Error: Note not found: test`

### `tool-serve-basic-invocation` (2 finding)

**1. [Ollama-mcp](https://github.com/NightTrek/Ollama-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to start Ollama server: Command failed: ollama serve
Error: listen tcp 127.0.0.1:11434: bind: address already in use
`

**2. [coding-standards-mcp](https://github.com/manasvi-turing/coding-standards-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to start Ollama server: Command failed: ollama serve
Error: listen tcp 127.0.0.1:11434: bind: address already in use
`

### `tool-show-basic-invocation` (2 finding)

**1. [Ollama-mcp](https://github.com/NightTrek/Ollama-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to show model info: Command failed: ollama show test
Error: model 'test' not found
`

**2. [coding-standards-mcp](https://github.com/manasvi-turing/coding-standards-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to show model info: Command failed: ollama show test
Error: model 'test' not found
`

### `tool-excel_copy_sheet-basic-invocation` (2 finding)

**1. [excel-mcp-server](https://github.com/negokaz/excel-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: zip: not a valid zip file`

**2. [mcp-servers-manu](https://github.com/manuel2f/mcp-servers-manu)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: zip: not a valid zip file`

### `tool-search_emails-basic-invocation` (2 finding)

**1. [jmap-mcp-server](https://github.com/jahfer/jmap-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**2. [email-mcp](https://github.com/adamswanglin/email-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 缺少必要的IMAP配置。请检查环境变量: IMAP_HOST, EMAIL_USER, EMAIL_PASSWORD`

### `tool-fork_repository-basic-invocation` (2 finding)

**1. [gitee-mcp-server](https://github.com/normal-coder/gitee-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found Project`

**2. [vibecoding-mcp-servers](https://github.com/mastoica/vibecoding-mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found Project`

### `tool-create_branch-basic-invocation` (2 finding)

**1. [gitee-mcp-server](https://github.com/normal-coder/gitee-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found Project`

**2. [vibecoding-mcp-servers](https://github.com/mastoica/vibecoding-mcp-servers)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found Project`

### `tool-get_notice_details-basic-invocation` (2 finding)

**1. [nornir_mcp](https://github.com/yhvh-chen/nornir_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Resource not found`

**2. [e-oglasna-mcp](https://github.com/matejsarlija/e-oglasna-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Resource not found`

### `tool-roll_dice-basic-invocation` (2 finding)

**1. [NetBrain_MCP](https://github.com/IKoreyoshiI/NetBrain_MCP)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to roll dice: Invalid dice notation: test. Expected format: NdS (e.g., 3d6, d20)`

**2. [mcp-dice-roller](https://github.com/matthewholliday/mcp-dice-roller)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to roll dice: Invalid dice notation: test. Expected format: NdS (e.g., 3d6, d20)`

### `tool-get_paper_details-basic-invocation` (2 finding)

**1. [iacr-mcp-server](https://github.com/doomdagadiggiedahdah/iacr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Paper details retrieval failed: Request failed with status code 403`

**2. [mcp-smartsheet](https://github.com/mattjhughes/mcp-smartsheet)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Paper details retrieval failed: Request failed with status code 403`

### `tool-download_paper-basic-invocation` (2 finding)

**1. [iacr-mcp-server](https://github.com/doomdagadiggiedahdah/iacr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Paper download failed: Request failed with status code 403`

**2. [mcp-smartsheet](https://github.com/mattjhughes/mcp-smartsheet)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Paper download failed: Request failed with status code 403`

### `tool-wallet_balance-basic-invocation` (2 finding)

**1. [zapmail-mcp](https://github.com/dsouzaalan/zapmail-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: ZAPMAIL_API_KEY not configured`

**2. [mcp_agent_slackbot_sse-server](https://github.com/mayank240903/mcp_agent_slackbot_sse-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: ZAPMAIL_API_KEY not configured`

### `tool-list_workspaces-basic-invocation` (2 finding)

**1. [zapmail-mcp](https://github.com/dsouzaalan/zapmail-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: ZAPMAIL_API_KEY not configured`

**2. [mcp_agent_slackbot_sse-server](https://github.com/mayank240903/mcp_agent_slackbot_sse-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: ZAPMAIL_API_KEY not configured`

### `tool-provide_feature_input-basic-invocation` (2 finding)

**1. [mcp-feature-discussion](https://github.com/squirrelogic/mcp-feature-discussion)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Feature test not found`

**2. [supabase-mcp-server](https://github.com/mcp-use/supabase-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Feature test not found`

### `tool-browser_launch-basic-invocation` (2 finding)

**1. [mcp-browser-screenshot](https://github.com/seabassgonzalez/mcp-browser-screenshot)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Could not find Chrome (ver. 138.0.7204.94). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [mcp-client](https://github.com/mechizen/mcp-client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Could not find Chrome (ver. 138.0.7204.94). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-browser_navigate-basic-invocation` (2 finding)

**1. [mcp-browser-screenshot](https://github.com/seabassgonzalez/mcp-browser-screenshot)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Could not find Chrome (ver. 138.0.7204.94). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

**2. [mcp-client](https://github.com/mechizen/mcp-client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Could not find Chrome (ver. 138.0.7204.94). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-get_stamp-basic-invocation` (2 finding)

**1. [stampchain-mcp](https://github.com/stampchain-io/stampchain-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: Validation failed: [
  {
    "code": "custom",
    "message": "stamp_id must be a positive number",
    "path": [
      "stamp_id"
    ]
  }
]`

**2. [hevy-mcp-server](https://github.com/meimakes/hevy-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: Validation failed: [
  {
    "code": "custom",
    "message": "stamp_id must be a positive number",
    "path": [
      "stamp_id"
    ]
  }
]`

### `tool-search_stamps-basic-invocation` (2 finding)

**1. [stampchain-mcp](https://github.com/stampchain-io/stampchain-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: resource not found: /stamps`

**2. [hevy-mcp-server](https://github.com/meimakes/hevy-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: resource not found: /stamps`

### `tool-get_recent_stamps-basic-invocation` (2 finding)

**1. [stampchain-mcp](https://github.com/stampchain-io/stampchain-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: resource not found: /stamps`

**2. [hevy-mcp-server](https://github.com/meimakes/hevy-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Execution Error: resource not found: /stamps`

### `tool-generate_document-basic-invocation` (2 finding)

**1. [youtube-transcript-mcp](https://github.com/RahulPatkiWork/youtube-transcript-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'forEach')`

**2. [docgen-mcp](https://github.com/mideliberto/docgen-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'forEach')`

### `tool-start_interactive_command-basic-invocation` (2 finding)

**1. [kalilinuxmcp](https://github.com/sfz009900/kalilinuxmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

**2. [mcp](https://github.com/mubeensadiq/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

### `tool-send_input_to_command-basic-invocation` (2 finding)

**1. [kalilinuxmcp](https://github.com/sfz009900/kalilinuxmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

**2. [mcp](https://github.com/mubeensadiq/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 无法读取SSH私钥文件: C:\Users\hack004\.ssh\kali000`

### `tool-convert_docx_to_markdown-basic-invocation` (2 finding)

**1. [mcp](https://github.com/kittolau/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: convert_docx_to_markdown failed`

**2. [skills-integrate-mcp-with-copilot2](https://github.com/mumustafa/skills-integrate-mcp-with-copilot2)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: convert_docx_to_markdown failed`

### `tool-analyze_images_directory-basic-invocation` (2 finding)

**1. [mcp](https://github.com/kittolau/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: analyze_images_directory failed`

**2. [skills-integrate-mcp-with-copilot2](https://github.com/mumustafa/skills-integrate-mcp-with-copilot2)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: analyze_images_directory failed`

### `tool-generate-dataset-basic-invocation` (2 finding)

**1. [faker-mcp](https://github.com/funsjanssen/faker-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Validation error: schema.entities: Schema must contain at least one entity`

**2. [competitions-reporter-mcp](https://github.com/mzkrasner/competitions-reporter-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Validation error: schema.entities: Schema must contain at least one entity`

### `tool-get_note-basic-invocation` (2 finding)

**1. [PySqlitMCP](https://github.com/Python51888/PySqlitMCP)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: note request failed: Get "test/api/notes/test": unsupported protocol scheme ""`

**2. [mcpserver-demo](https://github.com/napat/mcpserver-demo)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: note request failed: Get "test/api/notes/test": unsupported protocol scheme ""`

### `tool-get_visitor_count-basic-invocation` (2 finding)

**1. [PySqlitMCP](https://github.com/Python51888/PySqlitMCP)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: visitor count request failed: Get "test/api/visitors": unsupported protocol scheme ""`

**2. [mcpserver-demo](https://github.com/napat/mcpserver-demo)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: visitor count request failed: Get "test/api/visitors": unsupported protocol scheme ""`

### `tool-python_script-basic-invocation` (2 finding)

**1. [mcp_quickstart_python](https://github.com/jessicarod7/mcp_quickstart_python)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行错误: Python脚本执行失败: Command failed: python3 -c "test"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'test' is not defined
`

**2. [simple-mcp-server](https://github.com/neozhangtcl/simple-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行错误: Python脚本执行失败: Command failed: python3 -c "test"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'test' is not defined
`

### `tool-recall_memory-basic-invocation` (2 finding)

**1. [memory-mcp](https://github.com/hridaya423/memory-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: memory.tags.join is not a function`

**2. [mcp-automem](https://github.com/verygoodplugins/mcp-automem)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found`

### `tool-get_temperature-basic-invocation` (2 finding)

**1. [pgsql-mcp](https://github.com/surajmandalcell/pgsql-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: temperature service returned status: 404 Not Found`

**2. [go-mcp-temperature-server](https://github.com/omaciel/go-mcp-temperature-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: temperature service returned status: 404 Not Found`

### `tool-steady_login-basic-invocation` (2 finding)

**1. [steady-mcp](https://github.com/Sarthak-ignite/steady-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: STEADY_EMAIL is not set (or email argument missing).`

**2. [MCP-server-omkar](https://github.com/omkar1930/MCP-server-omkar)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: STEADY_EMAIL is not set (or email argument missing).`

### `tool-signavio_authenticate-basic-invocation` (2 finding)

**1. [signavio-mcp](https://github.com/willpowell8/signavio-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_authenticate: Authentication error: Request failed with status code 500`

**2. [mcp-server-chart-bach](https://github.com/pengfeiJoker/mcp-server-chart-bach)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_authenticate: Authentication error: Request failed with status code 500`

### `tool-signavio_get_root_folders-basic-invocation` (2 finding)

**1. [signavio-mcp](https://github.com/willpowell8/signavio-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_get_root_folders: Authentication error: Request failed with status code 500`

**2. [mcp-server-chart-bach](https://github.com/pengfeiJoker/mcp-server-chart-bach)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_get_root_folders: Authentication error: Request failed with status code 500`

### `tool-signavio_get_folder_contents-basic-invocation` (2 finding)

**1. [signavio-mcp](https://github.com/willpowell8/signavio-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_get_folder_contents: Authentication error: Request failed with status code 500`

**2. [mcp-server-chart-bach](https://github.com/pengfeiJoker/mcp-server-chart-bach)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool signavio_get_folder_contents: Authentication error: Request failed with status code 500`

### `tool-get_disk_usage-basic-invocation` (2 finding)

**1. [MCP](https://github.com/markolive1501/MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 127: Command failed: wmic logicaldisk get size,freespace,caption
/bin/sh: 1: wmic: not found
`

**2. [job-app-mcp](https://github.com/pt-perkasa-pilar-utama/job-app-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 127: Command failed: wmic logicaldisk get size,freespace,caption
/bin/sh: 1: wmic: not found
`

### `tool-list_workflows-basic-invocation` (2 finding)

**1. [n8n-workflow-builder](https://github.com/makafeli/n8n-workflow-builder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

**2. [n8n-mcp-server](https://github.com/rakeshgangwar/n8n-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-get_workflow-basic-invocation` (2 finding)

**1. [n8n-workflow-builder](https://github.com/makafeli/n8n-workflow-builder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

**2. [n8n-mcp-server](https://github.com/rakeshgangwar/n8n-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-create_workflow-basic-invocation` (2 finding)

**1. [n8n-workflow-builder](https://github.com/makafeli/n8n-workflow-builder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

**2. [n8n-mcp-server](https://github.com/rakeshgangwar/n8n-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-get_focus_zone-basic-invocation` (2 finding)

**1. [calcom-mcp](https://github.com/Danielpeter-99/calcom-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: e[2].split is not a function`

**2. [project-graph-mcp](https://github.com/rnd-pro/project-graph-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: e[2].split is not a function`

### `tool-create_connection-basic-invocation` (2 finding)

**1. [ssh-mcp-server](https://github.com/vilasone455/ssh-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unknown machine_id 'test'.`

**2. [mobile-pixel-mcp](https://github.com/rogerfuentes/mobile-pixel-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unknown machine_id 'test'.`

### `tool-run-collection-basic-invocation` (2 finding)

**1. [bruno-mcp](https://github.com/hungthai1401/bruno-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: CLI stderr: /bin/sh: 1: bru: not found
`

**2. [mcp-notion](https://github.com/roygabriel/mcp-notion)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: CLI stderr: /bin/sh: 1: bru: not found
`

### `tool-jira_search-basic-invocation` (2 finding)

**1. [jira-mcp-server](https://github.com/SunWooBang/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_search: Invalid URL`

**2. [chess-mcp-server](https://github.com/sagarjaink/chess-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_search: Invalid URL`

### `tool-jira_get_issue-basic-invocation` (2 finding)

**1. [jira-mcp-server](https://github.com/SunWooBang/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_get_issue: Invalid URL`

**2. [chess-mcp-server](https://github.com/sagarjaink/chess-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_get_issue: Invalid URL`

### `tool-jira_create_issue-basic-invocation` (2 finding)

**1. [jira-mcp-server](https://github.com/SunWooBang/jira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_create_issue: Project test not found or not accessible`

**2. [chess-mcp-server](https://github.com/sagarjaink/chess-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing jira_create_issue: Project test not found or not accessible`

### `tool-courses-basic-invocation` (2 finding)

**1. [firecrawl-mcp-server](https://github.com/JayceeTran1995/firecrawl-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

**2. [classroom_mcp](https://github.com/salshah20/classroom_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

### `tool-course-details-basic-invocation` (2 finding)

**1. [firecrawl-mcp-server](https://github.com/JayceeTran1995/firecrawl-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

**2. [classroom_mcp](https://github.com/salshah20/classroom_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

### `tool-assignments-basic-invocation` (2 finding)

**1. [firecrawl-mcp-server](https://github.com/JayceeTran1995/firecrawl-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

**2. [classroom_mcp](https://github.com/salshah20/classroom_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Google Classroom API not initialized. Please run: npm run setup-auth`

### `tool-mysql_query-basic-invocation` (2 finding)

**1. [mcp-server-mysql](https://github.com/zhengyun1008/mcp-server-mysql)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No database configurations found.`

**2. [mysql-mcp-server](https://github.com/eddevfront/mysql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to connect to MySQL: Error`

### `tool-nasa_mars_rover_photos-basic-invocation` (2 finding)

**1. [mcp-ts-stdio-nasa](https://github.com/jezweb/mcp-ts-stdio-nasa)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Failed to fetch Mars Rover photos: NasaApiError: NASA API returned 404: Not Found`

**2. [development-mcp-server](https://github.com/saudqsaleshandy/development-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Failed to fetch Mars Rover photos: NasaApiError: NASA API returned 404: Not Found`

### `tool-rezdy_agent_search_products-basic-invocation` (2 finding)

**1. [rezdy-agent-mcp](https://github.com/jezweb/rezdy-agent-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing rezdy_agent_search_products: Failed to make request to /marketplace/products?: Rezdy API Error: `

**2. [fyta-mcp-server](https://github.com/schimmmi/fyta-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing rezdy_agent_search_products: Failed to make request to /marketplace/products?: Rezdy API Error: `

### `tool-rezdy_agent_get_product-basic-invocation` (2 finding)

**1. [rezdy-agent-mcp](https://github.com/jezweb/rezdy-agent-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing rezdy_agent_get_product: Failed to make request to /marketplace/products/50: Rezdy API Error: `

**2. [fyta-mcp-server](https://github.com/schimmmi/fyta-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing rezdy_agent_get_product: Failed to make request to /marketplace/products/50: Rezdy API Error: `

### `tool-proxychains_run-basic-invocation` (2 finding)

**1. [genesys-cloud-mcp-server](https://github.com/MakingChatbots/genesys-cloud-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: SSH command failed: The argument 'command' must be a string without null bytes. Received `ssh kali "echo '# ProxyChains-ng configuration generated by proxychains-mcp\n` +
  '\n' +
  'dynamic_chain\n' +
  '\n' +
  'pro...`

**2. [sec-proxychains-mcp](https://github.com/schwarztim/sec-proxychains-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: SSH command failed: The argument 'command' must be a string without null bytes. Received `ssh kali "echo '# ProxyChains-ng configuration generated by proxychains-mcp\n` +
  '\n' +
  'dynamic_chain\n' +
  '\n' +
  'pro...`

### `tool-read_task-basic-invocation` (2 finding)

**1. [agent-comm-mcp-server](https://github.com/jerfowler/agent-comm-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: File not found: /home/tecnico/Desktop/Frameworks/mcp-check/comm/test/test/INIT.md`

**2. [mcp_server](https://github.com/skpriya12/mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: File not found: /home/tecnico/Desktop/Frameworks/mcp-check/comm/test/test/INIT.md`

### `tool-github_flow_start-basic-invocation` (2 finding)

**1. [local-search-mcp](https://github.com/PatrickRuddiman/local-search-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: sessionManager.get is not a function`

**2. [slambed-mcp](https://github.com/slamb2k/slambed-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: sessionManager.get is not a function`

### `tool-exec-basic-invocation` (2 finding)

**1. [microsoft-planner-mcp](https://github.com/vyente-ruffin/microsoft-planner-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: EOF`

**2. [prolog_mcp](https://github.com/snoglobe/prolog_mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: EOF`

### `tool-run_tests-basic-invocation` (2 finding)

**1. [mcp-test-runner](https://github.com/privsim/mcp-test-runner)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, mkdir 'test/test_reports'`

**2. [skills-integrate-mcp-with-copilot](https://github.com/speedloader007-shaken/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, mkdir 'test/test_reports'`

### `tool-get_pattern_details-basic-invocation` (2 finding)

**1. [design_patterns_mcp](https://github.com/apolosan/design_patterns_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to create prepared statement: no such table: patterns`

**2. [spiralmem](https://github.com/spiralbewilder/spiralmem)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to create prepared statement: no such table: patterns`

### `tool-task_natural-basic-invocation` (2 finding)

**1. [money-manager-mcp](https://github.com/shahlaukik/money-manager-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task list project:mcp-check
/bin/sh: 1: task: not found
`

**2. [mcp-taskwarrior-ai](https://github.com/storypixel/mcp-taskwarrior-ai)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task list project:mcp-check
/bin/sh: 1: task: not found
`

### `tool-task_raw-basic-invocation` (2 finding)

**1. [money-manager-mcp](https://github.com/shahlaukik/money-manager-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task test
/bin/sh: 1: task: not found
`

**2. [mcp-taskwarrior-ai](https://github.com/storypixel/mcp-taskwarrior-ai)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task test
/bin/sh: 1: task: not found
`

### `tool-task_context_set-basic-invocation` (2 finding)

**1. [money-manager-mcp](https://github.com/shahlaukik/money-manager-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task context define test project:test or +test
/bin/sh: 1: task: not found
`

**2. [mcp-taskwarrior-ai](https://github.com/storypixel/mcp-taskwarrior-ai)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Taskwarrior error: Command failed: task context define test project:test or +test
/bin/sh: 1: task: not found
`

### `tool-generate_and_upload_image-basic-invocation` (2 finding)

**1. [FinanceMCP](https://github.com/Xxx00xxX33/FinanceMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FAL_KEY environment variable is not set`

**2. [ai-image-generator-mcp](https://github.com/sumitpore/ai-image-generator-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FAL_KEY environment variable is not set`

### `tool-search_pages-basic-invocation` (2 finding)

**1. [mcp-bookstack](https://github.com/yellowgg2/mcp-bookstack)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch pages: TypeError: Invalid URL`

**2. [notion-mcp-server](https://github.com/tonutoz/notion-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: NOTION_API_KEY not configured`

### `tool-rss_to_md-basic-invocation` (2 finding)

**1. [mcp-proxmox](https://github.com/Zaptimist/mcp-proxmox)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to process RSS feed: Request failed with status code 404`

**2. [mcp-rss-md](https://github.com/taweili/mcp-rss-md)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to process RSS feed: Request failed with status code 404`

### `tool-search_packages-basic-invocation` (2 finding)

**1. [flutter-package-mcp-server](https://github.com/OrtakProje-1/flutter-package-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool çalıştırılırken hata: Cannot read properties of undefined (reading 'version')`

**2. [azureDevops-mcp](https://github.com/techsouvik/azureDevops-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool çalıştırılırken hata: Cannot read properties of undefined (reading 'version')`

### `tool-opensearch_list_clusters-basic-invocation` (2 finding)

**1. [Hackernews_mcp](https://github.com/sam3690/Hackernews_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

**2. [opensearch-mcp-server](https://github.com/thabiso-m-absa/opensearch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

### `tool-opensearch_search-basic-invocation` (2 finding)

**1. [Hackernews_mcp](https://github.com/sam3690/Hackernews_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

**2. [opensearch-mcp-server](https://github.com/thabiso-m-absa/opensearch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

### `tool-opensearch_aggregate-basic-invocation` (2 finding)

**1. [Hackernews_mcp](https://github.com/sam3690/Hackernews_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

**2. [opensearch-mcp-server](https://github.com/thabiso-m-absa/opensearch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize OpenSearch: Failed to connect to any OpenSearch cluster`

### `tool-list_tracks-basic-invocation` (2 finding)

**1. [fathom-video-mcp](https://github.com/trevorwelch/fathom-video-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid YouTube URL or video ID`

**2. [mcp-youtube-transcript-pro](https://github.com/thisis-romar/mcp-youtube-transcript-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid YouTube URL or video ID`

### `tool-get_transcript-basic-invocation` (2 finding)

**1. [fathom-video-mcp](https://github.com/trevorwelch/fathom-video-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get transcript: Invalid YouTube URL`

**2. [mcp-youtube-transcript-pro](https://github.com/thisis-romar/mcp-youtube-transcript-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get transcript: Invalid YouTube URL`

### `tool-get_timed_transcript-basic-invocation` (2 finding)

**1. [fathom-video-mcp](https://github.com/trevorwelch/fathom-video-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get transcript: Invalid YouTube URL`

**2. [mcp-youtube-transcript-pro](https://github.com/thisis-romar/mcp-youtube-transcript-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get transcript: Invalid YouTube URL`

### `tool-append_entry-basic-invocation` (2 finding)

**1. [obsidian-dictionary-mcp](https://github.com/SaraHan774/obsidian-dictionary-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

**2. [NeuralFoundry](https://github.com/thomaskty/NeuralFoundry)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

### `tool-search_entry-basic-invocation` (2 finding)

**1. [obsidian-dictionary-mcp](https://github.com/SaraHan774/obsidian-dictionary-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

**2. [NeuralFoundry](https://github.com/thomaskty/NeuralFoundry)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

### `tool-get_entry-basic-invocation` (2 finding)

**1. [obsidian-dictionary-mcp](https://github.com/SaraHan774/obsidian-dictionary-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

**2. [NeuralFoundry](https://github.com/thomaskty/NeuralFoundry)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: No file_path provided and no default glossary path configured. Either provide file_path parameter or start the server with --glossary-path argument.`

### `tool-read_clipboard-basic-invocation` (2 finding)

**1. [WSLSnapit-MCP](https://github.com/peterparker57/WSLSnapit-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to read clipboard: Command failed: powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand CgAgACAAIAAgACAAIAAgACAAdAByAHkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEUAcgByAG8AcgBBAGMAdABpAG8AbgBQAHIAZQBmAGUAcgBlAG4AYwBlACAAPQAgACcAUwB0AG8AcAAnAAoAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzAAoAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQB...`

**2. [mcp_server](https://github.com/tonyreuropa/mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to read clipboard: Command failed: powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand CgAgACAAIAAgACAAIAAgACAAdAByAHkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAkAEUAcgByAG8AcgBBAGMAdABpAG8AbgBQAHIAZQBmAGUAcgBlAG4AYwBlACAAPQAgACcAUwB0AG8AcAAnAAoAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzAAoAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQB...`

### `tool-session_create-basic-invocation` (2 finding)

**1. [firefox-mcp-server](https://github.com/JediLuke/firefox-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing session_create: Firefox browser is not running. Please launch it first using the launch_firefox_multi tool.`

**2. [ntfy-hub-mcp](https://github.com/utenadev/ntfy-hub-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing session_create: Firefox browser is not running. Please launch it first using the launch_firefox_multi tool.`

### `tool-infracost_breakdown-basic-invocation` (2 finding)

**1. [infracost_mcp](https://github.com/phildougherty/infracost_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

**2. [tick-tick-mcp-server](https://github.com/vantarc/tick-tick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

### `tool-infracost_diff-basic-invocation` (2 finding)

**1. [infracost_mcp](https://github.com/phildougherty/infracost_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

**2. [tick-tick-mcp-server](https://github.com/vantarc/tick-tick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

### `tool-infracost_output-basic-invocation` (2 finding)

**1. [infracost_mcp](https://github.com/phildougherty/infracost_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

**2. [tick-tick-mcp-server](https://github.com/vantarc/tick-tick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Infracost CLI is not installed. Please install it from https://www.infracost.io/docs/`

### `tool-fetch_iiif_manifest-basic-invocation` (2 finding)

**1. [mcp-iiif-images](https://github.com/mikeapp/mcp-iiif-images)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF manifest: Invalid URL`

**2. [stock-mcp](https://github.com/very99/stock-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF manifest: Invalid URL`

### `tool-fetch_iiif_image-basic-invocation` (2 finding)

**1. [mcp-iiif-images](https://github.com/mikeapp/mcp-iiif-images)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF image: Invalid URL`

**2. [stock-mcp](https://github.com/very99/stock-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF image: Invalid URL`

### `tool-fetch_iiif_image_region-basic-invocation` (2 finding)

**1. [mcp-iiif-images](https://github.com/mikeapp/mcp-iiif-images)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF image region: Region must be "full" or in "pct:" format (e.g., "pct:20,20,50,50")`

**2. [stock-mcp](https://github.com/very99/stock-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch IIIF image region: Region must be "full" or in "pct:" format (e.g., "pct:20,20,50,50")`

### `tool-send_api_request-basic-invocation` (2 finding)

**1. [api-request-mcp-server](https://github.com/Nicolas-Gong/api-request-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

**2. [custom-mcp](https://github.com/vimaleshbe/custom-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-list_recent_failed_jobs-basic-invocation` (2 finding)

**1. [Jenkins-server-mcp](https://github.com/hekmon8/Jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**2. [mcpblox](https://github.com/vivekhaldar/mcpblox)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-count_failed_jobs-basic-invocation` (2 finding)

**1. [Jenkins-server-mcp](https://github.com/hekmon8/Jenkins-server-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

**2. [mcpblox](https://github.com/vivekhaldar/mcpblox)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-listFiles-basic-invocation` (2 finding)

**1. [columbo](https://github.com/rezo8/columbo)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, scandir '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

**2. [file-mcp-server](https://github.com/ylcnfrht/file-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, scandir '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

### `tool-capture_window-basic-invocation` (2 finding)

**1. [webhook-mcp-server](https://github.com/zebbern/webhook-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: One of windowHandle, windowTitle, or processName must be provided`

**2. [screenshot-mcp](https://github.com/ylubi/screenshot-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: One of windowHandle, windowTitle, or processName must be provided`

### `tool-capture_region-basic-invocation` (2 finding)

**1. [webhook-mcp-server](https://github.com/zebbern/webhook-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Linux platform implementation not yet complete`

**2. [screenshot-mcp](https://github.com/ylubi/screenshot-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Linux platform implementation not yet complete`

### `tool-list_windows-basic-invocation` (2 finding)

**1. [webhook-mcp-server](https://github.com/zebbern/webhook-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Linux platform implementation not yet complete`

**2. [screenshot-mcp](https://github.com/ylubi/screenshot-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Linux platform implementation not yet complete`

### `tool-download_image-basic-invocation` (2 finding)

**1. [stock-images-mcp](https://github.com/jeanpfs/stock-images-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "validation": "url",
    "code": "invalid_string",
    "message": "Invalid url",
    "path": [
      "url"
    ]
  }
]`

**2. [mcp-image-downloader](https://github.com/cced3000/mcp-image-downloader)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Invalid image URL: test`

### `tool-git_status-basic-invocation` (2 finding)

**1. [your-memory](https://github.com/jonathan-politzki/your-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

**2. [mcp-git](https://github.com/kwanLeeFrmVi/mcp-git)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

### `tool-git_diff_unstaged-basic-invocation` (2 finding)

**1. [your-memory](https://github.com/jonathan-politzki/your-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

**2. [mcp-git](https://github.com/kwanLeeFrmVi/mcp-git)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

### `tool-git_diff_staged-basic-invocation` (2 finding)

**1. [your-memory](https://github.com/jonathan-politzki/your-memory)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

**2. [mcp-git](https://github.com/kwanLeeFrmVi/mcp-git)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Git command failed: undefined`

### `tool-find-basic-invocation` (2 finding)

**1. [mongodb-mcp-that-works](https://github.com/sourabhfb/mongodb-mcp-that-works)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

**2. [jimeng-web-mcp](https://github.com/LupinLin1/jimeng-web-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

### `tool-findOne-basic-invocation` (2 finding)

**1. [mongodb-mcp-that-works](https://github.com/sourabhfb/mongodb-mcp-that-works)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

**2. [jimeng-web-mcp](https://github.com/LupinLin1/jimeng-web-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MONGODB_URI environment variable is required`

### `tool-execute-basic-invocation` (2 finding)

**1. [mysql-mcp-server](https://github.com/koh-yoshimoto/mysql-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: MySQL connection not established`

**2. [mcp-graphiti](https://github.com/steven0lisa/mcp-graphiti)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MySQL connection not established`

### `tool-process_get_execution-basic-invocation` (2 finding)

**1. [plex_mcp_server](https://github.com/richarddas/plex_mcp_server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Execution with ID test not found`

**2. [mcp-shell-server](https://github.com/mako10k/mcp-shell-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Execution with ID test not found`

### `tool-create-stream-basic-invocation` (2 finding)

**1. [moveflow_aptos_mcp_server](https://github.com/ctianming/moveflow_aptos_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot convert test to a BigInt`

**2. [mcp-server-google-workspace](https://github.com/alanse-inc/mcp-server-google-workspace)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot convert test to a BigInt`

### `tool-check_vulnerabilities-basic-invocation` (2 finding)

**1. [mcp-osv](https://github.com/gleicon/mcp-osv)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: OSV API returned non-OK status: 405 405 Method Not Allowed`

**2. [google-ads-mcp-server](https://github.com/channel47/google-ads-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OSV API returned non-OK status: 405 405 Method Not Allowed`

### `tool-distance_and_duration_bw_starts_and_stops-basic-invocation` (2 finding)

**1. [vcenter-mcp-server](https://github.com/lijian-ui/vcenter-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

**2. [api-market-mcp-server](https://github.com/fastmcp-me/api-market-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

### `tool-Get_audio_analysis_URL-basic-invocation` (2 finding)

**1. [vcenter-mcp-server](https://github.com/lijian-ui/vcenter-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

**2. [api-market-mcp-server](https://github.com/fastmcp-me/api-market-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

### `tool-Whisper_Audio_Processing-basic-invocation` (2 finding)

**1. [vcenter-mcp-server](https://github.com/lijian-ui/vcenter-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

**2. [api-market-mcp-server](https://github.com/fastmcp-me/api-market-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API request failed: Request failed with status code 400 - {"message":"No x-api-market-key or x-magicapi-key defined in headers"}`

### `tool-get_lunar-basic-invocation` (2 finding)

**1. [lunar-calendar-mcp](https://github.com/RaoHai/lunar-calendar-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: illegal solar year: NaN`

**2. [obsidian-mcp-server](https://github.com/fromsko/obsidian-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: illegal solar year: NaN`

### `tool-get_taboo-basic-invocation` (2 finding)

**1. [lunar-calendar-mcp](https://github.com/RaoHai/lunar-calendar-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: illegal solar year: NaN`

**2. [obsidian-mcp-server](https://github.com/fromsko/obsidian-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: illegal solar year: NaN`

### `tool-fakestore_get_product-basic-invocation` (2 finding)

**1. [mcp-server-graphql](https://github.com/setyolegowo/mcp-server-graphql)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch product: Product with ID 50 not found`

**2. [mcp-server-fakestore](https://github.com/habibsalimov/mcp-server-fakestore)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch product: Product with ID 50 not found`

### `tool-futurevuls_get_cves-basic-invocation` (2 finding)

**1. [trading_mcp_server](https://github.com/vaibhavanand31/trading_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Internal error: HTTP 502: <html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
</body>
</html>
`

**2. [futurevuls-mcp](https://github.com/keides2/futurevuls-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Internal error: HTTP 502: <html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
</body>
</html>
`

### `tool-gemini_multimodal_query-basic-invocation` (2 finding)

**1. [mcp-ssh-server](https://github.com/yoi-hibino/mcp-ssh-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

**2. [Gemini-mcp](https://github.com/LKbaba/Gemini-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

### `tool-gemini_analyze_content-basic-invocation` (2 finding)

**1. [mcp-ssh-server](https://github.com/yoi-hibino/mcp-ssh-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

**2. [Gemini-mcp](https://github.com/LKbaba/Gemini-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

### `tool-gemini_analyze_codebase-basic-invocation` (2 finding)

**1. [mcp-ssh-server](https://github.com/yoi-hibino/mcp-ssh-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

**2. [Gemini-mcp](https://github.com/LKbaba/Gemini-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No authentication configured. Set one of:
  - GEMINI_API_KEY for AI Studio mode
  - GOOGLE_GENAI_USE_VERTEXAI=true + GOOGLE_CLOUD_PROJECT for Vertex AI mode
  - Paste your service account JSON directly into the env field
See README.md for details.`

### `tool-spawn-basic-invocation` (2 finding)

**1. [tmux-claude-mcp-server](https://github.com/michael-abdo/tmux-claude-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to spawn instance: ENOTDIR: not a directory, mkdir 'test/exec_413116'`

**2. [mcp-server](https://github.com/remem-mcp/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to spawn instance: ENOTDIR: not a directory, mkdir 'test/exec_413116'`

### `tool-send-basic-invocation` (2 finding)

**1. [tmux-claude-mcp-server](https://github.com/michael-abdo/tmux-claude-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to send to instance: Instance not found: test`

**2. [mcp-server](https://github.com/remem-mcp/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to send to instance: Instance not found: test`

### `tool-read-basic-invocation` (2 finding)

**1. [tmux-claude-mcp-server](https://github.com/michael-abdo/tmux-claude-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to read from instance: Instance not found: test`

**2. [mcp-server](https://github.com/remem-mcp/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Failed to read from instance: Instance not found: test`

### `tool-search_products-basic-invocation` (2 finding)

**1. [nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

**2. [sun_ecommerce_mcp](https://github.com/solana8800/sun_ecommerce_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: this.toolHandler.handleToolCall is not a function`

### `tool-puppeteer_list_tabs-basic-invocation` (2 finding)

**1. [apostrophe-cms-generator](https://github.com/andrewmat32/apostrophe-cms-generator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

**2. [puppeteer-mcp-server](https://github.com/todoforai/puppeteer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

### `tool-puppeteer_select_tab-basic-invocation` (2 finding)

**1. [apostrophe-cms-generator](https://github.com/andrewmat32/apostrophe-cms-generator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

**2. [puppeteer-mcp-server](https://github.com/todoforai/puppeteer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing X server to start the headful browser. Either set headless to true or use xvfb-run to run your Puppeteer script.`

### `tool-read_file_force-basic-invocation` (2 finding)

**1. [iconfont-mcp](https://github.com/zys8119/iconfont-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

**2. [smart-fs-mcp](https://github.com/zio3/smart-fs-mcp)** (nodejs)
- Type: `InvalidResponse`
- Message: `Tool response does not match expected structure`

### `tool-android_open_app-basic-invocation` (2 finding)

**1. [mcp-token-bench](https://github.com/0x5457/mcp-token-bench)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_open_app: Error executing command 'android_open_app': Failed to open app test: Command failed: adb  shell monkey -p test -c android.intent.category.LAUNCHER 1
/bin/sh: 1: adb: not found
`

**2. [Android-Automation-MCP](https://github.com/growvv/Android-Automation-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_open_app: Error executing command 'android_open_app': Failed to open app test: Command failed: adb  shell monkey -p test -c android.intent.category.LAUNCHER 1
/bin/sh: 1: adb: not found
`

### `tool-android_get_applist-basic-invocation` (2 finding)

**1. [mcp-token-bench](https://github.com/0x5457/mcp-token-bench)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_get_applist: Error executing command 'android_get_applist': Failed to get installed apps: Command failed: adb  shell pm list packages -3
/bin/sh: 1: adb: not found
`

**2. [Android-Automation-MCP](https://github.com/growvv/Android-Automation-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_get_applist: Error executing command 'android_get_applist': Failed to get installed apps: Command failed: adb  shell pm list packages -3
/bin/sh: 1: adb: not found
`

### `tool-android_tap-basic-invocation` (2 finding)

**1. [mcp-token-bench](https://github.com/0x5457/mcp-token-bench)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_tap: Error executing command 'android_tap': Failed to tap at (50, 50): Command failed: adb  shell input tap 50 50
/bin/sh: 1: adb: not found
`

**2. [Android-Automation-MCP](https://github.com/growvv/Android-Automation-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool android_tap: Error executing command 'android_tap': Failed to tap at (50, 50): Command failed: adb  shell input tap 50 50
/bin/sh: 1: adb: not found
`

### `tool-build_project-basic-invocation` (2 finding)

**1. [MCP-Demo](https://github.com/167AliRaza/MCP-Demo)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Unsupported framework: test. Supported frameworks: spring-boot, spring, spring-mvc, spring-webflux, react, react-vite, react-cra, vue, vue3, vue-vite, fastapi, fastapi-uvicorn, fastapi-gunicorn, django, django-rest, django-cms, flask, flask-rest, flask-sqlalchemy, vite, vite-vanilla, vite-ts, express, express-ts, express-rest, fastify, fastify-ts, fastify-rest, nestjs, nest, nestjs-rest, nestjs-graphql, next, nextjs, next-app, next-pages, nuxt, nuxt3`

**2. [builder-proj-mcp](https://github.com/fhyxz1/builder-proj-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unsupported framework: test. Supported frameworks: spring-boot, spring, spring-mvc, spring-webflux, react, react-vite, react-cra, vue, vue3, vue-vite, fastapi, fastapi-uvicorn, fastapi-gunicorn, django, django-rest, django-cms, flask, flask-rest, flask-sqlalchemy, vite, vite-vanilla, vite-ts, express, express-ts, express-rest, fastify, fastify-ts, fastify-rest, nestjs, nest, nestjs-rest, nestjs-graphql, next, nextjs, next-app, next-pages, nuxt, nuxt3`

### `tool-project_create-basic-invocation` (2 finding)

**1. [labellerr-mcp-server](https://github.com/1sarthakbhardwaj/labellerr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

**2. [classic-level](https://github.com/Addoneer-Project/classic-level)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

### `tool-project_list-basic-invocation` (2 finding)

**1. [labellerr-mcp-server](https://github.com/1sarthakbhardwaj/labellerr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

**2. [classic-level](https://github.com/Addoneer-Project/classic-level)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

### `tool-project_get-basic-invocation` (2 finding)

**1. [labellerr-mcp-server](https://github.com/1sarthakbhardwaj/labellerr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

**2. [classic-level](https://github.com/Addoneer-Project/classic-level)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Labellerr client not initialized. Please check your environment variables.`

### `tool-optimize_image-basic-invocation` (2 finding)

**1. [ticktick-mcp-server](https://github.com/AdityaKhandelwal10/ticktick-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing optimize_image: ImageMagick is not installed or not in PATH. Please install ImageMagick first.`

**2. [image-tools-mcp-server](https://github.com/jon-the-dev/image-tools-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing optimize_image: ImageMagick is not installed or not in PATH. Please install ImageMagick first.`

### `tool-create_thumbnail-basic-invocation` (2 finding)

**1. [ticktick-mcp-server](https://github.com/AdityaKhandelwal10/ticktick-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing create_thumbnail: ImageMagick is not installed or not in PATH. Please install ImageMagick first.`

**2. [image-tools-mcp-server](https://github.com/jon-the-dev/image-tools-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing create_thumbnail: ImageMagick is not installed or not in PATH. Please install ImageMagick first.`

### `tool-find_security_vulnerabilities-basic-invocation` (2 finding)

**1. [CodeAnalysisMCP](https://github.com/AlotfyDev/CodeAnalysisMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: ENOTDIR: not a directory, mkdir 'test/CodeAnalysisReports/analysis_2026-07-14T11-56-57-063Z'`

**2. [frontend-rag](https://github.com/wn01011/frontend-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: ENOTDIR: not a directory, mkdir 'test/CodeAnalysisReports/analysis_2026-07-14T11-56-57-063Z'`

### `tool-create_invoice_from_template-basic-invocation` (2 finding)

**1. [dev-mcp](https://github.com/AnEntrypoint/dev-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Cannot read properties of undefined (reading 'companyName')`

**2. [mcp-invoice-excel](https://github.com/maplefukku/mcp-invoice-excel)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Cannot read properties of undefined (reading 'companyName')`

### `tool-parse_code-basic-invocation` (2 finding)

**1. [google-drive-mcp-server](https://github.com/Arpit-saxena-2004/google-drive-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to parse code in test: Unsupported file type: test`

**2. [mcp-vue](https://github.com/YamadaAoi/mcp-vue)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to parse code in test: Unsupported file type: test`

### `tool-search_tracks-basic-invocation` (2 finding)

**1. [Grokipedia-MCP](https://github.com/Atharvsinh-codez/Grokipedia-MCP)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 403`

**2. [melodies-mcp-server](https://github.com/vincentsong/melodies-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 403`

### `tool-simplified_search_tracks-basic-invocation` (2 finding)

**1. [Grokipedia-MCP](https://github.com/Atharvsinh-codez/Grokipedia-MCP)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 403`

**2. [melodies-mcp-server](https://github.com/vincentsong/melodies-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 403`

### `tool-runCollection-basic-invocation` (2 finding)

**1. [RepoRadar](https://github.com/AvatanshuGupta/RepoRadar)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

**2. [newman-mcp](https://github.com/sangdth/newman-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-get_root_conjugation-basic-invocation` (2 finding)

**1. [esm_mcp](https://github.com/Biomolecular-Design-Nexus/esm_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get conjugation: Failed to fetch conjugation for "test": Root not found: test`

**2. [spoken-il-arabic-mcp](https://github.com/avi-the-coach/spoken-il-arabic-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get conjugation: Failed to fetch conjugation for "test": Root not found: test`

### `tool-spruthub_get_method_schema-basic-invocation` (2 finding)

**1. [ligandmpnn_mcp](https://github.com/Biomolecular-Design-Nexus/ligandmpnn_mcp)** (docker)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to get method schema: Method "test" not found. Available methods: hub.list, server.clientInfo, accessory.list, characteristic.update, scenario.list, scenario.get, scenario.create, scenario.update, scenario.delete, scenario.run...`

**2. [spruthub-mcp-server](https://github.com/shady2k/spruthub-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to get method schema: Method "test" not found. Available methods: hub.list, server.clientInfo, accessory.list, characteristic.update, scenario.list, scenario.get, scenario.create, scenario.update, scenario.delete, scenario.run...`

### `tool-spruthub_call_method-basic-invocation` (2 finding)

**1. [ligandmpnn_mcp](https://github.com/Biomolecular-Design-Nexus/ligandmpnn_mcp)** (docker)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to call method: Method "test" not found. Available methods: hub.list, server.clientInfo, accessory.list, characteristic.update, scenario.list, scenario.get, scenario.create, scenario.update, scenario.delete, scenario.run...`

**2. [spruthub-mcp-server](https://github.com/shady2k/spruthub-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to call method: Method "test" not found. Available methods: hub.list, server.clientInfo, accessory.list, characteristic.update, scenario.list, scenario.get, scenario.create, scenario.update, scenario.delete, scenario.run...`

### `tool-link_commit-basic-invocation` (2 finding)

**1. [clickmongrel-mcp](https://github.com/buildappolis/clickmongrel-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to validate list statuses: ClickUp API error: 400`

**2. [clickmongrel](https://github.com/hellocory/clickmongrel)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to validate list statuses: ClickUp API error: 400`

### `tool-generate_report-basic-invocation` (2 finding)

**1. [clickmongrel-mcp](https://github.com/buildappolis/clickmongrel-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: List ID not initialized`

**2. [clickmongrel](https://github.com/hellocory/clickmongrel)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: List ID not initialized`

### `tool-ingest_file-basic-invocation` (2 finding)

**1. [mcp-local-rag](https://github.com/yikizi/mcp-local-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to ingest file: ValidationError: File path must be absolute path (received: test). Please provide an absolute path within BASE_DIR.
    at DocumentParser.validateFilePath (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:96:19)
    at DocumentParser.parseFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:136:14)
    at RAGServer.handleIngestFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp...`

**2. [mcp-local-rag](https://github.com/fastmcp-me/mcp-local-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to ingest file: ValidationError: File path must be absolute path (received: test). Please provide an absolute path within BASE_DIR.
    at DocumentParser.validateFilePath (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:59:19)
    at DocumentParser.parseFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:99:14)
    at RAGServer.handleIngestFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-...`

### `tool-delete_file-basic-invocation` (2 finding)

**1. [mcp-local-rag](https://github.com/yikizi/mcp-local-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to delete file: ValidationError: File path must be absolute path (received: test). Please provide an absolute path within BASE_DIR.
    at DocumentParser.validateFilePath (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:96:19)
    at RAGServer.handleDeleteFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/server/index.js:782:29)
    at /home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/server/ind...`

**2. [mcp-local-rag](https://github.com/fastmcp-me/mcp-local-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to delete file: ValidationError: File path must be absolute path (received: test). Please provide an absolute path within BASE_DIR.
    at DocumentParser.validateFilePath (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/parser/index.js:59:19)
    at RAGServer.handleDeleteFile (/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/server/index.js:322:25)
    at /home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/mcp-local-rag/dist/server/ind...`

### `tool-execute_in_session-basic-invocation` (2 finding)

**1. [claude-code-mcp](https://github.com/democratize-technology/claude-code-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execute_in_session failed: Session test not found`

**2. [claude-code-container-mcp](https://github.com/zudsniper/claude-code-container-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execute_in_session failed: Session test not found`

### `tool-get_component_docs-basic-invocation` (2 finding)

**1. [forge-mcp](https://github.com/fastmcp-me/forge-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to execute tool: Invalid resource URI: forge://components/names`

**2. [templui-mcp-server](https://github.com/tggo/templui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Resource not found: Failed to get documentation for component "test": Documentation not found for component "test"`

### `tool-list-realms-basic-invocation` (1 finding)

**1. [keycloak-model-context-protocol](https://github.com/ChristophEnglisch/keycloak-model-context-protocol)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Network response was not OK.`

### `tool-iiif-search-basic-invocation` (1 finding)

**1. [IIIF_MCP](https://github.com/code4history/IIIF_MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Search failed: Invalid URL`

### `tool-iiif-manifest-basic-invocation` (1 finding)

**1. [IIIF_MCP](https://github.com/code4history/IIIF_MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to retrieve manifest: Invalid URL`

### `tool-list_shortcuts-basic-invocation` (1 finding)

**1. [mcp-server-siri-shortcuts](https://github.com/dvcrn/mcp-server-siri-shortcuts)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to list shortcuts: Command failed: shortcuts list --show-identifiers
/bin/sh: 1: shortcuts: not found
`

### `tool-open_shortcut-basic-invocation` (1 finding)

**1. [mcp-server-siri-shortcuts](https://github.com/dvcrn/mcp-server-siri-shortcuts)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to open shortcut: Command failed: shortcuts view 'test'
/bin/sh: 1: shortcuts: not found
`

### `tool-get_crystallization_guidance-basic-invocation` (1 finding)

**1. [context-crystallizer](https://github.com/hubertciebiada/context-crystallizer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Repository path not available. Ensure repository is initialized or provide repoPath parameter.`

### `tool-init_crystallization-basic-invocation` (1 finding)

**1. [context-crystallizer](https://github.com/hubertciebiada/context-crystallizer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, mkdir 'test/.context-crystallizer'`

### `tool-get_next_file_to_crystallize-basic-invocation` (1 finding)

**1. [context-crystallizer](https://github.com/hubertciebiada/context-crystallizer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No crystallization found in /home/tecnico/Desktop/Frameworks/mcp-check. Please run init_crystallization first to set up the repository.`

### `tool-recommend-mcp-servers-basic-invocation` (1 finding)

**1. [mcp-compass](https://github.com/liuyoshio/mcp-compass)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: COMPASS API request failed with status 525`

### `tool-github_get_latest_pinned_version-basic-invocation` (1 finding)

**1. [pinner-mcp](https://github.com/safedep/pinner-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to get latest release: GET https://api.github.com/repos/test/test/releases/latest: 404 Not Found []`

### `tool-protect_data-basic-invocation` (1 finding)

**1. [thales-cdsp-crdp-mcp-server](https://github.com/sanyambassi/thales-cdsp-crdp-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: CRDP API error: `

### `tool-protect_bulk-basic-invocation` (1 finding)

**1. [thales-cdsp-crdp-mcp-server](https://github.com/sanyambassi/thales-cdsp-crdp-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: CRDP API error: `

### `tool-rpc_call-basic-invocation` (1 finding)

**1. [openrpc-mpc-server](https://github.com/shanejonas/openrpc-mpc-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: "undefined" is not valid JSON`

### `tool-rpc_discover-basic-invocation` (1 finding)

**1. [openrpc-mpc-server](https://github.com/shanejonas/openrpc-mpc-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 7979: Only absolute URLs are supported`

### `tool-todos_list-basic-invocation` (1 finding)

**1. [things3-mcp](https://github.com/urbanogardun/things3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch Things3`

### `tool-todos_get-basic-invocation` (1 finding)

**1. [things3-mcp](https://github.com/urbanogardun/things3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch Things3`

### `tool-todos_create-basic-invocation` (1 finding)

**1. [things3-mcp](https://github.com/urbanogardun/things3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to launch Things3`

### `tool-configure-basic-invocation` (1 finding)

**1. [OPNSenseMCP](https://github.com/vespo92/OPNSenseMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Configuration failed: [
  {
    "code": "invalid_format",
    "format": "url",
    "path": [
      "host"
    ],
    "message": "Invalid URL"
  }
]`

### `tool-list_vlans-basic-invocation` (1 finding)

**1. [OPNSenseMCP](https://github.com/vespo92/OPNSenseMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: OPNsense client not initialized. Use configure tool first.`

### `tool-get_vlan-basic-invocation` (1 finding)

**1. [OPNSenseMCP](https://github.com/vespo92/OPNSenseMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: OPNsense client not initialized. Use configure tool first.`

### `tool-modify_order-basic-invocation` (1 finding)

**1. [zerodha-kite-mcp](https://github.com/anshuljain90/zerodha-kite-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Kite Connect not initialized. Check API credentials.`

### `tool-cancel_order-basic-invocation` (1 finding)

**1. [zerodha-kite-mcp](https://github.com/anshuljain90/zerodha-kite-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Kite Connect not initialized. Check API credentials.`

### `tool-fofa-basic-invocation` (1 finding)

**1. [uncover-mcp](https://github.com/Co5mos/uncover-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute FOFA query: [uncover:RUNTIME] agents [fofa] requires keys but no keys were found`

### `tool-shodan-basic-invocation` (1 finding)

**1. [uncover-mcp](https://github.com/Co5mos/uncover-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute shodan query: [uncover:RUNTIME] agents [shodan] requires keys but no keys were found`

### `tool-add_graph_observations-basic-invocation` (1 finding)

**1. [xgmem](https://github.com/meetdhanani17/xgmem)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Entity with name test not found in project test`

### `tool-get_briefcase_status-basic-invocation` (1 finding)

**1. [mcp-dichvucong](https://github.com/phake-studio/mcp-dichvucong)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Lỗi khi gọi công cụ`

### `tool-apply_fixes-basic-invocation` (1 finding)

**1. [flutter-tools](https://github.com/dkpoulsen/flutter-tools)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Flutter SDK not found in PATH. Please ensure Flutter is installed and in your PATH.`

### `tool-hello_world-basic-invocation` (1 finding)

**1. [mcp-server-email](https://github.com/CocaineCong/mcp-server-email)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 535 Login fail. Account is abnormal, service is not open, password is incorrect, login frequency limited, or system is busy. More information at https://help.mail.qq.com/detail/108/1023`

### `tool-create_directory-basic-invocation` (1 finding)

**1. [jarvis-mcp](https://github.com/eugener/jarvis-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: mkdir test: file exists`

### `tool-ping-basic-invocation` (1 finding)

**1. [mcp-domaintools](https://github.com/patrickdappollonio/mcp-domaintools)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to resolve target test: lookup test on 127.0.0.53:53: server misbehaving`

### `tool-initialize_memory_bank-basic-invocation` (1 finding)

**1. [Cline-Memory-Bank](https://github.com/dazeb/Cline-Memory-Bank)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to initialize Memory Bank: ENOTDIR: not a directory, mkdir 'test/memory-bank'`

### `tool-update_context-basic-invocation` (1 finding)

**1. [Cline-Memory-Bank](https://github.com/dazeb/Cline-Memory-Bank)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to update context: ENOTDIR: not a directory, open 'test/memory-bank/activeContext.md'`

### `tool-record_decision-basic-invocation` (1 finding)

**1. [Cline-Memory-Bank](https://github.com/dazeb/Cline-Memory-Bank)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to record decision: ENOTDIR: not a directory, open 'test/memory-bank/decisionLog.md'`

### `tool-open_article-basic-invocation` (1 finding)

**1. [reading_support](https://github.com/ser163/reading_support)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 未找到资源: test`

### `tool-run_nrql_query-basic-invocation` (1 finding)

**1. [newrelic-mcp](https://github.com/cloudbring/newrelic-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Account ID must be provided`

### `tool-list_apm_applications-basic-invocation` (1 finding)

**1. [newrelic-mcp](https://github.com/cloudbring/newrelic-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Account ID must be provided`

### `tool-search_entities-basic-invocation` (1 finding)

**1. [newrelic-mcp](https://github.com/cloudbring/newrelic-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Account ID must be provided`

### `tool-svelte_definition-basic-invocation` (1 finding)

**1. [mcp-svelte-docs](https://github.com/spences10/mcp-svelte-docs)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 0: Error in svelte_definition: Definition for 'test' not found.

Did you mean:
• layout-groups

Use format="syntax" for quicker responses, or try: $state, $derived, $props, $effect, snippets, onclick, component-events`

### `tool-device_vibrate-basic-invocation` (1 finding)

**1. [buttplug-mcp](https://github.com/ConAcademy/buttplug-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Device 50 not found`

### `tool-analyze_audio-basic-invocation` (1 finding)

**1. [cochl-mcp-server](https://github.com/cochlearai/cochl-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid file path: path must be absolute: test`

### `tool-read_serial_line-basic-invocation` (1 finding)

**1. [mcp-iot-go](https://github.com/sukeesh/mcp-iot-go)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid serial port: error getting term settings: inappropriate ioctl for device`

### `tool-get_daily_prayer_times-basic-invocation` (1 finding)

**1. [prayer-time-mcp-server](https://github.com/imsaar/prayer-time-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid date format. Please use YYYY-MM-DD.`

### `tool-mark_todo_done-basic-invocation` (1 finding)

**1. [todo_mcp_server](https://github.com/imsaar/todo_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Todo test not found`

### `tool-change_directory-basic-invocation` (1 finding)

**1. [terminal](https://github.com/stat-guy/terminal)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to change directory: ENOTDIR: not a directory, chdir '/home/tecnico/Desktop/Frameworks/mcp-check' -> '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

### `tool-list_voices-basic-invocation` (1 finding)

**1. [say-mcp-server](https://github.com/bmorphism/say-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to list voices: Command failed: say -v "?"
/bin/sh: 1: say: not found
`

### `tool-listTargets-basic-invocation` (1 finding)

**1. [mcp-ayd-server](https://github.com/macrat/mcp-ayd-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch targets: Get "/targets.json": unsupported protocol scheme ""`

### `tool-getStatusOverview-basic-invocation` (1 finding)

**1. [mcp-ayd-server](https://github.com/macrat/mcp-ayd-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch status from Ayd: failed to fetch: Get "/home/tecnico/Desktop/Pipeline/tool_mcp_check_w1/mcp-ayd-server/status.json": unsupported protocol scheme ""`

### `tool-getTargetStatus-basic-invocation` (1 finding)

**1. [mcp-ayd-server](https://github.com/macrat/mcp-ayd-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch status from Ayd: failed to fetch: Get "/home/tecnico/Desktop/Pipeline/tool_mcp_check_w1/mcp-ayd-server/status.json": unsupported protocol scheme ""`

### `tool-gemini-advanced-image-basic-invocation` (1 finding)

**1. [gemini-mcp-server](https://github.com/Garblesnarff/gemini-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: Error calling tool 'gemini-advanced-image': Advanced image generation failed: Advanced image generation failed on all available providers. OpenRouter: OpenRouter API error (401): Missing Authentication header. Gemini API: this.geminiService.generateAdvancedImage is not a function

If this is a repeated error, try using standard mode without reference images.`

### `tool-search_files-basic-invocation` (1 finding)

**1. [code-explorer-mcp](https://github.com/jordankamto/code-explorer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Directory not found: `

### `tool-analyze_code-basic-invocation` (1 finding)

**1. [code-explorer-mcp](https://github.com/jordankamto/code-explorer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: File or directory not found: test`

### `tool-clear_breakpoint-basic-invocation` (1 finding)

**1. [dlv-mcp](https://github.com/xhd2015/dlv-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: debug session not found: test`

### `tool-clear_checkpoint-basic-invocation` (1 finding)

**1. [dlv-mcp](https://github.com/xhd2015/dlv-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: debug session not found: test`

### `tool-create_meeting-basic-invocation` (1 finding)

**1. [zoom-mcp-server](https://github.com/JavaProgrammerLB/zoom-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Bad request`

### `tool-list_meetings-basic-invocation` (1 finding)

**1. [zoom-mcp-server](https://github.com/JavaProgrammerLB/zoom-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Bad request`

### `tool-delete_a_meeting-basic-invocation` (1 finding)

**1. [zoom-mcp-server](https://github.com/JavaProgrammerLB/zoom-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Bad request`

### `tool-decode_tx-basic-invocation` (1 finding)

**1. [bitcoin-mcp](https://github.com/AbdelStark/bitcoin-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to decode transaction`

### `tool-generate_er_diagram-basic-invocation` (1 finding)

**1. [singlestore-mcp-server](https://github.com/madhukarkumar/singlestore-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Database connection error: `

### `tool-list_tables-basic-invocation` (1 finding)

**1. [singlestore-mcp-server](https://github.com/madhukarkumar/singlestore-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Database connection error: `

### `tool-query_table-basic-invocation` (1 finding)

**1. [singlestore-mcp-server](https://github.com/madhukarkumar/singlestore-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Database connection error: `

### `tool-list_databases-basic-invocation` (1 finding)

**1. [mongodb-mcp](https://github.com/jonfreeland/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MONGODB_URI environment variable is required`

### `tool-list_collections-basic-invocation` (1 finding)

**1. [mongodb-mcp](https://github.com/jonfreeland/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MONGODB_URI environment variable is required`

### `tool-get_schema-basic-invocation` (1 finding)

**1. [mongodb-mcp](https://github.com/jonfreeland/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MONGODB_URI environment variable is required`

### `tool-add_observations-basic-invocation` (1 finding)

**1. [memories-with-lessons-mcp-server](https://github.com/T1nker-1220/memories-with-lessons-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Entity with name test not found`

### `tool-compare_funds-basic-invocation` (1 finding)

**1. [fonparam-mcp](https://github.com/kemalersin/fonparam-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: FonParam API Error: API Error 400: Bad Request`

### `tool-fetch_docs-basic-invocation` (1 finding)

**1. [WhatsUpDoc](https://github.com/paradiselabs-ai/WhatsUpDoc)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-observe-basic-invocation` (1 finding)

**1. [auto-mobile](https://github.com/zillow/auto-mobile)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to list AVDs: Error: Command failed: emulator -list-avds
/bin/sh: 1: emulator: not found
`

### `tool-listApps-basic-invocation` (1 finding)

**1. [auto-mobile](https://github.com/zillow/auto-mobile)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to list AVDs: Error: Command failed: emulator -list-avds
/bin/sh: 1: emulator: not found
`

### `tool-clearText-basic-invocation` (1 finding)

**1. [auto-mobile](https://github.com/zillow/auto-mobile)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to list AVDs: Error: Command failed: emulator -list-avds
/bin/sh: 1: emulator: not found
`

### `tool-analyze-image-basic-invocation` (1 finding)

**1. [mcp](https://github.com/prooflie/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error undefined: Failed to analyze image: Request failed with status code 526`

### `tool-analyze-basic-invocation` (1 finding)

**1. [mcp](https://github.com/prooflie/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error undefined: Failed to analyze image URL: Invalid URL`

### `tool-check-session-status-basic-invocation` (1 finding)

**1. [mcp](https://github.com/prooflie/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error undefined: Failed to check session status: Request failed with status code 526`

### `tool-update_prompt-basic-invocation` (1 finding)

**1. [promptopia-mcp](https://github.com/lumile/promptopia-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 500: MCP error 500: An unexpected error occurred: At least one field to update must be provided`

### `tool-get_prompt-basic-invocation` (1 finding)

**1. [promptopia-mcp](https://github.com/lumile/promptopia-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 500: MCP error 500: An unexpected error occurred: Prompt not found: test`

### `tool-start_instance-basic-invocation` (1 finding)

**1. [scrapybara-mcp](https://github.com/scrapybara/scrapybara-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Status code: 404
Body: {
  "ok": false,
  "error": {
    "reason": "non-json",
    "statusCode": 404,
    "rawBody": "\n<html><head>\n<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<title>404 Page not found</title>\n</head>\n<body text=#000000 bgcolor=#ffffff>\n<h1>Error: Page not found</h1>\n<h2>The requested URL was not found on this server.</h2>\n<h2></h2>\n</body></html>\n"
  }
}`

### `tool-get_instances-basic-invocation` (1 finding)

**1. [scrapybara-mcp](https://github.com/scrapybara/scrapybara-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Status code: 404
Body: {
  "ok": false,
  "error": {
    "reason": "non-json",
    "statusCode": 404,
    "rawBody": "\n<html><head>\n<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<title>404 Page not found</title>\n</head>\n<body text=#000000 bgcolor=#ffffff>\n<h1>Error: Page not found</h1>\n<h2>The requested URL was not found on this server.</h2>\n<h2></h2>\n</body></html>\n"
  }
}`

### `tool-stop_instance-basic-invocation` (1 finding)

**1. [scrapybara-mcp](https://github.com/scrapybara/scrapybara-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Status code: 404
Body: {
  "ok": false,
  "error": {
    "reason": "non-json",
    "statusCode": 404,
    "rawBody": "\n<html><head>\n<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<title>404 Page not found</title>\n</head>\n<body text=#000000 bgcolor=#ffffff>\n<h1>Error: Page not found</h1>\n<h2>The requested URL was not found on this server.</h2>\n<h2></h2>\n</body></html>\n"
  }
}`

### `tool-bmad-task-basic-invocation` (1 finding)

**1. [bmad-mcp-server](https://github.com/cexll/bmad-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot read properties of undefined (reading 'toLowerCase')`

### `tool-setKnowledgeSource-basic-invocation` (1 finding)

**1. [community-express-dev-mcp](https://github.com/EnventDigital/community-express-dev-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool setKnowledgeSource has no outputSchema but returned structuredContent`

### `tool-write_file-basic-invocation` (1 finding)

**1. [mcp-software-engineer](https://github.com/Rajawatrajat/mcp-software-engineer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error executing tool write_file: [write_file] Error writing file: fs.writeFile is not a function`

### `tool-decode_qrcode_data_url-basic-invocation` (1 finding)

**1. [scan-qrcode-mcp](https://github.com/ericyangpan/scan-qrcode-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid data URL. Expected format: data:<mime>;base64,<data>`

### `tool-decode_qrcode_image_url-basic-invocation` (1 finding)

**1. [scan-qrcode-mcp](https://github.com/ericyangpan/scan-qrcode-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Only http(s) URLs are supported for imageUrl`

### `tool-add_tasks-basic-invocation` (1 finding)

**1. [task-orchestrator](https://github.com/hrishirc/task-orchestrator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No plan found for goal 50`

### `tool-remove_tasks-basic-invocation` (1 finding)

**1. [task-orchestrator](https://github.com/hrishirc/task-orchestrator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No plan found for goal 50`

### `tool-get_entity-basic-invocation` (1 finding)

**1. [BRREG-MCP](https://github.com/reidar80/BRREG-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: API request failed: 400 `

### `tool-get_entity_roles-basic-invocation` (1 finding)

**1. [BRREG-MCP](https://github.com/reidar80/BRREG-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: API request failed: 400 `

### `tool-get_scan_status-basic-invocation` (1 finding)

**1. [burpsuite-mcp-server](https://github.com/Cyreslab-AI/burpsuite-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Scan test not found`

### `tool-get_scan_issues-basic-invocation` (1 finding)

**1. [burpsuite-mcp-server](https://github.com/Cyreslab-AI/burpsuite-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Scan test not found`

### `tool-browser_close_instance-basic-invocation` (1 finding)

**1. [concurrent-browser-mcp](https://github.com/sailaoda/concurrent-browser-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Instance test not found`

### `tool-buy_supplies-basic-invocation` (1 finding)

**1. [Lemonade-Stand-MCP-Server](https://github.com/jimmcq/Lemonade-Stand-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Game not found`

### `tool-set_price-basic-invocation` (1 finding)

**1. [Lemonade-Stand-MCP-Server](https://github.com/jimmcq/Lemonade-Stand-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Game not found`

### `tool-trace-basic-invocation` (1 finding)

**1. [think](https://github.com/letsgomaslow/think)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid thought data: thoughtNumber: Expected integer, received float, totalThoughts: Expected integer, received float`

### `tool-fetch_summoner_context-basic-invocation` (1 finding)

**1. [lolbyte-mcp-server](https://github.com/lolbyte-code/lolbyte-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool fetch_summoner_context: Use format GameName#TagLine`

### `tool-fetch_tft_summoner_context-basic-invocation` (1 finding)

**1. [lolbyte-mcp-server](https://github.com/lolbyte-code/lolbyte-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool fetch_tft_summoner_context: Use format GameName#TagLine`

### `tool-get_summoner-basic-invocation` (1 finding)

**1. [lolbyte-mcp-server](https://github.com/lolbyte-code/lolbyte-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool get_summoner: Use format GameName#TagLine`

### `tool-ssh_exec-basic-invocation` (1 finding)

**1. [mcp-ssh](https://github.com/atlcomgit/mcp-ssh)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Не указан host или username в .env.`

### `tool-example_operation-basic-invocation` (1 finding)

**1. [mcp-server-typescript-template](https://github.com/minimind-org/mcp-server-typescript-template)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not Found: Resource not found: Resource`

### `tool-list_objects-basic-invocation` (1 finding)

**1. [aws-ow-s3-mcp](https://github.com/OpenWorkspace-o1/aws-ow-s3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Bucket name is not set.`

### `tool-get_object-basic-invocation` (1 finding)

**1. [aws-ow-s3-mcp](https://github.com/OpenWorkspace-o1/aws-ow-s3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Bucket name is not set.`

### `tool-put_object-basic-invocation` (1 finding)

**1. [aws-ow-s3-mcp](https://github.com/OpenWorkspace-o1/aws-ow-s3-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Bucket name is not set.`

### `tool-get_ticker_price-basic-invocation` (1 finding)

**1. [stock-market-server](https://github.com/MCP-100/stock-market-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cannot convert undefined or null to object`

### `tool-gdrive_search-basic-invocation` (1 finding)

**1. [drive-mcp](https://github.com/rishipradeep-think41/drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to authenticate`

### `tool-gdrive_read_file-basic-invocation` (1 finding)

**1. [drive-mcp](https://github.com/rishipradeep-think41/drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to authenticate`

### `tool-add_git_repository-basic-invocation` (1 finding)

**1. [mcp-docs-rag](https://github.com/kazuph/mcp-docs-rag)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 128: Command failed: cd "/home/tecnico/docs" && git clone test
fatal: repository 'test' does not exist
`

### `tool-list_files-basic-invocation` (1 finding)

**1. [mcp-local-file-reader](https://github.com/sworddut/mcp-local-file-reader)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: 工具调用错误: ENOTDIR: not a directory, scandir 'test'`

### `tool-delete_folder-basic-invocation` (1 finding)

**1. [Windows-MCP](https://github.com/emilioejus/Windows-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: La ruta no existe`

### `tool-fetch_website_nested-basic-invocation` (1 finding)

**1. [better-fetch](https://github.com/flutterninja9/better-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch website: TypeError: Invalid URL`

### `tool-fetch_website_single-basic-invocation` (1 finding)

**1. [better-fetch](https://github.com/flutterninja9/better-fetch)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch single page: TypeError: Invalid URL`

### `tool-get_latest_launch-basic-invocation` (1 finding)

**1. [SpaceX-mcp](https://github.com/rftsngl/SpaceX-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: En son fırlatma verisi alınamadı`

### `tool-get_upcoming_launches-basic-invocation` (1 finding)

**1. [SpaceX-mcp](https://github.com/rftsngl/SpaceX-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: Yaklaşan fırlatma verileri alınamadı`

### `tool-get_company_info-basic-invocation` (1 finding)

**1. [SpaceX-mcp](https://github.com/rftsngl/SpaceX-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32000: Şirket bilgileri alınamadı`

### `tool-fetch_code_diff-basic-invocation` (1 finding)

**1. [gitlab-review-mcp](https://github.com/lininn/gitlab-review-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Either pullRequestNumber or commitSha must be provided`

### `tool-analyze-csv-basic-invocation` (1 finding)

**1. [MCP-CSV-Analysis-with-Gemini-AI](https://github.com/falahgs/MCP-CSV-Analysis-with-Gemini-AI)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: CSV file is empty or could not be parsed`

### `tool-visualize-data-basic-invocation` (1 finding)

**1. [MCP-CSV-Analysis-with-Gemini-AI](https://github.com/falahgs/MCP-CSV-Analysis-with-Gemini-AI)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: CSV file is empty or could not be parsed`

### `tool-ultrade_wallet_signin-basic-invocation` (1 finding)

**1. [ultrade-mcp](https://github.com/ultrade-org/ultrade-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ultrade API error: 403 Forbidden {"statusCode":403,"message":"Verification failed","error":"Forbidden"}`

### `tool-ultrade_wallet_key_message-basic-invocation` (1 finding)

**1. [ultrade-mcp](https://github.com/ultrade-org/ultrade-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ultrade API error: 500 Internal Server Error {"statusCode":500,"message":"Internal server error"}`

### `tool-fetch_swagger_info-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/amrsa1/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch Swagger info: Failed to fetch Swagger documentation: No API_BASE_URL configured and no explicit Swagger URL provided`

### `tool-list_endpoints-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/amrsa1/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to list endpoints: Swagger documentation not loaded. Call fetch_swagger_info first.`

### `tool-get_endpoint_details-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/amrsa1/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get endpoint details: Swagger documentation not loaded. Call fetch_swagger_info first.`

### `tool-analyze_existing_docs-basic-invocation` (1 finding)

**1. [mcp-rtfm](https://github.com/ryanjoachim/mcp-rtfm)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error analyzing existing documentation: MCP error -32600: Documentation directory not found at test/.handoff_docs`

### `tool-analyze_project_with_metadata-basic-invocation` (1 finding)

**1. [mcp-rtfm](https://github.com/ryanjoachim/mcp-rtfm)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error initializing documentation with metadata: ENOTDIR: not a directory, mkdir 'test/.handoff_docs'`

### `tool-analyze_project-basic-invocation` (1 finding)

**1. [mcp-rtfm](https://github.com/ryanjoachim/mcp-rtfm)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error initializing documentation: ENOTDIR: not a directory, mkdir 'test/.handoff_docs'`

### `tool-ddev_composer_command-basic-invocation` (1 finding)

**1. [ddev-mcp](https://github.com/AkibaAT/ddev-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [object Object]`

### `tool-ddev_db_query-basic-invocation` (1 finding)

**1. [ddev-mcp](https://github.com/AkibaAT/ddev-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [object Object]`

### `tool-ddev_exec_command-basic-invocation` (1 finding)

**1. [ddev-mcp](https://github.com/AkibaAT/ddev-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [object Object]`

### `tool-analyze_pagespeed-basic-invocation` (1 finding)

**1. [mcp-server-pagespeed](https://github.com/enemyrr/mcp-server-pagespeed)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to analyze URL`

### `tool-generate_ui_flow-basic-invocation` (1 finding)

**1. [uiflowchartcreator](https://github.com/umshere/uiflowchartcreator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Failed to read local repository: ENOTDIR: not a directory, scandir 'test'`

### `tool-generate_release_note-basic-invocation` (1 finding)

**1. [release-notes-generator-iris-mcp-server](https://github.com/Sunwood-ai-labs/release-notes-generator-iris-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: リリースノートの生成に失敗しました: fs.writeFile is not a function`

### `tool-get_raw_text-basic-invocation` (1 finding)

**1. [mcp-server-fetch-typescript](https://github.com/tatn/mcp-server-fetch-typescript)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid URL`

### `tool-get_vault_info-basic-invocation` (1 finding)

**1. [obsidian-mcp](https://github.com/quinny1187/obsidian-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute get_vault_info: Invalid vault path: test`

### `tool-convert_video_to_gif-basic-invocation` (1 finding)

**1. [gif-creator-mcp](https://github.com/ananddtyagi/gif-creator-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to convert video to GIF: ffmpeg exited with code 1: test: Invalid data found when processing input
`

### `tool-get_mailboxes-basic-invocation` (1 finding)

**1. [jmap-mcp-server](https://github.com/jahfer/jmap-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-get_email_content-basic-invocation` (1 finding)

**1. [jmap-mcp-server](https://github.com/jahfer/jmap-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-get_price-basic-invocation` (1 finding)

**1. [okx-mcp](https://github.com/esshka/okx-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch data: OKX API error: Instrument ID, Instrument ID code, or Spread ID doesn't exist.`

### `tool-get_candlesticks-basic-invocation` (1 finding)

**1. [okx-mcp](https://github.com/esshka/okx-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch data: OKX API error: Instrument ID, Instrument ID code, or Spread ID doesn't exist.`

### `tool-decompose_task-basic-invocation` (1 finding)

**1. [mcp-task-manager](https://github.com/blizzy78/mcp-task-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Task not found: test`

### `tool-a11y-basic-invocation` (1 finding)

**1. [cursor-a11y-mcp](https://github.com/westsideori/cursor-a11y-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Must provide either 'url' or 'relativePath'`

### `tool-generate_structure-basic-invocation` (1 finding)

**1. [source-sage-mcp-server](https://github.com/Sunwood-ai-labs/source-sage-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: ENOTDIR: not a directory, open '/home/tecnico/Desktop/Frameworks/mcp-check/test/.SourceSageignore'`

### `tool-getDiagnostics-basic-invocation` (1 finding)

**1. [mcp-diagnostics-trae](https://github.com/lin037/mcp-diagnostics-trae)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: [handleGetDiagnostics] 获取诊断失败: fetch failed. 请确保配套的 "Diagnostics Server" VS Code 扩展已安装、已启用，并且 VS Code 正在运行中。`

### `tool-getDiagnosticsForFile-basic-invocation` (1 finding)

**1. [mcp-diagnostics-trae](https://github.com/lin037/mcp-diagnostics-trae)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: [handleGetDiagnosticsForFile] 获取诊断失败: fetch failed. 请确保配套的 "Diagnostics Server" VS Code 扩展已安装、已启用，并且 VS Code 正在运行中。`

### `tool-getDiagnosticsForPath-basic-invocation` (1 finding)

**1. [mcp-diagnostics-trae](https://github.com/lin037/mcp-diagnostics-trae)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: [handleGetDiagnosticsForPath] 获取诊断失败: fetch failed. 请确保配套的 "Diagnostics Server" VS Code 扩展已安装、已启用，并且 VS Code 正在运行中。`

### `tool-convert_excel_to_pdf-basic-invocation` (1 finding)

**1. [excel-to-pdf-mcp](https://github.com/kmexnx/excel-to-pdf-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: LibreOffice is not installed or not found in PATH. Please install LibreOffice to use this tool.`

### `tool-convert_numbers_to_pdf-basic-invocation` (1 finding)

**1. [excel-to-pdf-mcp](https://github.com/kmexnx/excel-to-pdf-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: LibreOffice is not installed or not found in PATH. Please install LibreOffice to use this tool.`

### `tool-cursor.review-basic-invocation` (1 finding)

**1. [reviewer-mcp](https://github.com/kodaimaehata/reviewer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Cursor CLI not found: install 'cursor-agent'.`

### `tool-codex.review-basic-invocation` (1 finding)

**1. [reviewer-mcp](https://github.com/kodaimaehata/reviewer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Codex CLI not found: set REVIEWER_MCP_CODEX_BIN or install 'codex'.`

### `tool-check_task_status-basic-invocation` (1 finding)

**1. [mcp-task](https://github.com/just-every/mcp-task)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to execute task: Task test not found`

### `tool-get_task_result-basic-invocation` (1 finding)

**1. [mcp-task](https://github.com/just-every/mcp-task)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to execute task: Task test not found`

### `tool-analyze_image-basic-invocation` (1 finding)

**1. [mcp-server-gemini-pro](https://github.com/gurveeer/mcp-server-gemini-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Image analysis failed: Either imageUrl or imageBase64 must be provided`

### `tool-sentry_capture_exception-basic-invocation` (1 finding)

**1. [sentry-mcp-cursor](https://github.com/diegofornalha/sentry-mcp-cursor)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Sentry is not initialized. Please provide a DSN.`

### `tool-sentry_capture_message-basic-invocation` (1 finding)

**1. [sentry-mcp-cursor](https://github.com/diegofornalha/sentry-mcp-cursor)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Sentry is not initialized. Please provide a DSN.`

### `tool-sentry_add_breadcrumb-basic-invocation` (1 finding)

**1. [sentry-mcp-cursor](https://github.com/diegofornalha/sentry-mcp-cursor)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Sentry is not initialized. Please provide a DSN.`

### `tool-get_binary_info-basic-invocation` (1 finding)

**1. [bn_cline_mcp](https://github.com/opensensor/bn_cline_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: request to http://localhost:8088/ failed, reason: `

### `tool-list_functions-basic-invocation` (1 finding)

**1. [bn_cline_mcp](https://github.com/opensensor/bn_cline_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: request to http://localhost:8088/ failed, reason: `

### `tool-disassemble_function-basic-invocation` (1 finding)

**1. [bn_cline_mcp](https://github.com/opensensor/bn_cline_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: request to http://localhost:8088/ failed, reason: `

### `tool-get_status-basic-invocation` (1 finding)

**1. [aira-mcp-server](https://github.com/Sunwood-ai-labs/aira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get git status: Error: MCP error -32600: 指定されたパス 'test' はGitリポジトリではありません。`

### `tool-create_commit-basic-invocation` (1 finding)

**1. [aira-mcp-server](https://github.com/Sunwood-ai-labs/aira-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: 指定されたパス 'test' はGitリポジトリではありません。`

### `tool-generate_documentation-basic-invocation` (1 finding)

**1. [claude-4.5-mcp-tutorial](https://github.com/Njengah/claude-4.5-mcp-tutorial)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "path"
    ],
    "message": "Required"
  }
]`

### `tool-detect_missing_docs-basic-invocation` (1 finding)

**1. [claude-4.5-mcp-tutorial](https://github.com/Njengah/claude-4.5-mcp-tutorial)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "path"
    ],
    "message": "Required"
  }
]`

### `tool-doppler_secrets_get-basic-invocation` (1 finding)

**1. [doppler-mcp](https://github.com/aledlie/doppler-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Doppler CLI error: Doppler CLI command failed: /bin/sh: 1: doppler: not found
`

### `tool-doppler_secrets_list-basic-invocation` (1 finding)

**1. [doppler-mcp](https://github.com/aledlie/doppler-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Doppler CLI error: Doppler CLI command failed: /bin/sh: 1: doppler: not found
`

### `tool-doppler_secrets_set-basic-invocation` (1 finding)

**1. [doppler-mcp](https://github.com/aledlie/doppler-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Doppler CLI error: Doppler CLI command failed: /bin/sh: 1: doppler: not found
`

### `tool-api_get_endpoint_info-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/zidong0822/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 获取端点详情失败: 端点 GET test 不存在`

### `tool-get_tweet-basic-invocation` (1 finding)

**1. [x-mcp-server](https://github.com/DataWhisker/x-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid tweet ID format for 'tweet_id'`

### `tool-get_ecology-basic-invocation` (1 finding)

**1. [mcp-fishbase](https://github.com/lundgrenalex/mcp-fishbase)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool get_ecology: Error: Failed to get ecology data: Error: Species not found: test`

### `tool-make-html-page-basic-invocation` (1 finding)

**1. [html-maker-mcp](https://github.com/ricleedo/html-maker-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-fetch_website-basic-invocation` (1 finding)

**1. [website-to-markdown-mcp](https://github.com/SunZhi-Will/website-to-markdown-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 無法獲取網站 test: Invalid URL`

### `tool-get_build_log-basic-invocation` (1 finding)

**1. [jenkins-mcp-server](https://github.com/ddang-jung/jenkins-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unknown error occurred`

### `tool-read_docs_by_list-basic-invocation` (1 finding)

**1. [generic_mcp](https://github.com/dewoller/generic_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: File not in allowed directories: test`

### `tool-get_user_by_username-basic-invocation` (1 finding)

**1. [twitterapi-mcp-server](https://github.com/Jing-yilin/twitterapi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: TwitterAPI.io error: TwitterAPI.io API error (403): Forbidden`

### `tool-get_user_by_id-basic-invocation` (1 finding)

**1. [twitterapi-mcp-server](https://github.com/Jing-yilin/twitterapi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: TwitterAPI.io error: TwitterAPI.io API error (403): Forbidden`

### `tool-get_user_tweets-basic-invocation` (1 finding)

**1. [twitterapi-mcp-server](https://github.com/Jing-yilin/twitterapi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: TwitterAPI.io error: Either username or userId must be provided`

### `tool-check-hat-wearer-basic-invocation` (1 finding)

**1. [mcp-hats](https://github.com/dennisonbertram/mcp-hats)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unsupported network: test`

### `tool-get-hat-details-basic-invocation` (1 finding)

**1. [mcp-hats](https://github.com/dennisonbertram/mcp-hats)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unsupported network: test`

### `tool-query-hats-by-wearer-basic-invocation` (1 finding)

**1. [mcp-hats](https://github.com/dennisonbertram/mcp-hats)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Unsupported network: test`

### `tool-validate_generated_code-basic-invocation` (1 finding)

**1. [mcp-context-manager](https://github.com/bswa006/mcp-context-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "context"
    ],
    "message": "Required"
  }
]`

### `tool-read_logs_from_tab-basic-invocation` (1 finding)

**1. [Terminally-mcp](https://github.com/NightTrek/Terminally-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error reading logs: Failed to read logs: tmux exited with code 1: can't find pane: test
`

### `tool-get_products-basic-invocation` (1 finding)

**1. [cscart-mcp](https://github.com/hungryweb/cscart-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing get_products: Invalid URL`

### `tool-get_weather_alerts-basic-invocation` (1 finding)

**1. [muti-mcps](https://github.com/TaylorChen/muti-mcps)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: OPENWEATHER_API_KEY is not configured`

### `tool-get_gimbal_position-basic-invocation` (1 finding)

**1. [obsbot-camera-mcp](https://github.com/Radar105/obsbot-camera-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to get gimbal position: Command failed: v4l2-ctl -d /dev/video0 --get-ctrl=pan_absolute,tilt_absolute,zoom_absolute
/bin/sh: 1: v4l2-ctl: not found
`

### `tool-center_camera-basic-invocation` (1 finding)

**1. [obsbot-camera-mcp](https://github.com/Radar105/obsbot-camera-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Gimbal control failed: Command failed: v4l2-ctl -d /dev/video0 --set-ctrl=pan_absolute=0,tilt_absolute=0,zoom_absolute=0
/bin/sh: 1: v4l2-ctl: not found
`

### `tool-generate_api_client-basic-invocation` (1 finding)

**1. [swiftcode-mcp-server](https://github.com/hongaah/swiftcode-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate API client`

### `tool-generate_sfc_template_client-basic-invocation` (1 finding)

**1. [swiftcode-mcp-server](https://github.com/hongaah/swiftcode-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate SFC template files`

### `tool-generate_sfc_client-basic-invocation` (1 finding)

**1. [swiftcode-mcp-server](https://github.com/hongaah/swiftcode-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate SFC files`

### `tool-aem_install_package-basic-invocation` (1 finding)

**1. [aem-mcp](https://github.com/pradeep-moolemane/aem-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool aem_install_package: Package installation failed: `

### `tool-aem_list_packages-basic-invocation` (1 finding)

**1. [aem-mcp](https://github.com/pradeep-moolemane/aem-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool aem_list_packages: Failed to list packages: `

### `tool-azure_java_sdk_code_samples-basic-invocation` (1 finding)

**1. [mcp-azure-java-sdk-assist](https://github.com/weidongxu-microsoft/mcp-azure-java-sdk-assist)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool azure_java_sdk_code_samples: Cannot read properties of null (reading '1')`

### `tool-bruno_run_request-basic-invocation` (1 finding)

**1. [bruno-mcp-server](https://github.com/jcr82/bruno-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Bruno CLI error: ENOTDIR: not a directory, scandir 'test'`

### `tool-bruno_list_requests-basic-invocation` (1 finding)

**1. [bruno-mcp-server](https://github.com/jcr82/bruno-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Bruno CLI error: Collection path is not a directory: test`

### `tool-check_spelling-basic-invocation` (1 finding)

**1. [SpellChecker-MCP](https://github.com/morahan/SpellChecker-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No spell checkers initialized`

### `tool-add_to_dictionary-basic-invocation` (1 finding)

**1. [SpellChecker-MCP](https://github.com/morahan/SpellChecker-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No spell checkers initialized`

### `tool-is_correct-basic-invocation` (1 finding)

**1. [SpellChecker-MCP](https://github.com/morahan/SpellChecker-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No spell checkers initialized`

### `tool-get_commit_stats-basic-invocation` (1 finding)

**1. [git-metrics-mcp-server](https://github.com/jonmatum/git-metrics-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not a git repository: /home/tecnico/Desktop/Frameworks/mcp-check/test`

### `tool-get_author_metrics-basic-invocation` (1 finding)

**1. [git-metrics-mcp-server](https://github.com/jonmatum/git-metrics-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Not a git repository: /home/tecnico/Desktop/Frameworks/mcp-check/test`

### `tool-natural_search-basic-invocation` (1 finding)

**1. [everything-search-mcp-server](https://github.com/ananyaakamat/everything-search-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not connect to Everything Search. Make sure the HTTP server is enabled in Everything's settings (Tools > Options > HTTP Server).`

### `tool-generate_storybook_image-basic-invocation` (1 finding)

**1. [MCP-Storybook-Image-Generator](https://github.com/falahgs/MCP-Storybook-Image-Generator)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: got status: 400 Bad Request. {"error":{"message":"exception parsing response","code":400,"status":"Bad Request"}}`

### `tool-update_card-basic-invocation` (1 finding)

**1. [anki-mcp](https://github.com/letuanvu08/anki-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: cardId and ease are required for 'answer' operation`

### `tool-list-resources-basic-invocation` (1 finding)

**1. [coolify-mcp-server](https://github.com/StuMason/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: {"error":"Coolify API error: 503 Service Unavailable","status":503,"details":{}}`

### `tool-list-applications-basic-invocation` (1 finding)

**1. [coolify-mcp-server](https://github.com/StuMason/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: {"error":"Coolify API error: 503 Service Unavailable","status":503,"details":{}}`

### `tool-get-application-basic-invocation` (1 finding)

**1. [coolify-mcp-server](https://github.com/StuMason/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: {"error":"Coolify API error: 503 Service Unavailable","status":503,"details":{}}`

### `tool-get_profile-basic-invocation` (1 finding)

**1. [linkedin-mcp-server](https://github.com/Jing-yilin/linkedin-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: HarvestAPI error: At least one of url, publicIdentifier, or profileId is required`

### `tool-search_profiles-basic-invocation` (1 finding)

**1. [linkedin-mcp-server](https://github.com/Jing-yilin/linkedin-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: HarvestAPI error: HarvestAPI error (401): [object Object]`

### `tool-get_profile_posts-basic-invocation` (1 finding)

**1. [linkedin-mcp-server](https://github.com/Jing-yilin/linkedin-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: HarvestAPI error: At least one of profile, profileId, or profilePublicIdentifier is required`

### `tool-get_study_details-basic-invocation` (1 finding)

**1. [mcp-ClinicalTrial](https://github.com/Aki894/mcp-ClinicalTrial)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool get_study_details: Error: ClinicalTrials.gov API error (400): Parameter `nctId` has incorrect format`

### `tool-generate_3d_cartoon-basic-invocation` (1 finding)

**1. [mcp-3d-style-cartoon-gen-server](https://github.com/falahgs/mcp-3d-style-cartoon-gen-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: got status: 400 Bad Request. {"error":{"message":"exception parsing response","code":400,"status":"Bad Request"}}`

### `tool-list_tabs-basic-invocation` (1 finding)

**1. [yandex-browser-mcp](https://github.com/T1Trit/yandex-browser-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Browser was not found at the configured executablePath (C:\Users\Professional\AppData\Local\Yandex\YandexBrowser\Application\browser.exe)`

### `tool-firecrawl_scrape-basic-invocation` (1 finding)

**1. [firecrawl-local-mcp](https://github.com/ViperBlackSkull/firecrawl-local-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Scrape failed: Request failed with status code 404`

### `tool-firecrawl_crawl-basic-invocation` (1 finding)

**1. [firecrawl-local-mcp](https://github.com/ViperBlackSkull/firecrawl-local-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Crawl failed: Request failed with status code 404`

### `tool-firecrawl_crawl_status-basic-invocation` (1 finding)

**1. [firecrawl-local-mcp](https://github.com/ViperBlackSkull/firecrawl-local-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Get crawl status failed: Request failed with status code 404`

### `tool-get_command_output-basic-invocation` (1 finding)

**1. [wcli0](https://github.com/s2005/wcli0)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Log entry not found: test. It may have expired.`

### `tool-searxng_search-basic-invocation` (1 finding)

**1. [searxng-mcp](https://github.com/baadir/searxng-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: SearXNG error: 404 Not Found`

### `tool-gk_reload_abilities-basic-invocation` (1 finding)

**1. [gravity-mcp](https://github.com/GravityKit/gravity-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Neither Gravity Forms nor WordPress credentials are usable. Set GRAVITY_FORMS_* and/or GRAVITYKIT_WP_* in .env.`

### `tool-wave_plan-basic-invocation` (1 finding)

**1. [universal-infinite-loop-mcp-server](https://github.com/gptprojectmanager/universal-infinite-loop-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool wave_plan: [
  {
    "code": "too_small",
    "minimum": 1000,
    "type": "number",
    "inclusive": true,
    "exact": false,
    "message": "Number must be greater than or equal to 1000",
    "path": [
      "contextBudget"
    ]
  }
]`

### `tool-resize_image-basic-invocation` (1 finding)

**1. [imagician](https://github.com/flowy11/imagician)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image processing error: Cannot use same file for input and output`

### `tool-convert_format-basic-invocation` (1 finding)

**1. [imagician](https://github.com/flowy11/imagician)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image processing error: Cannot use same file for input and output`

### `tool-crop_image-basic-invocation` (1 finding)

**1. [imagician](https://github.com/flowy11/imagician)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Image processing error: Cannot use same file for input and output`

### `tool-moveFile-basic-invocation` (1 finding)

**1. [ts-refactor-mcp](https://github.com/schicks/ts-refactor-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to move file: Could not find tsserver. Make sure typescript is installed in node_modules.`

### `tool-warmup-basic-invocation` (1 finding)

**1. [ts-refactor-mcp](https://github.com/schicks/ts-refactor-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to warm up project: Could not find tsserver. Make sure typescript is installed in node_modules.`

### `tool-get_token-basic-invocation` (1 finding)

**1. [zentao-mcp-server](https://github.com/Valiant-Cat/zentao-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing ZENTAO_BASE_URL`

### `tool-call-basic-invocation` (1 finding)

**1. [zentao-mcp-server](https://github.com/Valiant-Cat/zentao-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing ZENTAO_BASE_URL`

### `tool-listMyProjects-basic-invocation` (1 finding)

**1. [zentao-mcp-server](https://github.com/Valiant-Cat/zentao-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing ZENTAO_BASE_URL`

### `tool-read_connections-basic-invocation` (1 finding)

**1. [cdata-sync-mcp-server](https://github.com/CDataSoftware/cdata-sync-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Invalid connection read action: undefined`

### `tool-write_connections-basic-invocation` (1 finding)

**1. [cdata-sync-mcp-server](https://github.com/CDataSoftware/cdata-sync-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Missing required parameters: providerName, connectionString`

### `tool-advanced_search-basic-invocation` (1 finding)

**1. [PubMed-MCP-Server](https://github.com/Augmented-Nature/PubMed-MCP-Server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: At least one search field must be provided`

### `tool-get_latest_stable_version-basic-invocation` (1 finding)

**1. [maven-version-server](https://github.com/kristijan-rotim/maven-version-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: Invalid Maven coordinate format. Expected "groupId:artifactId" or "groupId:artifactId:version"`

### `tool-get_all_versions-basic-invocation` (1 finding)

**1. [maven-version-server](https://github.com/kristijan-rotim/maven-version-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: Invalid Maven coordinate format. Expected "groupId:artifactId" or "groupId:artifactId:version"`

### `tool-check_version_exists-basic-invocation` (1 finding)

**1. [maven-version-server](https://github.com/kristijan-rotim/maven-version-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: Invalid Maven coordinate format. Expected "groupId:artifactId" or "groupId:artifactId:version"`

### `tool-get_cell-basic-invocation` (1 finding)

**1. [excel-reader-mcp](https://github.com/ArchimedesCrypto/excel-reader-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid cell address: test`

### `tool-reasoner-basic-invocation` (1 finding)

**1. [deepseek-r1-mcp](https://github.com/michaelneale/deepseek-r1-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Ollama API error: 404 Not Found`

### `tool-list_tasks-basic-invocation` (1 finding)

**1. [mcp-orchestro](https://github.com/khaoss85/mcp-orchestro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env`

### `tool-ethics_check-basic-invocation` (1 finding)

**1. [ethics-check-mcp](https://github.com/r-huijts/ethics-check-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute tool: Failed to complete ethics analysis`

### `tool-ethics_guide-basic-invocation` (1 finding)

**1. [ethics-check-mcp](https://github.com/r-huijts/ethics-check-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute tool: Failed to generate ethics guidance`

### `tool-visualize_fen-basic-invocation` (1 finding)

**1. [chess-FEN-mcp](https://github.com/Bigsy/chess-FEN-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error visualizing FEN: Invalid FEN: FEN must have exactly 6 fields`

### `tool-close-basic-invocation` (1 finding)

**1. [chromedp-mcp](https://github.com/KePatrick/chromedp-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: id should be provide`

### `tool-compile-d2-basic-invocation` (1 finding)

**1. [d2-mcp](https://github.com/h0rv/d2-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: either 'code' or 'file_path' parameter must be provided`

### `tool-render-d2-basic-invocation` (1 finding)

**1. [d2-mcp](https://github.com/h0rv/d2-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: either 'code' or 'file_path' parameter must be provided`

### `tool-log_thought-basic-invocation` (1 finding)

**1. [deliberate-reasoning-engine](https://github.com/haasonsaas/deliberate-reasoning-engine)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error: SQLITE_BUSY: database is locked`

### `tool-list-users-basic-invocation` (1 finding)

**1. [keycloak-mcp-server](https://github.com/M0-AR/keycloak-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Keycloak server connection failed. The server may be temporarily unavailable or experiencing network issues. Please check server status and try again in a moment.`

### `tool-check-contract-basic-invocation` (1 finding)

**1. [mcp-sourcify](https://github.com/soyrubio/mcp-sourcify)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool 'check-contract' failed: Sourcify API error: Invalid addresses: test`

### `tool-get-contract-source-basic-invocation` (1 finding)

**1. [mcp-sourcify](https://github.com/soyrubio/mcp-sourcify)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool 'get-contract-source' failed: Sourcify API error: Invalid address: test`

### `tool-get-contract-metadata-basic-invocation` (1 finding)

**1. [mcp-sourcify](https://github.com/soyrubio/mcp-sourcify)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool 'get-contract-metadata' failed: Sourcify API error: Invalid address: test`

### `tool-puppeteer_screenshot-basic-invocation` (1 finding)

**1. [puppeteer-mcp](https://github.com/code-craka/puppeteer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not find Chrome (ver. 131.0.6778.204). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-puppeteer_click-basic-invocation` (1 finding)

**1. [puppeteer-mcp](https://github.com/code-craka/puppeteer-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not find Chrome (ver. 131.0.6778.204). This can occur if either
 1. you did not perform an installation before running the script (e.g. `npx puppeteer browsers install chrome`) or
 2. your cache path is incorrectly configured (which is: /home/tecnico/.cache/puppeteer).
For (2), check out our guide on configuring puppeteer at https://pptr.dev/guides/configuration.`

### `tool-download_images_batch-basic-invocation` (1 finding)

**1. [mcp-image-downloader](https://github.com/cced3000/mcp-image-downloader)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Invalid URLs found: test`

### `tool-git-summary-basic-invocation` (1 finding)

**1. [dcr-mcp](https://github.com/cybersiddhu/dcr-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: validation error: Key: 'GitSummaryRequest.APIKey' Error:Field validation for 'APIKey' failed on the 'required' tag`

### `tool-literature-fetch-basic-invocation` (1 finding)

**1. [dcr-mcp](https://github.com/cybersiddhu/dcr-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: invalid pmid format: PMID must contain only digits, got: test`

### `tool-linear_auth_callback-basic-invocation` (1 finding)

**1. [mcp-server-linear](https://github.com/dvcrn/mcp-server-linear)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to handle authentication callback: MCP error -32600: OAuth config not initialized`

### `tool-generate_images-basic-invocation` (1 finding)

**1. [image-gen3-google-mcp-server](https://github.com/falahgs/image-gen3-google-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 2: MCP error 2: Failed to generate images: Could not load the default credentials. Browse to https://cloud.google.com/docs/authentication/getting-started for more information.`

### `tool-eth_blockNumber-basic-invocation` (1 finding)

**1. [evm-rpc-mcp-server](https://github.com/karacurt/evm-rpc-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RPC call failed: RPC_URL is not set`

### `tool-eth_getBalance-basic-invocation` (1 finding)

**1. [evm-rpc-mcp-server](https://github.com/karacurt/evm-rpc-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RPC call failed: RPC_URL is not set`

### `tool-eth_getTransactionCount-basic-invocation` (1 finding)

**1. [evm-rpc-mcp-server](https://github.com/karacurt/evm-rpc-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RPC call failed: RPC_URL is not set`

### `tool-youtube_downloader-basic-invocation` (1 finding)

**1. [mcp_in_docker_container](https://github.com/keerapon-som/mcp_in_docker_container)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: yt-dlp error: exec: "yt-dlp": executable file not found in $PATH
Output: `

### `tool-get_web_inspiration-basic-invocation` (1 finding)

**1. [mcp-copy-web-ui](https://github.com/maoxiaoke/mcp-copy-web-ui)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to download website: Failed to fetch HTML content`

### `tool-upload_files-basic-invocation` (1 finding)

**1. [file-store-mcp](https://github.com/sjzar/file-store-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: storage service not configured or initialization failed. `

### `tool-upload_url_files-basic-invocation` (1 finding)

**1. [file-store-mcp](https://github.com/sjzar/file-store-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to download file from test: Get "test": unsupported protocol scheme ""`

### `tool-list_agents-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/weikio/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Weik.io CLI error: Command failed: weikio agents ls
/bin/sh: 1: weikio: not found
`

### `tool-apply_config-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/weikio/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Weik.io CLI error: Command failed: weikio config apply test
/bin/sh: 1: weikio: not found
`

### `tool-get_hacktricks_page-basic-invocation` (1 finding)

**1. [hacktricks-mcp-server](https://github.com/xplo8e/hacktricks-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: File not found: test`

### `tool-get_hacktricks_outline-basic-invocation` (1 finding)

**1. [hacktricks-mcp-server](https://github.com/xplo8e/hacktricks-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: File not found: test`

### `tool-execute_python-basic-invocation` (1 finding)

**1. [mcp-python-executor](https://github.com/bsmi021/mcp-python-executor)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid Python execution arguments`

### `tool-config-basic-invocation` (1 finding)

**1. [brew-mcp](https://github.com/nagypeterjob/brew-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: find brew binary :exec: "brew": executable file not found in $PATH`

### `tool-get_package_version-basic-invocation` (1 finding)

**1. [brew-mcp](https://github.com/nagypeterjob/brew-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: find brew binary :exec: "brew": executable file not found in $PATH`

### `tool-golang_inspect_package-basic-invocation` (1 finding)

**1. [godoc-mcp](https://github.com/budougumi0617/godoc-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error 0: failed to handle tools/call: failed to get package: package not found: test`

### `tool-golang_get_struct_doc-basic-invocation` (1 finding)

**1. [godoc-mcp](https://github.com/budougumi0617/godoc-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error 0: failed to handle tools/call: failed to get struct info: package not found: test`

### `tool-launch_browser-basic-invocation` (1 finding)

**1. [viewport-control](https://github.com/chipsxp/viewport-control)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to launch browser: Protocol error (Page.navigate): Cannot navigate to invalid URL`

### `tool-quickjs-basic-invocation` (1 finding)

**1. [quickjsmcpserver](https://github.com/mauri870/quickjsmcpserver)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: ReferenceError: 'test' is not defined`

### `tool-add_card-basic-invocation` (1 finding)

**1. [yanki-mcp-server](https://github.com/htlin222/yanki-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to create deck: 00_Inbox::2026::07::14`

### `tool-ulysses_new_sheet-basic-invocation` (1 finding)

**1. [ulysses-mcp](https://github.com/sonofagl1tch/ulysses-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MCP error -32603: Command failed: open ulysses://x-callback-url/new-sheet?text=test
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'ulysses://x-callback-url/new-sheet?text=test'
`

### `tool-ulysses_new_group-basic-invocation` (1 finding)

**1. [ulysses-mcp](https://github.com/sonofagl1tch/ulysses-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MCP error -32603: Command failed: open ulysses://x-callback-url/new-group?name=test
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'ulysses://x-callback-url/new-group?name=test'
`

### `tool-ulysses_insert-basic-invocation` (1 finding)

**1. [ulysses-mcp](https://github.com/sonofagl1tch/ulysses-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: MCP error -32603: Command failed: open ulysses://x-callback-url/insert?id=test&text=test
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'ulysses://x-callback-url/insert?id=test&text=test'
`

### `tool-send_ntfy-basic-invocation` (1 finding)

**1. [simple-ntfy-mcp](https://github.com/Aaryan-Kapoor/simple-ntfy-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No topic specified and no default topic configured`

### `tool-sprite_manager-basic-invocation` (1 finding)

**1. [mcp-pvsneslib](https://github.com/Atomic-Germ/mcp-pvsneslib)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Input validation failed: /action: Expected required property; /action: Expected union value`

### `tool-sound_engine-basic-invocation` (1 finding)

**1. [mcp-pvsneslib](https://github.com/Atomic-Germ/mcp-pvsneslib)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Input validation failed: /action: Expected required property; /action: Expected union value`

### `tool-graphics_converter-basic-invocation` (1 finding)

**1. [mcp-pvsneslib](https://github.com/Atomic-Germ/mcp-pvsneslib)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Input validation failed: /action: Expected required property; /action: Expected union value`

### `tool-calculator-basic-invocation` (1 finding)

**1. [mcp-template](https://github.com/Atomic-Germ/mcp-template)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unsupported operation: test. Supported operations: add, subtract, multiply, divide, power`

### `tool-simulate_battle-basic-invocation` (1 finding)

**1. [pok-mon-battle-simulation](https://github.com/ananya5151/pok-mon-battle-simulation)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Request failed with status code 404`

### `tool-read_output_page-basic-invocation` (1 finding)

**1. [paginate-mcp](https://github.com/andrelip/paginate-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Output ID 'test' not found. It may have expired or been invalid.`

### `tool-execute_query-basic-invocation` (1 finding)

**1. [mysql_mcp](https://github.com/ashellearl123/mysql_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: ❌ 执行失败: MCP error -32600: ❌ 请先使用 connect_database 工具连接到数据库`

### `tool-create_alert_rule-basic-invocation` (1 finding)

**1. [mcp-grafana](https://github.com/ashishnagargoje0/mcp-grafana)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: create alert rule: invalid duration format "test": time: invalid duration "test"`

### `tool-device-list-basic-invocation` (1 finding)

**1. [balenamcp](https://github.com/balena-io-experimental/balenamcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute command: exec: "balena": executable file not found in $PATH
Output: `

### `tool-device-logs-basic-invocation` (1 finding)

**1. [balenamcp](https://github.com/balena-io-experimental/balenamcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute command: exec: "balena": executable file not found in $PATH
Output: `

### `tool-fleet-list-basic-invocation` (1 finding)

**1. [balenamcp](https://github.com/balena-io-experimental/balenamcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute command: exec: "balena": executable file not found in $PATH
Output: `

### `tool-update_component-basic-invocation` (1 finding)

**1. [components-mcp](https://github.com/bodangren/components-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Component not found`

### `tool-install_mcp_server-basic-invocation` (1 finding)

**1. [mcp-easy-installer-amazonq-cli](https://github.com/bonjourzzz/mcp-easy-installer-amazonq-cli)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Operation failed: Invalid GitHub URL or shorthand format. Use format like `owner/repo` or `https://github.com/owner/repo`.`

### `tool-get_sdk_doc-basic-invocation` (1 finding)

**1. [bosbase-sdk-docs-mcp](https://github.com/bosbase/bosbase-sdk-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: SDK type is required when topic is not "overview"`

### `tool-GetUnitBaseByAdCode-basic-invocation` (1 finding)

**1. [mcp-server-ad-code](https://github.com/centanetdc/mcp-server-ad-code)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate : HTTP error! status: 401`

### `tool-GetUnitMarketByAdCode-basic-invocation` (1 finding)

**1. [mcp-server-ad-code](https://github.com/centanetdc/mcp-server-ad-code)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate : HTTP error! status: 401`

### `tool-get_pod_logs-basic-invocation` (1 finding)

**1. [trace_gateway_failures](https://github.com/challamani/trace_gateway_failures)** (go)
- Type: `InvocationError`
- Message: `MCP error -32000: Failed to retrieve pod logs`

### `tool-query_dataset-basic-invocation` (1 finding)

**1. [mcp-maryland-opendata](https://github.com/christyfrink/mcp-maryland-opendata)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Maryland Open Data API error: Not found`

### `tool-cms_query_dataset-basic-invocation` (1 finding)

**1. [cms-datagov-mcp-server](https://github.com/clarifyhealth/cms-datagov-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: CMS API error (404): Request failed with status code 404`

### `tool-get_price_history-basic-invocation` (1 finding)

**1. [steammarketmcp](https://github.com/coledie/steammarketmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Steam API error: Request failed with status code 400`

### `tool-create_idea-basic-invocation` (1 finding)

**1. [mcp-project-manager](https://github.com/croffasia/mcp-project-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool: 🚫 APPROVAL REQUIRED: Tool "create_idea" requires user approval.

WORKFLOW:
1. Propose your changes to the user
2. Wait for explicit approval (e.g., "Yes, create these tasks")
3. Call this tool again with "_approval_confirmed: true" parameter

EXAMPLE:
create_idea({
  ...your_parameters,
  _approval_confirmed: true
})`

### `tool-create_epic-basic-invocation` (1 finding)

**1. [mcp-project-manager](https://github.com/croffasia/mcp-project-manager)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool: 🚫 APPROVAL REQUIRED: Tool "create_epic" requires user approval.

WORKFLOW:
1. Propose your changes to the user
2. Wait for explicit approval (e.g., "Yes, create these tasks")
3. Call this tool again with "_approval_confirmed: true" parameter

EXAMPLE:
create_epic({
  ...your_parameters,
  _approval_confirmed: true
})`

### `tool-get_user_data-basic-invocation` (1 finding)

**1. [SAP-SuccessFactors-mcp-server-V0.1](https://github.com/david-rodrig/SAP-SuccessFactors-mcp-server-V0.1)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32603: User not found: test`

### `tool-search_user_by_email-basic-invocation` (1 finding)

**1. [SAP-SuccessFactors-mcp-server-V0.1](https://github.com/david-rodrig/SAP-SuccessFactors-mcp-server-V0.1)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32603: Failed to search by email: SuccessFactors API Error: 401 - "[LGN0008]Company INSTANSENAME not found. Make sure you have entered the correct company ID. Please note that the company ID is case sensitive."`

### `tool-post_user_data-basic-invocation` (1 finding)

**1. [SAP-SuccessFactors-mcp-server-V0.1](https://github.com/david-rodrig/SAP-SuccessFactors-mcp-server-V0.1)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32603: Failed to update user: SuccessFactors API Error: 401 - "[LGN0008]Company INSTANSENAME not found. Make sure you have entered the correct company ID. Please note that the company ID is case sensitive."`

### `tool-get-weather-basic-invocation` (1 finding)

**1. [mcp-weather-server](https://github.com/dbsxortime/mcp-weather-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Request failed with status code 401`

### `tool-analyze_jira_issue-basic-invocation` (1 finding)

**1. [jira-utilities-mcp-server](https://github.com/deepakjain12345/jira-utilities-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid JIRA issue key: "test". Expected format: PROJECT-123 (e.g., IOAUT-23009)`

### `tool-get_issue_details-basic-invocation` (1 finding)

**1. [jira-utilities-mcp-server](https://github.com/deepakjain12345/jira-utilities-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid JIRA issue key: "test". Expected format: PROJECT-123 (e.g., IOAUT-23009)`

### `tool-list_subtasks-basic-invocation` (1 finding)

**1. [jira-utilities-mcp-server](https://github.com/deepakjain12345/jira-utilities-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid JIRA issue key: "test". Expected format: PROJECT-123 (e.g., IOAUT-23009)`

### `tool-get_cursor_position-basic-invocation` (1 finding)

**1. [mcp-terminal-bridge](https://github.com/devdotbo/mcp-terminal-bridge)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: session_id must be a valid UUID`

### `tool-get_screen_size-basic-invocation` (1 finding)

**1. [mcp-terminal-bridge](https://github.com/devdotbo/mcp-terminal-bridge)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: session_id must be a valid UUID`

### `tool-compile-basic-invocation` (1 finding)

**1. [arduino-mcp-server](https://github.com/dido18/arduino-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute arduino-cli: exec: "arduino-cli": executable file not found in $PATH`

### `tool-list_boards-basic-invocation` (1 finding)

**1. [arduino-mcp-server](https://github.com/dido18/arduino-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute arduino-cli: exec: "arduino-cli": executable file not found in $PATH`

### `tool-upload-basic-invocation` (1 finding)

**1. [arduino-mcp-server](https://github.com/dido18/arduino-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to execute arduino-cli: exec: "arduino-cli": executable file not found in $PATH`

### `tool-calculate_planetary_positions-basic-invocation` (1 finding)

**1. [swiss-ephemeris-mcp-server](https://github.com/dm0lz/swiss-ephemeris-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Swiss Ephemeris calculation failed: Invalid datetime format. Use ISO8601 format like 1985-04-12T23:20:50Z`

### `tool-calculate_transits-basic-invocation` (1 finding)

**1. [swiss-ephemeris-mcp-server](https://github.com/dm0lz/swiss-ephemeris-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Swiss Ephemeris calculation failed: Invalid datetime format. Use ISO8601 format like 1985-04-12T23:20:50Z`

### `tool-batch_get_info-basic-invocation` (1 finding)

**1. [d365fo-mcp-server](https://github.com/dynamics365ninja/d365fo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: database is locked`

### `tool-generate_object-basic-invocation` (1 finding)

**1. [d365fo-mcp-server](https://github.com/dynamics365ninja/d365fo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: database is locked`

### `tool-generate_config-basic-invocation` (1 finding)

**1. [eib-mcp](https://github.com/e-minguez/eib-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32000: configuration is invalid:
- (root): image is required
- (root): operatingSystem is required
- (root): apiVersion is required
- (root): Must validate all the schemas (allOf)
`

### `tool-create-issue-basic-invocation` (1 finding)

**1. [mcp-git-issues](https://github.com/e-roux/mcp-git-issues)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create issue: POST https://api.github.com/repos/mcereal/mcp-check/issues: 401 Requires authentication []`

### `tool-get-issue-basic-invocation` (1 finding)

**1. [mcp-git-issues](https://github.com/e-roux/mcp-git-issues)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to get issue: GET https://api.github.com/repos/mcereal/mcp-check/issues/50: 404 Not Found []`

### `tool-mysql_list_tables-basic-invocation` (1 finding)

**1. [mysql-mcp-server](https://github.com/eddevfront/mysql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to connect to MySQL: Error`

### `tool-mysql_describe_table-basic-invocation` (1 finding)

**1. [mysql-mcp-server](https://github.com/eddevfront/mysql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to connect to MySQL: Error`

### `tool-getAddressByCEP-basic-invocation` (1 finding)

**1. [viacep-brasil-mcp-server](https://github.com/edum-compassuol/viacep-brasil-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "origin": "string",
    "code": "invalid_format",
    "format": "regex",
    "pattern": "/^[0-9]{8}$/",
    "path": [
      "cep"
    ],
    "message": "The CEP must have 8 digits."
  }
]`

### `tool-getCEPByAddress-basic-invocation` (1 finding)

**1. [viacep-brasil-mcp-server](https://github.com/edum-compassuol/viacep-brasil-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "origin": "string",
    "code": "invalid_format",
    "format": "regex",
    "pattern": "/^[A-Z]{2}$/",
    "path": [
      "uf"
    ],
    "message": "The UF must be a two-letter state code."
  }
]`

### `tool-generate_pdf-basic-invocation` (1 finding)

**1. [pdf-mcp-server](https://github.com/fabiangenell/pdf-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: name is not defined`

### `tool-generate_pdf_from_template-basic-invocation` (1 finding)

**1. [pdf-mcp-server](https://github.com/fabiangenell/pdf-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: name is not defined`

### `tool-read_dir-basic-invocation` (1 finding)

**1. [go-mcp-servers](https://github.com/gfffrtt/go-mcp-servers)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: open test: not a directory`

### `tool-health_export_query-basic-invocation` (1 finding)

**1. [apple-health-chat-mcp](https://github.com/gh33k/apple-health-chat-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Query execution failed: Missing SELECT clause`

### `tool-themes_get_component_source-basic-invocation` (1 finding)

**1. [radix-mcp-server](https://github.com/gianpieropuleo/radix-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch themes component source "test": Themes component "test" not found in repository`

### `tool-themes_get_component_documentation-basic-invocation` (1 finding)

**1. [radix-mcp-server](https://github.com/gianpieropuleo/radix-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch themes component documentation "test": Request failed with status code 404 Not Found: GET https://raw.githubusercontent.com/radix-ui/website/main/data/themes/docs/components/test.mdx`

### `tool-createDeployment-basic-invocation` (1 finding)

**1. [simple-k8s-mcp-server](https://github.com/hendzormati/simple-k8s-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: kubernetes client not available`

### `tool-createPod-basic-invocation` (1 finding)

**1. [simple-k8s-mcp-server](https://github.com/hendzormati/simple-k8s-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: kubernetes client not available`

### `tool-analyze_issue_priority-basic-invocation` (1 finding)

**1. [github-mcp-server](https://github.com/himanshusharma89/github-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: GET https://api.github.com/repos/test/test/issues?per_page=20&state=open: 401 Bad credentials []`

### `tool-get_pending_reviews-basic-invocation` (1 finding)

**1. [github-mcp-server](https://github.com/himanshusharma89/github-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: GET https://api.github.com/repos/test/test/pulls?per_page=100&state=open: 401 Bad credentials []`

### `tool-list_sessions-basic-invocation` (1 finding)

**1. [mcp-gemini-assistant](https://github.com/hvantoan/mcp-gemini-assistant)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: session.problem_description.substring is not a function`

### `tool-z3-basic-invocation` (1 finding)

**1. [z3-mcp](https://github.com/igorwwwwwwwwwwwwwwwwwwww/z3-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: error executing Z3: exec: "z3": executable file not found in $PATH `

### `tool-csw_configure-basic-invocation` (1 finding)

**1. [CSW-MCP-SERVER](https://github.com/jquintero17/CSW-MCP-SERVER)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Configuration failed: Configuration validation failed:
cluster_url: Invalid cluster URL`

### `tool-csw_list_scopes-basic-invocation` (1 finding)

**1. [CSW-MCP-SERVER](https://github.com/jquintero17/CSW-MCP-SERVER)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: CSW client not configured. Please run csw_configure first.`

### `tool-csw_get_scope-basic-invocation` (1 finding)

**1. [CSW-MCP-SERVER](https://github.com/jquintero17/CSW-MCP-SERVER)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: CSW client not configured. Please run csw_configure first.`

### `tool-update_page-basic-invocation` (1 finding)

**1. [mediawiki-mcp](https://github.com/jthou/mediawiki-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Either 'content' or 'fromFile' parameter is required`

### `tool-login_user-basic-invocation` (1 finding)

**1. [testOMSMCP](https://github.com/kushal45/testOMSMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Login failed: Request failed with status code 404`

### `tool-fetch_products-basic-invocation` (1 finding)

**1. [testOMSMCP](https://github.com/kushal45/testOMSMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: User not logged in or session expired. Please use the login_user tool first.`

### `tool-listCollections-basic-invocation` (1 finding)

**1. [mongodb-mcp](https://github.com/leorosignoli/mongodb-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: MONGODB_URI environment variable is required`

### `tool-get_activity_leaderboard-basic-invocation` (1 finding)

**1. [mcp-osrs-stats](https://github.com/lukehollenback/mcp-osrs-stats)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Failed to fetch activity leaderboard: Invalid activity`

### `tool-start_link_x_account-basic-invocation` (1 finding)

**1. [avalogica-x-mcp](https://github.com/mdwillman/avalogica-x-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: X_CLIENT_ID is not configured for avalogica-x-mcp.`

### `tool-link_x_account-basic-invocation` (1 finding)

**1. [avalogica-x-mcp](https://github.com/mdwillman/avalogica-x-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: No redirect URI configured. Set X_REDIRECT_BASE_URL (and optional X_REDIRECT_PATH) for avalogica-x-mcp.`

### `tool-post_to_x-basic-invocation` (1 finding)

**1. [avalogica-x-mcp](https://github.com/mdwillman/avalogica-x-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to post to X: Unable to detect a Project Id in the current environment. 
To learn more about authentication and Google APIs, visit: 
https://cloud.google.com/docs/authentication/getting-started`

### `tool-get_block-basic-invocation` (1 finding)

**1. [bitcoin-data-mcp](https://github.com/myownipgit/bitcoin-data-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch block: AxiosError: Request failed with status code 400`

### `tool-get_transaction-basic-invocation` (1 finding)

**1. [bitcoin-data-mcp](https://github.com/myownipgit/bitcoin-data-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch transaction: AxiosError: Request failed with status code 400`

### `tool-get_address-basic-invocation` (1 finding)

**1. [bitcoin-data-mcp](https://github.com/myownipgit/bitcoin-data-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to fetch address: AxiosError: Request failed with status code 400`

### `tool-get_resolved_address_of_nad_name-basic-invocation` (1 finding)

**1. [nns-mcp](https://github.com/nadnameservice/nns-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: The contract function "getResolvedAddress" returned no data ("0x").

This could be due to any of the following:
  - The contract does not have the function "getResolvedAddress",
  - The parameters passed to the contract function may be invalid, or
  - The address is not a contract.
 
Contract Call:
  address:   0x3019BF1dfB84E5b46Ca9D0eEC37dE08a59A41308
  function:  getResolvedAddress(bytes32 node)
  args:                        (0x04f740db81dc36c853ab4205bddd785f46e79ccedca351...`

### `tool-get_profile_of_wallet_address-basic-invocation` (1 finding)

**1. [nns-mcp](https://github.com/nadnameservice/nns-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid wallet address: test`

### `tool-transfer_mon_to_wallet_address-basic-invocation` (1 finding)

**1. [nns-mcp](https://github.com/nadnameservice/nns-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid wallet address: test`

### `tool-get_balance-basic-invocation` (1 finding)

**1. [tron_mcp_server](https://github.com/netts-official/tron_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get balance: All sources failed: undefined, MCP error -32603: TronGrid API call failed: TronGrid API error: 429 Too Many Requests, MCP error -32603: TronScan API call failed: TronScan API error: 400 Bad Request`

### `tool-get_account_resources-basic-invocation` (1 finding)

**1. [tron_mcp_server](https://github.com/netts-official/tron_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to get account resources: All sources failed: undefined, MCP error -32603: TronGrid API call failed: TronGrid API error: 429 Too Many Requests, MCP error -32603: TronScan API call failed: TronScan API error: 400 Bad Request`

### `tool-ambari_clusters_getclusters-basic-invocation` (1 finding)

**1. [ambari-mcp-server](https://github.com/nikita15p/ambari-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ambari API Error: GET http://localhost:8080/api/v1/clusters | HTTP 404 Not Found`

### `tool-ambari_clusters_getcluster-basic-invocation` (1 finding)

**1. [ambari-mcp-server](https://github.com/nikita15p/ambari-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ambari API Error: GET http://localhost:8080/api/v1/clusters/test | HTTP 404 Not Found`

### `tool-update_knowledge-basic-invocation` (1 finding)

**1. [mcp-knowledge-server](https://github.com/nikolausm/mcp-knowledge-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eintrag mit ID test nicht gefunden`

### `tool-get_appliances-basic-invocation` (1 finding)

**1. [mcp-server-home-connect](https://github.com/nikolausm/mcp-server-home-connect)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 401`

### `tool-get_appliance_status-basic-invocation` (1 finding)

**1. [mcp-server-home-connect](https://github.com/nikolausm/mcp-server-home-connect)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 401`

### `tool-get_appliance_programs-basic-invocation` (1 finding)

**1. [mcp-server-home-connect](https://github.com/nikolausm/mcp-server-home-connect)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Request failed with status code 401`

### `tool-kubernetes_list_resources-basic-invocation` (1 finding)

**1. [mcp-server-k8s-go](https://github.com/nokamoto/mcp-server-k8s-go)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create config: failed to get kubeconfig: invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable`

### `tool-kubernetes_version-basic-invocation` (1 finding)

**1. [mcp-server-k8s-go](https://github.com/nokamoto/mcp-server-k8s-go)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to create config: failed to get kubeconfig: invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable`

### `tool-load_epub-basic-invocation` (1 finding)

**1. [epub-mcp](https://github.com/notfounds/epub-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Invalid/missing file test`

### `tool-read_epub_metadata-basic-invocation` (1 finding)

**1. [epub-mcp](https://github.com/notfounds/epub-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No EPUB file loaded. Use load_epub first.`

### `tool-read_epub_toc-basic-invocation` (1 finding)

**1. [epub-mcp](https://github.com/notfounds/epub-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No EPUB file loaded. Use load_epub first.`

### `tool-webflow_scrape_multiple-basic-invocation` (1 finding)

**1. [Agenticledger_MCP_ZeekeeWebflow](https://github.com/oregpt/Agenticledger_MCP_ZeekeeWebflow)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to scrape any posts from the provided 1 URLs. Check that the URLs are valid Webflow blog posts.`

### `tool-auth.setToken-basic-invocation` (1 finding)

**1. [wi-graphql-mcp-server](https://github.com/philip-hayden/wi-graphql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-auth.refreshToken-basic-invocation` (1 finding)

**1. [wi-graphql-mcp-server](https://github.com/philip-hayden/wi-graphql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-discoverObservations-basic-invocation` (1 finding)

**1. [wi-graphql-mcp-server](https://github.com/philip-hayden/wi-graphql-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: keyValidator._parse is not a function`

### `tool-generateImage-basic-invocation` (1 finding)

**1. [gemini-mcp-server](https://github.com/rtbui2012/gemini-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Could not load the default credentials. Browse to https://cloud.google.com/docs/authentication/getting-started for more information.`

### `tool-aiSearch-basic-invocation` (1 finding)

**1. [gemini-mcp-server](https://github.com/rtbui2012/gemini-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Could not load the default credentials. Browse to https://cloud.google.com/docs/authentication/getting-started for more information.`

### `tool-ask_gemini-basic-invocation` (1 finding)

**1. [ask-ai-mcp](https://github.com/rudiarta/ask-ai-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to call Gemini: /bin/sh: 1: gemini: not found
`

### `tool-ask_gemini_with_file-basic-invocation` (1 finding)

**1. [ask-ai-mcp](https://github.com/rudiarta/ask-ai-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to call Gemini: /bin/sh: 1: gemini: not found
`

### `tool-get-space-basic-invocation` (1 finding)

**1. [huggingface-mcp](https://github.com/samihalawa/huggingface-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Request failed with status code 404`

### `tool-create_comment-basic-invocation` (1 finding)

**1. [docbase-mcp-server](https://github.com/shogo-ma/docbase-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: post_id must be a valid number`

### `tool-create_post-basic-invocation` (1 finding)

**1. [docbase-mcp-server](https://github.com/shogo-ma/docbase-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: unexpected status code: 404`

### `tool-get_post_by_post_id-basic-invocation` (1 finding)

**1. [docbase-mcp-server](https://github.com/shogo-ma/docbase-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: post_id is not a number`

### `tool-open_note-basic-invocation` (1 finding)

**1. [mcp-server-bear](https://github.com/ssiswent/mcp-server-bear)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Either title or id must be provided`

### `tool-search_notes-basic-invocation` (1 finding)

**1. [mcp-server-bear](https://github.com/ssiswent/mcp-server-bear)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 3: Command failed: open "bear://x-callback-url/search?term=test"
/usr/bin/open: 882: www-browser: not found
/usr/bin/open: 882: links2: not found
/usr/bin/open: 882: elinks: not found
/usr/bin/open: 882: links: not found
/usr/bin/open: 882: lynx: not found
/usr/bin/open: 882: w3m: not found
xdg-open: no method available for opening 'bear://x-callback-url/search?term=test'
`

### `tool-get_company_overview-basic-invocation` (1 finding)

**1. [financial-mcp-server](https://github.com/suraif16/financial-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing get_company_overview: API request failed: Thank you for using Alpha Vantage! Please consider spreading out your free API requests more sparingly (1 request per second). You may subscribe to any of the premium plans at https://www.alphavantage.co/premium/ to lift the free key rate limit (25 requests per day), raise the per-second burst limit, and instantly unlock all premium endpoints`

### `tool-get_technical_analysis-basic-invocation` (1 finding)

**1. [financial-mcp-server](https://github.com/suraif16/financial-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing get_technical_analysis: API request failed: Thank you for using Alpha Vantage! Please consider spreading out your free API requests more sparingly (1 request per second). You may subscribe to any of the premium plans at https://www.alphavantage.co/premium/ to lift the free key rate limit (25 requests per day), raise the per-second burst limit, and instantly unlock all premium endpoints`

### `tool-edge_connect-basic-invocation` (1 finding)

**1. [Edge-DevTools-MCP](https://github.com/syunnrai123/Edge-DevTools-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 执行工具 edge_connect 时发生错误: Error: 连接Edge浏览器失败: Error: 找不到Edge浏览器可执行文件，请手动指定browserPath参数`

### `tool-edge_get_targets-basic-invocation` (1 finding)

**1. [Edge-DevTools-MCP](https://github.com/syunnrai123/Edge-DevTools-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 执行工具 edge_get_targets 时发生错误: Error: 浏览器未连接`

### `tool-brave_navigate-basic-invocation` (1 finding)

**1. [brave-mcp-server](https://github.com/tamas54/brave-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Brave böngésző nem található. Állítsd be a BRAVE_PATH környezeti változót!`

### `tool-brave_marked_snapshot-basic-invocation` (1 finding)

**1. [brave-mcp-server](https://github.com/tamas54/brave-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Brave böngésző nem található. Állítsd be a BRAVE_PATH környezeti változót!`

### `tool-brave_scrape-basic-invocation` (1 finding)

**1. [brave-mcp-server](https://github.com/tamas54/brave-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Brave böngésző nem található. Állítsd be a BRAVE_PATH környezeti változót!`

### `tool-get_action_versions-basic-invocation` (1 finding)

**1. [mcp-github-actions-versions](https://github.com/tgrall/mcp-github-actions-versions)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Repository must be in format 'owner/repo'`

### `tool-get_latest_action_version-basic-invocation` (1 finding)

**1. [mcp-github-actions-versions](https://github.com/tgrall/mcp-github-actions-versions)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Repository must be in format 'owner/repo'`

### `tool-timescale_create_service-basic-invocation` (1 finding)

**1. [tigerdata-pulumi-mcp-server](https://github.com/thesurfingcoder/tigerdata-pulumi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Pulumi stack operation failed: Invalid workDir passed to local workspace: '/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/infra' does not exist`

### `tool-timescale_create_services-basic-invocation` (1 finding)

**1. [tigerdata-pulumi-mcp-server](https://github.com/thesurfingcoder/tigerdata-pulumi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Pulumi stack operation failed: Invalid workDir passed to local workspace: '/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/infra' does not exist`

### `tool-timescale_delete_service-basic-invocation` (1 finding)

**1. [tigerdata-pulumi-mcp-server](https://github.com/thesurfingcoder/tigerdata-pulumi-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Pulumi stack operation failed: Invalid workDir passed to local workspace: '/home/tecnico/Desktop/Pipeline/tool_mcp_check_w2/infra' does not exist`

### `tool-update_task_status-basic-invocation` (1 finding)

**1. [zihtasks-mcp](https://github.com/thiiz/zihtasks-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Projeto test não encontrado`

### `tool-venly_settle_invoice-basic-invocation` (1 finding)

**1. [venly-mcp-enterprise](https://github.com/timdierckxsens/venly-mcp-enterprise)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Treasury wallet not configured`

### `tool-venly_get_treasury_position-basic-invocation` (1 finding)

**1. [venly-mcp-enterprise](https://github.com/timdierckxsens/venly-mcp-enterprise)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Treasury wallet not configured`

### `tool-GetSingleAPIDetail-basic-invocation` (1 finding)

**1. [mcp-api-tester](https://github.com/tinymurky/mcp-api-tester)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: OpenAPI file hasn't read, please use "ReadOpenAPIDocument" tool to read file first `

### `tool-ListAllAPIFromDocument-basic-invocation` (1 finding)

**1. [mcp-api-tester](https://github.com/tinymurky/mcp-api-tester)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: OpenAPI file hasn't read, please use "ReadOpenAPIDocument" tool to read file first `

### `tool-ReadOpenAPIDocument-basic-invocation` (1 finding)

**1. [mcp-api-tester](https://github.com/tinymurky/mcp-api-tester)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Error happened when convert openAPI Binary to document from path: "test", error: spec type not supported by libopenapi, sorry`

### `tool-search_databases-basic-invocation` (1 finding)

**1. [notion-mcp-server](https://github.com/tonutoz/notion-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: NOTION_API_KEY not configured`

### `tool-get_page-basic-invocation` (1 finding)

**1. [notion-mcp-server](https://github.com/tonutoz/notion-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: NOTION_API_KEY not configured`

### `tool-retrieve_xsd-basic-invocation` (1 finding)

**1. [mcp-xsd-retreival](https://github.com/tudor44/mcp-xsd-retreival)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to retrieve XSD: Failed to retrieve XSD: Retrieved content does not appear to be valid XML/XSD`

### `tool-docker_deployer-basic-invocation` (1 finding)

**1. [go-mcp-docker](https://github.com/wahyurudiyan/go-mcp-docker)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: no actions specified`

### `tool-open_project-basic-invocation` (1 finding)

**1. [demo-mcp-server](https://github.com/xu1211/demo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to open directory: Command failed: xdg-open "test"
/usr/bin/xdg-open: 882: www-browser: not found
/usr/bin/xdg-open: 882: links2: not found
/usr/bin/xdg-open: 882: elinks: not found
/usr/bin/xdg-open: 882: links: not found
/usr/bin/xdg-open: 882: lynx: not found
/usr/bin/xdg-open: 882: w3m: not found
xdg-open: no method available for opening 'test'
`

### `tool-gmail_search_messages-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/yurifriedman/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No client_secret_*.json file found. Please download OAuth credentials from Google Cloud Console.`

### `tool-gmail_get_message-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/yurifriedman/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No client_secret_*.json file found. Please download OAuth credentials from Google Cloud Console.`

### `tool-gmail_send_message-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/yurifriedman/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No client_secret_*.json file found. Please download OAuth credentials from Google Cloud Console.`

### `tool-your_tool_here-basic-invocation` (1 finding)

**1. [mcp-boilerplate](https://github.com/zcaceres/mcp-boilerplate)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "object",
    "received": "undefined",
    "path": [
      "objectParameters"
    ],
    "message": "Required"
  }
]`

### `tool-get_available_models-basic-invocation` (1 finding)

**1. [mcp-image](https://github.com/mako10k/mcp-image)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: AI Image MCP server is not configured correctly. Ensure MODAL_JOB_API_URL (or JOB_API_SERVER_URL/JOBAPI_URL) is set before using this tool.`

### `tool-get_model_detail-basic-invocation` (1 finding)

**1. [mcp-image](https://github.com/mako10k/mcp-image)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: AI Image MCP server is not configured correctly. Ensure MODAL_JOB_API_URL (or JOB_API_SERVER_URL/JOBAPI_URL) is set before using this tool.`

### `tool-getSwaggerDefinition-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/tigawanna/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Failed to fetch Swagger definition: Invalid URL`

### `tool-fetch_confluence_page-basic-invocation` (1 finding)

**1. [fetch-mcp](https://github.com/h16rkim/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid url: must be a valid URL`

### `tool-fetch_jira_issue-basic-invocation` (1 finding)

**1. [fetch-mcp](https://github.com/h16rkim/fetch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid url: must be a valid URL`

### `tool-send-usage-basic-invocation` (1 finding)

**1. [ccusage-mcp-server](https://github.com/robb-lee/ccusage-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: N8N_WEBHOOK_URL is not configured. Please run with --setup flag or set it in your environment.`

### `tool-update_filter-basic-invocation` (1 finding)

**1. [playwright-min-network-mcp](https://github.com/bun913/playwright-min-network-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Network monitoring is not active. Use start_monitor first.`

### `tool-list_mailboxes-basic-invocation` (1 finding)

**1. [email-mcp](https://github.com/adamswanglin/email-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 缺少必要的IMAP配置。请检查环境变量: IMAP_HOST, EMAIL_USER, EMAIL_PASSWORD`

### `tool-test_connection-basic-invocation` (1 finding)

**1. [email-mcp](https://github.com/adamswanglin/email-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 缺少必要的IMAP配置。请检查环境变量: IMAP_HOST, EMAIL_USER, EMAIL_PASSWORD`

### `tool-create-object-basic-invocation` (1 finding)

**1. [parse-mcp-server](https://github.com/asaje379/parse-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Parse error: XMLHttpRequest failed: "You need to call Parse.initialize before using Parse."`

### `tool-get-object-basic-invocation` (1 finding)

**1. [parse-mcp-server](https://github.com/asaje379/parse-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Parse error: XMLHttpRequest failed: "You need to call Parse.initialize before using Parse."`

### `tool-update-object-basic-invocation` (1 finding)

**1. [parse-mcp-server](https://github.com/asaje379/parse-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Parse error: XMLHttpRequest failed: "You need to call Parse.initialize before using Parse."`

### `tool-get_config_file-basic-invocation` (1 finding)

**1. [klipper-config-mcp](https://github.com/grego33/klipper-config-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Cannot connect to Moonraker at localhost:7125. Is the printer running?`

### `tool-list_config_files-basic-invocation` (1 finding)

**1. [klipper-config-mcp](https://github.com/grego33/klipper-config-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Cannot connect to Moonraker at localhost:7125. Is the printer running?`

### `tool-parse_config-basic-invocation` (1 finding)

**1. [klipper-config-mcp](https://github.com/grego33/klipper-config-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Cannot connect to Moonraker at localhost:7125. Is the printer running?`

### `tool-send_wecom_message-basic-invocation` (1 finding)

**1. [wecombot-mcp](https://github.com/kedoupi/wecombot-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: WECOM_WEBHOOK_URL environment variable is required`

### `tool-search_icons-basic-invocation` (1 finding)

**1. [mcp-server-icon](https://github.com/liliangshan/mcp-server-icon)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Request error: API returned error: have_no_query`

### `tool-kubectl_search-basic-invocation` (1 finding)

**1. [mcp-server-kubernetes](https://github.com/raihan0824/mcp-server-kubernetes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error: Search failed: Failed to get namespaces: Error: Command failed: kubectl get namespaces -o name
/bin/sh: 1: kubectl: not found
`

### `tool-kubectl_cluster_overview-basic-invocation` (1 finding)

**1. [mcp-server-kubernetes](https://github.com/raihan0824/mcp-server-kubernetes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Cluster overview failed: Failed to get namespaces: Error: Command failed: kubectl get namespaces -o name
/bin/sh: 1: kubectl: not found
`

### `tool-get_youtube_transcript-basic-invocation` (1 finding)

**1. [youtube-summarizer-mcp-server](https://github.com/ryanmarc/youtube-summarizer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute get_youtube_transcript: Invalid YouTube URL. Please provide a valid YouTube video URL.`

### `tool-get_youtube_video_info-basic-invocation` (1 finding)

**1. [youtube-summarizer-mcp-server](https://github.com/ryanmarc/youtube-summarizer-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute get_youtube_video_info: Invalid YouTube URL. Please provide a valid YouTube video URL.`

### `tool-get_component_source-basic-invocation` (1 finding)

**1. [shadcn-ui-mcp-server](https://github.com/sherifbutt/shadcn-ui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Component "test" not found`

### `tool-get_component_metadata-basic-invocation` (1 finding)

**1. [shadcn-ui-mcp-server](https://github.com/sherifbutt/shadcn-ui-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Component "test" not found`

### `tool-create_item-basic-invocation` (1 finding)

**1. [mcp-knowledge-base](https://github.com/ShirokumaLibrary/mcp-knowledge-base)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: SQLITE_ERROR: no such table: items`

### `tool-get_item-basic-invocation` (1 finding)

**1. [mcp-knowledge-base](https://github.com/ShirokumaLibrary/mcp-knowledge-base)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: SQLITE_ERROR: no such table: items`

### `tool-update_item-basic-invocation` (1 finding)

**1. [mcp-knowledge-base](https://github.com/ShirokumaLibrary/mcp-knowledge-base)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: SQLITE_ERROR: no such table: items`

### `tool-set_project_context-basic-invocation` (1 finding)

**1. [softypm-mcp-server](https://github.com/techcyclist/softypm-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Failed to set project context: Failed to get project 50: Resource not found.`

### `tool-get_project_info-basic-invocation` (1 finding)

**1. [softypm-mcp-server](https://github.com/techcyclist/softypm-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No project context set. Use set_project_context first or provide project_id.`

### `tool-create_story-basic-invocation` (1 finding)

**1. [softypm-mcp-server](https://github.com/techcyclist/softypm-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: No project context set. Use set_project_context first or provide project_id.`

### `tool-coding_configure-basic-invocation` (1 finding)

**1. [coding-mcp](https://github.com/ForeverWorld/coding-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: 配置失败: API 连接验证失败，请检查配置`

### `tool-add_tool-basic-invocation` (1 finding)

**1. [diy-tools-mcp](https://github.com/hesreallyhim/diy-tools-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to add tool: Must specify either code or codePath`

### `tool-process_docx-basic-invocation` (1 finding)

**1. [DocxMCP](https://github.com/alephnull1678/DocxMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: File must be a .docx document`

### `tool-complete_auth-basic-invocation` (1 finding)

**1. [exactmcp](https://github.com/ArjandenHartog/exactmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Must authenticate first using the authenticate tool`

### `tool-get_sales_orders-basic-invocation` (1 finding)

**1. [exactmcp](https://github.com/ArjandenHartog/exactmcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Must authenticate first`

### `tool-create_file-basic-invocation` (1 finding)

**1. [filemanager-mcp-server](https://github.com/leemwood/filemanager-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 创建文件失败: EISDIR: illegal operation on a directory, open '/home/tecnico/Desktop/Frameworks/mcp-check/test'`

### `tool-generate_component-basic-invocation` (1 finding)

**1. [fomantic-mcp](https://github.com/fridzema/fomantic-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Unsupported component: test`

### `tool-mermaid-to-file-basic-invocation` (1 finding)

**1. [mcp-mermaid-img](https://github.com/gkctou/mcp-mermaid-img)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to save file: Download failed: Bad Request`

### `tool-mermaid-to-svg-basic-invocation` (1 finding)

**1. [mcp-mermaid-img](https://github.com/gkctou/mcp-mermaid-img)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to fetch SVG content: Failed to fetch SVG: Bad Request`

### `tool-get_document-basic-invocation` (1 finding)

**1. [misonote-mcp-client](https://github.com/leeguooooo/misonote-mcp-client)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: 工具执行失败: 获取文档失败: MCP_API_KEY 环境变量未设置。请在 Cursor 配置中设置此变量。`

### `tool-get_task-basic-invocation` (1 finding)

**1. [pyrus-mcp](https://github.com/staners2/pyrus-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: MCP error -32600: PYRUS_LOGIN environment variable is required`

### `tool-create_spartacus_component-basic-invocation` (1 finding)

**1. [spartacusMCP](https://github.com/aaalla-d/spartacusMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create component: ENOTDIR: not a directory, mkdir 'test/test'`

### `tool-generate_spartacus_service-basic-invocation` (1 finding)

**1. [spartacusMCP](https://github.com/aaalla-d/spartacusMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to create service: ENOTDIR: not a directory, mkdir 'test/test'`

### `tool-spartan_get_component-basic-invocation` (1 finding)

**1. [spartan-ng-mcp-server](https://github.com/paulschick/spartan-ng-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get Spartan NG component "test". Component "test" does not exist in the Spartan NG repository. Use the list components tool to see available components.`

### `tool-get_plugin_info-basic-invocation` (1 finding)

**1. [wordpress-org-mcp](https://github.com/juanma-wp/wordpress-org-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Plugin not found: test`

### `tool-download_plugin-basic-invocation` (1 finding)

**1. [wordpress-org-mcp](https://github.com/juanma-wp/wordpress-org-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Failed to download plugin: test`

## Interpretazione

Gli **other_errors** filtrati sono errori runtime che non rientrano nelle altre categorie. Dopo aver rimosso errori di setup/infrastruttura, rimangono errori applicativi potenzialmente interessanti.

