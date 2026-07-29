# tool_invocation/unauthorized_or_auth_missing - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 134 |
| Finding filtrati | 134 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 108 |
| python | 15 |
| go | 10 |
| unknown | 1 |

## Finding per tipo di test

### `tool-create_or_update_file-basic-invocation` (8 finding)

**1. [github-mcp-server](https://github.com/minimind-org/github-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**2. [mcp-github](https://github.com/tuanle96/mcp-github)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**3. [weather-mcp-server-typescript](https://github.com/codewith1984/weather-mcp-server-typescript)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**4. [server-github-mcp](https://github.com/195440/server-github-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**5. [google-calendar-mcp-server-py](https://github.com/jpcurada/google-calendar-mcp-server-py)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**6. [github-mcp-server-fork](https://github.com/madhav-07/github-mcp-server-fork)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**7. [mcp-github-server](https://github.com/s2005/mcp-github-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**8. [github-mcp-server-sse](https://github.com/yamagai/github-mcp-server-sse)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 認証トークンがありません。環境変数GITHUB_TOKENを設定するか、Authorizationヘッダーを指定してください`

### `tool-create_repository-basic-invocation` (7 finding)

**1. [github-mcp-server](https://github.com/minimind-org/github-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**2. [mcp-github](https://github.com/tuanle96/mcp-github)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**3. [weather-mcp-server-typescript](https://github.com/codewith1984/weather-mcp-server-typescript)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**4. [server-github-mcp](https://github.com/195440/server-github-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**5. [google-calendar-mcp-server-py](https://github.com/jpcurada/google-calendar-mcp-server-py)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**6. [github-mcp-server-fork](https://github.com/madhav-07/github-mcp-server-fork)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

**7. [mcp-github-server](https://github.com/s2005/mcp-github-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Requires authentication`

### `tool-generate_image-basic-invocation` (4 finding)

**1. [gemini-mcp-server](https://github.com/Garblesnarff/gemini-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32000: Error calling tool 'generate_image': Error generating image: Gemini image generation failed: [GoogleGenerativeAI Error]: Error fetching from https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent: [400 Bad Request] API key not valid. Please pass a valid API key. [{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type....`

**2. [Nano-Banana-MCP](https://github.com/ConechoAI/Nano-Banana-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

**3. [activitywatch-mcp](https://github.com/Auriora/activitywatch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

**4. [nano-banana-mcp-azure-blob](https://github.com/ctoicqtao/nano-banana-mcp-azure-blob)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

### `tool-linear_auth_callback-basic-invocation` (4 finding)

**1. [linear-mcp](https://github.com/cline/linear-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to handle authentication callback: MCP error -32603: OAuth token exchange failed: Token request failed: Bad Request. Response: {"error":"invalid_client","error_description":"Invalid client: client is invalid"}`

**2. [mcp](https://github.com/Refaerds/mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to handle authentication callback: MCP error -32603: OAuth token exchange failed: Token request failed: Bad Request. Response: {"error":"invalid_client","error_description":"Invalid client: client is invalid"}`

**3. [linear-mcp](https://github.com/locomotive-agency/linear-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to handle authentication callback: MCP error -32603: OAuth token exchange failed: Token request failed: Bad Request. Response: {"error":"invalid_client","error_description":"Invalid client: client is invalid"}`

**4. [linear-mcp](https://github.com/odgrim/linear-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to handle authentication callback: MCP error -32603: OAuth token exchange failed: Token request failed: Bad Request. Response: {"error":"invalid_client","error_description":"Invalid client: client is invalid"}`

### `tool-pluggedin_discover_tools-basic-invocation` (4 finding)

**1. [pluggedin-mcp](https://github.com/VeriTeknik/pluggedin-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for discovery trigger.`

**2. [pluggedin-mcp-proxy](https://github.com/VeriTeknik/pluggedin-mcp-proxy)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for discovery trigger.`

**3. [Economic-survey-2026](https://github.com/anirudhyadavMS/Economic-survey-2026)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for discovery trigger.`

**4. [writefreely-mcp-server](https://github.com/laxmena/writefreely-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for discovery trigger.`

### `tool-pluggedin_ask_knowledge_base-basic-invocation` (4 finding)

**1. [pluggedin-mcp](https://github.com/VeriTeknik/pluggedin-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for RAG query.`

**2. [pluggedin-mcp-proxy](https://github.com/VeriTeknik/pluggedin-mcp-proxy)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for RAG query.`

**3. [Economic-survey-2026](https://github.com/anirudhyadavMS/Economic-survey-2026)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for RAG query.`

**4. [writefreely-mcp-server](https://github.com/laxmena/writefreely-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Pluggedin API Key or Base URL is not configured for RAG query.`

### `tool-get_event-basic-invocation` (3 finding)

**1. [sonic-mcp-server](https://github.com/mcscribble/sonic-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Authentication token is required. Set SONIC_API_TOKEN environment variable or pass token in arguments.`

**2. [gru-sandbox](https://github.com/babelcloud/gru-sandbox)** (unknown)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

**3. [eventbrite-mcp-server](https://github.com/joshuachestang/eventbrite-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

### `tool-create_event-basic-invocation` (3 finding)

**1. [sonic-mcp-server](https://github.com/mcscribble/sonic-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Authentication token is required. Set SONIC_API_TOKEN environment variable or pass token in arguments.`

**2. [gru-sandbox](https://github.com/babelcloud/gru-sandbox)** (unknown)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

**3. [eventbrite-mcp-server](https://github.com/joshuachestang/eventbrite-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

### `tool-get_current_user-basic-invocation` (3 finding)

**1. [Replit-MCP](https://github.com/NOVA-3951/Replit-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: REPLIT_TOKEN environment variable is not set. Please provide your Replit connect.sid token.`

**2. [alibabacloud-devops-mcp-server](https://github.com/aliyun/alibabacloud-devops-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

**3. [linear-mcp-server](https://github.com/efabien/linear-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

### `tool-list_portals-basic-invocation` (3 finding)

**1. [Office-Visio-MCP-Server](https://github.com/GongRzhe/Office-Visio-MCP-Server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**2. [zoho-projects-mcp](https://github.com/qpiai/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**3. [zoho-projects-mcp](https://github.com/andrewcraigmorgan/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

### `tool-get_portal-basic-invocation` (3 finding)

**1. [Office-Visio-MCP-Server](https://github.com/GongRzhe/Office-Visio-MCP-Server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**2. [zoho-projects-mcp](https://github.com/qpiai/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**3. [zoho-projects-mcp](https://github.com/andrewcraigmorgan/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

### `tool-list_projects-basic-invocation` (3 finding)

**1. [Office-Visio-MCP-Server](https://github.com/GongRzhe/Office-Visio-MCP-Server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**2. [zoho-projects-mcp](https://github.com/qpiai/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

**3. [zoho-projects-mcp](https://github.com/andrewcraigmorgan/zoho-projects-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Zoho access token not configured. Set ZOHO_ACCESS_TOKEN environment variable.`

### `tool-get_github_actions-basic-invocation` (3 finding)

**1. [github-action-trigger-mcp](https://github.com/nextDriveIoE/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Actions: GitHub API error: 401 Unauthorized - Bad credentials`

**2. [SimpleMCPSearchServer](https://github.com/MartinSchlott/SimpleMCPSearchServer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Actions: GitHub API error: 401 Unauthorized - Bad credentials`

**3. [github-action-trigger-mcp](https://github.com/fastmcp-me/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Actions: GitHub API error: 401 Unauthorized - Bad credentials`

### `tool-get_github_action-basic-invocation` (3 finding)

**1. [github-action-trigger-mcp](https://github.com/nextDriveIoE/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Action details: GitHub API error: 401 Unauthorized - Bad credentials`

**2. [SimpleMCPSearchServer](https://github.com/MartinSchlott/SimpleMCPSearchServer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Action details: GitHub API error: 401 Unauthorized - Bad credentials`

**3. [github-action-trigger-mcp](https://github.com/fastmcp-me/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to get GitHub Action details: GitHub API error: 401 Unauthorized - Bad credentials`

### `tool-trigger_github_action-basic-invocation` (3 finding)

**1. [github-action-trigger-mcp](https://github.com/nextDriveIoE/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to trigger GitHub Action: Authentication failed: Bad credentials. Make sure your token has the 'workflow' scope.`

**2. [SimpleMCPSearchServer](https://github.com/MartinSchlott/SimpleMCPSearchServer)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to trigger GitHub Action: Authentication failed: Bad credentials. Make sure your token has the 'workflow' scope.`

**3. [github-action-trigger-mcp](https://github.com/fastmcp-me/github-action-trigger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to trigger GitHub Action: Authentication failed: Bad credentials. Make sure your token has the 'workflow' scope.`

### `tool-edit_image-basic-invocation` (3 finding)

**1. [Nano-Banana-MCP](https://github.com/ConechoAI/Nano-Banana-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to edit image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

**2. [activitywatch-mcp](https://github.com/Auriora/activitywatch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to edit image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

**3. [nano-banana-mcp-azure-blob](https://github.com/ctoicqtao/nano-banana-mcp-azure-blob)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to edit image: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

### `tool-get_issues-basic-invocation` (3 finding)

**1. [gitlab-mcp](https://github.com/ttpears/gitlab-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

**2. [mcp-weather-alert-tool](https://github.com/nahilahmed/mcp-weather-alert-tool)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

**3. [jira-mcp](https://github.com/ahmetbarut/jira-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing Jira configuration. Please set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.`

### `initialization` (3 finding)

**1. [wpcom-mcp-bundle](https://github.com/Automattic/wpcom-mcp-bundle)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: No authentication method available. Please configure JWT_TOKEN, OAuth, Basic Auth (WP_API_USERNAME+WP_API_PASSWORD), or CUSTOM_HEADERS.`

**2. [mcp-proxy-hub](https://github.com/naotaka3/mcp-proxy-hub)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**3. [apis-mcp](https://github.com/Synergy-Shock/apis-mcp)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `tool-publish_linkedin_post-basic-invocation` (2 finding)

**1. [linkedin-mcp-runner](https://github.com/ertiqah/linkedin-mcp-runner)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

**2. [azsap-mcp](https://github.com/architectravi/azsap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

### `tool-schedule_linkedin_post-basic-invocation` (2 finding)

**1. [linkedin-mcp-runner](https://github.com/ertiqah/linkedin-mcp-runner)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

**2. [azsap-mcp](https://github.com/architectravi/azsap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

### `tool-publish_twitter_post-basic-invocation` (2 finding)

**1. [linkedin-mcp-runner](https://github.com/ertiqah/linkedin-mcp-runner)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

**2. [azsap-mcp](https://github.com/architectravi/azsap-mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32001: Server Configuration Error: API Key not set.`

### `tool-anytype_list_spaces-basic-invocation` (2 finding)

**1. [mcp-anytype](https://github.com/cryptonahue/mcp-anytype)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

**2. [mcp-chatbot-client](https://github.com/jorgegoco/mcp-chatbot-client)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

### `tool-anytype_get_space-basic-invocation` (2 finding)

**1. [mcp-anytype](https://github.com/cryptonahue/mcp-anytype)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

**2. [mcp-chatbot-client](https://github.com/jorgegoco/mcp-chatbot-client)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

### `tool-anytype_create_space-basic-invocation` (2 finding)

**1. [mcp-anytype](https://github.com/cryptonahue/mcp-anytype)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

**2. [mcp-chatbot-client](https://github.com/jorgegoco/mcp-chatbot-client)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set ANYTYPE_API_KEY environment variable.`

### `tool-list_events-basic-invocation` (2 finding)

**1. [gru-sandbox](https://github.com/babelcloud/gru-sandbox)** (unknown)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

**2. [eventbrite-mcp-server](https://github.com/joshuachestang/eventbrite-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Eventbrite API key not configured. Please set EVENTBRITE_API_KEY environment variable.`

### `tool-list_mailboxes-basic-invocation` (2 finding)

**1. [fastmail-mcp](https://github.com/MadLlama25/fastmail-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

**2. [hubspot-web-editor-MCP](https://github.com/andrewodonnell10/hubspot-web-editor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

### `tool-get_mailbox_by_name-basic-invocation` (2 finding)

**1. [fastmail-mcp](https://github.com/MadLlama25/fastmail-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

**2. [hubspot-web-editor-MCP](https://github.com/andrewodonnell10/hubspot-web-editor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

### `tool-create_mailbox-basic-invocation` (2 finding)

**1. [fastmail-mcp](https://github.com/MadLlama25/fastmail-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

**2. [hubspot-web-editor-MCP](https://github.com/andrewodonnell10/hubspot-web-editor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FASTMAIL_API_TOKEN environment variable is required`

### `tool-getAllAddresses-basic-invocation` (2 finding)

**1. [mews-mcp](https://github.com/code-rabi/mews-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/mirelyrp14/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

### `tool-addAddresses-basic-invocation` (2 finding)

**1. [mews-mcp](https://github.com/code-rabi/mews-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/mirelyrp14/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

### `tool-getAllCustomers-basic-invocation` (2 finding)

**1. [mews-mcp](https://github.com/code-rabi/mews-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/mirelyrp14/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Invalid Mews configuration. Please set MEWS_CLIENT_TOKEN, MEWS_ACCESS_TOKEN environment variables. [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "clientToken"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "accessToken"
    ],
    "message": "Required"
  }
]`

### `tool-search_meetings-basic-invocation` (2 finding)

**1. [fellow-mcp](https://github.com/liba2k/fellow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

**2. [skills-integrate-mcp-with-copilot](https://github.com/jefeish/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

### `tool-get_meeting_transcript-basic-invocation` (2 finding)

**1. [fellow-mcp](https://github.com/liba2k/fellow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

**2. [skills-integrate-mcp-with-copilot](https://github.com/jefeish/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

### `tool-get_meeting_summary-basic-invocation` (2 finding)

**1. [fellow-mcp](https://github.com/liba2k/fellow-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

**2. [skills-integrate-mcp-with-copilot](https://github.com/jefeish/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: API key required: use --api-key <key> or set FELLOW_API_KEY env var`

### `tool-search-basic-invocation` (2 finding)

**1. [combine-mcp](https://github.com/nazar256/combine-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

**2. [google-drive-mcp](https://github.com/piotr-agier/google-drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

### `tool-createTextFile-basic-invocation` (2 finding)

**1. [combine-mcp](https://github.com/nazar256/combine-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

**2. [google-drive-mcp](https://github.com/piotr-agier/google-drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

### `tool-updateTextFile-basic-invocation` (2 finding)

**1. [combine-mcp](https://github.com/nazar256/combine-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

**2. [google-drive-mcp](https://github.com/piotr-agier/google-drive-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Error loading OAuth keys: OAuth credentials not found. Please provide credentials using one of these methods:

1. Config directory (recommended):
   Place your gcp-oauth.keys.json file in: /home/tecnico/.config/google-drive-mcp/

2. Environment variable:
   Set GOOGLE_DRIVE_OAUTH_CREDENTIALS to the path of your credentials file:
   export GOOGLE_DRIVE_OAUTH_CREDENTIALS="/path/to/gcp-oauth.keys.json"

Token storage:
- Tokens are saved to: /home/tecnico/.config/google-drive-mcp/t...`

### `tool-figma_list_frames-basic-invocation` (2 finding)

**1. [kortx-mcp](https://github.com/effatico/kortx-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

**2. [figma-mcp-server](https://github.com/zhaojian2626/figma-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

### `tool-figma_download_and_simplify-basic-invocation` (2 finding)

**1. [kortx-mcp](https://github.com/effatico/kortx-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

**2. [figma-mcp-server](https://github.com/zhaojian2626/figma-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

### `tool-figma_download_images-basic-invocation` (2 finding)

**1. [kortx-mcp](https://github.com/effatico/kortx-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

**2. [figma-mcp-server](https://github.com/zhaojian2626/figma-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma accessToken is required. Please configure it in config.json, environment variable FIGMA_ACCESS_TOKEN, or provide via HTTP header X-Figma-Access-Token.`

### `tool-list_containers-basic-invocation` (2 finding)

**1. [mcp-demo](https://github.com/anilsharmay/mcp-demo)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Jindacloud API Key not set`

**2. [mcp-server-jindacloud](https://github.com/neter-aa/mcp-server-jindacloud)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Jindacloud API Key not set`

### `tool-get_seismic_data-basic-invocation` (2 finding)

**1. [mcp_server_ipma](https://github.com/brandao-20/mcp_server_ipma)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Erro ao obter dados sísmicos: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**2. [ipma-mcp-server](https://github.com/DiogoAzevedo03/ipma-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Erro ao obter dados sísmicos: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `tool-generate_ai_image-basic-invocation` (2 finding)

**1. [image-mcp](https://github.com/iplanwebsites/image-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

**2. [infomentor_mcp](https://github.com/villaume/infomentor_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

### `tool-square_image-basic-invocation` (2 finding)

**1. [image-mcp](https://github.com/iplanwebsites/image-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

**2. [infomentor_mcp](https://github.com/villaume/infomentor_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

### `tool-landscape_image-basic-invocation` (2 finding)

**1. [image-mcp](https://github.com/iplanwebsites/image-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

**2. [infomentor_mcp](https://github.com/villaume/infomentor_mcp)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to generate image with library: [AI-IMAGE] API key for openai not found. Please provide it via parameter or environment variable.`

### `tool-search_pixabay_images-basic-invocation` (2 finding)

**1. [pixabay-mcp](https://github.com/zym9863/pixabay-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Pixabay API key (PIXABAY_API_KEY) is not configured in the environment.`

**2. [weather-mcp-server](https://github.com/nesheep5/weather-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Pixabay API key (PIXABAY_API_KEY) is not configured in the environment.`

### `tool-search_pixabay_videos-basic-invocation` (2 finding)

**1. [pixabay-mcp](https://github.com/zym9863/pixabay-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Pixabay API key (PIXABAY_API_KEY) is not configured in the environment.`

**2. [weather-mcp-server](https://github.com/nesheep5/weather-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Pixabay API key (PIXABAY_API_KEY) is not configured in the environment.`

### `tool-get_project-basic-invocation` (2 finding)

**1. [gitlab-mcp](https://github.com/ttpears/gitlab-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

**2. [mcp-weather-alert-tool](https://github.com/nahilahmed/mcp-weather-alert-tool)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

### `tool-get_merge_requests-basic-invocation` (2 finding)

**1. [gitlab-mcp](https://github.com/ttpears/gitlab-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

**2. [mcp-weather-alert-tool](https://github.com/nahilahmed/mcp-weather-alert-tool)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: This operation requires authentication. Configure GITLAB_TOKEN, GITLAB_READ_TOKEN, or pass per-call user credentials.`

### `tool-geocode-basic-invocation` (2 finding)

**1. [tinify-mcp](https://github.com/Alvinnn1/tinify-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

**2. [quantaroute-geocoder](https://github.com/mapdevsaikat/quantaroute-geocoder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

### `tool-reverse_geocode-basic-invocation` (2 finding)

**1. [tinify-mcp](https://github.com/Alvinnn1/tinify-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

**2. [quantaroute-geocoder](https://github.com/mapdevsaikat/quantaroute-geocoder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

### `tool-coordinates_to_digipin-basic-invocation` (2 finding)

**1. [tinify-mcp](https://github.com/Alvinnn1/tinify-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

**2. [quantaroute-geocoder](https://github.com/mapdevsaikat/quantaroute-geocoder)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: API key is required. Provide it via Authorization header (Bearer token) or x-api-key header.`

### `tool-get_weather-basic-invocation` (2 finding)

**1. [mcp-agent-ts](https://github.com/Aystar09140/mcp-agent-ts)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: OpenWeather API key not configured`

**2. [node-red-nodes](https://github.com/node-red/node-red-nodes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: OpenWeather API key not configured`

### `tool-get_news-basic-invocation` (2 finding)

**1. [mcp-agent-ts](https://github.com/Aystar09140/mcp-agent-ts)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: News API key not configured`

**2. [node-red-nodes](https://github.com/node-red/node-red-nodes)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: News API key not configured`

### `tool-getDraft-basic-invocation` (2 finding)

**1. [pitstop](https://github.com/praneethravuri/pitstop)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**2. [hashnode-mcp](https://github.com/rawveg/hashnode-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `tool-getPost-basic-invocation` (2 finding)

**1. [pitstop](https://github.com/praneethravuri/pitstop)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**2. [hashnode-mcp](https://github.com/rawveg/hashnode-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `tool-createDraft-basic-invocation` (2 finding)

**1. [pitstop](https://github.com/praneethravuri/pitstop)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

**2. [hashnode-mcp](https://github.com/rawveg/hashnode-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unexpected token '<', "<!DOCTYPE "... is not valid JSON`

### `tool-web_search_chat_completion-basic-invocation` (2 finding)

**1. [zai-mcp-server](https://github.com/groxaxo/zai-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Web search chat completion error: OpenAI API Error: 401 - {
    "error": {
        "message": "Incorrect API key provided: undefined. You can find your API key at https://platform.openai.com/account/api-keys.",
        "type": "invalid_request_error",
        "param": null,
        "code": "invalid_api_key"
    }
}
`

**2. [openai-websearch-mcp](https://github.com/minimumdaan/openai-websearch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Web search chat completion error: OpenAI API Error: 401 - {
    "error": {
        "message": "Incorrect API key provided: undefined. You can find your API key at https://platform.openai.com/account/api-keys.",
        "type": "invalid_request_error",
        "param": null,
        "code": "invalid_api_key"
    }
}
`

### `tool-web_search_responses-basic-invocation` (2 finding)

**1. [zai-mcp-server](https://github.com/groxaxo/zai-mcp-server)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: Web search responses error: OpenAI API Error: 401 - {
  "error": {
    "message": "Incorrect API key provided: undefined. You can find your API key at https://platform.openai.com/account/api-keys.",
    "type": "invalid_request_error",
    "param": null,
    "code": "invalid_api_key"
  }
}`

**2. [openai-websearch-mcp](https://github.com/minimumdaan/openai-websearch-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Web search responses error: OpenAI API Error: 401 - {
  "error": {
    "message": "Incorrect API key provided: undefined. You can find your API key at https://platform.openai.com/account/api-keys.",
    "type": "invalid_request_error",
    "param": null,
    "code": "invalid_api_key"
  }
}`

### `tool-get_current_organization_info-basic-invocation` (2 finding)

**1. [alibabacloud-devops-mcp-server](https://github.com/aliyun/alibabacloud-devops-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

**2. [linear-mcp-server](https://github.com/efabien/linear-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

### `tool-get_user_organizations-basic-invocation` (2 finding)

**1. [alibabacloud-devops-mcp-server](https://github.com/aliyun/alibabacloud-devops-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

**2. [linear-mcp-server](https://github.com/efabien/linear-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Yunxiao API error (401): Invalid token.
 Full Response: {
  "message": "Invalid token."
}`

### `tool-coolify_application_management-basic-invocation` (2 finding)

**1. [coolify-mcp-server](https://github.com/GoCoder7/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/hmoreno82/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

### `tool-coolify_environment_configuration-basic-invocation` (2 finding)

**1. [coolify-mcp-server](https://github.com/GoCoder7/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/hmoreno82/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

### `tool-coolify_system_management-basic-invocation` (2 finding)

**1. [coolify-mcp-server](https://github.com/GoCoder7/coolify-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

**2. [skills-integrate-mcp-with-copilot](https://github.com/hmoreno82/skills-integrate-mcp-with-copilot)** (python)
- Type: `InvocationError`
- Message: `MCP error -32603: [
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_BASE_URL"
    ],
    "message": "Required"
  },
  {
    "code": "invalid_type",
    "expected": "string",
    "received": "undefined",
    "path": [
      "COOLIFY_API_TOKEN"
    ],
    "message": "Required"
  }
]`

### `tool-comment_enterprise_issue-basic-invocation` (2 finding)

**1. [mcp-gitee-ent](https://github.com/oschina/mcp-gitee-ent)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

**2. [mcp-mercury](https://github.com/dennisonbertram/mcp-mercury)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-comment_enterprise_pull-basic-invocation` (2 finding)

**1. [mcp-gitee-ent](https://github.com/oschina/mcp-gitee-ent)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

**2. [mcp-mercury](https://github.com/dennisonbertram/mcp-mercury)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-create_enterprise_issue-basic-invocation` (2 finding)

**1. [mcp-gitee-ent](https://github.com/oschina/mcp-gitee-ent)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

**2. [mcp-mercury](https://github.com/dennisonbertram/mcp-mercury)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-write_note-basic-invocation` (2 finding)

**1. [mcp-server-inbox](https://github.com/maoruibin/mcp-server-inbox)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: inBox token or URL not set. Please provide it via:
1. Token format: --inbox_user_token=your_token
2. URL format: --inbox_user_token=https://inbox.gudong.site/api/inbox/your_token`

**2. [vue-to-react-mcp](https://github.com/jianger666/vue-to-react-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: inBox token or URL not set. Please provide it via:
1. Token format: --inbox_user_token=your_token
2. URL format: --inbox_user_token=https://inbox.gudong.site/api/inbox/your_token`

### `tool-gdrive_search-basic-invocation` (1 finding)

**1. [mcp-gdrive](https://github.com/General-Intelligence-Labs/mcp-gdrive)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

### `tool-gdrive_read_file-basic-invocation` (1 finding)

**1. [mcp-gdrive](https://github.com/General-Intelligence-Labs/mcp-gdrive)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error 403: Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.`

### `tool-get_token_info-basic-invocation` (1 finding)

**1. [deai-api-mcp-server](https://github.com/decenterailab/deai-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API_KEY environment variable is required. Set it with your DeAI API key.`

### `tool-get_top_holders-basic-invocation` (1 finding)

**1. [deai-api-mcp-server](https://github.com/decenterailab/deai-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API_KEY environment variable is required. Set it with your DeAI API key.`

### `tool-get_token_holder_balance_changes-basic-invocation` (1 finding)

**1. [deai-api-mcp-server](https://github.com/decenterailab/deai-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API_KEY environment variable is required. Set it with your DeAI API key.`

### `tool-create-room-basic-invocation` (1 finding)

**1. [embedded-api-mcp-server](https://github.com/digitalsamba/embedded-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set DIGITAL_SAMBA_DEVELOPER_KEY or provide via authentication.`

### `tool-update-room-basic-invocation` (1 finding)

**1. [embedded-api-mcp-server](https://github.com/digitalsamba/embedded-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set DIGITAL_SAMBA_DEVELOPER_KEY or provide via authentication.`

### `tool-delete-room-basic-invocation` (1 finding)

**1. [embedded-api-mcp-server](https://github.com/digitalsamba/embedded-api-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not configured. Set DIGITAL_SAMBA_DEVELOPER_KEY or provide via authentication.`

### `tool-generate_audio-basic-invocation` (1 finding)

**1. [mcp-minimax-music-server](https://github.com/falahgs/mcp-minimax-music-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: API key not found. Please provide it in claude_desktop_config.json or as a parameter`

### `tool-get_events-basic-invocation` (1 finding)

**1. [sonic-mcp-server](https://github.com/mcscribble/sonic-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Authentication token is required. Set SONIC_API_TOKEN environment variable or pass token in arguments.`

### `tool-create_note-basic-invocation` (1 finding)

**1. [evernote_mcp](https://github.com/sqrel/evernote_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Evernote API key not configured`

### `tool-search_notes-basic-invocation` (1 finding)

**1. [evernote_mcp](https://github.com/sqrel/evernote_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Evernote API key not configured`

### `tool-get_note-basic-invocation` (1 finding)

**1. [evernote_mcp](https://github.com/sqrel/evernote_mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Evernote API key not configured`

### `tool-get_backlinks-basic-invocation` (1 finding)

**1. [fetchserp-mcp-server-node](https://github.com/fastmcp-me/fetchserp-mcp-server-node)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FETCHSERP_API_TOKEN is required`

### `tool-get_domain_emails-basic-invocation` (1 finding)

**1. [fetchserp-mcp-server-node](https://github.com/fastmcp-me/fetchserp-mcp-server-node)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FETCHSERP_API_TOKEN is required`

### `tool-get_domain_info-basic-invocation` (1 finding)

**1. [fetchserp-mcp-server-node](https://github.com/fastmcp-me/fetchserp-mcp-server-node)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: FETCHSERP_API_TOKEN is required`

### `tool-search_mcp_server-basic-invocation` (1 finding)

**1. [mcp-easy-installer-amazonq-cli](https://github.com/bonjourzzz/mcp-easy-installer-amazonq-cli)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: GitHub token not found in environment. Please set GITHUB_TOKEN in your MCP server config.`

### `tool-get_accounts-basic-invocation` (1 finding)

**1. [QuestradeMCP](https://github.com/zachmelin/QuestradeMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Missing refresh token. Either set QUESTRADE_REFRESH_TOKEN environment variable or ensure token file exists. Get your token from Questrade API Centre -> Generate new token`

### `tool-get_positions-basic-invocation` (1 finding)

**1. [QuestradeMCP](https://github.com/zachmelin/QuestradeMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Missing refresh token. Either set QUESTRADE_REFRESH_TOKEN environment variable or ensure token file exists. Get your token from Questrade API Centre -> Generate new token`

### `tool-get_balances-basic-invocation` (1 finding)

**1. [QuestradeMCP](https://github.com/zachmelin/QuestradeMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: Missing refresh token. Either set QUESTRADE_REFRESH_TOKEN environment variable or ensure token file exists. Get your token from Questrade API Centre -> Generate new token`

### `tool-list_models-basic-invocation` (1 finding)

**1. [model-hub-mcp](https://github.com/akiojin/model-hub-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: OpenAI API key not configured`

### `tool-get_model-basic-invocation` (1 finding)

**1. [model-hub-mcp](https://github.com/akiojin/model-hub-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: OpenAI API key not configured`

### `tool-list_repls-basic-invocation` (1 finding)

**1. [Replit-MCP](https://github.com/NOVA-3951/Replit-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: REPLIT_TOKEN environment variable is not set. Please provide your Replit connect.sid token.`

### `tool-get_repl_by_url-basic-invocation` (1 finding)

**1. [Replit-MCP](https://github.com/NOVA-3951/Replit-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: REPLIT_TOKEN environment variable is not set. Please provide your Replit connect.sid token.`

### `tool-get_budgets-basic-invocation` (1 finding)

**1. [ynab-mcpb](https://github.com/mbmccormick/ynab-mcpb)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: YNAB_API_TOKEN environment variable is required. Please configure your API token in Claude Desktop settings. Get your personal access token from https://app.ynab.com/settings/developer`

### `tool-get_budget-basic-invocation` (1 finding)

**1. [ynab-mcpb](https://github.com/mbmccormick/ynab-mcpb)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: YNAB_API_TOKEN environment variable is required. Please configure your API token in Claude Desktop settings. Get your personal access token from https://app.ynab.com/settings/developer`

### `tool-get_budget_settings-basic-invocation` (1 finding)

**1. [ynab-mcpb](https://github.com/mbmccormick/ynab-mcpb)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: MCP error -32600: YNAB_API_TOKEN environment variable is required. Please configure your API token in Claude Desktop settings. Get your personal access token from https://app.ynab.com/settings/developer`

### `tool-generate_guest_access_token-basic-invocation` (1 finding)

**1. [miaw-mcp-server](https://github.com/skyrmionz/miaw-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32600: Tool generate_guest_access_token has an output schema but did not return structured content`

### `tool-list_assets-basic-invocation` (1 finding)

**1. [air-mcp](https://github.com/binalyze/air-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: AIR_API_TOKEN not provided. Please configure the MCP server with a valid airApiToken to execute tools.`

### `tool-get_asset_by_id-basic-invocation` (1 finding)

**1. [air-mcp](https://github.com/binalyze/air-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: AIR_API_TOKEN not provided. Please configure the MCP server with a valid airApiToken to execute tools.`

### `tool-get_asset_tasks_by_id-basic-invocation` (1 finding)

**1. [air-mcp](https://github.com/binalyze/air-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: AIR_API_TOKEN not provided. Please configure the MCP server with a valid airApiToken to execute tools.`

### `tool-upload_document-basic-invocation` (1 finding)

**1. [handwriting-ocr-mcp-server](https://github.com/Handwriting-OCR/handwriting-ocr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API_TOKEN environment variable is required`

### `tool-check_status-basic-invocation` (1 finding)

**1. [handwriting-ocr-mcp-server](https://github.com/Handwriting-OCR/handwriting-ocr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API_TOKEN environment variable is required`

### `tool-get_text-basic-invocation` (1 finding)

**1. [handwriting-ocr-mcp-server](https://github.com/Handwriting-OCR/handwriting-ocr-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API_TOKEN environment variable is required`

### `tool-pumble_validate_api_key-basic-invocation` (1 finding)

**1. [pumble-mcp-server](https://github.com/shoutkol/pumble-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key not configured. Please initialize the server with an API key.`

### `tool-pumble_send_message-basic-invocation` (1 finding)

**1. [pumble-mcp-server](https://github.com/shoutkol/pumble-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key not configured. Please initialize the server with an API key.`

### `tool-pumble_send_reply-basic-invocation` (1 finding)

**1. [pumble-mcp-server](https://github.com/shoutkol/pumble-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: API key not configured. Please initialize the server with an API key.`

### `tool-get_user_projects-basic-invocation` (1 finding)

**1. [ticktick-mcp-server](https://github.com/alexarevalo9/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Authentication failed`

### `tool-get_project_by_id-basic-invocation` (1 finding)

**1. [ticktick-mcp-server](https://github.com/alexarevalo9/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Authentication failed`

### `tool-get_project_with_data-basic-invocation` (1 finding)

**1. [ticktick-mcp-server](https://github.com/alexarevalo9/ticktick-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication Failed: Authentication failed`

### `tool-appknox_whoami-basic-invocation` (1 finding)

**1. [appknox-mcp](https://github.com/appknox/appknox-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication failed. Please set APPKNOX_ACCESS_TOKEN environment variable or configure it using: appknox init`

### `tool-appknox_organizations-basic-invocation` (1 finding)

**1. [appknox-mcp](https://github.com/appknox/appknox-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication failed. Please set APPKNOX_ACCESS_TOKEN environment variable or configure it using: appknox init`

### `tool-appknox_projects-basic-invocation` (1 finding)

**1. [appknox-mcp](https://github.com/appknox/appknox-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication failed. Please set APPKNOX_ACCESS_TOKEN environment variable or configure it using: appknox init`

### `tool-get_me-basic-invocation` (1 finding)

**1. [Famulor-MCP](https://github.com/bekservice/Famulor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication not configured. Get an API key at https://app.famulor.de/api-keys and connect this MCP server via OAuth.`

### `tool-get_assistants-basic-invocation` (1 finding)

**1. [Famulor-MCP](https://github.com/bekservice/Famulor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication not configured. Get an API key at https://app.famulor.de/api-keys and connect this MCP server via OAuth.`

### `tool-get_outbound_assistants-basic-invocation` (1 finding)

**1. [Famulor-MCP](https://github.com/bekservice/Famulor-MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Authentication not configured. Get an API key at https://app.famulor.de/api-keys and connect this MCP server via OAuth.`

### `tool-send-message-basic-invocation` (1 finding)

**1. [Claude_Desktop_API_USE_VIA_MCP](https://github.com/mlobo2012/Claude_Desktop_API_USE_VIA_MCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Could not resolve authentication method. Expected one of apiKey, authToken, credentials, config, or profile to be set. Or for one of the "X-Api-Key" or "Authorization" headers to be explicitly omitted`

### `tool-group-text-by-json-basic-invocation` (1 finding)

**1. [custom-context-mcp](https://github.com/omer-ayhan/custom-context-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to process template: Error: Invalid template format: SyntaxError: Unexpected token 'e', "test" is not valid JSON`

### `tool-text-to-json-basic-invocation` (1 finding)

**1. [custom-context-mcp](https://github.com/omer-ayhan/custom-context-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Failed to process template: SyntaxError: Unexpected token 'e', "test" is not valid JSON`

### `tool-exportFullFile-basic-invocation` (1 finding)

**1. [mcp-figma](https://github.com/wyvern800/mcp-figma)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma API token is required. Provide it as 'token' parameter or set FIGMA_API_TOKEN environment variable.`

### `tool-exportPages-basic-invocation` (1 finding)

**1. [mcp-figma](https://github.com/wyvern800/mcp-figma)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma API token is required. Provide it as 'token' parameter or set FIGMA_API_TOKEN environment variable.`

### `tool-exportPageFrames-basic-invocation` (1 finding)

**1. [mcp-figma](https://github.com/wyvern800/mcp-figma)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Figma API token is required. Provide it as 'token' parameter or set FIGMA_API_TOKEN environment variable.`

### `tool-list_code_scanning_alerts-basic-invocation` (1 finding)

**1. [ghas-mcp-server](https://github.com/rajbos/ghas-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GITHUB_PERSONAL_ACCESS_TOKEN is not set in environment variables. This is needed to be able to find code scanning alerts.`

### `tool-list_secret_scanning_alerts-basic-invocation` (1 finding)

**1. [ghas-mcp-server](https://github.com/rajbos/ghas-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GITHUB_PERSONAL_ACCESS_TOKEN is not set in environment variables. This is needed to be able to find code scanning alerts.`

### `tool-list_dependabot_alerts-basic-invocation` (1 finding)

**1. [ghas-mcp-server](https://github.com/rajbos/ghas-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: GITHUB_PERSONAL_ACCESS_TOKEN is not set in environment variables. This is needed to be able to find code scanning alerts.`

### `tool-ha_conversation-basic-invocation` (1 finding)

**1. [mcp-for-ha-conversation](https://github.com/goxofy/mcp-for-ha-conversation)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Home Assistant configuration not provided. Please set HOME_ASSISTANT_URL and HOME_ASSISTANT_TOKEN environment variables.`

### `tool-list-my-spaces-basic-invocation` (1 finding)

**1. [huggingface-mcp](https://github.com/samihalawa/huggingface-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: HuggingFace API token is required for this operation`

### `tool-fetch_token_balance-basic-invocation` (1 finding)

**1. [web3-mcp-server](https://github.com/EmanuelJr/web3-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Invalid input: [{"origin":"string","code":"invalid_format","format":"starts_with","prefix":"0x","path":["tokenAddress"],"message":"Invalid string: must start with \"0x\""},{"origin":"string","code":"invalid_format","format":"starts_with","prefix":"0x","path":["walletAddress"],"message":"Invalid string: must start with \"0x\""}]`

### `tool-payware_authentication_create_jwt_token-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/payware/mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Error executing tool payware_authentication_create_jwt_token: Partner ID is required. Provide via 'partnerId' parameter or set PAYWARE_PARTNER_ID environment variable.`

### `tool-trace_execution_path-basic-invocation` (1 finding)

**1. [deep-code-reasoning-mcp](https://github.com/haasonsaas/deep-code-reasoning-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: External API error: [GoogleGenerativeAI Error]: Error fetching from https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro-preview-06-05:generateContent: [400 Bad Request] API key not valid. Please pass a valid API key. [{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","lo...`

### `tool-hypothesis_test-basic-invocation` (1 finding)

**1. [deep-code-reasoning-mcp](https://github.com/haasonsaas/deep-code-reasoning-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: External API error: [GoogleGenerativeAI Error]: Error fetching from https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro-preview-06-05:generateContent: [400 Bad Request] API key not valid. Please pass a valid API key. [{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","lo...`

### `tool-azure_cli-basic-invocation` (1 finding)

**1. [mcp-azure-cloudshell](https://github.com/cameronking4/mcp-azure-cloudshell)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute command: Cloud Shell connection failed: ChainedTokenCredential authentication failed.
CredentialUnavailableError: EnvironmentCredential is unavailable. No underlying credential could be used. To troubleshoot, visit https://aka.ms/azsdk/js/identity/environmentcredential/troubleshoot.
CredentialUnavailableError: ManagedIdentityCredential: Authentication failed. Message Attempted to use the IMDS endpoint, but it is not available.
CredentialUnava...`

### `tool-azure_shell_reconnect-basic-invocation` (1 finding)

**1. [mcp-azure-cloudshell](https://github.com/cameronking4/mcp-azure-cloudshell)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to execute command: Cloud Shell connection failed: ChainedTokenCredential authentication failed.
CredentialUnavailableError: EnvironmentCredential is unavailable. No underlying credential could be used. To troubleshoot, visit https://aka.ms/azsdk/js/identity/environmentcredential/troubleshoot.
CredentialUnavailableError: ManagedIdentityCredential: Authentication failed. Message Attempted to use the IMDS endpoint, but it is not available.
CredentialUnava...`

### `tool-linkedin_post-basic-invocation` (1 finding)

**1. [linkedin-mcp-server](https://github.com/bakiucartasarim/linkedin-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Failed to share LinkedIn post: Invalid access token`

### `tool-imagen4-basic-invocation` (1 finding)

**1. [fal-image-video-mcp](https://github.com/RamboRogers/fal-image-video-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Imagen 4 generation failed: Error: FAL_KEY is required. Please configure your API key via environment variable or query parameter.`

### `tool-flux_kontext-basic-invocation` (1 finding)

**1. [fal-image-video-mcp](https://github.com/RamboRogers/fal-image-video-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: FLUX Kontext Pro generation failed: Error: FAL_KEY is required. Please configure your API key via environment variable or query parameter.`

### `tool-ideogram_v3-basic-invocation` (1 finding)

**1. [fal-image-video-mcp](https://github.com/RamboRogers/fal-image-video-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Ideogram V3 generation failed: Error: FAL_KEY is required. Please configure your API key via environment variable or query parameter.`

### `tool-save_memory-basic-invocation` (1 finding)

**1. [memory-box-mcp](https://github.com/amotivv/memory-box-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Memory Box token not configured. Please set the MEMORY_BOX_TOKEN environment variable.`

### `tool-search_memories-basic-invocation` (1 finding)

**1. [memory-box-mcp](https://github.com/amotivv/memory-box-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Memory Box token not configured. Please set the MEMORY_BOX_TOKEN environment variable.`

### `tool-get_all_memories-basic-invocation` (1 finding)

**1. [memory-box-mcp](https://github.com/amotivv/memory-box-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Memory Box token not configured. Please set the MEMORY_BOX_TOKEN environment variable.`

### `tool-create_task-basic-invocation` (1 finding)

**1. [mcp-google-tasks](https://github.com/mstfe/mcp-google-tasks)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tasks API error: Error: No access, refresh token, API key or refresh handler callback is set.`

### `tool-list_tasks-basic-invocation` (1 finding)

**1. [mcp-google-tasks](https://github.com/mstfe/mcp-google-tasks)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tasks API error: Error: No access, refresh token, API key or refresh handler callback is set.`

### `tool-delete_task-basic-invocation` (1 finding)

**1. [mcp-google-tasks](https://github.com/mstfe/mcp-google-tasks)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tasks API error: Error: No access, refresh token, API key or refresh handler callback is set.`

### `tool-search_addresses_semantic-basic-invocation` (1 finding)

**1. [chainfetch-mcp-server](https://github.com/chainfetch/chainfetch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: CHAINFETCH_API_TOKEN is required`

### `tool-search_addresses_json-basic-invocation` (1 finding)

**1. [chainfetch-mcp-server](https://github.com/chainfetch/chainfetch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: CHAINFETCH_API_TOKEN is required`

### `tool-search_addresses_llm-basic-invocation` (1 finding)

**1. [chainfetch-mcp-server](https://github.com/chainfetch/chainfetch-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: CHAINFETCH_API_TOKEN is required`

### `tool-generate_documentation-basic-invocation` (1 finding)

**1. [autonomous-docs-mcp](https://github.com/perryjr1444-ux/autonomous-docs-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: SyntaxError: Unexpected token 'e', "test" is not valid JSON`

### `tool-pushover_send_message-basic-invocation` (1 finding)

**1. [mcp-pushover](https://github.com/pyang2045/mcp-pushover)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Pushover API token and user key are required. Provide them as parameters or set PUSHOVER_DEFAULT_TOKEN and PUSHOVER_DEFAULT_USER environment variables.`

### `tool-get_fan_token_price-basic-invocation` (1 finding)

**1. [chiliz-mcp](https://github.com/BrunoPessoa22/chiliz-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Token test not found or not supported`

### `tool-get_multiple_prices-basic-invocation` (1 finding)

**1. [chiliz-mcp](https://github.com/BrunoPessoa22/chiliz-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: No valid tokens found`

### `tool-get_market_chart-basic-invocation` (1 finding)

**1. [chiliz-mcp](https://github.com/BrunoPessoa22/chiliz-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Token test not found or not supported`

### `tool-seal_artifact-basic-invocation` (1 finding)

**1. [deepadata-edm-mcp-server](https://github.com/deepadata/deepadata-edm-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: DeepaData API key required for sealing. Set DEEPADATA_API_KEY environment variable.`

### `tool-ambari_clusters_createcluster-basic-invocation` (1 finding)

**1. [ambari-mcp-server](https://github.com/nikita15p/ambari-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed for ambari_clusters_createcluster: Unexpected token 'e', "test" is not valid JSON`

### `tool-splitwise_get_groups-basic-invocation` (1 finding)

**1. [splitwise-mcp-server](https://github.com/svarun115/splitwise-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: Failed to initialize Splitwise client: SPLITWISE_ACCESS_TOKEN environment variable is required`

### `tool-splitwise_get_group-basic-invocation` (1 finding)

**1. [splitwise-mcp-server](https://github.com/svarun115/splitwise-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: Failed to initialize Splitwise client: SPLITWISE_ACCESS_TOKEN environment variable is required`

### `tool-splitwise_get_expenses-basic-invocation` (1 finding)

**1. [splitwise-mcp-server](https://github.com/svarun115/splitwise-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: MCP error -32600: Failed to initialize Splitwise client: SPLITWISE_ACCESS_TOKEN environment variable is required`

### `tool-connect_jmap-basic-invocation` (1 finding)

**1. [jmap_mcp_server](https://github.com/vaderyang/jmap_mcp_server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: Invalid URL`

### `tool-listEndpoints-basic-invocation` (1 finding)

**1. [swagger-mcp](https://github.com/tigawanna/swagger-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Error listing endpoints: Unexpected token 'e', "test" is not valid JSON`

### `tool-mcp_authenticate-basic-invocation` (1 finding)

**1. [jaumemory-mcp-server](https://github.com/Jau-app/jaumemory-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: Tool execution failed: Authentication failed: request_id is required. Please provide the request_id from the mcp_login response (it was shown after you ran mcp_login).`

### `tool-get_home_timeline-basic-invocation` (1 finding)

**1. [x-mcp-server](https://github.com/DataWhisker/x-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: X API error: No Twitter credentials configured. Set OAuth 1.0a vars (TWITTER_API_KEY, TWITTER_API_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET) or OAuth 2.0 vars (TWITTER_OAUTH2_ACCESS_TOKEN or TWITTER_CLIENT_ID + TWITTER_OAUTH2_REFRESH_TOKEN).`

### `tool-search_tweets-basic-invocation` (1 finding)

**1. [x-mcp-server](https://github.com/DataWhisker/x-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: MCP error -32603: X API error: No Twitter credentials configured. Set OAuth 1.0a vars (TWITTER_API_KEY, TWITTER_API_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET) or OAuth 2.0 vars (TWITTER_OAUTH2_ACCESS_TOKEN or TWITTER_CLIENT_ID + TWITTER_OAUTH2_REFRESH_TOKEN).`

### `tool-get_server_info-basic-invocation` (1 finding)

**1. [sacloud-mcp](https://github.com/hidenorigoto/sacloud-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing API credentials. Set SACLOUD_API_TOKEN and SACLOUD_API_SECRET environment variables.`

### `tool-get_server_list-basic-invocation` (1 finding)

**1. [sacloud-mcp](https://github.com/hidenorigoto/sacloud-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing API credentials. Set SACLOUD_API_TOKEN and SACLOUD_API_SECRET environment variables.`

### `tool-get_switch_list-basic-invocation` (1 finding)

**1. [sacloud-mcp](https://github.com/hidenorigoto/sacloud-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing API credentials. Set SACLOUD_API_TOKEN and SACLOUD_API_SECRET environment variables.`

### `tool-get_boards-basic-invocation` (1 finding)

**1. [jira-mcp](https://github.com/ahmetbarut/jira-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing Jira configuration. Please set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.`

### `tool-get_current_user_info-basic-invocation` (1 finding)

**1. [jira-mcp](https://github.com/ahmetbarut/jira-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Missing Jira configuration. Please set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.`

### `tool-create_spreadsheet-basic-invocation` (1 finding)

**1. [google-drive-mcp-server](https://github.com/seeun0210/google-drive-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No access, refresh token, API key or refresh handler callback is set.`

### `tool-read_spreadsheet-basic-invocation` (1 finding)

**1. [google-drive-mcp-server](https://github.com/seeun0210/google-drive-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: No access, refresh token, API key or refresh handler callback is set.`

### `tool-execute_query-basic-invocation` (1 finding)

**1. [mcp_kusto](https://github.com/abhirockzz/mcp_kusto)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Op(OpQuery): Kind(KInternal): Error while getting token : Get "https://test.kusto.windows.net/v1/rest/auth/metadata": dial tcp: lookup test.kusto.windows.net on 127.0.0.53:53: no such host`

### `tool-get_table_schema-basic-invocation` (1 finding)

**1. [mcp_kusto](https://github.com/abhirockzz/mcp_kusto)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Op(OpMgmt): Kind(KInternal): Error while getting token : Get "https://test.kusto.windows.net/v1/rest/auth/metadata": dial tcp: lookup test.kusto.windows.net on 127.0.0.53:53: no such host`

### `tool-list_databases-basic-invocation` (1 finding)

**1. [mcp_kusto](https://github.com/abhirockzz/mcp_kusto)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Op(OpMgmt): Kind(KInternal): Error while getting token : Get "https://test.kusto.windows.net/v1/rest/auth/metadata": dial tcp: lookup test.kusto.windows.net on 127.0.0.53:53: no such host`

### `tool-pylon_get_me-basic-invocation` (1 finding)

**1. [pylon-mcp](https://github.com/marcinwyszynski/pylon-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: PYLON_API_TOKEN environment variable is required`

### `tool-pylon_get_contacts-basic-invocation` (1 finding)

**1. [pylon-mcp](https://github.com/marcinwyszynski/pylon-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: PYLON_API_TOKEN environment variable is required`

### `tool-pylon_create_contact-basic-invocation` (1 finding)

**1. [pylon-mcp](https://github.com/marcinwyszynski/pylon-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: PYLON_API_TOKEN environment variable is required`

### `tool-GetNetWork-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/aapanel/mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Post "/system?action=GetNetWork&request_time=&request_token=": unsupported protocol scheme ""`

### `tool-add_mailbox-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/aapanel/mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Post "/mail/main/add_mailbox?request_time=&request_token=": unsupported protocol scheme ""`

### `tool-add_site-basic-invocation` (1 finding)

**1. [mcp-server](https://github.com/aapanel/mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: Post "/site?action=AddSite&request_time=&request_token=": unsupported protocol scheme ""`

### `tool-create-bookmark-basic-invocation` (1 finding)

**1. [raindrop-io-mcp-server](https://github.com/hiromitsusasaki/raindrop-io-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RAINDROP_TOKEN is not set`

### `tool-search-bookmarks-basic-invocation` (1 finding)

**1. [raindrop-io-mcp-server](https://github.com/hiromitsusasaki/raindrop-io-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RAINDROP_TOKEN is not set`

### `tool-list-collections-basic-invocation` (1 finding)

**1. [raindrop-io-mcp-server](https://github.com/hiromitsusasaki/raindrop-io-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: RAINDROP_TOKEN is not set`

### `tool-get_my_profile-basic-invocation` (1 finding)

**1. [threads-mcp](https://github.com/baguskto/threads-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: THREADS_ACCESS_TOKEN environment variable is required`

### `tool-get_my_threads-basic-invocation` (1 finding)

**1. [threads-mcp](https://github.com/baguskto/threads-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: THREADS_ACCESS_TOKEN environment variable is required`

### `tool-publish_thread-basic-invocation` (1 finding)

**1. [threads-mcp](https://github.com/baguskto/threads-mcp)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: THREADS_ACCESS_TOKEN environment variable is required`

### `tool-coolify_system-basic-invocation` (1 finding)

**1. [CoolifyMCP](https://github.com/HowieDuhzit/CoolifyMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Coolify API token is required. Set COOLIFY_API_TOKEN environment variable or pass token in arguments.`

### `tool-coolify_teams-basic-invocation` (1 finding)

**1. [CoolifyMCP](https://github.com/HowieDuhzit/CoolifyMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Coolify API token is required. Set COOLIFY_API_TOKEN environment variable or pass token in arguments.`

### `tool-coolify_projects-basic-invocation` (1 finding)

**1. [CoolifyMCP](https://github.com/HowieDuhzit/CoolifyMCP)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: Coolify API token is required. Set COOLIFY_API_TOKEN environment variable or pass token in arguments.`

### `tool-gyazo_search-basic-invocation` (1 finding)

**1. [gyazo-mcp-server](https://github.com/nota/gyazo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: GYAZO_ACCESS_TOKEN environment variable is required`

### `tool-gyazo_image-basic-invocation` (1 finding)

**1. [gyazo-mcp-server](https://github.com/nota/gyazo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: GYAZO_ACCESS_TOKEN environment variable is required`

### `tool-gyazo_latest_image-basic-invocation` (1 finding)

**1. [gyazo-mcp-server](https://github.com/nota/gyazo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Tool execution failed: GYAZO_ACCESS_TOKEN environment variable is required`

### `tool-list_devices-basic-invocation` (1 finding)

**1. [nature-remo-mcp-server](https://github.com/noboru-i/nature-remo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unauthorized`

### `tool-list_appliances-basic-invocation` (1 finding)

**1. [nature-remo-mcp-server](https://github.com/noboru-i/nature-remo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unauthorized`

### `tool-operate_tv-basic-invocation` (1 finding)

**1. [nature-remo-mcp-server](https://github.com/noboru-i/nature-remo-mcp-server)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: Unauthorized`

### `tool-generate-thinking-basic-invocation` (1 finding)

**1. [MCP-CSV-Analysis-with-Gemini-AI](https://github.com/falahgs/MCP-CSV-Analysis-with-Gemini-AI)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: [GoogleGenerativeAI Error]: Error fetching from https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent: [400 Bad Request] API key not valid. Please pass a valid API key. [{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pas...`

### `tool-generate_text-basic-invocation` (1 finding)

**1. [mcp-server-gemini-pro](https://github.com/gurveeer/mcp-server-gemini-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

### `tool-count_tokens-basic-invocation` (1 finding)

**1. [mcp-server-gemini-pro](https://github.com/gurveeer/mcp-server-gemini-pro)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: {"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com","metadata":{"service":"generativelanguage.googleapis.com"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"API key not valid. Please pass a valid API key."}]}}`

### `tool-list_sites-basic-invocation` (1 finding)

**1. [mcp-server-gsc](https://github.com/Bdmarvin1/mcp-server-gsc)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: __google_access_token__ not provided or invalid in arguments by the MCP OAuth Controller.`

### `tool-search_analytics-basic-invocation` (1 finding)

**1. [mcp-server-gsc](https://github.com/Bdmarvin1/mcp-server-gsc)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: __google_access_token__ not provided or invalid in arguments by the MCP OAuth Controller.`

### `tool-index_inspect-basic-invocation` (1 finding)

**1. [mcp-server-gsc](https://github.com/Bdmarvin1/mcp-server-gsc)** (nodejs)
- Type: `InvocationError`
- Message: `MCP error -32603: __google_access_token__ not provided or invalid in arguments by the MCP OAuth Controller.`

### `tool-compare_branches_tags-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/oschina/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-create_comment-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/oschina/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-create_issue-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/oschina/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-comment_issue-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/jj-h/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-comment_pull-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/jj-h/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-create_enterprise_repo-basic-invocation` (1 finding)

**1. [mcp-gitee](https://github.com/jj-h/mcp-gitee)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: [auth_error] Authentication failed, please check your access token (code: 0)`

### `tool-docker_get_image_versions-basic-invocation` (1 finding)

**1. [pinner-mcp](https://github.com/safedep/pinner-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to list available versions: GET https://index.docker.io/v2/library/test/tags/list?n=1000: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:library/test Type:repository]]`

### `tool-docker_resolve_image_to_digest-basic-invocation` (1 finding)

**1. [pinner-mcp](https://github.com/safedep/pinner-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: failed to fetch image digest: GET https://index.docker.io/v2/library/test/manifests/test: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:library/test Type:repository]]`

### `tool-list_netbird_groups-basic-invocation` (1 finding)

**1. [mcp-netbird](https://github.com/aantti/mcp-netbird)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: netbird API token not found in context`

### `tool-list_netbird_nameservers-basic-invocation` (1 finding)

**1. [mcp-netbird](https://github.com/aantti/mcp-netbird)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: netbird API token not found in context`

### `tool-list_netbird_networks-basic-invocation` (1 finding)

**1. [mcp-netbird](https://github.com/aantti/mcp-netbird)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: netbird API token not found in context`

### `tool-convert_markdown-basic-invocation` (1 finding)

**1. [md2wechat-mcp-server](https://github.com/geekjourneyx/md2wechat-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 未找到 API Key，请设置环境变量 MD2WECHAT_API_KEY`

### `tool-create_pull_request-basic-invocation` (1 finding)

**1. [github-mcp-server-sse](https://github.com/yamagai/github-mcp-server-sse)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 認証トークンがありません。環境変数GITHUB_TOKENを設定するか、Authorizationヘッダーを指定してください`

### `tool-create_pull_request_review-basic-invocation` (1 finding)

**1. [github-mcp-server-sse](https://github.com/yamagai/github-mcp-server-sse)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: 認証トークンがありません。環境変数GITHUB_TOKENを設定するか、Authorizationヘッダーを指定してください`

## Interpretazione

Gli errori di **auth** indicano server che richiedono autenticazione per funzionare. Non sono vulnerabilità in sé, ma sono informativi: mostrano quali server hanno un layer di auth attivo.

