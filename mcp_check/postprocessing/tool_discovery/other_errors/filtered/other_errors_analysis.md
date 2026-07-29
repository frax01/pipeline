# tool_discovery/other_errors - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 70 |
| Finding filtrati | 49 |
| Rimossi | 21 (30.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 39 |
| python | 6 |
| go | 3 |
| unknown | 1 |

## Finding per tipo di test

### `tool-enumeration` (23 finding)

**1. [mcp-jetbrains](https://github.com/JetBrains/mcp-jetbrains)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: No working IDE endpoint available.`

**2. [mcp-proxy-sidecar](https://github.com/dortegau/mcp-proxy-sidecar)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: No working IDE endpoint available.`

**3. [mcp-assistant](https://github.com/nodlab/mcp-assistant)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: The "path" argument must be of type string or an instance of Buffer or URL. Received undefined`

**4. [mcp-wordpress-remote](https://github.com/automattic/mcp-wordpress-remote)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: MCP error -32603: Cannot process tools/list: WordPress connection failed during initialization`

**5. [DotnetMCPServer](https://github.com/kasirajan22/DotnetMCPServer)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: Failed to get tools`

**6. [mcp](https://github.com/docker-hackerxbt68/mcp)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: Request failed: Not Found`

**7. [notemd-mcp](https://github.com/Jacobinwwey/notemd-mcp)** (nodejs)
- Type: `ToolListError`
- Message: `MCP error -32603: Failed to parse URL from /tools`

**8. [azure-pricing-mcp](https://github.com/charris-msft/azure-pricing-mcp)** (python)
- Type: `ToolListError`
- Message: `MCP error 0: name 'true' is not defined`

**9. [mcp-server-gravatar](https://github.com/Automattic/mcp-server-gravatar)** (nodejs)
- Type: `ToolListError`
- Message: `can't resolve reference #/components/schemas/VerifiedAccount from id #`

**10. [handsai-bridge](https://github.com/Vrivaans/handsai-bridge)** (go)
- Type: `ToolListError`
- Message: `MCP error -32603: HTTP 401`

*... e altri 13 finding simili*

### `unique-tool-names` (21 finding)

**1. [github-mcp-server](https://github.com/0xshariq/github-mcp-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: git_flow, git_sync`

**2. [air-mcp](https://github.com/binalyze/air-mcp)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: get_repository_by_id`

**3. [locallama-mcp](https://github.com/Heratiki/locallama-mcp)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: retriv_init`

**4. [mcp-json-db-collection-server](https://github.com/jimpick/mcp-json-db-collection-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: connect_json_doc_database_to_cloud`

**5. [ticktick-mcp-server](https://github.com/liadgez/ticktick-mcp-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: ticktick_get_task_details`

**6. [reddit-mcp-server](https://github.com/jordanburke/reddit-mcp-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: update_list_entry, update_record`

**7. [kali-mcp-server](https://github.com/Vasanthadithya-mundrathi/kali-mcp-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: kali_reverse_engineering`

**8. [claude-writers-aid-mcp](https://github.com/xiaolai/claude-writers-aid-mcp)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: track_concept_evolution`

**9. [nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)** (nodejs)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: create_inventory, get_inventory, update_inventory, check_inventory_availability, get_inventory_by_product, reserve_inventory, list_partners, create_partner, get_partner, list_sales_channels, create_sales_channel, get_sales_channel, get_sales_channel_by_code, update_sales_channel, delete_sales_channel, activate_sales_channel, deactivate_sales_channel, get_sales_channel_statistics`

**10. [skills-integrate-mcp-with-copilot](https://github.com/2403a52074-hub/skills-integrate-mcp-with-copilot)** (python)
- Type: `DuplicateToolNames`
- Message: `Duplicate tool names found: start_coding_session, end_coding_session, get_session_history`

*... e altri 11 finding simili*

### `initialization` (5 finding)

**1. [notion-knowledge-mcp](https://github.com/YuHuanHsu/notion-knowledge-mcp)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**2. [MCP-](https://github.com/markjukerburg/MCP-)** (python)
- Type: `InitializationError`
- Message: `MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**3. [mcp-server](https://github.com/luffy050596/mcp-server)** (go)
- Type: `InitializationError`
- Message: `MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**4. [mcp-server](https://github.com/wangle201210/mcp-server)** (go)
- Type: `InitializationError`
- Message: `MCP error -32603: protocol version not supported, supported version is 2024-11-05`

**5. [garnet-platform-mcp](https://github.com/garnet-org/garnet-platform-mcp)** (nodejs)
- Type: `InitializationError`
- Message: `MCP error -32603: Invalid response from server`

## Interpretazione

Gli **other_errors** filtrati sono errori runtime che non rientrano nelle altre categorie. Dopo aver rimosso errori di setup/infrastruttura, rimangono errori applicativi potenzialmente interessanti.

