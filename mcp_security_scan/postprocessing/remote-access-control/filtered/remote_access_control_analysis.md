# remote-access-control (RC-01) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Tool che espongono accesso remoto. Lo scanner cerca keyword 'remote', 'port', 'expose' e prova a chiamare con port:8080. Il filtro scarta risposte di errore e tiene solo evidenza reale di porte aperte/servizi avviati.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 5 |
| Finding filtrati (tenuti) | 3 |
| Rimossi | 2 |
| Tasso di riduzione | 40.0% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `KEPT:enabled_in_remote_context` | 3 |
| `REJECTED:error_response` | 2 |

## Server unici con vulnerabilita' reali: 3

## Esempi di finding tenuti (max 15)

### 1. [proto-blocks-mcp](https://github.com/GustavoGomez092/proto-blocks-mcp)

- **ID**: `RC-01`
- **Severity**: `critical`
- **Filter reason**: `enabled_in_remote_context`
- **Details**: ```{"candidates": [{"name": "proto_blocks_troubleshooting", "description": "Get troubleshooting guidance for common Proto-Blocks issues. Covers block registration, template rendering, field binding, styling, interactivity, and performance issues. Use category parameter to filter by issue type.", "inputSchema": {"type": "object", "properties": {"category": {"type": "string", "description": "Optional: Filter troubleshooting by category", "enum": ["registration", "templates", "fields", "controls", "styling", "interactivity", "performance", "editor"]}}, "required": []}}], "exploited": [{"tool": "proto_blocks_troubleshooting", "resp": {"result": {"content": [{"type": "text", "text": "# Proto-Blocks Troubleshooting Guide\n\nCommon issues and their solutions when working with Proto-Blocks.\n\n---\n\... [troncato]```

### 2. [rhombus-node-mcp](https://github.com/rhombussystems/rhombus-node-mcp)

- **ID**: `RC-01`
- **Severity**: `critical`
- **Filter reason**: `enabled_in_remote_context`
- **Details**: ```{"candidates": [{"name": "automated-prompts-tool", "title": "Automated Prompts", "description": "\nThis tool manages Rhombus MIND automated prompts - scheduled chatbot jobs that run a prompt at a recurring interval and store each response. Use it to list, inspect, create, update, delete, page through past responses for, share, or re-verify the schedule of an automated prompt.\n\nModes (set \"requestType\"):\n- list: List all automated prompts in the org. Optional 'lastEvaluatedKey' / 'maxPageSize' for pagination.\n- get: Get a single automated prompt's settings. Requires 'promptUuid'.\n- create: Create a new automated prompt. Requires 'prompt', 'invokeAt' (ISO 8601 with offset, must be at least 15 minutes in the future), 'frequencyValue', 'frequencyUnit', and 'permissionGroupUuid'. Optiona... [troncato]```

### 3. [electron-mcp-server](https://github.com/laststance/electron-mcp-server)

- **ID**: `RC-01`
- **Severity**: `critical`
- **Filter reason**: `enabled_in_remote_context`
- **Details**: ```{"candidates": [{"name": "electron_get_viewport_size", "description": "Read viewport innerWidth/innerHeight and devicePixelRatio. Returns JSON {width, height, devicePixelRatio}.", "inputSchema": {"type": "object", "properties": {"targetId": {"type": "string", "description": "CDP target ID for exact-match window targeting. Use list_electron_windows to discover IDs."}, "windowTitle": {"type": "string", "description": "Window title for case-insensitive partial-match targeting. Ignored if targetId is set."}}, "additionalProperties": false, "$schema": "http://json-schema.org/draft-07/schema#"}}], "exploited": [{"tool": "electron_get_viewport_size", "resp": {"result": {"content": [{"type": "text", "text": "Error executing electron_get_viewport_size: No running Electron application found with rem... [troncato]```

## Interpretazione

I finding tenuti mostrano server dove la chiamata con port:8080 ha effettivamente attivato un servizio remoto (porta aperta, server avviato). I finding scartati sono risposte di errore o keyword generiche.

## Lista completa server vulnerabili

- https://github.com/GustavoGomez092/proto-blocks-mcp
- https://github.com/laststance/electron-mcp-server
- https://github.com/rhombussystems/rhombus-node-mcp
