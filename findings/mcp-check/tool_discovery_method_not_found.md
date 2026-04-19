### Tool discovery / method_not_found

**Finding originali (dopo filtro Stage 1)**: 42

1. ToolListError con codice JSON-RPC `-32601`
```typescript
// src/suites/tool-discovery.ts
try {
  const toolsStart = Date.now();
  const tools = await client.listTools();
  ...
} catch (error) {
  cases.push({
    name: 'tool-enumeration',
    status: 'failed',
    durationMs: 0,
    error: {
      type: 'ToolListError',
      message: error.message,
    },
  });
}
```

Quando `client.listTools()` invia la richiesta JSON-RPC `tools/list`, un server che risponde con `-32601 Method not found` indica che non implementa il metodo MCP `tools/list`. Questo e' un bug di conformance: ogni server MCP che dichiara la capability `tools` deve supportare `tools/list`.

**Finding dopo filtro**: 42

| Messaggio | Count |
|---|---:|
| `MCP error -32601: Method not found` (su `tools/list`) | 42 |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/method_not_found
def hc_rules_tool_discovery_method_not_found(entry: dict) -> tuple[str | None, str]:
    """Tutti VP: tools/list non implementato -> server non espone tool (-32601)."""
    return "VP", "tools_list_not_implemented"
```

**Veri positivi confermati dopo analisi LLM**: 42

Ripartizione finale: 42 VP + 0 FP = 42 (tutti classificati dalla regola HC, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "mcp-server-simulator-ios-idb", "test": "tool-enumeration",
 "error": {"type": "ToolListError",
 "message": "MCP error -32601: Method not found"}}

{"server_name": "specbridge", "test": "tool-enumeration",
 "error": {"type": "ToolListError",
 "message": "MCP error -32601: Method not found"}}

{"server_name": "mcp-confluent", "test": "tool-enumeration",
 "error": {"type": "ToolListError",
 "message": "MCP error -32601: Method not found"}}
