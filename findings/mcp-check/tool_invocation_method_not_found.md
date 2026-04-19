### Tool invocation / method_not_found

**Finding originali (dopo filtro Stage 1)**: 50

1. InvocationError con codice JSON-RPC `-32601` su un tool dichiarato in `tools/list`
```typescript
// src/suites/tool-invocation.ts - testTool
try {
  const response = await client.callTool(toolName, basicInput);
  ...
} catch (error) {
  cases.push({
    name: `tool-${toolName}-basic-invocation`,
    status: 'failed',
    error: {
      type: 'InvocationError',
      message: error.message,  // "MCP error -32601: Method not found" / "Tool not implemented"
    },
  });
}
```

mcp-check chiama `tools/call` solo su tool che il server ha **dichiarato** nella propria risposta `tools/list`. Se lo stesso server risponde `-32601 Method not found` / `Tool implementation pending` / `Tool not implemented in standalone version`, significa che ha annunciato un tool che non ha effettivamente implementato.

**Finding dopo filtro**: 50

| Messaggio | Count |
|---|---:|
| `-32601: Method not found` (generico) | — |
| `-32601: <Tool> implementation pending` | — |
| `-32601: Tool not implemented in standalone version: <tool>` | — |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/method_not_found
def hc_rules_tool_invocation_method_not_found(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: tool dichiarato ma non implementato (-32601).
    Include "Tool implementation pending" e "Tool not implemented in standalone version".
    """
    return "VP", "tool_not_implemented"
```

**Veri positivi confermati dopo analisi LLM**: 50

Ripartizione finale: 50 VP + 0 FP = 50 (tutti classificati dalla regola HC, UNCERTAIN=0). Dichiarare un tool in `tools/list` e poi rispondere `-32601` al momento dell'invocazione e' un bug di conformance: il client non ha modo di sapere in anticipo quali tool dichiarati siano effettivamente disponibili.

**Esempi di VP confermati:**

{"server_name": "calibre-rag-mcp-nodejs", "test": "tool-fetch-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32601: Fetch tool implementation pending"}}

{"server_name": "render-question-mcp", "test": "tool-render_question-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32601: MCP error -32601: Method not found"}}

{"server_name": "mcp_server_google", "test": "tool-drive_create_folder-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32601: MCP error -32601: Tool not implemented in standalone version: drive_create_folder"}}
