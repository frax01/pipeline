### Tool invocation / panic_or_crash

**Finding originali (dopo filtro Stage 1)**: 4

1. InvocationError con "panic recovered" nel messaggio
```typescript
// src/suites/tool-invocation.ts - testTool
try {
  const response = await client.callTool(toolName, basicInput);
  ...
} catch (error) {
  cases.push({
    name: `tool-${toolName}-basic-invocation`,
    status: 'failed',
    durationMs: 0,
    error: {
      type: 'InvocationError',
      message: error.message,  // <-- "MCP error -32603: panic recovered in <tool> tool handler: ..."
    },
  });
}
```

Lo Stage 1 estrae da `other_errors` gli `InvocationError` il cui messaggio contiene `panic recovered` (Go) o `nil pointer dereference` — sintomi diretti di un crash runtime nel server. In Go, `panic recovered` significa che il server ha un recover() middleware che previene il crash del processo ma l'handler del tool ha sollevato un panic per un bug di programmazione (tipicamente un nil check mancante).

**Finding dopo filtro**: 4

| Pattern | Count |
|---|---:|
| `panic recovered ... interface conversion: interface {} is nil, not float64` | 2 |
| `panic recovered ... runtime error: invalid memory address or nil pointer dereference` | 1 |
| `panic recovered ... interface conversion: interface {} is nil` (Sonar) | 1 |

Categoria senza HC (`has_hc: False`): classificazione diretta via cache in-chat (4 finding -> tutti VP confermati).

```python
# CATEGORIA senza HC rules: classificata via _llm_api_cache.json
"tool_invocation/panic_or_crash": {
    "phase": "tool_invocation",
    "category": "panic_or_crash",
    "filename": "panic_or_crash_filtered.json",
    "description": "Crash/panic del server Go durante invocazione tool",
    "has_hc": False,
},
```

Un `panic` non gestito durante l'invocazione di un tool e' sempre un bug: un input ben formato (mcp-check genera input valido conforme a `inputSchema`) non deve mai far crashare il server. I 4 server affetti sono tutti scritti in Go e condividono lo stesso pattern "nil interface{} conversion" — accesso a un campo di una struct arrivata a nil senza check preventivo.

**Veri positivi confermati dopo analisi LLM**: 4

Ripartizione finale: 4 VP + 0 FP = 4 (tutti classificati via cache in-chat).

**Esempi di VP confermati:**

{"server_name": "mcp-iot-go", "test": "tool-buzzer_control-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32603: panic recovered in buzzer_control tool handler: interface conversion: interface {} is nil, not float64"}}

{"server_name": "opgen-mcp-server", "test": "tool-generate_password_characters-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32603: panic recovered in generate_password_characters tool handler: interface conversion: interface {} is nil, not float64"}}

{"server_name": "talos-mcp", "test": "tool-list_cpu-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32603: panic recovered in list_cpu tool handler: runtime error: invalid memory address or nil pointer dereference"}}
