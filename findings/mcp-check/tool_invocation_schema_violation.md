### Tool invocation / schema_violation

**Finding originali (dopo filtro Stage 1)**: 4.860

1. ValidationFailure: server accetta input invalido
```typescript
// src/suites/tool-invocation.ts
// Test case 2: Input validation (invalid input)
if (tool.inputSchema) {
  try {
    const invalidInput = this.generateInvalidInput(tool);
    try {
      await client.callTool(toolName, invalidInput);
      // If we get here, the tool didn't reject invalid input
      cases.push({
        name: `tool-${toolName}-input-validation`,
        status: 'failed',
        error: {
          type: 'ValidationFailure',
          message: 'Tool accepted invalid input without error',
        },
      });
    } catch (error) {
      // Good - the tool rejected invalid input
      cases.push({ name: `...-input-validation`, status: 'passed', ... });
    }
  } catch (error) { ... }
}
```

2. InvocationError con `output schema but did not return structured content`
```typescript
// src/suites/tool-invocation.ts (basic-invocation)
const response = await client.callTool(toolName, basicInput);
const isValidResponse = this.validateToolResponse(response);
...
// Il SDK MCP valida la risposta contro outputSchema dichiarato.
// Se il tool dichiara outputSchema ma ritorna solo content non strutturato,
// la call lancia "-32600: Tool X has an output schema but did not return structured content"
```

3. InitializationError con Zod validation sulla risposta `tools/list` (path `tools`)

**Finding dopo filtro**: 4.860

| Tipo errore | Count |
|---|---:|
| `ValidationFailure` + `InvocationError` (output schema mismatch) | grande maggioranza |
| `InitializationError` con Zod su `tools` | rilevante |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/schema_violation
def hc_rules_tool_invocation_schema_violation(entry: dict) -> tuple[str | None, str]:
    types_list = _types(entry)
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: ValidationFailure (server accetta input non validi)
    if "ValidationFailure" in types_list:
        return "VP", "accepts_invalid_input"

    # HC-VP: output schema dichiarato ma non ritorna structured content
    if "output schema but did not return structured content" in msgs_joined:
        return "VP", "output_schema_mismatch"

    # VP: InitializationError con Zod schema errors su tools/nextCursor
    # -> server ritorna risposta tools/list non conforme alla specifica MCP
    if "InitializationError" in types_list:
        msgs_j = " ".join(_msgs(entry))
        if re.search(r'invalid_value|invalid_type|"path".*tools', msgs_j, re.I | re.DOTALL):
            return "VP", "tools_list_response_schema_invalid"
        return None, "initialization_error_uncertain"

    return "VP", "schema_violation_default"
```

**Veri positivi confermati dopo analisi LLM**: 4.860

Ripartizione finale: 4.860 VP + 0 FP = 4.860 (tutti classificati da regole HC deterministiche, UNCERTAIN=0). Tutti gli `InitializationError` in questa categoria ricadono nel pattern Zod `"path": ["tools"]` — il server ritorna una risposta `tools/list` non conforme alla specifica MCP (campo `tools` mancante o di tipo sbagliato).

**Esempi di VP confermati:**

{"server_name": "mcp-gateway", "test": "tool-batch_request-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32600: Tool batch_request has an output schema but did not return structured content"}}

{"server_name": "librarian", "test": "tool-brief-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32600: Tool brief has an output schema but did not return structured content"}}

{"server_name": "miaw-mcp-server", "test": "tool-create_conversation-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32600: Tool create_conversation has an output schema but did not return structured content"}}
