### Tool invocation / invalid_arguments

**Finding originali (dopo filtro Stage 1)**: 253

1. InvocationError con codice JSON-RPC `-32602` (Invalid params)
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
      message: error.message,  // "MCP error -32602: Invalid parameters: ..."
    },
  });
}
```

mcp-check genera l'input di test con `generateBasicInput` conforme al `inputSchema` dichiarato dal tool: prende i `required`, genera valori coerenti per ogni tipo (string='test', number=50, boolean=true, array=['test'], enum=enum[0], format=valori standard tipo '127.0.0.1', 'test@example.com'...). Se il server risponde con `-32602` significa che:
- **VP**: il server ha un bug (parameter parsing incompleto, outputSchema dichiarato ma non implementato, codice di errore sbagliato).
- **FP**: mcp-check ha generato un valore che non conosceva (es. "test" come timezone, enum value sbagliato, URL finto) e il server correttamente rifiuta l'input.

**Finding dopo filtro**: 253

| Pattern | Count |
|---|---:|
| `-32602: parameter parsing not fully implemented` | 52 (VP) |
| `-32602: Invalid tools/call result` / `invalid_union` | 7 (VP) |
| `Structured content does not match output schema` | 6 (VP) |
| `-32603:.*Invalid arguments` (wrong error code) | 6 (VP) |
| `Invalid structured content for tool X` | 3 (VP) |
| Zod validation correttamente applicata dal server | ~100 (FP) |
| Domain format validation (ETH address, timezone, ...) | ~50 (FP) |
| Argomenti richiesti non forniti da mcp-check | ~30 (FP) |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/invalid_arguments (estratto)
def hc_rules_tool_invocation_invalid_arguments(entry: dict) -> tuple[str | None, str]:
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: implementazione incompleta (bug server)
    if re.search(r'not fully implemented|parsing not fully', msgs_joined, re.I):
        return "VP", "parameter_parsing_not_implemented"

    # HC-VP: schema output mismatch
    if "Structured content does not match" in msgs_joined:
        return "VP", "output_schema_mismatch"

    # HC-VP: risposta server formato sbagliato
    if re.search(r'Invalid tools/call result|invalid_union', msgs_joined, re.I):
        return "VP", "invalid_tools_call_result_format"

    if re.search(r'Invalid structured content for tool', msgs_joined, re.I):
        return "VP", "invalid_structured_content"

    # HC-FP: URL invalida / auth / 'test' placeholder
    if _URL_FP.search(msgs_joined): return "FP", "invalid_url_from_mcp_check"
    if _AUTH_FP.search(msgs_joined): return "FP", "auth_or_config_missing"
    if _TEST_ID_FP.search(msgs_joined): return "FP", "test_placeholder_id"

    # HC-VP: server usa -32603 invece di -32602 per arg invalido
    if re.search(r'MCP error -32603:.*(?:Invalid arguments?:|Unknown method:)',
                 msgs_joined, re.I):
        return "VP", "wrong_error_code_for_validation"
    if re.search(r'MCP error -32603:.*arguments.*Required|'
                 r'MCP error -32603:.*key.*Required',
                 msgs_joined, re.I):
        return "VP", "wrong_error_code_for_validation"

    # HC-FP: enum/format non conosciuti da mcp-check
    if re.search(r'Must be one of:|Invalid chart type|Invalid Maven|'
                 r'Invalid client:.*Must be|Expected format: S\d+E\d+|'
                 r'chromosome.*Invalid|Expected a SELECT statement|'
                 r'filePath must be an absolute path',
                 msgs_joined, re.I):
        return "FP", "mcp_check_unknown_enum_or_format"

    # HC-FP: required args mancanti
    if re.search(r'Either .* must be provided|must be provided|'
                 r'is required|required parameter|missing.*required',
                 msgs_joined, re.I):
        return "FP", "mcp_check_missing_required_arg"

    # HC-FP: "Invalid arguments for tool X:" -> server valida correttamente
    if re.search(r'Invalid arguments for (tool )?[\w.-]+[\w-]*:',
                 msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    if re.search(r"Tool '[^']+' parameter validation failed:", msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: Zod too_small/too_big, expected object/email, blockchain address, ecc.
    if re.search(r'"code"\s*:\s*"too_small"|"code"\s*:\s*"too_big"',
                 msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"
    if re.search(r'[Ii]nvalid Ethereum (address|wallet)|'
                 r'Token contract must be a valid|Invalid mnemonic',
                 msgs_joined, re.I):
        return "FP", "mcp_check_domain_validation"

    # ... molti altri pattern FP per domini specifici (SQL type, timezone,
    #     GIS format, FEN chess, viacep regex, summoner GameName#TagLine, ecc.)

    return None, "uncertain"
```

**Veri positivi confermati dopo analisi LLM**: 74

Ripartizione VP per tipo:
| Tipo di bug | VP |
|---|---:|
| `parameter_parsing_not_implemented` | 52 |
| `invalid_tools_call_result_format` | 7 |
| `output_schema_mismatch` | 6 |
| `wrong_error_code_for_validation` (-32603 invece di -32602) | 6 |
| `invalid_structured_content` | 3 |

Ripartizione finale: 74 VP + 179 FP = 253 (tutti classificati da regole HC deterministiche + cache in-chat, UNCERTAIN finale=0).

**Esempi di VP confermati:**

{"server_name": "mcp-ads-manager", "test": "tool-update_project-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32602: Invalid parameters: parameter parsing not fully implemented for this type"}}

{"server_name": "mcp-antifraud-engine", "test": "tool-describe_stack-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32602: Invalid parameters: parameter parsing not fully implemented for this type"}}

{"server_name": "mcp-campaign-planner", "test": "tool-delete_project-basic-invocation",
 "error": {"type": "InvocationError",
 "message": "MCP error -32602: Invalid parameters: parameter parsing not fully implemented for this type"}}
