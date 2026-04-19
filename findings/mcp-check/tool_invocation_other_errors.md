### Tool invocation / other_errors

**Finding originali (dopo filtro Stage 1)**: 3.817

1. ErrorHandlingFailure — server non ritorna errore per tool inesistente
```typescript
// src/suites/tool-invocation.ts - testErrorHandling
const nonExistentToolName = 'non-existent-tool-' + Date.now();

try {
  await client.callTool(nonExistentToolName, {});
  cases.push({
    name: 'error-handling-nonexistent-tool',
    status: 'failed',
    durationMs: 0,
    error: {
      type: 'ErrorHandlingFailure',
      message: 'Server did not return error for non-existent tool',
    },
  });
} catch (error) {
  // Good - the server returned an error
  cases.push({ name: 'error-handling-nonexistent-tool', status: 'passed', ... });
}
```

2. InvocationError generica durante basic-invocation
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
      message: error.message,
    },
  });
}
```

**Finding dopo filtro**: 3.817

| Tipo errore | Count |
|---|---:|
| `ErrorHandlingFailure` (tool name injection) | ~3.294 |
| `InvocationError` (JS runtime / Go unmarshal / SQL injection test / wrong error code) | ~523 |

La categoria e' dominata da `ErrorHandlingFailure`: il server accetta una chiamata a un tool che non esiste invece di ritornare `-32602`/`-32601`. Se il server non distingue tool veri da tool inventati, un attaccante puo' inviare nomi di tool arbitrari senza essere respinto (tool-name injection).

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/other_errors (estratto)
def hc_rules_tool_invocation_other_errors(entry: dict) -> tuple[str | None, str]:
    types_list = _types(entry)
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: tool name injection (il finding dominante)
    if "ErrorHandlingFailure" in types_list:
        return "VP", "tool_name_injection_no_error_returned"

    # HC-VP: JS runtime errors / Go unmarshal / Node __dirname bug
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "js_runtime_error"
    if _UNMARSHAL_VP.search(msgs_joined):
        return "VP", "unmarshal_parse_error"

    # HC-FP: URL invalida / auth mancante / 'test' placeholder
    if _URL_FP.search(msgs_joined):
        return "FP", "invalid_url_from_mcp_check"
    if _AUTH_FP.search(msgs_joined):
        return "FP", "auth_or_config_missing"
    if _TEST_ID_FP.search(msgs_joined):
        return "FP", "test_placeholder_id"

    # HC-FP: config/env/CLI/servizio mancanti (catch-all)
    if _ENV_MISSING_FP.search(msgs_joined):
        return "FP", "env_config_missing"
    if _CLI_MISSING_FP.search(msgs_joined):
        return "FP", "external_cli_not_installed"
    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    # HC-FP: Windows path su Linux / "test" e' una directory nel test env
    if re.search(r'C:\\Users\\|C:/Users/', msgs_joined):
        return "FP", "windows_path_on_linux_vm"
    if re.search(r'EISDIR: illegal operation on a directory|'
                 r'read test: is a directory|'
                 r'The path test is not a valid directory',
                 msgs_joined, re.I):
        return "FP", "test_is_directory_in_env"

    # HC-VP: "Tool response does not match expected structure"
    if re.search(r'Tool response does not match expected structure',
                 msgs_joined, re.I):
        return "VP", "tool_response_wrong_structure"

    # HC-VP: server usa -32603 al posto di -32601 per tool sconosciuti
    if re.search(r'MCP error -32603:.*Unknown tool', msgs_joined, re.I):
        return "VP", "wrong_error_code_unknown_tool"

    # HC-VP: Claude-Code-only tool / DB schema mismatch / Date non JSON
    if re.search(r'Tool use ID not provided by Claude Code', msgs_joined, re.I):
        return "VP", "tool_requires_claude_code_client"
    if re.search(r'SQLITE_ERROR: no such column', msgs_joined, re.I):
        return "VP", "db_schema_mismatch"
    if re.search(r'Date cannot be represented in JSON Schema', msgs_joined, re.I):
        return "VP", "date_not_json_schema_serializable"

    # HC-VP: "test" in SQL -> SQL injection (input utente concatenato in query)
    if re.search(r'MCP error -32000:.*SQL logic error', msgs_joined, re.I):
        return "VP", "sql_injection_test_in_query"

    # ... (decine di pattern FP aggiuntivi: domain validation, CLI missing,
    #      localized messages JP/CN/KR/VN, API esterne 404/500, ecc.) ...
```

Il file sorgente `pipeline_mcp_check.py` contiene ~80 pattern di regex che distinguono errori di bug reale del server da rumore infrastrutturale/di test env (Zod validation corretta, `test` usato come ID/path/domain, API esterne non disponibili, CLI non installate, messaggi di errore localizzati, ecc.).

**Veri positivi confermati dopo analisi LLM**: 3.361

Ripartizione VP per tipo:
| Tipo di bug | VP |
|---|---:|
| `tool_name_injection_no_error_returned` | ~3.294 |
| `js_runtime_error` (TypeError, ReferenceError, "is not a function") | ~44 |
| `wrong_error_code_unknown_tool` (-32603 invece di -32601) | ~9 |
| `tool_requires_claude_code_client` | 7 |
| `sql_injection_test_in_query` | 3 |
| `db_schema_mismatch` | 1 |
| `date_not_json_schema_serializable` | 1 |
| `tool_response_wrong_structure` / altri | ~3 |

Ripartizione finale: 3.361 VP + 456 FP = 3.817 (tutti classificati da regole HC deterministiche, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "docker-mcp-server", "test": "error-handling-nonexistent-tool",
 "error": {"type": "ErrorHandlingFailure",
 "message": "Server did not return error for non-existent tool"}}

{"server_name": "github-mcp-server", "test": "error-handling-nonexistent-tool",
 "error": {"type": "ErrorHandlingFailure",
 "message": "Server did not return error for non-existent tool"}}

{"server_name": "aws-mcp",
 "error": {"type": "InvocationError",
 "message": "MCP error -32603: Cannot read properties of undefined (reading 'sso_start_url')"}}

{"server_name": "openrpc-mpc-server",
 "error": {"type": "InvocationError",
 "message": "MCP error -32603: \"undefined\" is not valid JSON"}}
