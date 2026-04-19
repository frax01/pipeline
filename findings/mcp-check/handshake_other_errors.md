### Handshake / other_errors

**Finding originali (dopo filtro Stage 1)**: 117

La suite `handshake` esegue, oltre alla connection-establishment, i test `ping-test`, `resource-discovery` e `prompt-discovery`. Ogni fallimento runtime in questi test produce un errore tipizzato:

1. PingError / ResourceDiscoveryError / PromptDiscoveryError
```typescript
// src/suites/handshake.ts
try {
  await client.ping();
  ...
} catch (error) {
  cases.push({
    name: 'ping-test',
    status: 'failed',
    error: { type: 'PingError', message: `Ping failed: ${error.message}`, ... },
  });
}

try {
  const resources = await client.listResources();
  ...
} catch (error) {
  cases.push({
    name: 'resource-discovery',
    status: 'failed',
    error: { type: 'ResourceDiscoveryError',
             message: `Resource discovery failed: ${error.message}`, ... },
  });
}

try {
  const prompts = await client.listPrompts();
  ...
} catch (error) {
  cases.push({
    name: 'prompt-discovery',
    status: 'failed',
    error: { type: 'PromptDiscoveryError',
             message: `Prompt discovery failed: ${error.message}`, ... },
  });
}
```

**Finding dopo filtro**: 117

| Tipo errore (tra i principali) | Count |
|---|---:|
| ResourceDiscoveryError / PromptDiscoveryError con unmarshal JSON | rilevante |
| PingError con `Unsupported method: ping` | rilevante |
| RuntimeError JS / Python durante discovery | rilevante |

Le regole HC distinguono errori infrastrutturali (FP) da bug/non-conformance del server (VP):

```python
# FRAMEWORK: mcp-check | CATEGORIA: handshake/other_errors
def hc_rules_handshake_other_errors(entry: dict) -> tuple[str | None, str]:
    msgs_joined = " ".join(_msgs(entry))

    # HC-FP: auth/config mancante
    if _AUTH_FP.search(msgs_joined):
        return "FP", "auth_or_config_missing"
    if re.search(r'Authentication required|authentication not ready|'
                 r'could not read Username|Login.*invalid|'
                 r'Cloning.*fatal:.*Username|no access.*token', msgs_joined, re.I):
        return "FP", "auth_required"

    # HC-FP: WebSocket non disponibile
    if "websocket" in msgs_joined.lower() and "not available" in msgs_joined.lower():
        return "FP", "websocket_infrastructure"

    # HC-FP: dipendenza locale non disponibile (DB, daemon locale)
    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    if re.search(r'No database connection|database.*URL.*should be provided|'
                 r'SSE connection|Failed to connect to.*:\d+', msgs_joined, re.I):
        return "FP", "db_or_transport_not_configured"

    # HC-VP: ping response con chiavi non riconosciute
    if "unrecognized_keys" in msgs_joined:
        return "VP", "ping_response_unrecognized_keys"

    # HC-VP: errori di unmarshal (server Go con bug nel parsing)
    if _UNMARSHAL_VP.search(msgs_joined):
        return "VP", "unmarshal_parse_error"

    # HC-VP: runtime JS/Python error durante discovery
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "js_python_runtime_error"

    # HC-VP: metodo ping/prompts non implementato
    if re.search(r'Unknown method.*ping|Unknown method.*prompts|'
                 r'Unsupported method.*ping', msgs_joined, re.I):
        return "VP", "method_not_implemented"

    # HC-VP: mismatch versione protocollo MCP
    if re.search(r'Unsupported protocol version|protocol version not supported',
                 msgs_joined, re.I):
        return "VP", "protocol_version_mismatch"

    # HC-VP: "Failed to list/get resources/prompts/tools"
    if re.search(r'Failed to (list|get) (resources|prompts|tools)',
                 msgs_joined, re.I):
        return "VP", "discovery_internal_error"

    if re.search(r'Date cannot be represented|Failed to parse URL from|'
                 r'type must be JSONType|invalid_type.*expected.*object',
                 msgs_joined, re.I):
        return "VP", "schema_type_error"

    if "internal error" in msgs_joined.lower():
        return "VP", "internal_error"

    if not msgs_joined.strip() or msgs_joined.strip() in ("-32603: ", "MCP error -32603: "):
        return "FP", "empty_error_message"

    return "VP", "other_error_default_vp"
```

**Veri positivi confermati dopo analisi LLM**: 110

Ripartizione finale: 110 VP + 7 FP = 117 (tutti classificati da regole HC deterministiche, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "FastDomainCheck-MCP-Server", "test": "resource-discovery",
 "error": {"type": "ResourceDiscoveryError",
 "message": "Resource discovery failed: MCP error -32000: failed to unmarshal arguments: unexpected end of JSON input"}}

{"server_name": "domain-lookup-mcp", "test": "prompt-discovery",
 "error": {"type": "PromptDiscoveryError",
 "message": "Prompt discovery failed: MCP error -32000: failed to unmarshal arguments: unexpected end of JSON input"}}

{"server_name": "mcp-server-flomo", "test": "resource-discovery",
 "error": {"type": "ResourceDiscoveryError",
 "message": "Resource discovery failed: MCP error -32603: Cannot destructure property 'name' of 'request.params' as it is undefined."}}
