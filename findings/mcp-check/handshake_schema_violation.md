### Handshake / schema_violation

**Finding originali (dopo filtro Stage 1)**: 49

1. ConnectionError durante `connection-establishment` (suite `handshake`)
```typescript
// src/suites/handshake.ts
try {
  const client = new MCPTestClient(context.logger);
  try {
    await client.connectFromTarget(context.config.target);
  } catch (error) {
    await client.connectWithCustomTransport(context.transport);
  }
  // Get server info from SDK client
  const serverCapabilities = client.getServerCapabilities();
  const serverVersion = client.getServerVersion();
  ...
} catch (error) {
  cases.push({
    name: 'connection-establishment',
    status: 'failed',
    durationMs: Date.now() - startTime,
    error: {
      type: 'ConnectionError',
      message: `Failed to establish connection: ${error.message}`,
      details: { error: error.message },
    },
  });
}
```

Il SDK MCP valida la risposta del server all'`initialize` con uno schema Zod; se il server ritorna `capabilities`/`protocolVersion`/`serverInfo` non conformi, il parsing Zod fallisce e il connect lancia `ConnectionError` con l'array di errori `invalid_type` / `invalid_value` / `custom`.

**Finding dopo filtro**: 49

| Tipo errore | Count |
|---|---:|
| ConnectionError (Zod validation su `initialize`) | 49 |

Le regole HC per questa categoria sono banali (tutti VP), perche' ogni entry qui rappresenta un server che viola la specifica MCP nella risposta di handshake:

```python
# FRAMEWORK: mcp-check | CATEGORIA: handshake/schema_violation
def hc_rules_handshake_schema_violation(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: schema invalido durante initialize.
    Il server manda capabilities non conformi alla specifica MCP -> ConnectionError.
    """
    return "VP", "invalid_schema_during_initialize"
```

**Veri positivi confermati dopo analisi LLM**: 49

Ripartizione finale: 49 VP + 0 FP = 49 (tutti classificati da regola HC deterministica, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "Netlify-MCP-Server", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: [{\"code\":\"custom\",\"path\":[\"capabilities\",\"experimental\",\"customWorkflows\"],\"message\":\"Invalid input\"}]"}}

{"server_name": "crypto-signal-mcp", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: [{\"expected\":\"string\",\"code\":\"invalid_type\",\"path\":[\"protocolVersion\"],\"message\":\"Invalid input: expected string, received undefined\"}]"}}

{"server_name": "mcp-server", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: [{\"expected\":\"object\",\"code\":\"invalid_type\",\"path\":[\"capabilities\",\"tools\"],\"message\":\"Invalid input: expected object, received ...\"}]"}}
