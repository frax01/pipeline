### Handshake / method_not_found

**Finding originali (dopo filtro Stage 1)**: 289

1. ConnectionError con codice JSON-RPC `-32601` (Method not found)
```typescript
// src/suites/handshake.ts
try {
  await client.connectFromTarget(context.config.target);
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

Durante `connect()` il SDK invia la chiamata `initialize`; se il server risponde con `-32601 Method not found` (oppure `Method not found: initialize`) il SDK propaga l'errore come `ConnectionError`. Tutti i 289 finding contengono il marker `-32601` e indicano server che non implementano affatto il metodo MCP `initialize` (o la versione handshake richiesta), cioe' non espongono un endpoint MCP conforme.

**Finding dopo filtro**: 289

| Messaggio | Count |
|---|---:|
| `-32601: Method not found` (generico) | — |
| `-32601: Method not found: initialize` | — |

```python
# FRAMEWORK: mcp-check | CATEGORIA: handshake/method_not_found
def hc_rules_handshake_method_not_found(entry: dict) -> tuple[str | None, str]:
    """Tutti VP: server non implementa initialize o altri metodi richiesti (-32601)."""
    return "VP", "method_not_found_during_handshake"
```

**Veri positivi confermati dopo analisi LLM**: 289

Ripartizione finale: 289 VP + 0 FP = 289 (tutti classificati dalla regola HC, UNCERTAIN=0). Un server che non implementa `initialize` non e' un server MCP conforme: il client non puo' proseguire con alcun altro metodo.

**Esempi di VP confermati:**

{"server_name": "sleeper-scraper-mcp", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: MCP error -32601: Method not found"}}

{"server_name": "network_utility_mcp_server", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: MCP error -32601: Method not found: initialize"}}

{"server_name": "python-sdk-to-mcp-converter", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: MCP error -32601: method not found: initialize"}}
