### Handshake / invalid_arguments

**Finding originali (dopo filtro Stage 1)**: 7

1. ConnectionError con codice JSON-RPC `-32602` (Invalid params)
```typescript
// src/suites/handshake.ts
try {
  await client.connectFromTarget(context.config.target);
} catch (error) {
  cases.push({
    name: 'connection-establishment',
    status: 'failed',
    error: {
      type: 'ConnectionError',
      message: `Failed to establish connection: ${error.message}`,
      details: { error: error.message },
    },
  });
}
```

Durante l'handshake il client invia `initialize` con `protocolVersion`/`capabilities`/`clientInfo` standard. Un `-32602 Invalid request parameters` significa che il server sta rifiutando parametri del SDK MCP ufficiale — puo' essere un bug (VP) oppure una validazione legittima per un server che richiede auth/context preliminare (FP).

**Finding dopo filtro**: 7

Categoria senza HC (`has_hc: False`): classificazione esclusivamente via cache in-chat popolata da Sonnet.

```python
# CATEGORIA senza HC rules: classificata direttamente via _llm_api_cache.json
"handshake/invalid_arguments": {
    "phase": "handshake",
    "category": "invalid_arguments",
    "filename": "invalid_arguments_filtered.json",
    "description": "Errori -32602 durante handshake",
    "has_hc": False,
},
```

La cache in-chat distingue:
- **VP**: il server rifiuta un handshake SDK-standard senza motivo documentato (client MCP ufficiale dovrebbe essere sempre accettato).
- **FP**: il server richiede per design parametri extra (auth token, session context) che il SDK generico non fornisce — comportamento sensato ma non conforme alla spec MCP base.

**Veri positivi confermati dopo analisi LLM**: 2

Ripartizione finale: 2 VP + 5 FP = 7 (tutti classificati via cache in-chat, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "talebook-mcp", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: MCP error -32602: Invalid request parameters"}}

{"server_name": "prayer-times-mcp-server", "test": "connection-establishment",
 "error": {"type": "ConnectionError",
 "message": "Failed to establish connection: MCP error -32602: Invalid request parameters"}}
