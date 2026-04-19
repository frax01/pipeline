### Tool discovery / schema_violation

**Finding originali (dopo filtro Stage 1)**: 229

1. InvalidToolSchemas — `tool-schema-validation` fallisce su AJV vs JSON Schema meta-schema
```typescript
// src/suites/tool-discovery.ts
const JSON_SCHEMA_META = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'MCP Tool Schema Validator',
  ...
};

constructor() {
  this.ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
  this.schemaValidator = this.ajv.compile(JSON_SCHEMA_META);
}

// Test case 3: Tool schema validation (using AJV)
let schemaErrors = 0;
const schemaDetails: any = { validSchemas: [], invalidSchemas: [] };
for (const tool of tools) {
  const validation = this.validateToolSchema(tool);
  if (validation.valid) {
    schemaDetails.validSchemas.push(tool.name);
  } else {
    schemaErrors++;
    schemaDetails.invalidSchemas.push({ name: tool.name, errors: validation.errors });
  }
}

cases.push({
  name: 'tool-schema-validation',
  status: schemaErrors === 0 ? 'passed' : 'failed',
  details: schemaDetails,
  ...(schemaErrors > 0 ? {
    error: {
      type: 'InvalidToolSchemas',
      message: `${schemaErrors} tools have invalid schemas`,
      details: schemaDetails,
    },
  } : {}),
});
```

`validateToolSchema` compila il `tool.inputSchema` di ogni tool MCP contro il meta-schema JSON Schema draft-07 e applica controlli semantici aggiuntivi (tipo valido, `required` consistente con `properties`, range min/max, regex compilabile). Un tool MCP con `inputSchema` invalido non e' invocabile da client conformi.

**Finding dopo filtro**: 229

| Tipo errore | Count |
|---|---:|
| `InvalidToolSchemas` — N tools have invalid schemas | 229 |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/schema_violation
def hc_rules_tool_discovery_schema_violation(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: InvalidToolSchemas — N tool have invalid schemas.
    Schema invalidi rendono i tool non invocabili da client MCP conformi.
    """
    return "VP", "invalid_tool_schema"
```

**Veri positivi confermati dopo analisi LLM**: 229

Ripartizione finale: 229 VP + 0 FP = 229 (tutti classificati dalla regola HC, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "mempool-mcp-server", "test": "tool-schema-validation",
 "error": {"type": "InvalidToolSchemas", "message": "10 tools have invalid schemas"}}

{"server_name": "mcp-quran", "test": "tool-schema-validation",
 "error": {"type": "InvalidToolSchemas", "message": "10 tools have invalid schemas"}}

{"server_name": "re-stack-mcp", "test": "tool-schema-validation",
 "error": {"type": "InvalidToolSchemas", "message": "11 tools have invalid schemas"}}
