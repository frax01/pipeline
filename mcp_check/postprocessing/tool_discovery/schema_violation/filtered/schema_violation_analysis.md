# tool_discovery/schema_violation - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 275 |
| Finding filtrati | 275 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 179 |
| go | 69 |
| python | 24 |
| unknown | 3 |

## Finding per tipo di test

### `tool-schema-validation` (237 finding)

**1. [mcp-python](https://github.com/hdresearch/mcp-python)** (python)
- Type: `InvalidToolSchemas`
- Message: `10 tools have invalid schemas`

**2. [awesome-ionic-mcp](https://github.com/Tommertom/awesome-ionic-mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `10 tools have invalid schemas`

**3. [mcp-quran](https://github.com/farabiinnovations/mcp-quran)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `10 tools have invalid schemas`

**4. [dotnet-api-mcp](https://github.com/sametbrr/dotnet-api-mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `10 tools have invalid schemas`

**5. [mcp](https://github.com/vuetifyjs/mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `10 tools have invalid schemas`

**6. [re-stack-mcp](https://github.com/jagreetdg/re-stack-mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `11 tools have invalid schemas`

**7. [mcptestgenerator](https://github.com/atakan-emre/mcptestgenerator)** (python)
- Type: `InvalidToolSchemas`
- Message: `12 tools have invalid schemas`

**8. [aptos-mcp](https://github.com/tamago-labs/aptos-mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `12 tools have invalid schemas`

**9. [nest-llm-aigent](https://github.com/luis1232023/nest-llm-aigent)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `14 tools have invalid schemas`

**10. [anki-connect-mcp](https://github.com/spacholski1225/anki-connect-mcp)** (nodejs)
- Type: `InvalidToolSchemas`
- Message: `14 tools have invalid schemas`

*... e altri 227 finding simili*

### `tool-enumeration` (36 finding)

**1. [mcp-server-rubygems](https://github.com/6/mcp-server-rubygems)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "type"
    ],
    "message": "Invalid input"
  },
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "additionalProperties"
    ],
    "message": "Invalid input"
  },
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "$schema"
    ],
    "message": "Invalid input"
 ...`

**2. [Skolverket-MCP](https://github.com/KSAklfszf921/Skolverket-MCP)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "custom",
    "path": [
      "tools",
      86,
      "inputSchema",
      "properties",
      "_cached"
    ],
    "message": "Invalid input"
  }
]`

**3. [mcp-on-cloudrun-1](https://github.com/divyumsinghal/mcp-on-cloudrun-1)** (python)
- Type: `ToolListError`
- Message: `[
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "type"
    ],
    "message": "Invalid input"
  },
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "additionalProperties"
    ],
    "message": "Invalid input"
  },
  {
    "code": "custom",
    "path": [
      "tools",
      0,
      "inputSchema",
      "properties",
      "$schema"
    ],
    "message": "Invalid input"
 ...`

**4. [rae-mcp](https://github.com/rae-api-com/rae-mcp)** (go)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "outputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      1,
      "outputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path":...`

**5. [valjs](https://github.com/thomasdavis/valjs)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  }
]`

**6. [nmap-mcp-server](https://github.com/PhialsBasement/nmap-mcp-server)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  }
]`

**7. [vuln-fs](https://github.com/0pstech/vuln-fs)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      1,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [...`

**8. [usql-mcp](https://github.com/jvm/usql-mcp)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "outputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      1,
      "outputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  },
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path":...`

**9. [mcp-stock-analysis](https://github.com/giptilabs/mcp-stock-analysis)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      1,
      "outputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  }
]`

**10. [mcp-moments](https://github.com/reyesbho/mcp-moments)** (nodejs)
- Type: `ToolListError`
- Message: `[
  {
    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      4,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""
  }
]`

*... e altri 26 finding simili*

### `initialization` (2 finding)

**1. [smart-tree](https://github.com/8b-is/smart-tree)** (nodejs)
- Type: `InitializationError`
- Message: `[
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "protocolVersion"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

**2. [ioehub-mcp-time-server](https://github.com/ioehub/ioehub-mcp-time-server)** (nodejs)
- Type: `InitializationError`
- Message: `[
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "protocolVersion"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

## Interpretazione

Le **schema violation** indicano tool con schema JSON non valido secondo la specifica MCP/JSON Schema Draft-07. Questo può causare problemi di interoperabilità con i client MCP e potenzialmente comportamenti inattesi. La maggior parte sono **veri positivi** di conformance.

