# handshake/schema_violation - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 51 |
| Finding filtrati | 51 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| nodejs | 43 |
| python | 5 |
| go | 3 |

## Finding per tipo di test

### `tool-discovery` (36 finding)

**1. [mcp-server-rubygems](https://github.com/6/mcp-server-rubygems)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
    "mess...`

**2. [Skolverket-MCP](https://github.com/KSAklfszf921/Skolverket-MCP)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
    "mess...`

**4. [rae-mcp](https://github.com/rae-api-com/rae-mcp)** (go)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
      "obj...`

**5. [valjs](https://github.com/thomasdavis/valjs)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
      "objec...`

**8. [usql-mcp](https://github.com/jvm/usql-mcp)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
      "obj...`

**9. [mcp-stock-analysis](https://github.com/giptilabs/mcp-stock-analysis)** (nodejs)
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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
- Type: `ToolDiscoveryError`
- Message: `Tool discovery failed: [
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

### `resource-discovery` (8 finding)

**1. [npm-helper-mcp](https://github.com/pinkpixel-dev/npm-helper-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "array",
    "code": "invalid_type",
    "path": [
      "resources"
    ],
    "message": "Invalid input: expected array, received undefined"
  }
]`

**2. [mcp-memory](https://github.com/sdimitrov/mcp-memory)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      0,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      1,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

**3. [mcp-hats](https://github.com/dennisonbertram/mcp-hats)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "array",
    "code": "invalid_type",
    "path": [
      "resources"
    ],
    "message": "Invalid input: expected array, received object"
  }
]`

**4. [build-mcp](https://github.com/ekdh600/build-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      0,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      1,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resource...`

**5. [trademark-mcp-server](https://github.com/jordanburke/trademark-mcp-server)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      0,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      1,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

**6. [liveagent-mcp-server](https://github.com/qualityunit/liveagent-mcp-server)** (python)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      0,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      1,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resource...`

**7. [architecture-mcp](https://github.com/regul4rj0hn/architecture-mcp)** (go)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "array",
    "code": "invalid_type",
    "path": [
      "resources"
    ],
    "message": "Invalid input: expected array, received null"
  }
]`

**8. [helperpro-mcp](https://github.com/jonathanhecl/helperpro-mcp)** (nodejs)
- Type: `ResourceDiscoveryError`
- Message: `Resource discovery failed: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      0,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "resources",
      1,
      "uri"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

### `connection-establishment` (6 finding)

**1. [crypto-signal-mcp](https://github.com/myownipgit/crypto-signal-mcp)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "protocolVersion"
    ],
    "message": "Invalid input: expected string, received undefined"
  },
  {
    "expected": "object",
    "code": "invalid_type",
    "path": [
      "capabilities"
    ],
    "message": "Invalid input: expected object, received undefined"
  }
]`

**2. [smart-tree](https://github.com/8b-is/smart-tree)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "protocolVersion"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

**3. [mcp-server](https://github.com/elijahdev0/mcp-server)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "object",
    "code": "invalid_type",
    "path": [
      "capabilities",
      "tools"
    ],
    "message": "Invalid input: expected object, received boolean"
  }
]`

**4. [filesys](https://github.com/gomcpgo/filesys)** (go)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "array",
    "code": "invalid_type",
    "path": [
      "serverInfo",
      "icons",
      0,
      "sizes"
    ],
    "message": "Invalid input: expected array, received string"
  }
]`

**5. [mcp-ping-app](https://github.com/cantrk21/mcp-ping-app)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "serverInfo",
      "version"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

**6. [ioehub-mcp-time-server](https://github.com/ioehub/ioehub-mcp-time-server)** (nodejs)
- Type: `ConnectionError`
- Message: `Failed to establish connection: [
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "protocolVersion"
    ],
    "message": "Invalid input: expected string, received undefined"
  }
]`

### `prompt-discovery` (1 finding)

**1. [tradovate-mcp-server](https://github.com/alexanimal/tradovate-mcp-server)** (nodejs)
- Type: `PromptDiscoveryError`
- Message: `Prompt discovery failed: [
  {
    "expected": "array",
    "code": "invalid_type",
    "path": [
      "prompts",
      0,
      "arguments"
    ],
    "message": "Invalid input: expected array, received object"
  }
]`

## Interpretazione

Le **schema violation** indicano tool con schema JSON non valido secondo la specifica MCP/JSON Schema Draft-07. Questo può causare problemi di interoperabilità con i client MCP e potenzialmente comportamenti inattesi. La maggior parte sono **veri positivi** di conformance.

