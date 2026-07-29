# tool_invocation/panic_or_crash - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Statistiche

| Metrica | Valore |
|---------|--------|
| Finding originali | 5 |
| Finding filtrati | 5 |
| Rimossi | 0 (0.0%) |

## Distribuzione per linguaggio

| Linguaggio | Count |
|------------|-------|
| go | 5 |

## Finding per tipo di test

### `tool-authorize_api-basic-invocation` (1 finding)

**1. [asgardeo-mcp-server](https://github.com/asgardeo/asgardeo-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in authorize_api tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-create_api_resource-basic-invocation` (1 finding)

**1. [asgardeo-mcp-server](https://github.com/asgardeo/asgardeo-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in create_api_resource tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-create_m2m_app-basic-invocation` (1 finding)

**1. [asgardeo-mcp-server](https://github.com/asgardeo/asgardeo-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in create_m2m_app tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-buzzer_control-basic-invocation` (1 finding)

**1. [mcp-iot-go](https://github.com/sukeesh/mcp-iot-go)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in buzzer_control tool handler: interface conversion: interface {} is nil, not float64`

### `tool-generate_password_characters-basic-invocation` (1 finding)

**1. [opgen-mcp-server](https://github.com/syumai/opgen-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in generate_password_characters tool handler: interface conversion: interface {} is nil, not float64`

### `tool-generate_password_words-basic-invocation` (1 finding)

**1. [opgen-mcp-server](https://github.com/syumai/opgen-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in generate_password_words tool handler: interface conversion: interface {} is nil, not float64`

### `tool-list_cpu-basic-invocation` (1 finding)

**1. [talos-mcp](https://github.com/qjoly/talos-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in list_cpu tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-list_disks-basic-invocation` (1 finding)

**1. [talos-mcp](https://github.com/qjoly/talos-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in list_disks tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-list_memory-basic-invocation` (1 finding)

**1. [talos-mcp](https://github.com/qjoly/talos-mcp)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in list_memory tool handler: runtime error: invalid memory address or nil pointer dereference`

### `tool-sonar_duplications-basic-invocation` (1 finding)

**1. [sonar-mcp-server](https://github.com/lreimer/sonar-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in sonar_duplications tool handler: interface conversion: interface {} is nil, not string`

### `tool-sonar_hotspots-basic-invocation` (1 finding)

**1. [sonar-mcp-server](https://github.com/lreimer/sonar-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in sonar_hotspots tool handler: interface conversion: interface {} is nil, not []interface {}`

### `tool-sonar_issues-basic-invocation` (1 finding)

**1. [sonar-mcp-server](https://github.com/lreimer/sonar-mcp-server)** (go)
- Type: `InvocationError`
- Message: `MCP error -32603: panic recovered in sonar_issues tool handler: interface conversion: interface {} is nil, not string`

## Interpretazione

I **panic/crash** indicano bug reali nel codice del server. Un server MCP che va in panic su input validi è potenzialmente vulnerabile a DoS. Tutti i finding in questa categoria sono **veri positivi**.

