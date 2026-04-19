### Tool discovery / warnings

**Finding originali (dopo filtro Stage 1)**: 357

1. Warning `tool-description-quality` — tool senza description
```typescript
// src/suites/tool-discovery.ts
// Test case 5: Tool description quality
const toolsWithoutDescription = tools.filter(
  (t) => !t.description || t.description.trim().length === 0,
);
const hasDescriptionIssues = toolsWithoutDescription.length > 0;

cases.push({
  name: 'tool-description-quality',
  status: hasDescriptionIssues ? 'warning' : 'passed',
  durationMs: 5,
  details: {
    totalTools: tools.length,
    toolsWithDescription: tools.length - toolsWithoutDescription.length,
    toolsWithoutDescription: toolsWithoutDescription.map((t) => t.name),
  },
  ...(hasDescriptionIssues ? {
    warnings: [`${toolsWithoutDescription.length} tools lack descriptions`],
  } : {}),
});
```

**Finding dopo filtro**: 357

| Warning | Count |
|---|---:|
| `tool-description-quality` (`N tools lack descriptions`) | 357 |

Un tool MCP senza `description` non e' esplicitamente vietato dalla spec ma e' un serio problema di usabilita': l'LLM orchestrante riceve soltanto il nome del tool e deve indovinare quando/come invocarlo.

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/warnings
def hc_rules_tool_discovery_warnings(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP (quality): tool senza description.
    Un tool MCP senza description non puo' essere usato correttamente dall'LLM.
    """
    return "VP", "tool_missing_description"
```

**Veri positivi confermati dopo analisi LLM**: 357

Ripartizione finale: 357 VP + 0 FP = 357 (tutti classificati dalla regola HC, UNCERTAIN=0). Tutti VP di tipo "quality" — non sono bug di conformance stretti ma problemi di usabilita' concreti per l'LLM orchestrante.

**Esempi di VP confermati:**

{"server_name": "hyperbolic-mcp", "test": "tool-description-quality",
 "warning": {"message": "9 tools lack descriptions"}}

{"server_name": "mcp-server-leetcode", "test": "tool-description-quality",
 "warning": {"message": "7 tools lack descriptions"}}

{"server_name": "pulumi-mcp-server", "test": "tool-description-quality",
 "warning": {"message": "1 tools lack descriptions"}}
