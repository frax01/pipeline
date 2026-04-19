### Tool discovery / other_errors

**Finding originali (dopo filtro Stage 1)**: 29

1. DuplicateToolNames — test `unique-tool-names` fallisce
```typescript
// src/suites/tool-discovery.ts
const toolNames = tools.map((t) => t.name);
const duplicateNames = this.findDuplicates(toolNames);

cases.push({
  name: 'unique-tool-names',
  status: duplicateNames.length === 0 ? 'passed' : 'failed',
  details: { toolNames, duplicateNames },
  ...(duplicateNames.length > 0 ? {
    error: {
      type: 'DuplicateToolNames',
      message: `Duplicate tool names found: ${duplicateNames.join(', ')}`,
      details: { duplicateNames },
    },
  } : {}),
});
```

2. ToolListError — crash durante `tools/list`
```typescript
// src/suites/tool-discovery.ts
} catch (error) {
  cases.push({
    name: 'tool-enumeration',
    status: 'failed',
    durationMs: 0,
    error: { type: 'ToolListError', message: error.message },
  });
}
```

**Finding dopo filtro**: 29

| Tipo errore | Count |
|---|---:|
| `DuplicateToolNames` | ~11 |
| `ToolListError` (JS/Python runtime) | ~15 |
| `ToolListError` (unmarshal / schema / method_not_found) | ~3 |

```python
# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/other_errors
def hc_rules_tool_discovery_other_errors(entry: dict) -> tuple[str | None, str]:
    msgs_joined = " ".join(_msgs(entry))
    types_list = _types(entry)

    if "DuplicateToolNames" in types_list or "Duplicate tool names" in msgs_joined:
        return "VP", "duplicate_tool_names"

    # FP: infrastruttura / dipendenza esterna
    if "InitializationError" in types_list:
        return "FP", "initialization_error_infrastructure"

    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    # VP: JS/Python runtime errors durante tools/list
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "runtime_error_during_tools_list"

    if re.search(r'Date cannot be represented|Failed to parse URL|'
                 r'type must be JSONType|Unknown method.*tools', msgs_joined, re.I):
        return "VP", "schema_error_during_tools_list"

    if re.search(r'Failed to get tools|Failed to list tools', msgs_joined, re.I):
        return "VP", "tools_list_crash"

    # Default ToolListError -> VP
    return "VP", "tool_list_error_default_vp"
```

**Veri positivi confermati dopo analisi LLM**: 26

Ripartizione finale: 26 VP + 3 FP = 29 (tutti classificati da regole HC deterministiche, UNCERTAIN=0).

**Esempi di VP confermati:**

{"server_name": "github-mcp-server", "test": "unique-tool-names",
 "error": {"type": "DuplicateToolNames",
 "message": "Duplicate tool names found: git_flow, git_sync"}}

{"server_name": "meta-api-mcp-server", "test": "unique-tool-names",
 "error": {"type": "DuplicateToolNames",
 "message": "Duplicate tool names found: SubscripitonItems_Retrieveasubs"}}

{"server_name": "air-mcp", "test": "unique-tool-names",
 "error": {"type": "DuplicateToolNames",
 "message": "Duplicate tool names found: get_repository_by_id"}}
