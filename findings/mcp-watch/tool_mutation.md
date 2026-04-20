### TOOL-MUTATION

**Finding originali**: 18.856 (solo `DYNAMIC_TOOL_MUTATION`;
`TOOL_NAME_COLLISION` escluso da analisi).

**Severity**: high.

Lo scanner `ToolMutationScanner` cerca nel codice sorgente pattern di
modifica runtime della lista dei tool visibili al client:

```typescript
const mutationPatterns = [
  /tools?\.push\s*\(/,
  /tools?\.splice\s*\(/,
  /tools?\.pop\s*\(/,
  /tools?\.shift\s*\(/,
  /tools?\.unshift\s*\(/,
  /tools?\s*\[\s*\w+\s*\]\s*=/,
];
```

L'idea è rilevare un **rug pull dinamico**: il server aggiunge, modifica o
rimuove tool **dopo** il completamento del handshake `tools/list`.

**Il problema**: i pattern matchano qualsiasi assegnazione a un dict chiamato
`tools` — e il *paradigma standard* di registrazione in MCP Python/TS è proprio
`self.tools[name] = handler` nel costruttore o in `setup_tools()`. La stragrande
maggioranza dei 18.856 finding è codice di registrazione, non di mutazione
runtime.

---

## Stage 1 — filter_remaining_categories.py

**Finding dopo filtro**: 2.577 (riduzione 86.3%)

Il filtro scarta: test/spec, bundle minificati, third-party, documentazione,
e pattern di registration chiaramente intenzionali (init/register/setup/
configure/forEach/map contexts, `categoriesTools[x].push` bucket builds).

Tiene tutto ciò che ha `filter_confidence='tools_index_assignment'` —
cioè `self.tools[key] = value` o `tools[x] = y` in contesti non-esclusi.

---

## Stage 2A — Regole HC

`hc_rules_tool_mutation` applica 3 livelli di esclusione:

1. **File path di registry** (`tool_registry.py`, `tools_config.py`,
   `registry.py`, `setup.py`, ...) → HC-FP
2. **Evidence di read-only** (`for tool in tools`, `tool["name"] == ...`) →
   HC-FP
3. **Pattern di registration noti** (10+ regex):
   - prefissi comuni (`all_`, `available_`, `enabled_`, `registered_`,
     `preferred_`, `transformed_`, `converted_`, `namespaced_`,
     `discovered_`, `processed_`, ...)
   - `self.tools[...]`, `this.tools[...]`, `cls.tools[...]`
   - namespaced (`capabilities.tools`, `server._tool_manager._tools`)
   - field tagging (`tool["key"] = value`)
   - catch-all `\w+_?tools?\[...\] = ...`

**Risultato Stage 2A**: 2.577 HC-FP, 0 HC-VP, 0 UNCERTAIN.

---

## Stage 2B — Analisi LLM

**Nessuna Stage 2B**: l'analisi campionaria di 40 + 50 finding ha confermato
che 100% dei pattern residui sono registration/aggregation/transformation.

---

**Veri positivi confermati**: 0

Ripartizione finale: **0 VP + 2.577 FP = 2.577**.

### Categorie di pattern osservati (tutti FP)

1. **Registry standard MCP Python**: `self.tools[tool.name] = tool`,
   `self._tools[name] = func` — il pattern idiomatico del framework FastMCP.
2. **TypeScript registrar**: `this.tools[options.name] = options`,
   `capabilities.tools["name"] = {...}` — implementazioni del server SDK.
3. **Tool transformation/namespacing**: `transformed_tools[key] = tool`,
   `namespaced_tool["name"] = namespace + name` — middleware MCP che
   riesporta tool da server a valle.
4. **Aggregation dictionaries**: `all_servers_with_tools[server_name] = ...`,
   `server_tools[key] = [...]` — gateway/proxy che collezionano tool da
   più server.
5. **Metadata tagging**: `tool["_metadata"] = {...}`,
   `tool["success_rate"] = ...` — aggiunta di campi ausiliari, non mutazione
   della lista.
6. **Security/audit tooling**: `shadowed_tools[tool_name] = instruction`
   (honeypot `mcp_vulnerable_testbed`), `zombie_tools[server_name] = ...`
   (detector), `diff.modified_tools[...]` (`mcp-context-protector`) —
   strumenti che **osservano** mutazioni, non le eseguono.

### Perché DYNAMIC_TOOL_MUTATION non produce VP con analisi statica

Un vero rug-pull tool mutation richiede:
- modifica della lista `tools` **visibile al client**
- **dopo** `initialize` e `tools/list`
- in un handler runtime (event listener, websocket, setInterval)

Nessuno di questi elementi è rilevabile dalla riga di codice isolata che lo
scanner vede. Il probe **dinamico** di `mcp-security-scan` (categoria
`rug-pull`) confronta `tools/list` prima e dopo un intervallo — ma anche
quello ha trovato 0 VP (tutti startup race). Il vettore "tool mutation" è
largamente teorico nell'ecosistema MCP reale.
