### TOOL-POISONING

**Finding originali**: 136 (solo `HIDDEN_TOOL_INSTRUCTIONS`; `TOOL_SHADOWING` escluso da analisi)

**Severity**: critical.

Lo scanner `ToolPoisoningScanner` cerca, nelle stesse righe che contengono la parola `description`, pattern di prompt injection nascosta:

```typescript
private hasHiddenInstructions(line: string): boolean {
  const injectionPatterns = [
    /ignore\s+(previous|all)\s+instructions/i,
    /system\s*:\s*you\s+are\s+now/i,
    /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]/i,
    /act\s+as\s+(?:if|a)/i,
    /forget\s+(everything|all)/i,
  ];
  return (
    line.toLowerCase().includes("description") &&
    injectionPatterns.some((pattern) => pattern.test(line))
  );
}
```

**Il problema**: il requisito "riga contiene `description`" è soddisfatto da qualsiasi
file che definisce modelli Pydantic o campi di schema JSON. I pattern come
`act\s+as\s+(?:if|a)` matchano frasi inglesi comuni (`users who act as additional
requesters`), `\[SYSTEM\]` matcha etichette legittime (`[SYSTEM][SAFE] Find
workflows...`), e `overrides:` come nome di campo Pydantic è scambiato per
l'istruzione "override".

---

## Stage 1 — filter_remaining_categories.py

**Finding dopo filtro**: 7 (riduzione 94.9%)

Il filtro scarta: test/spec, bundle minificati, third-party (`node_modules`,
`site-packages`), documentazione, server honeypot/scanner intenzionalmente
vulnerabili, README/DOC files, cataloghi di modelli LLM, `# type: ignore[override]`
di mypy, label `[ADMIN]`/`[SYSTEM]` come prefisso di CLI tool legittimo.

```python
_SECURITY_SCANNER_SERVERS = {
    "vulnicheck", "AgentShield", "ZugaShield", "mcp-scanner", "mcpscc",
    "MCP-Security-Agent", "MUSUBIX", "wundr", "tool-scan",
    "mighty-security", "mcp-inject-bender", "secure-mcp-gateway",
    "agentscore-mcp", "agent-security-scanner-mcp", ...
}
```

---

## Stage 2A — Regole HC

Il modulo `hc_rules_tool_poisoning` in `pipeline_mcp_watch.py` applica 6 pattern HC-FP:

- `_TP_PYDANTIC_OVERRIDE` → campo Pydantic `overrides:`/`admins:` scambiato per
  istruzione "override"/"admin"
- `_TP_DESC_PASSTHROUGH` → `description: (artifact as any).description` — passa
  la description esistente, non contiene injection
- `_TP_SAFE_LABEL` → `[SYSTEM][SAFE]` come prefisso di tool benigno
- `_TP_ACT_AS_BENIGN` → `who act as`, `act as a delegate/requester/persona`
- `_TP_PERSONA_ROLEPLAY` → `roleplay as legendary founder` (startup-sim MCP)
- `_TP_LONG_API_DESC` → descrizione REST API lunga senza contenuto di injection

**Risultato Stage 2A**: 7 HC-FP, 0 HC-VP, 0 UNCERTAIN.

---

## Stage 2B — Analisi LLM

**Nessuna Stage 2B**: tutti i 7 finding classificati dalle regole HC. Nessun
UNCERTAIN da mandare a Ollama.

---

**Veri positivi confermati**: 0

Ripartizione finale: **0 VP + 7 FP = 7**.

### I 7 FP

| Server | Evidence |
|--------|----------|
| `pagerduty-mcp-server` | `overrides: list[Override] = Field(description="The list of overrides to create...")` — campo Pydantic |
| `ag2-mcp-servers/my-business-account-management-api` | `admins: Optional[List[Admin]] = Field(...)` — campo Pydantic |
| `mcp-zebrunner` (×2) | `description: (artifact as any).description` — passthrough |
| `blender-ai-mcp` | `[SYSTEM][SAFE] Find workflows similar to a description.` — label legittimo |
| `ag2-mcp-servers/lgtm-api-specification` | `description="The REST API for LGTM provides data..."` — descrizione API REST lunga |
| `dhinesh-superops/mcp_server_demo` | `"The list of client users who act as additional requesters..."` — inglese normale |

### Perché tool-poisoning non produce VP

Il pattern di attacco modellato (injection nascosta nella description di un
tool) è teoricamente serio, ma la regex dello scanner richiede solo che la
stessa riga contenga `description` + una keyword generica. Nel dataset di
60.205 server non si è mai trovata una vera tool description con contenuto di
injection — tutti i 136 finding (e i 7 residui dopo filtro) sono:
- campi Pydantic con nomi che matchano keyword ("overrides", "admins")
- label legittimi usati come prefissi di modalità operative
- frasi inglesi che contengono "act as" in senso non-istruzionale

Il vero rilevamento di tool poisoning richiede **analisi semantica della
description** (come fa `mcp-shield` con Claude API, v. `hidden_instructions.md`),
non keyword matching.
