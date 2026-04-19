# POTENTIAL-EXFILTRATION

**Finding originali**: 1.621

Ripartizione per severity: 73 HIGH + 1.548 MEDIUM.

mcp-shield rileva tool con parametri che **potrebbero essere usati per esfiltrazione dati** (context, metadata, notes, debug, reasoning, details, feedback, annotation, ecc.). Tutti i trigger raccolti nei 1621 finding sono nel formato `<nome_parametro> (<tipo>)`, ad esempio:

- `"context (string)"`
- `"metadata (object)"`
- `"notes (array)"`
- `"debug (boolean)"`
- `"reasoning (string)"`
- `"details (object)"`

In pratica mcp-shield flagga qualsiasi tool il cui schema dichiara un parametro con uno di questi nomi "sospetti", anche quando la tool description non contiene alcuna evidenza reale di esfiltrazione.

---

**Finding dopo filtro**: 1.621 (nessun filtro regex intermedio applicato)

Come per le altre categorie mcp-shield, non c'e' Fase 2 a regex: si passa direttamente allo Stage 2A di regole HC deterministiche dentro `pipeline_mcp_shield.py`.

**Regole HC principali** (da `pipeline_mcp_shield.py`, funzione `hc_rules_potential_exfiltration`):

```python
_PE_PARAM_TYPE = r"(?:string|object|boolean|array|integer|number|unknown|null)"
_PE_PARAM_SCHEMA_PAT = re.compile(
    rf"^\w+\s+\({_PE_PARAM_TYPE}(?:,{_PE_PARAM_TYPE})*\)$",
    re.IGNORECASE,
)

def hc_rules_potential_exfiltration(f: dict) -> tuple[str, str]:
    descriptions = _desc_list(f)
    # Tutti i trigger sono annotazioni schema parametro: "<nome> (<tipo>)"
    # Avere un parametro "context" o "metadata" non e' evidenza di esfiltrazione.
    if descriptions and all(_PE_PARAM_SCHEMA_PAT.match(d) for d in descriptions):
        return "HC-FP", "hc_fp:parameter_schema_annotation_not_exfiltration"
    return "UNCERTAIN", ""
```

Tutti i 1.621 trigger matchano il pattern `<parola> (<tipo>)` = annotazione schema parametro, **non** istruzione di esfiltrazione.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: 0 VP + 1.621 FP = 1.621 (tutti HC-FP, 0 UNCERTAIN).

### Perche' tutti sono FP

Analisi del dataset completo:

- **Nessun finding con llm_risk=HIGH nel gruppo HIGH severity** (34 LOW + 34 MEDIUM sul lato LLM di shield).
- Solo **13 MEDIUM severity con llm_risk=HIGH**, tutti FP a ispezione (campi CRM, kubectl, memory tools).
- **Nessuna description contiene linguaggio di esfiltrazione esplicita** (URL attaccante, "send conversation to", "collect all", ecc.).

Esempi di falsi positivi "sospetti" analizzati manualmente:

- `librarian/record`: il termine "webhook" era in un **esempio testuale** nella description, non nel comportamento del tool.
- `mcp-memento/checkpoint_context`: "entire conversation" si riferisce al **salvataggio locale** della conversazione, non all'invio esterno.
- `ccusage-mcp-server/send-usage`: invia **conteggi di token** a uno spreadsheet dell'utente, non dati della conversazione.

### Limite del detector

La detection e' puramente basata sul nome dei parametri nello schema del tool. Un MCP server che definisce un parametro `metadata: object` viene flaggato esattamente come un server malevolo che definisse `exfiltrated_conversation: string`. Serve un'analisi semantica (LLM o manuale) della description e dell'implementazione per distinguere i due casi — e in questo dataset nessuno dei 1.621 finding mostra segnali di esfiltrazione reale.
