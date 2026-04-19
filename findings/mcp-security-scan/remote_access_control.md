# RC-01 — REMOTE ACCESS CONTROL EXPOSURE

**Finding originali**: 5

Severity: **critical**.

Lo scanner cerca tool con keyword `remote`, `port`, `expose`, `bind` e prova a chiamarli passando `{"port": 8080}`. Se il response contiene indicatori come `enabled`, `listening`, `bound to`, il tool è considerato un'esposizione di accesso remoto.

```python
def check_remote_access_control_exposure(
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    """
    RC-01: Remote access control exposure.
    Check if server exposes tools that enable/disable remote access or open ports
    without strong authorization.
    """
    if len(tools) == 0:
        return _finding(spec, passed=True, details="No tools were discovered")

    candidates: list[dict[str, Any]] = []
    for tool in tools:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()

        remote_keywords_name = ["remote_access", "remote", "port"]
        remote_keywords_desc = ["remote access", "open port", "expose", "bind"]

        if (any(keyword in name for keyword in remote_keywords_name)
            or any(keyword in desc for keyword in remote_keywords_desc)):
            candidates.append(tool)

    exploited = []
    for tool in candidates:
        tool_name = tool.get("name")
        if tool_name:
            try:
                resp = send_recv_func("tools/call", {"name": tool_name, "arguments": {"port": 8080}})
                text = json.dumps(resp).lower()

                success_indicators = [
                    "remote_access_enabled:true", "remote-access:true",
                    "enabled", "listening", "bound to", "server started"
                ]

                if any(indicator in text for indicator in success_indicators):
                    exploited.append({"tool": tool_name, "resp": resp})
            except Exception:
                continue

    passed = len(exploited) == 0
    details = json.dumps({"candidates": candidates, "exploited": exploited})
    return _finding(spec, passed, details)
```

**Il problema**: il check ha due falle:
1. Keyword troppo permissive: `remote` matcha `remote_config`, `remote_storage`, `remote_query`; `port` matcha `portfolio`, `report`, `important`
2. Indicatori di successo generici: `enabled` appare in qualsiasi response JSON (es. `{"debug_enabled": false}`), `listening` può riferirsi a event listener

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 1 (riduzione −80.0%)

Il filtro cerca pattern REALI di server che ha attivato accesso remoto (listening on port, bound to, server started on) e scarta `enabled` fuori contesto.

```python
def filter_remote_access(finding):
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = str(details) if details else details_str

    # Se c'e' un errore, il server ha rifiutato
    if re.search(r'"isError"\s*:\s*true', details_text):
        return None, "server_rejected"
    if re.search(r'"error"', details_text) and not re.search(r'"result"', details_text):
        return None, "error_response"

    # Evidenza REALE di accesso remoto
    real_access_patterns = [
        re.compile(r'(listening|bound)\s+(on|to|at)\s+\S*:\d+', re.I),
        re.compile(r'server\s+started\s+on\s+\S*:\d+', re.I),
        re.compile(r'remote.?access.?(enabled|activated|opened)', re.I),
        re.compile(r'port\s+\d+\s+(is\s+)?(now\s+)?(open|listening|active)', re.I),
    ]

    for pat in real_access_patterns:
        if pat.search(details_text):
            return details, f"real_remote_access:{pat.pattern[:40]}"

    # "enabled" da solo e' troppo generico
    if re.search(r'\benabled\b', details_text, re.I):
        if re.search(r'(remote|access|port|bind|listen)', details_text, re.I):
            return details, "enabled_in_remote_context"
        return None, "enabled_generic_context"

    return None, "no_remote_access_evidence"
```

---

## Stage 2A — Regole HC

**Nessuna Stage 2A**: solo 1 finding filtrato, analizzato in-chat.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 1 FP manuale.

**FP 1: rhombussystems/rhombus-node-mcp — `report-tool`**

```json
{
    "candidates": [{
        "name": "report-tool",
        "description": "**Scope:** This tool returns **aggregated counts and time-series summaries** over specified intervals and scopes. Use **events-tool** when you need raw, event-level data (individual events with timestamps)..."
    }]
}
```

Il tool è un **report aggregator** per il sistema Rhombus (video surveillance commerciale). La keyword `port` matcha perché `report` contiene la stringa "port" (`re**port**-tool`). Non ha nulla a che vedere con port opening o accesso remoto — restituisce conteggi aggregati e summary temporali di eventi camera/occupancy.

Il tool non accetta nemmeno il parametro `port`: la chiamata di probe ha restituito semplicemente un response descrittivo senza attivare accesso remoto alcuno.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: **0 VP + 1 FP = 1**.

### Perché RC-01 non trova nulla di critico

Il check è progettato su un modello di attacco molto specifico: un tool MCP che quando chiamato apre effettivamente un listener di rete. Nell'ecosistema reale dei 60.205 server analizzati:
- Server MCP girano quasi sempre come processo locale (stdio transport)
- I tool che gestiscono "remote" sono quasi sempre API client (Slack, Jira, GitHub) — "remote" nel nome si riferisce a chiamate HTTP verso API terze, non a listener locali
- Aprire un listener di rete richiederebbe privilegi specifici e capability shell che sono già coperti da X-01 (dangerous-capabilities)

Il risultato 0 VP è coerente: l'attacco modelato da RC-01 non è realistico per server MCP con architettura stdio. Per individuare esposizione di rete reale servirebbe analisi del codice sorgente (listener creation, `net.Listen`, `socket.bind`) — fuori dallo scope di un probe dinamico.
