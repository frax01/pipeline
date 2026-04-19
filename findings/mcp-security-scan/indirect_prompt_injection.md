# P-03 — INDIRECT PROMPT INJECTION VIA EXTERNAL RESOURCES

**Finding originali**: 3

Severity: **high**.

Lo scanner identifica risorse con URI esterno (`external://`, `http://`, `https://`), le legge e cerca pattern di prompt injection nel contenuto. Se trova un tool di summarize, prova anche a farlo elaborare la risorsa per vedere se l'injection si propaga.

```python
def check_indirect_prompt_injection(
    resources: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    """
    P-03: Indirect prompt injection via external resources.
    """
    p03_hits: list[dict[str, Any]] = []

    external_candidates = [
        r for r in (resources or [])
        if isinstance(r, dict) and isinstance(r.get("uri"), str)
        and (r["uri"].startswith("external://")
             or r["uri"].startswith("http://")
             or r["uri"].startswith("https://"))
    ]

    inj_patterns = [
        "ignore previous instructions",
        "do not disclose",
        "exfiltrate",
        "send secrets",
        "hidden instruction",
        "override",
        "leak",
    ]

    # Trova tool di summarize
    summarize_tool = None
    for t in tools or []:
        name = (t.get("name") or "").lower()
        desc = (t.get("description") or "").lower()
        if any(k in name for k in ["summarize", "summary"]) or any(
            k in desc for k in ["summarize", "summary"]
        ):
            summarize_tool = t.get("name")
            break

    for r in external_candidates:
        uri = r.get("uri")
        read_resp = send_recv_func("resources/read", {"uri": uri})
        text = json.dumps(read_resp).lower()
        suspicious = any(p in text for p in inj_patterns)
        exploited = False
        summary_resp = None

        if summarize_tool:
            try:
                summary_resp = send_recv_func("tools/call",
                    {"name": summarize_tool, "arguments": {"uri": uri}})
                stext = json.dumps(summary_resp).lower()
                if any(p in stext for p in inj_patterns) or any(
                    k in stext for k in ["secret", "token", "password"]):
                    exploited = True
            except Exception:
                pass

        if suspicious or exploited:
            p03_hits.append({
                "resource": r, "suspicious": suspicious, "exploited": exploited,
                "resource_read": read_resp, "summary": summary_resp,
            })

    passed = len(p03_hits) == 0
    details = json.dumps(p03_hits)
    return _finding(spec, passed, details)
```

**Il problema**: gli `inj_patterns` includono parole generiche come `override` e `leak` che appaiono molto spesso in documentazione tecnica legittima (es. "override a default", "memory leak"). Inoltre risorse esterne come `llms.txt` o documentazione MCP contengono termini come "instructions" nel contesto normale.

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 3 (riduzione 0%, nessuno scartato)

Il filtro per P-03 è minimo: scarta solo crash/no-response. I 3 finding vanno direttamente all'analisi semantica.

```python
def filter_indirect_prompt_injection(finding):
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)
    if details:
        return details, "kept"
    return None, "empty_details"
```

---

## Stage 2A — Regole HC

**Nessuna Stage 2A**: solo 3 finding, analizzati direttamente in-chat.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 3 FP manuali.

Tutti e 3 i finding sono falsi positivi — risorse di documentazione legittima (`llms.txt`) che contengono termini generici flaggati dallo scanner:

**FP 1: olaservo/mcp-advisor — risorsa `modelcontextprotocol.io/tutorials/index.md`**

```json
{
    "resource": {"uri": "https://modelcontextprotocol.io/tutorials/index.md", ...},
    "suspicious": true,
    "resource_read": {"text": "> ## Documentation Index\n> Fetch the complete documentation index at: https://modelcontextprotocol.io/llms.txt\n> Use this file to discover..."}
}
```

La risorsa è la documentazione ufficiale di Model Context Protocol. Lo scanner ha flaggato keyword "instructions" presente nel testo normale della documentazione. Nessuna injection reale.

**FP 2: SecretiveShell/MCP-llms-txt — risorsa `ast-grep.github.io/llms-full.txt`**

```json
{
    "resource": {"uri": "https://ast-grep.github.io/llms-full.txt", ...},
    "suspicious": true,
    "resource_read": {"text": "---\nurl: /reference/cli/new.md\n---\n\n# `ast-grep new`\n\nCreate new ast-grep project or items like rules/tes..."}
}
```

File `llms.txt` di `ast-grep` (tool di code search legittimo). Il server MCP è un aggregatore di `llms.txt` files. Il match su `override` o `leak` è in contesto tecnico completamente normale.

**FP 3: LostInBrittany/clever-doc-mcp-server — risorsa `clever-cloud.com/developers/llms.txt`**

```json
{
    "resource": {"uri": "https://www.clever-cloud.com/developers/llms.txt", ...},
    "suspicious": true,
    "resource_read": {"text": "# Clever Cloud Documentation\n\n> Clever Cloud is a Platform-as-a-Service (PaaS)..."}
}
```

Documentazione di Clever Cloud. Nessuna injection reale nel contenuto.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: **0 VP + 3 FP = 3**.

### Perché P-03 non trova nulla

L'attacco modelato (injection nascosta in risorse `llms.txt` o altre risorse esterne controllate da attaccanti) è teoricamente rilevante, ma i pattern di match dello scanner sono troppo generici. Parole come `override`, `leak`, `instructions` sono parte del vocabolario tecnico ordinario.

Nessuno dei 3 server analizzati espone risorse con veri payload di prompt injection — sono tutti aggregatori di documentazione pubblica legittima. Per rilevare injection reali servirebbe analisi semantica (come quella fatta da mcp-shield con Claude API sulle tool description, non sui contenuti di risorse esterne).

I 3 finding sono conseguenza di un match troppo permissivo: `exfiltrate` o `ignore previous instructions` non appaiono nei contenuti, ma basta che appaiano parole come `override` o `leak` perché un finding venga creato.
