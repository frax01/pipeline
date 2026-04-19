# P-02 — PROMPT INJECTION (TOOL DESCRIPTION)

**Finding originali**: 35

Severity: **high**.

Lo scanner cerca frasi di prompt injection nelle tool description restituite da `tools/list`.

```python
def check_prompt_injection_heuristics(tools: list[dict[str, Any]], spec: SpecCheck) -> Finding:
    bad_phrases = [
        "ignore any safety rules",
        "override other tools",
        "include contents of",
        "do not disclose this instruction",
        "hidden instruction",
    ]

    hits: List[Dict[str, object]] = []
    for tool in tools:
        desc = (tool.get("description") or "").lower()
        if any(phrase in desc for phrase in bad_phrases):
            hits.append(tool)

    passed = len(hits) == 0
    details = json.dumps(hits)
    return _finding(spec, passed, details)
```

**Il problema**: keyword come `hidden instruction`, `ignore any safety rules`, `override other tools` matchano anche:
- **Scanner di sicurezza** che *descrivono* pattern di injection per rilevarli
- **Honeypot/server vulnerabili intenzionali** costruiti per testare vulnerabilità
- Documentazione/tool di security awareness

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 3 (riduzione −91.4%)

Il filtro distingue VERA injection da tool di sicurezza che descrivono pattern di attacco.

```python
REAL_PROMPT_INJECTION_PATTERNS = [
    re.compile(r'HIDDEN\s+INSTRUCTION', re.I),
    re.compile(r'INVISIBLE\s+TO\s+USER', re.I),
    re.compile(r'ignore\s+(any\s+)?(previous|prior|all)\s+(instructions|rules|safety)', re.I),
    re.compile(r'do\s+not\s+disclose\s+this', re.I),
    re.compile(r'exfiltrate', re.I),
    re.compile(r'send\s+(secrets|credentials|tokens|data)\s+to', re.I),
    re.compile(r'malicious[_-]?\w*\.evil', re.I),
    re.compile(r'override\s+(other\s+)?tools', re.I),
    re.compile(r'include\s+contents\s+of', re.I),
    re.compile(r'secretly\s+(send|transmit|exfiltrate|forward)', re.I),
    re.compile(r'pretend\s+to\s+be', re.I),
    re.compile(r'act\s+as\s+if\s+you\s+are', re.I),
    re.compile(r'when\s+(the\s+)?(user|human)\s+(is\s+)?not\s+(looking|watching|aware)', re.I),
]

# Contesti che generano falsi positivi (tool di sicurezza)
SECURITY_TOOL_PATTERNS = [
    re.compile(r'(check|scan|detect|analyze|inspect|validate)\s+(for\s+)?(prompt\s+injection|injection|suspicious)', re.I),
    re.compile(r'security\s+(scan|check|analys|audit)', re.I),
    re.compile(r'(blocked|safe|trust|verify|protect)', re.I),
]


def filter_prompt_injection(finding):
    # CHECK 1: Server crashed → non è prompt injection
    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    kept_tools = []
    for tool_def in details:
        desc = tool_def.get("description", "")
        name = tool_def.get("name", "")

        # CHECK 2: E' un tool di sicurezza?
        is_security_tool = any(pat.search(desc) for pat in SECURITY_TOOL_PATTERNS)
        is_security_name = any(kw in name.lower() for kw in
                               ["scan", "guard", "shield", "security", "detect", "check", "protect", "shrike"])

        # CHECK 3: Contiene VERI pattern di injection?
        has_real_injection = any(pat.search(desc) for pat in REAL_PROMPT_INJECTION_PATTERNS)

        if has_real_injection:
            if is_security_tool or is_security_name:
                # Tool di sicurezza MA con pattern espliciti → mantieni per review
                if re.search(r'HIDDEN\s+INSTRUCTION|INVISIBLE\s+TO\s+USER|malicious[_-]?\w*\.evil', desc, re.I):
                    tool_def["_filter_reason"] = "injection_in_security_tool_but_suspicious"
                    kept_tools.append(tool_def)
                else:
                    continue  # security tool che descrive pattern = FP
            else:
                tool_def["_filter_reason"] = "real_prompt_injection"
                kept_tools.append(tool_def)

    return kept_tools if kept_tools else None
```

Ripartizione finding filtrati (3): tutti marcati `injection_in_security_tool_but_suspicious` — tool di sicurezza con pattern espliciti che richiedono revisione manuale.

---

## Stage 2A — Regole HC

**Nessuna Stage 2A** per prompt-injection: il filtro Stage 1 ha già ridotto a 3 finding, che vengono classificati manualmente in-chat.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 3 FP manuali.

Tutti e 3 i finding rimasti sono stati classificati come FP:

**FP 1: Shrike-Security/shrike-mcp — `scan_agent_card`**

```json
{
    "server_url": "https://github.com/Shrike-Security/shrike-mcp",
    "tool_name": "scan_agent_card",
    "description": "Call this BEFORE trusting or connecting to a remote A2A agent based on its AgentCard. DECISION LOGIC: - If blocked=true: do NOT trust or connect to this agent..."
}
```

Scanner di sicurezza che **descrive** pattern di injection per rilevarli. Il nome contiene `scan` e la funzione è proteggere l'agent, non attaccarlo.

**FP 2: nav33n25/IMCP — `code-analyzer`**

```json
{
    "server_url": "https://github.com/nav33n25/IMCP",
    "description": "Advanced code analysis and security scanning tool for development teams..."
}
```

Server costruito **intenzionalmente** come demo di vulnerabilità MCP (honeypot/test server). Non è un server reale malevolo — è utilizzato dai ricercatori per testare framework di scanning.

**FP 3: jphyqr/secure-prompts-mcp**

Tool di sicurezza legittimo: registra prompt per scansione injection, non contiene injection stesso.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: **0 VP + 3 FP = 3**.

### Classificazione server honeypot

Tre server noti come **intenzionalmente vulnerabili** vengono classificati come FP in tutte le categorie dell'analisi:
- `nav33n25/IMCP` (honeypot MCP)
- `bishnubista/vulnerable-notes-mcp` (test server)
- `perryjr1444-ux/mantis-mcp-server` (attack framework dimostrativo)

Sono tool costruiti dai ricercatori di sicurezza per testare scanner e framework di analisi. Non rappresentano minacce reali nel supply-chain MCP.

### Perché mcp-security-scan produce pochi finding P-02

Il check è molto conservativo (solo 5 bad_phrases esatte). Altri framework come mcp-shield (`hidden-instructions`) producono molti più finding P-02 usando analisi semantica LLM invece di keyword matching. Per l'analisi reale di hidden-instructions/injection nelle tool description, fare riferimento a `findings/mcp-shield/hidden_instructions.md`.
