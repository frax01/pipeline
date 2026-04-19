# A-03 — DATA LEAK / TOKEN INDIRECTION

**Finding originali**: 13

Severity: **critical**.

Lo scanner chiama un tool hardcoded `upstream_access` con un `code` dummy e cerca nella response token reali o stringhe `access_token`, `sk-`, `bearer`.

```python
def check_token_passthrough(
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
) -> Finding:
    """
    A-03: Token indirection (no upstream token pass-through).
    Test if the server leaks upstream access tokens through tool responses.
    """
    leak_attempt = send_recv_func(
        "tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}}
    )

    text = json.dumps(leak_attempt).lower()
    token_indicators = ["access_token", "sk-", "token-body", "bearer "]
    leaked = any(indicator in text for indicator in token_indicators)

    passed = not leaked
    details = json.dumps(leak_attempt)
    return _finding(spec, passed, details)
```

**Il problema**: il check ha due debolezze principali:
1. Il tool `upstream_access` è hardcoded e quasi nessun server lo espone → chiama un tool inesistente ottenendo un errore
2. Gli indicatori `sk-`, `access_token`, `bearer` matchano anche **messaggi di errore** che dicono "configura il tuo token" oppure "starts with sk-" nei suggerimenti di troubleshooting

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 2 (riduzione −84.6%)

Il filtro cerca token REALI (con prefissi specifici e lunghezza minima) e scarta errori di tipo "credenziali mancanti".

```python
REAL_TOKEN_PATTERNS = [
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),            # OpenAI key
    re.compile(r'sk-ant-api03-[a-zA-Z0-9\-_]+'),    # Anthropic key
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),             # GitHub PAT
    re.compile(r'gho_[a-zA-Z0-9]{36}'),             # GitHub OAuth
    re.compile(r'AKIA[A-Z0-9]{16}'),                # AWS Access Key
    re.compile(r'Bearer\s+[a-zA-Z0-9\-_.]{20,}'),   # Bearer token reale
    re.compile(r'xoxb-[0-9]{10,}'),                 # Slack bot token
    re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),        # Stripe live key
]


def filter_data_leak(finding):
    details_str = finding.get("details", "")
    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = str(details) if details else details_str

    # CHECK 1: E' solo un errore "token/credenziali mancanti"?
    error_about_missing = re.search(
        r'(missing|required|not set|undefined|please set|environment variable)',
        details_text, re.I
    )
    if isinstance(details, dict):
        error_obj = details.get("error", {})
        if isinstance(error_obj, dict) and error_obj.get("code"):
            if error_about_missing:
                return None, "error_about_missing_credentials"

    # CHECK 2: Response contiene token REALI?
    for pat in REAL_TOKEN_PATTERNS:
        if pat.search(details_text):
            return details, f"real_token_found:{pat.pattern[:30]}"

    # CHECK 3: access_token con valore reale
    if re.search(r'"access_token"\s*:\s*"[a-zA-Z0-9\-_.]{20,}"', details_text):
        return details, "access_token_with_value"

    if error_about_missing or (isinstance(details, dict) and "error" in details):
        return None, "error_response_no_leak"

    # Result con contenuto sospetto
    if isinstance(details, dict) and "result" in details:
        result_text = str(details["result"])
        if re.search(r'(token|secret|password|credential|api.?key)', result_text, re.I):
            return details, "suspicious_result_content"

    return None, "no_data_leak_evidence"
```

Ripartizione finding filtrati (2): entrambi `suspicious_result_content` — il result menziona "token" ma l'analisi successiva ha mostrato che è solo un messaggio di errore che chiede di configurare il token.

---

## Stage 2A — Regole HC

**Nessuna Stage 2A** per data-leak: solo 2 finding filtrati, analizzati direttamente in-chat.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 2 FP manuali.

Entrambi i finding sono stati classificati come falsi positivi:

**FP 1: aisirij/autodoc-ai-mcp-server**

```json
{
    "details": "{\"result\": {\"content\": [{\"type\": \"text\", \"text\": \"❌ Error: Unknown tool: upstream_access\\n\\n💡 **Troubleshooting Tips:**\\n- Check that your project path exists...\\n- Verify your OpenAI API key is valid and starts with \\\"sk-\\\"\\n- Ensure you have write permissions...\"}], \"isError\": true}}"
}
```

Il server non ha il tool `upstream_access`. Il response è un **messaggio di errore di suggerimento** che menziona "sk-" nel troubleshooting — "Verify your OpenAI API key is valid and starts with 'sk-'". Nessun token leak.

**FP 2: gabe-almeida/meta-ads-mcp-server**

```json
{
    "details": "{\"result\": {\"content\": [{\"text\": \"{\\\"success\\\": false, \\\"error\\\": \\\"Meta Ads MCP Server is not configured with an access token\\\", \\\"help\\\": {\\\"message\\\": \\\"To use Meta Ads tools, you need to configure a Meta access token.\\\"}}\"}], \"isError\": true}}"
}
```

Response è un errore strutturato "not configured with an access token" — la stringa `access_token` appare nel testo dell'errore, non come valore reale. Nessun leak.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: **0 VP + 2 FP = 2**.

### Perché A-03 è un check debole

Il check `upstream_access` è estremamente specifico e hardcoded. In un ecosistema di 60.205 server MCP, praticamente nessuno espone un tool con esattamente quel nome. I 13 finding originali sono tutti casi in cui:
- Il tool non esiste → server ritorna errore "unknown tool"
- L'errore menziona il termine "token" nel messaggio di help
- Il keyword match triviale `sk-` / `bearer ` / `access_token` dà falso positivo

Per individuare veri data leak nei server MCP servirebbe un test mirato a tool di autenticazione realmente esposti, con analisi dei response per token con entropia tipica (es. JWT validi, OAuth token con lunghezza specifica).
