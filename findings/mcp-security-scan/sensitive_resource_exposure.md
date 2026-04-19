# R-03 — SENSITIVE RESOURCE EXPOSURE

**Finding originali**: 2

Severity: **high**.

Lo scanner cerca risorse con nomi/URI contenenti keyword sensibili (`credential`, `secret`, `token`, `key`, `password`). Se trovate, legge il contenuto e cerca indicatori di informazioni sensibili reali (`password`, `apikey`, `sk-`, `postgresql://`).

```python
def check_sensitive_resource_exposure(
    resources: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    """
    R-03: Sensitive resource exposure.
    Check if any listed resources contain sensitive keywords that could
    indicate exposed credentials, secrets, or other sensitive data.
    """
    sensitive_keywords = ["credential", "secret", "token", "key", "password"]
    suspects = []

    for resource in resources:
        name = (resource.get("name") or "").lower()
        uri = (resource.get("uri") or "").lower()
        if any(keyword in name or keyword in uri for keyword in sensitive_keywords):
            if resource.get("uri"):
                resp = send_recv_func("resources/read", {"uri": resource["uri"]})
                text = json.dumps(resp).lower()
                content_indicators = [
                    "password", "apikey", "api key", "sk-",
                    "postgresql://", "username:",
                ]
                if any(indicator in text for indicator in content_indicators):
                    suspects.append({"resource": resource, "resp": resp})
            else:
                suspects.append({"resource": resource, "resp": None})

    passed = len(suspects) == 0
    details = json.dumps(suspects)
    return _finding(spec, passed, details)
```

**Il problema**: le keyword `key` e `token` sono troppo generiche. `key` matcha `keyboard`, `api_key documentation`, `keyway`, ecc. `token` matcha `oauth-token-guide`, `token counting`. E i content_indicators come `password` o `username:` matchano HTML di form di login presenti in qualsiasi config page.

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 2 (riduzione 0%, nessuno scartato)

Il filtro per R-03 è minimo: scarta solo crash.

```python
def filter_sensitive_resource_exposure(finding):
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    if details:
        return details, "kept"
    return None, "empty_details"
```

---

## Stage 2A — Regole HC

**Nessuna Stage 2A**: solo 2 finding, analizzati direttamente in-chat.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 2 FP manuali.

**FP 1: SecretiveShell/MCP-llms-txt — risorsa `github.com/SecretiveShell/MCP-llms-txt`**

```json
{
    "resource": {
        "name": "github.com",
        "uri": "https://github.com/SecretiveShell/MCP-llms-txt",
        "description": "MCP-llms-txt file for github.com"
    },
    "resp": {"text": "<!DOCTYPE html><html lang=\"en\" data-color-mode=\"auto\" data-light-theme=\"light\"..."}
}
```

Il matching ha triggerato sulla parola "Secret" nel nome utente del repository (`SecretiveShell`). La risorsa è la homepage GitHub del repository stesso — HTML pubblicamente accessibile, nessun segreto reale.

**FP 2: akari2600/keyboard-maestro-mcp — risorsa `ui://keyboard-maestro-mcp/config.html`**

```json
{
    "resource": {
        "uri": "ui://keyboard-maestro-mcp/config.html",
        "mimeType": "text/html;profile=mcp-app"
    },
    "resp": {"text": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Keyboard Maestro MCP Config</title>..."}
}
```

La keyword `key` matcha `keyboard` nel nome del server. La risorsa è una pagina di configurazione HTML del tool Keyboard Maestro (automazione macOS) — contiene form fields chiamati `username:` che fanno scattare il content_indicator, ma sono solo field vuoti di una UI.

---

**Veri positivi confermati dopo analisi LLM**: 0

Ripartizione finale: **0 VP + 2 FP = 2**.

### Perché R-03 non produce VP

Il modello di attacco è: un server MCP espone come risorsa un file/endpoint con credenziali reali (es. `credentials://db`, `file:///etc/shadow`, `secrets/api-keys.json`). L'analisi di 60.205 server ha mostrato che:

- Nessun server MCP reale espone come risorsa accessibile contenuti con secrets reali
- Le keyword `key`, `token`, `secret` matchano quasi sempre nomi tecnici legittimi (keyboard, token-counting, secret-santa-mcp)
- Le feature di esposizione di credenziali (come si è visto in R-01/R-02) passano attraverso bug di path traversal, non esposizione volontaria di risorse "credentials"

Per individuare esposizione reale di segreti in risorse MCP servirebbero pattern più stringenti (formato di JWT valido, prefissi API key provider-specific) — simili a quelli usati in A-03 (data-leak). Ma in questo dataset il vettore "server espone volontariamente file di credentials" non si è mai verificato.
