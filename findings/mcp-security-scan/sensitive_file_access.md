# R-02 — SENSITIVE FILE ACCESS / PER-RESOURCE ACCESS CONTROL

**Finding originali**: 116

Severity: **high**.

Lo scanner tenta di leggere `file:///etc/passwd` e verifica se il server restituisce un `result` dict (accettazione della lettura di file di sistema sensibile).

```python
def check_resource_access_control(
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
) -> Finding:
    """
    R-02: Per-resource access control.
    Test if the server properly controls access to sensitive system files.
    """
    attempt = send_recv_func("resources/read", {"uri": "file:///etc/passwd"})

    # Success means the server allowed access to passwd (bad)
    accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
    passed = not accepted
    details = json.dumps(attempt)
    return _finding(spec, passed, details)
```

**Il problema**: stesso di R-01 — la presenza di un `result` dict non prova che il server abbia letto `/etc/passwd`. Molti server rispondono con `result: {contents: []}` o wrappano un errore in un result.

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 5 (riduzione −95.7%)

Il filtro cerca nel response il contenuto LETTERALE di `/etc/passwd` (pattern `root:x:0:0:`) o di chiavi private (`BEGIN RSA PRIVATE KEY` ecc.).

```python
def filter_sensitive_file_access(finding):
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = text_lower(details) if details else details_str.lower()

    # Contenuto reale di /etc/passwd
    if re.search(r'root:[x*]:0:0:', str(details)):
        return details, "real_passwd_content"

    # Contenuto reale di chiavi private
    if re.search(r'(BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)', str(details)):
        return details, "real_private_key"

    # Errori = server ha rifiutato
    if re.search(r'(error|not found|denied|invalid|forbidden|does not exist)', details_text):
        return None, "server_rejected_access"

    # Result vuoto / no file content
    if details:
        if isinstance(details, dict):
            result = details.get("result", {})
            if isinstance(result, dict):
                contents = result.get("contents")
                if contents is None or contents == [] or contents == {}:
                    return None, "result_empty_no_file_read"
            if isinstance(result, dict) and "tools" in result:
                return None, "result_is_tool_list_not_file"
        if re.search(r'\\n.*\\n.*\\n', str(details)):
            return details, "has_multiline_content"
        return None, "result_no_file_content"

    return None, "no_file_access_evidence"
```

Ripartizione finding filtrati (5): tutti `real_passwd_content` — il response contiene la stringa `root:x:0:0:root:/root:/bin/bash` e altre righe tipiche di `/etc/passwd` Linux.

---

## Stage 2A — Regole HC

**Nessuna Stage 2A**: il filtro Stage 1 richiede match letterale con `/etc/passwd`, quindi non serve ulteriore stadio HC.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 5 VP.

Tutti e 5 i finding sono confermati come veri positivi. Notare che sono gli **stessi 5 server** che falliscono anche R-01 (path-traversal): chi non valida URI `file://` è vulnerabile sia a traversal che a lettura di file sensibili per URI assoluto.

---

**Veri positivi confermati dopo analisi LLM**: 5

Ripartizione finale: **5 VP + 0 FP = 5**.

### Esempi di VP confermati

**VP 1: worksona/-worksona-mcp-server**

```json
{
    "id": "R-02",
    "details": "{\"result\": {\"contents\": [{\"type\": \"text\", \"text\": \"root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n...\"}]}}"
}
```

Il server ha letto `/etc/passwd` e restituito l'intero contenuto — tutti gli account utente del sistema, comprese le home directory e shell.

**VP 2: nhatvu148/video-transcriber-mcp**

```json
{
    "details": "{\"result\": {\"contents\": [{\"uri\": \"file:///etc/passwd\", \"mimeType\": \"text/plain\", \"text\": \"root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon...\"}]}}"
}
```

**VP 3-5: kbyk004/my-docs-mcp-server, danielitus/mcp-document-server, uniswap/spec-workflow-mcp**

Pattern identico — lettura diretta di `/etc/passwd` via URI assoluto `file:///etc/passwd` senza alcuna validazione.

### Correlazione R-01/R-02

I 5 server che falliscono R-02 sono **esattamente** i 5 che falliscono R-01. La causa comune è mancanza di validazione sull'URI `file://`: qualsiasi path assoluto o relativo con `..` viene risolto e letto. Un client MCP malevolo può iterare su file sensibili noti (`~/.ssh/id_rsa`, `~/.aws/credentials`, `/etc/shadow` se il server gira come root).
