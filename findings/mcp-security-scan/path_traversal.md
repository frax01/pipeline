# R-01 — PATH TRAVERSAL / RESOURCE URI VALIDATION

**Finding originali**: 131

Severity: **high**.

Lo scanner tenta di leggere una risorsa con URI `file:///../../etc/hosts` e verifica se il server restituisce un `result` dict (accettazione del path traversal).

```python
def check_resource_traversal(
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
) -> Finding:
    """
    R-01: Resource URI validation & path traversal prevention.
    Test if the server accepts path traversal URIs like "file:///../../etc/hosts".
    """
    attempt = send_recv_func("resources/read", {"uri": "file:///../../etc/hosts"})

    # Success means the server accepted the traversal (bad)
    accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
    passed = not accepted
    details = json.dumps(attempt)
    return _finding(spec, passed, details)
```

**Il problema**: la sola presenza di un `result` dict non prova il path traversal. Molti server MCP restituiscono `result: {contents: []}` o un errore wrapped in un result dict senza avere realmente letto il file.

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 5 (riduzione −96.2%)

Il filtro cerca nel response contenuto REALE di `/etc/hosts` (o di altri file di sistema), distinguendolo da result vuoti ed errori wrapped.

```python
def filter_path_traversal(finding):
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = text_lower(details) if details else details_str.lower()

    # Se il response contiene contenuto reale di file di sistema
    if re.search(r'127\.0\.0\.1\s+localhost', str(details)):
        return details, "real_hosts_file_content"
    if re.search(r'root:[x*]:0:0:', str(details)):
        return details, "real_passwd_content"

    # Se contiene solo errori
    if re.search(r'(error|not found|denied|invalid|forbidden|does not exist)', details_text):
        return None, "server_rejected_traversal"

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

    return None, "no_traversal_evidence"
```

Ripartizione finding filtrati (5): tutti con `real_hosts_file_content` — il response contiene la stringa `127.0.0.1 localhost` e altre righe tipiche di `/etc/hosts`, prova inequivocabile che il server ha risolto il path traversal e letto il file.

---

## Stage 2A — Regole HC

**Nessuna Stage 2A** per path-traversal: il filtro Stage 1 è già estremamente selettivo (cerca il contenuto letterale di `/etc/hosts`), quindi non serve ulteriore stadio HC.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 5 VP.

Tutti e 5 i finding sono stati confermati come veri positivi: in ognuno il server MCP ha effettivamente restituito il contenuto reale di `/etc/hosts` (riga `127.0.0.1 localhost` + `manage_etc_hosts` comment generato da cloud-init).

---

**Veri positivi confermati dopo analisi LLM**: 5

Ripartizione finale: **5 VP + 0 FP = 5**. Questi 5 server accettano path traversal su risorse arbitrarie senza validazione.

### Esempi di VP confermati

**VP 1: worksona/-worksona-mcp-server**

```json
{
    "id": "R-01",
    "details": "{\"result\": {\"contents\": [{\"type\": \"text\", \"text\": \"# Your system has configured 'manage_etc_hosts' as True.\\n127.0.0.1 localhost\\n...\"}]}}"
}
```

Il server ha letto `/etc/hosts` attraverso il path `file:///../../etc/hosts` senza sanitizzazione. Il contenuto è quello reale del file di sistema di una VM Ubuntu con cloud-init.

**VP 2: nhatvu148/video-transcriber-mcp**

```json
{
    "details": "{\"result\": {\"contents\": [{\"uri\": \"file:///../../etc/hosts\", \"mimeType\": \"text/plain\", \"text\": \"# Your system has configured 'manage_etc_hosts'...127.0.0.1 localhost...\"}]}}"
}
```

Stesso pattern: il server accetta URI `file://` con `..` senza alcuna validazione e legge il file fuori dalla directory dichiarata come root.

**VP 3-5: kbyk004/my-docs-mcp-server, danielitus/mcp-document-server, uniswap/spec-workflow-mcp**

Pattern identico — tutti leggono `/etc/hosts` via traversal. `spec-workflow-mcp` è particolarmente notevole perché opera come document server nell'ecosistema Uniswap con potenziale esposizione pubblica.

### Perché questi finding sono critici

Un server MCP con path traversal permette a qualsiasi client connesso di leggere qualunque file leggibile dall'utente che esegue il server — incluse chiavi SSH (`~/.ssh/id_rsa`), file di configurazione (`.env`, `.aws/credentials`) e percorsi di sistema. Se il server gira come root, l'intero filesystem è esposto.
