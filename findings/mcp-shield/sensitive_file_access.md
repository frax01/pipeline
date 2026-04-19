# SENSITIVE-FILE-ACCESS

**Finding originali**: 3.094

Severity: **HIGH** per tutti i 3.094 finding.

mcp-shield rileva tool che menzionano file o risorse sensibili nella loro `tool_description` o nel nome dei parametri. Trigger phrase raccolte nei 3.094 finding:

| Trigger | Count | Tipologia tipica |
|---|---|---|
| `token` / `Token` / `TOKEN` | ~1.423 | Credenziali API, crypto token, LLM token |
| `..` | 640 | Path traversal in schema params / docstring |
| `credentials` | 361 | Credential manager, API wrapper |
| `API key` / `api_key` | 311 | Configurazione chiavi API |
| `password` | 221 | Device management, DB access |
| `secret` | 174 | Secret manager (GCP, Azure, Saturn) |
| `.env` / `config.json` / `mcp.json` | ~96 | Deployment e config tools |
| `Read file` / `Read content` | 89 | File reading legittimo |
| `~/.ssh` | 8 | SSH manager (legge `~/.ssh/config`) |
| `.cursor/` | 8 | Accesso config IDE Cursor |

In sostanza mcp-shield flagga **qualsiasi** tool che nomina credenziali, token, file sensibili, path traversal, ecc. — senza distinguere tra gestione legittima (credential vault, secret manager) e accesso abusivo.

---

**Finding dopo filtro**: 3.094 (nessun filtro regex intermedio applicato)

Come per le altre categorie mcp-shield, non c'e' Fase 2 a regex. Si passa direttamente allo Stage 2A di regole HC deterministiche dentro `pipeline_mcp_shield.py`.

**Regole HC principali** (da `pipeline_mcp_shield.py`, funzione `hc_rules_sensitive_file_access`):

```python
# Linguaggio da offensive tool — indica strumenti di attacco, non gestione legittima
_SFA_ATTACK_PAT = re.compile(
    r"DCSync|LSASS|WDigest|sekurlsa|lsadump"
    r"|Kerberoast|AS-REP\s+[Rr]oast|kerberoasting"
    r"|Kerberos\s+(?:delegation\s+abuse|preauthentication)"
    r"|NTLM\s+hash|credential\s+dump"
    r"|Elevate\s+to\s+SYSTEM\s+token|impersonate\s+another\s+user"
    r"|S4U2(?:Self|Proxy)"
    r"|mimikatz|rubeus"
    r"|Extract\s+\w+\s+credentials\s+from\s+LSASS"
    r"|Dump\s+(?:LSA|Windows\s+Vault)\s+(?:secrets|credentials)"
    r"|privilege\s+escalation.*delegation"
    r"|replicate\s+AD\s+credentials"
    r"|pass-the-hash|pass\s+the\s+hash",
    re.IGNORECASE,
)

def hc_rules_sensitive_file_access(f: dict) -> tuple[str, str]:
    desc = _tool_desc(f)
    # HC-VP: offensive tool wrappers (mimikatz, rubeus e simili)
    if _SFA_ATTACK_PAT.search(desc):
        return "HC-VP", "hc_vp:offensive_tool_credential_attack"
    # HC-FP: tutto il resto (credential manager, secret manager, API wrapper, ecc.)
    return "HC-FP", "hc_fp:legitimate_credential_or_file_management"
```

---

**Veri positivi confermati dopo analisi LLM**: 11

Ripartizione finale: 11 VP + 3.083 FP = 3.094 (11 HC-VP + 3.083 HC-FP + 0 UNCERTAIN).

### VP per server

| Server | Tool VP | Tecnica |
|---|---|---|
| `sec-mimikatz-mcp` | 6 | DCSync, LSASS/WDigest/MSV1_0 dump, LSA secrets, Windows Vault, token elevate |
| `sec-rubeus-mcp` | 3 | Kerberoasting, AS-REP Roasting, S4U delegation abuse |
| `sec-bloodhound-mcp` | 1 | Enumerazione principal con diritti DCSync |
| `sec-evil-winrm-mcp` | 1 | Pass-the-hash / NTLM auth su WinRM |

Tutti i VP appartengono a **wrapper MCP di strumenti offensivi** (mimikatz, rubeus, bloodhound, evil-winrm). Il pattern distintivo e' un linguaggio esplicito di attacco credenziale: DCSync, LSASS dumping, WDigest extraction, Kerberoasting, token elevation, pass-the-hash.

### Esempi di VP confermati

**VP 1: sec-mimikatz-mcp — `mimikatz_lsadump_dcsync`**

```json
{
    "server_name": "sec-mimikatz-mcp",
    "tool_name": "mimikatz_lsadump_dcsync",
    "tool_description": "Perform DCSync attack to replicate AD credentials. Requires domain admin or replication rights."
}
```

DCSync e' una tecnica MITRE ATT&CK (T1003.006) che usa il protocollo di replica Active Directory per estrarre hash delle credenziali di dominio senza toccare i domain controller. Il tool espone direttamente questa capability.

**VP 2: sec-mimikatz-mcp — `mimikatz_sekurlsa_wdigest`**

```json
{
    "tool_description": "Extract WDigest credentials from LSASS memory"
}
```

Estrazione di credenziali in chiaro dal processo LSASS tramite il provider WDigest.

**VP 3: sec-rubeus-mcp — `rubeus_kerberoast`**

```json
{
    "tool_description": "Perform Kerberoasting attack to extract service account password hashes. Requests TGS tickets for accounts with SPNs, which are encrypted with the service account's password hash. These can be cracked..."
}
```

Kerberoasting (MITRE T1558.003): richiede TGS per account di servizio e tenta di crackare offline le password hash.

**VP 4: sec-rubeus-mcp — `rubeus_s4u`**

```json
{
    "tool_description": "Perform S4U (Service for User) constrained/unconstrained delegation abuse. Implements S4U2Self: Obtain service ticket to yourself on behalf of another user, S4U2Proxy: Use constrained delegation..."
}
```

Abuso di delega Kerberos per impersonare utenti arbitrari (incluso Domain Admin in scenari di unconstrained delegation).

**VP 5: sec-evil-winrm-mcp — `evilwinrm_connect`**

```json
{
    "tool_description": "Establish connection parameters for Evil-WinRM session... Supports password, NTLM hash (pass-the-hash), SSL, and Kerberos authentication..."
}
```

Supporto esplicito per pass-the-hash: autenticazione con NTLM hash al posto della password.

**VP 6: sec-bloodhound-mcp — `bloodhound_dcsyncers`**

```json
{
    "tool_description": "Get principals with DCSync rights (can dump domain credentials)"
}
```

Enumerazione di account con diritti di replica AD, prerequisito per un attacco DCSync.

---

### Perche' il tasso di FP e' cosi' alto (~99,6%)

mcp-shield flagga qualsiasi menzione di `token`, `password`, `credential`, `secret`, `.env`, `api_key` nella tool description o nei parametri. Ma la stragrande maggioranza di questi 3.083 FP appartiene a tool **legittimi** che gestiscono credenziali per conto dell'utente:

- Secret manager (GCP Secret Manager, Azure Key Vault, HashiCorp Vault)
- Credential vault / password manager
- API wrapper con parametro `apiKey` o `token`
- SSH manager che legge `~/.ssh/config`
- Crypto token tools (ERC-20, Solana, ecc.)
- Deployment tool che legge `.env` o `mcp.json`
- File reader legittimi

La distinzione chiave e' che i VP **non gestiscono** credenziali: le **estraggono** in modo non autorizzato da sistemi altrui (LSASS dump, replica AD, pass-the-hash, Kerberoasting). Questa distinzione semantica non e' catturabile dal matcher statico di mcp-shield e richiede la regex HC `_SFA_ATTACK_PAT` con keyword di offensive security.
