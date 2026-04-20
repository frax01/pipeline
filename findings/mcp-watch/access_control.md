### ACCESS-CONTROL

**Finding originali**: 428.443 (solo `EXCESSIVE_PERMISSIONS`;
`CONSENT_FATIGUE_RISK` escluso da analisi — pattern di conferma "are you
sure?" in documentazione).

**Severity**: high.

Lo scanner `PermissionScanner` flagga ogni riga che contiene una keyword di
permesso **vicino** a una keyword di contesto:

```typescript
const permissionKeywords = [
  "admin", "root", "delete", "create", "update", "write", "read",
  "execute", "sudo", "privilege", "grant", "revoke",
];
const contextKeywords = [
  "user", "permission", "scope", "role", "access",
];
// Triggers when ≥1 keyword from each set is on the same line.
```

**Il problema**: le parole `admin`, `user`, `access`, `create`, `delete`,
`role` sono onnipresenti in qualsiasi codebase. Il 99.99% dei 428.443
finding è rumore puro.

---

## Stage 1 — filter_remaining_categories.py

**Finding dopo filtro**: 17 (riduzione 100.0%)

**Approccio whitelist**: invece di cercare di escludere il rumore, il
filtro accetta **solo** righe che matchano pattern di altissimo valore:

```python
_AC_HIGH_VALUE_PATS = [
    # IAM wildcard policies
    r'"Action"\s*:\s*"\*"', r'"Resource"\s*:\s*"\*"',
    # Dockerfile / container
    r'USER\s+root\b', r'chmod\s+777\b', r'chown\s+root\b',
    r'--privileged\b', r'CAP_SYS_ADMIN\b',
    # Kubernetes
    r'privileged\s*:\s*true', r'hostNetwork\s*:\s*true',
    r'hostPID\s*:\s*true', r'runAsUser\s*:\s*0\b',
    r'allowPrivilegeEscalation\s*:\s*true',
    r'verbs?\s*:\s*\[?\s*"\*"', r'resources?\s*:\s*\[?\s*"\*"',
    # AWS managed policies
    r'AdministratorAccess\b', r'PowerUserAccess\b',
    # SQL
    r'GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\b', r'GRANT\s+ALL\b',
]
```

428.443 → 17 finding.

---

## Stage 2A — Regole HC

`hc_rules_access_control` applica 8 pattern HC-FP + 2 pattern HC-VP:

**HC-FP**:
- `_AC_MOCK_OR_CACHE_FILE` → mock data, translation cache, example files
- `_AC_MITRE_DATASET` → `complete-mitre-attack-mcp-server` (dataset MITRE
  ATT&CK esplicito, per design)
- `_AC_TEST_USER_ROOT_CHECK` → test che **cerca** `USER root` in un
  Dockerfile
- `_AC_SCANNER_REPORT` → `agent-security-scanner-mcp` che produce report
  con `"matched_text"`
- `_AC_CAP_DROP_DESC` → extension manifest che **documenta** una flag
  "capabilities to drop"
- `_AC_ENABLE_ACCESS_DESC` → Pydantic field description `Enable access to
  the FUSE device`
- `_AC_BPF_EXAMPLE` → esempio di tracing BPF
- `_AC_PARAM_DESC_ADMIN_EXAMPLE` → parametro `role_name` con
  `AdministratorAccess` come valore di esempio

**HC-VP**:
- `_AC_AWS_PENTEST_EXPLOIT` + server `aws-pentest-mcp` → exploit di IAM
  privilege escalation
- `_AC_GRANT_ALL_DB_PAT` → SQL `GRANT ALL PRIVILEGES ON DATABASE` in
  runtime

**Risultato Stage 2A**: 10 HC-FP, 7 HC-VP, 0 UNCERTAIN.

---

## Stage 2B — Analisi LLM

**Nessuna Stage 2B**: tutti classificati dalle regole HC.

---

**Veri positivi confermati**: 7

Ripartizione finale: **7 VP + 10 FP = 17**.

### I 7 Veri Positivi

**aws-pentest-mcp** (6 VP) — Pentest tool per AWS IAM privilege escalation:

| Linea | Evidence |
|-------|----------|
| L5460 | `findings2.push(\`[CRITICAL] ${role.RoleName}: Attached to AdministratorAccess managed policy\`);` |
| L5985 | `exploitation: \`aws iam attach-user-policy --user-name CURRENT_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\`` |
| L5998 | `aws iam attach-role-policy --role-name TARGET_ROLE --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` |
| L6011 | `put-user-policy ... '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'` |
| L6024 | `put-role-policy ... '{"Action":"*","Resource":"*"}'` |
| L10689 | `if (role.includes('AdministratorAccess') || role.includes('FullAccess'))` |

Il server è un **offensive security tool** dichiarato: costruisce attack path
IAM, genera comandi di `attach-policy` con `AdministratorAccess`, embedded
policy documents con wildcard `Action/Resource: "*"`. Classificazione
coerente con `sec-mimikatz-mcp` / `sec-rubeus-mcp` in `sensitive-file-access`:
tool offensivi → VP.

**durandal-memory-bridge/database-setup.js L127** (1 VP):

```javascript
await adminPool.query(`GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${userName}`);
```

Script di setup che concede **tutti i privilegi su un intero database** a un
utente — senza restrizione. Plausibile per uno script di provisioning, ma il
pattern `GRANT ALL PRIVILEGES ON DATABASE` è eccessivo: normalmente un utente
applicativo dovrebbe ricevere solo `CONNECT, SELECT, INSERT, UPDATE, DELETE`
su tabelle specifiche.

### I 10 Falsi Positivi

| Server | File | Motivo |
|--------|------|--------|
| `eechat` (×2) | `mcpMock.json` | Mock data / cache di modelli LLM |
| `mcp-server-aws-sso` | `aws.sso.types.ts` | Parameter description: "role name to assume via SSO (e.g., 'AdministratorAccess')" |
| `cloud-life-sciences-api` | `mcp_server/models.py` | Pydantic field `description="Enable access to the FUSE device"` |
| `MCPtrace` | `tools/examples.json` | Esempio di BPF tracing |
| `complete-mitre-attack-mcp-server` | `data/v18.1/enterprise` | Dataset MITRE ATT&CK (intenzionale) |
| `vscode-mcp-acs-process` | `package.json` | Descrizione di una flag "capabilities to drop" in extension manifest |
| `harmony-claude-code` | `translation_workdir/cache/translation_db` | Cache di traduzioni |
| `armada-mcp` | `test-railway-deployment.js` | Test che **verifica** non ci sia `USER root` |
| `agent-security-scanner-mcp` | `clawhub-security-reports/...` | Output di scanner (matched_text) |

### Conclusione

Nessun server analizzato espone politiche IAM wildcard reali in codice
eseguibile: tutti i pattern `"Action":"*"` / `"Resource":"*"` trovati sono
o stringhe di exploit costruite da `aws-pentest-mcp` (offensive tool), o
riferimenti in documentazione/test.

Il `GRANT ALL PRIVILEGES` di `durandal-memory-bridge` è l'unico esempio di
grant eccessivo in uno script di setup operativo.

Su 428.443 finding, il vero rate di VP è **7/428.443 = 0.0016%** — lo scanner
`PermissionScanner` di mcp-watch non è utile per detection di access-control
nel contesto MCP senza un filtro whitelist aggressivo come quello qui
applicato.
