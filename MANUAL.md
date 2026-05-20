## 1. sql-injection (mcp-guard) — 2.375 VP totali

| # | Server | File:Line | Verdetto | Note |
|---|--------|-----------|:--------:|------|
| 1 | `GreatScottyMac/context-portal` | `db/database.py:535` | **VP-L (FP)** | `_get_latest_context_version(cursor, table_name)` — callers passano `"product_context_history"` e `"active_context_history"` hardcoded. Latente. |
| 2 | `GreptimeTeam/greptimedb-mcp-server` | `server.py:305` | **FP (FP)** | `table = validate_table_name(table)` con regex `^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$` (strict allowlist). Mitigato. |
| 3 | `JexinSam/mssql_mcp_server` | `server.py:82` | **VP-C (VP-C)** | `table = parts[0]` da URI MCP, zero validazione, pyodbc supporta stacked queries → RCE via `xp_cmdshell`. |

## 3. credential-leak (mcp-watch) — 619 VP

Verifica fetchando il valore concreto di `evidence`:

| # | Server | File | Evidence | Verdetto |
|---|--------|------|----------|:--------:|
| 1 | `ChromeDevTools/chrome-devtools-mcp` | `tools/performance.ts:229` | `key=AIzaSyBn5gimNjhiEyA_euicSKko6IlD3HdgUfk` | **FP (FP)** — Google CrUX API key pubblica (documentata da Google come key di lettura non ristretta). |
| 2 | `istanadodan/mcp_py_exam` | `.env:1` | `GOOGLE_API_KEY=AIzaSyDy6v...` | **VP-C (VP-C)** — `.env` committato con Google API key reale. |
| 3 | `istanadodan/mcp_py_exam` | `gemini_cli_mcp/.env` | stesso | **VP-C (VP-C)** |

## 5. untrusted-content (mcp-scan W015) — 599 VP

| # | Server | Verdetto |
|---|--------|:--------:|
| 1 | `0xshariq/github-mcp-server` | **VP-C (VP-C)** (ingestione contenuti GitHub pubblici) |
| 2 | `8enSmith/mcp-open-library` | **VP-C (VP-C)** (Open Library pubblica) |
| 3 | `AI-QL/mcp-devcontainers` | **VP-C (VP-C)** (devcontainer fetch da fonti esterne) |

## 6. path-traversal-static (mcp-guard) — 23 VP

| # | Server | File:Line | Pattern | Verdetto |
|---|--------|-----------|---------|:--------:|
| 1 | `zeromicro/mcp-zero` | `create_rpc_service.go:46` | `filepath.Join(outputDir, params.ServiceName+".proto")` | **VP-C (FP)** — ServiceName da MCP tool input. |
| 2 | `helixml/kodit` | `mcp/server.go:1312` | `filepath.Join(parts[lastIdx+2:]...)` | **VP-L (FP)** — `parts` proviene da split di path interno. |
| 3 | `helixml/kodit` | `chunk_files.go:293` | stesso pattern | **VP-L (FP)** |

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

## 10. protocol-violation (mcp-watch) — 79 VP

| # | Server | File | Tipo | Verdetto |
|---|--------|------|------|:--------:|
| 1 | `Lucassssss/eechat` | `electron/main/updater.ts` | INSECURE_TRANSPORT | **VP-C (VP-C)** — auto-updater su HTTP è ad alto rischio. |
| 3-6 | `moises-paschoalick/ai-agent-with-mcp` | `client.ts/index.ts` | INSECURE_TRANSPORT | **VP-L (FP)** — projct demo, HTTP localhost dev. |
| 9-10 | `sebszczec/pihole-mcp` | `main.py` | SESSION_ID_IN_URL | **VP-C (VP-C)** — session ID Pi-hole real (auth tokens in URL query string). |