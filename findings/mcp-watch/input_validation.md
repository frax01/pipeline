### INUT-VALIDATION

**Finding originali**: 764.234

1. critical
private containsCommandInjection(line: string): boolean {
    const dangerousPatterns = [
      /execSync?\s*\(/, /spawn\s*\(/, /exec\s*\(/,
      /system\s*\(/, /shell_exec/, /passthru\s*\(/, /popen\s*\(/
    ];

    return (
      dangerousPatterns.some(pattern => pattern.test(line)) &&
      (line.includes("req.") || line.includes("params") || line.includes("query") ||
       line.includes("body") || line.includes("input") || line.includes("user") ||
       line.includes("argv"))
    );
  }

2. high
private containsSSRF(line: string): boolean {
    const ssrfPatterns = [
      /fetch\s*\(\s*(?:req\.|params\.|query\.|input\.)/,
      /axios\.get\s*\(\s*(?:req\.|params\.|query\.|input\.)/,
      /request\s*\(\s*(?:req\.|params\.|query\.|input\.)/,
      /http\.get\s*\(\s*(?:req\.|params\.|query\.|input\.)/,
      /urllib\.request\s*\(\s*(?:req\.|params\.|query\.|input\.)/
    ];

    return ssrfPatterns.some(pattern => pattern.test(line));
  }

3. high
private containsPathTraversal(line: string): boolean {
    const pathTraversalPatterns = [
      /readFile\s*\([^)]*\.\./,
      /fs\.read.*\([^)]*\.\./,
      /open\s*\([^)]*\.\./,
      /path\.join\s*\([^)]*\.\./,
      /\.\.\/|\.\.\\/, // Direct path traversal
      /path.*\.\./
    ];

    return pathTraversalPatterns.some(pattern => pattern.test(line));
  }


**Finding dopo filtro**: 225

| SSRF_VULNERABILITY | 142 |
| COMMAND_INJECTION_RISK | 73 |
| PATH_TRAVERSAL | 10 |

# ═══════════════════════════════════════════════════════════════════════════
#  CATEGORY 5: INPUT-VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def filter_input_validation_finding(finding: dict) -> tuple[bool, str]:
    """Filter input validation findings."""
    vid = finding.get("id", "")
    evidence = finding.get("evidence", "") or ""
    filepath = finding.get("file", "") or ""

    if vid == "COMMAND_INJECTION_RISK":
        # mcp-watch requires exec/spawn + user input keyword on same line
        # But "user", "input", "body", "params" appear in many safe contexts

        # Filter out third-party / vendored code (not the server's own code)
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build|__pycache__|pip/_vendor)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|__test__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Filter out regex.exec() — not command execution!
        # Includes /pattern/.exec(str) and named regex vars
        if re.search(r'\.exec\s*\(', evidence) and (
            re.search(r'(?:regex|Regex|RegExp|linkRegex|pattern|match)', evidence) or
            re.search(r'/[^/]+/\w*\.exec\s*\(', evidence)  # /pattern/.exec(str)
        ):
            return False, "regex_exec_not_command"

        # Filter out SQL/DB exec (not OS command injection, different vuln class)
        if re.search(r'(?:sql|SQL|\.exec\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER))', evidence, re.IGNORECASE):
            return False, "sql_exec_not_command_injection"

        # Filter out DB/ORM .exec() — database query execution, not OS command
        if re.search(r'(?:query|statement|prepared|cursor|db|database|connection|conn|knex|sequelize|prisma|typeorm)\s*\.\s*exec', evidence, re.IGNORECASE):
            return False, "db_exec_not_command_injection"

        # Filter out CSS/style files — no command injection risk
        if re.search(r'\.(?:css|scss|sass|less)$', filepath, re.IGNORECASE):
            return False, "css_file"

        # Filter out description text and prompt examples (not actual code)
        if re.search(r'"description"', evidence, re.IGNORECASE):
            return False, "description_text"

        # Filter out example/documentation text (e.g. "if reviewer says 'change exec(userInput)'")
        if re.search(r'(?:example|e\.g\.|i\.e\.|says\s+"|change\s+`|reviewer|comment)', evidence, re.IGNORECASE):
            return False, "example_text"

        # Filter out prompt template strings
        if re.search(r'\.(?:ts|js)$', filepath) and re.search(r'(?:Example\s*-|`exec\()', evidence):
            return False, "prompt_template_text"

        # Filter out standard launcher scripts (spawn('node', [...process.argv]))
        # These pass through CLI args, not network user input
        if re.search(r'spawn\s*\(\s*["\']node["\']', evidence) and re.search(r'process\.argv', evidence):
            return False, "node_launcher_script"

        # Filter out rule description text / documentation strings (not actual code)
        if re.search(r'(?:Shell execution|Avoid\s+`|prefer\s+argument|strict\s+allowlist)', evidence, re.IGNORECASE):
            return False, "rule_description_text"

        # Filter out logger/monitoring methods that happen to have 'input' keyword nearby
        if re.search(r'(?:logger|log|monitor|analyze|report)\.\w+\s*\(', evidence, re.IGNORECASE):
            return False, "logging_not_execution"

        # Keep if it's genuinely exec/spawn with user-controlled input
        has_dangerous_exec = bool(re.search(
            r'(?:child_process|execSync|\bexec\b|spawn|\bsystem\b(?!\w)|popen|shell_exec|passthru)\s*\(',
            evidence
        ))
        has_user_input = bool(re.search(
            r'(?:req\.|params\.|query\.|body\.|input\.|args\.|user\w*Input)',
            evidence
        ))

        # argv is from process itself, not from network — lower risk
        has_only_argv = bool(re.search(r'argv', evidence)) and not has_user_input

        if has_dangerous_exec and has_user_input:
            return True, "command_injection_confirmed"

        if has_only_argv:
            return False, "process_argv_not_network_input"

        return False, "not_command_injection"

    elif vid == "SSRF_VULNERABILITY":
        # mcp-watch requires fetch/axios immediately followed by user input
        # This is already quite specific, but filter test/vendor files
        if re.search(r'(?:test|spec|mock|fixture|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Filter out database connection.fetch() — PostgreSQL asyncpg, not HTTP fetch
        if re.search(r'(?:connection|conn|pool|db|database|client|cursor)\s*\.\s*fetch', evidence, re.IGNORECASE):
            return False, "database_fetch_not_http"

        # Filter out ORM/DB query methods that look like fetch
        if re.search(r'(?:\.fetchone|\.fetchall|\.fetchmany|\.fetchval|\.fetchrow)\s*\(', evidence, re.IGNORECASE):
            return False, "database_fetch_method"

        # Filter out SDK/API .fetch() — Discord messages.fetch(), guild.stickers.fetch(), etc.
        if re.search(r'(?:messages?|channels?|guilds?|members?|users?|roles?|emojis?|reactions?|threads?|webhooks?|stickers?|bans?|invites?|pins?)\s*\.\s*fetch\s*\(', evidence, re.IGNORECASE):
            return False, "sdk_api_fetch_method"

        # Filter out any chained .something.fetch() on SDK objects (generic SDK pattern)
        if re.search(r'\.\w+\.\s*fetch\s*\(\s*(?:params|args|options|id|name)\b', evidence, re.IGNORECASE):
            return False, "sdk_chained_fetch"

        # Filter out CSS files — no SSRF from stylesheets
        if re.search(r'\.(?:css|scss|sass|less)$', filepath, re.IGNORECASE):
            return False, "css_file"

        # Filter out logger/monitor methods that happen to have 'request' and URL keywords
        if re.search(r'(?:logger|log)\.\w*(?:request|info|debug|warn)\s*\(', evidence, re.IGNORECASE):
            return False, "logging_not_fetch"

        # Filter out SDK client .request() — not direct HTTP fetch
        # e.g.: client.aiGateway.logs.request(), client.items.request()
        if re.search(r'(?:client|sdk|api|service)\.\w+(?:\.\w+)*\.request\s*\(', evidence, re.IGNORECASE):
            return False, "sdk_client_request"

        return True, "ssrf_pattern_confirmed"

    elif vid == "PATH_TRAVERSAL":
        # MASSIVE false positive source — matches any "../" including imports
        # Only keep if it's in a file read context with user input

        # Filter out import statements
        if re.search(r'(?:import|require|from)\s', evidence):
            return False, "import_statement"

        # Filter out relative path in string that's clearly a module reference
        if re.search(r'["\']\.\./', evidence) and re.search(r'(?:utils|lib|src|components|helpers|modules|services|config|types|interfaces)', evidence):
            return False, "module_relative_path"

        # Filter out comments
        if re.match(r'^\s*(?://|#|\*)', evidence):
            return False, "comment"

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture)', filepath, re.IGNORECASE):
            return False, "test_file"

        # path.join with __dirname or __file__ and .. is static directory navigation
        if re.search(r'(?:path\.join|os\.path\.join)\s*\([^)]*(?:__dirname|__file__|os\.path\.dirname)', evidence):
            return False, "dirname_relative_navigation"

        # Keep only if there's a file operation with user-influenced path
        has_file_op = bool(re.search(r'(?:readFile|readdir|open|createReadStream|fs\.|path\.join)', evidence))
        has_user_input = bool(re.search(r'(?:req\.|params\.|query\.|body\.|input\.|args\.)', evidence))

        if has_file_op and has_user_input:
            return True, "path_traversal_with_user_input"

        return False, "static_relative_path"

    return False, "unknown_id"

**Veri positivi confermati dopo analisi LLM**: 125

Ripartizione VP per tipo:
| SSRF_VULNERABILITY | 94 |
| COMMAND_INJECTION_RISK | 29 |
| PATH_TRAVERSAL | 2 |

Ripartizione finale: 125 VP + 100 FP = 225 (di cui 214 classificati da regole HC deterministiche e 11 UNCERTAIN classificati in-chat con Sonnet: 2 VP + 9 FP).

Il pattern piu' affidabile e' la chiamata HTTP globale con URL controllato dall'utente:
`fetch(params.url)`, `axios.get(params.url)`, `fetch(input.url)`.

**Esempi di VP confermati:**

{"server_name": "Telegram-AI-MCP-Assistant-Bot", "file": "mcp_server_1.py",
 "id": "COMMAND_INJECTION_RISK",
 "evidence": "exec(input.code, allowed_globals, local_vars)"}

{"server_name": "doclea-mcp", "file": "scripts/lib/llm-cli-runner.ts",
 "id": "COMMAND_INJECTION_RISK",
 "evidence": "const child = spawn(input.command, {"}

{"server_name": "XcodeBuildMCP", "file": "src/tools/bundleId.ts",
 "id": "COMMAND_INJECTION_RISK",
 "evidence": "bundleId = execSync(`defaults read \"${params.appPath}/Contents/Info\" CFBundleIdentifier`)"}

{"server_name": "lspace-server", "file": "src/orchestrator/orchestratorService.ts",
 "id": "SSRF_VULNERABILITY",
 "evidence": "const response = await axios.get(input.url, { timeout: 10000 });"}

{"server_name": "mcp-web-tools", "file": "src/server.js",
 "id": "SSRF_VULNERABILITY",
 "evidence": "const res = await fetch(input.url, {"}

{"server_name": "fetch-browser", "file": "src/url-fetcher.ts",
 "id": "SSRF_VULNERABILITY",
 "evidence": "const response = await fetch(params.url.toString(), {"}

{"server_name": "PromptX", "file": "packages/resource/resources/tool/pdf-reader/pdf-reader.tool.js",
 "id": "PATH_TRAVERSAL",
 "evidence": "return path.join(...args.parts);"}

**Possibili falsi positivi da verificare** (classificati FP in-chat):

{"server_name": "daytona", "file": "libs/sdk-python/src/daytona/_async/process.py",
 "id": "COMMAND_INJECTION_RISK",
 "evidence": "return await self.exec(command, env=params.env if params else None, timeout=timeout)",
 "note": "self.exec e' un metodo SDK Daytona che esegue il comando dentro sandbox isolato; feature intenzionale, non injection."}

{"server_name": "Agent4Molecule", "file": "mcp_agent/enzygen_server.py",
 "id": "COMMAND_INJECTION_RISK",
 "evidence": "os.system(f\"rm -f {ENZYGEN_PATH}/data/input.json\")",
 "note": "ENZYGEN_PATH e' costante interna, 'input.json' e' literal file name, nessun input utente."}