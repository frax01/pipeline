### PROTOCOL-VIOLATION

**Finding originali**: 381.429

1. high
private containsSessionIdInUrl(line: string): boolean {
    return (
      /(?:sessionId|session_id|sid)=/.test(line) &&
      (line.includes("GET") ||
        line.includes("url") ||
        line.includes("path") ||
        line.includes("route") ||
        line.includes("endpoint"))
    );
  }

2. high
private containsInsecureTransport(line: string): boolean {
    return (
      line.includes("http://") &&
      !line.includes("localhost") &&
      !line.includes("127.0.0.1") &&
      !line.includes("example.com") &&
      !this.isExampleCredential(line)
    );
  }

**Finding dopo filtro**: 2.927
| INSECURE_TRANSPORT | 2.775 |
| SESSION_ID_IN_URL | 152 |

# ═══════════════════════════════════════════════════════════════════════════
#  CATEGORY 4: PROTOCOL-VIOLATION
# ═══════════════════════════════════════════════════════════════════════════

def filter_protocol_violation_finding(finding: dict) -> tuple[bool, str]:
    """Filter protocol violation findings."""
    vid = finding.get("id", "")
    evidence = finding.get("evidence", "") or ""
    filepath = finding.get("file", "") or ""

    if vid == "INSECURE_TRANSPORT":
        # Already filters localhost/127.0.0.1/example.com, but still noisy

        # Filter out package-lock.json, package.json, lockfiles (license URLs, not code)
        if re.search(r'(?:package-lock\.json|package\.json|yarn\.lock|pnpm-lock|Pipfile\.lock|poetry\.lock|composer\.lock)', filepath, re.IGNORECASE):
            return False, "lockfile_or_manifest"

        # Filter out ALL data/config files — not executable code.
        # http:// URLs in these are references (HL7 FHIR, SNOMED, schemas, configs),
        # not code that makes insecure HTTP connections.
        if re.search(r'\.(?:json|yaml|yml|toml|ini|cfg|env|xml)$', filepath, re.IGNORECASE):
            return False, "data_config_file"

        # Filter out third-party / vendored code
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|__test__|__mock__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Filter out comments
        if re.match(r'^\s*(?://|#|\*|/\*)', evidence):
            return False, "comment"

        # Filter out documentation / markdown files
        if re.search(r'\.(?:md|rst|txt|html|htm)$', filepath, re.IGNORECASE):
            return False, "documentation_file"

        # Filter out docs/ directories
        if re.search(r'(?:^|/)docs?/', filepath, re.IGNORECASE):
            return False, "docs_directory"

        # Filter out README content in JSON
        if re.search(r'"(?:Readme|ReadmeCN|description|readme)"', evidence, re.IGNORECASE):
            return False, "readme_content"

        # Filter out URLs with template variables (Python f-strings, JS template literals, etc.)
        # Catches: http://{settings.host}, http://${HOST}, http://{{host}}, http://$HOST
        if re.search(r'http://[^"]*(?:\{[a-zA-Z_]|\$[a-zA-Z_{]|\{\{)', evidence):
            return False, "template_variable_url"

        # Filter out common safe HTTP URLs (schemas, specs, namespaces, registries)
        safe_urls = [
            r'http://www\.w3\.org',
            r'http://schemas?\.',
            r'http://xmlns\.',
            r'http://purl\.org',
            r'http://json-schema\.org',
            r'http://www\.apache\.org',
            r'http://maven\.',
            r'http://creativecommons\.org',
            r'http://(?:www\.)?example\.',
            r'http://[a-zA-Z0-9_-]+\.github\.io',  # GitHub Pages (docs/licenses)
            r'http://www\.opengis\.net',             # OGC namespaces
            r'http://www\.idpf\.org',                # EPUB spec
            r'http://www\.color\.org',               # ICC color profiles
            r'http://ns\.',                          # XML namespaces
            r'http://www\.openarchives\.org',         # OAI
            r'http://ogp\.me',                        # Open Graph Protocol
            r'http://www\.sitemaps\.org',              # Sitemaps
            r'http://www\.rssboard\.org',              # RSS
            r'http://purl\.oclc\.org',                 # Dublin Core
            r'http://dbpedia\.org',                    # DBpedia
            r'http://www\.w3\.org',                    # W3C (already there but being thorough)
            r'http://rdfs?\.',                         # RDF schemas
            r'http://xmlns\.com',                      # XML namespaces
        ]
        for pattern in safe_urls:
            if re.search(pattern, evidence, re.IGNORECASE):
                return False, "safe_schema_url"

        # Filter out config for local services (common in MCP servers)
        # Includes hostnames without dots (internal services like "teradata-mcp-server")
        if re.search(r'http://(?:0\.0\.0\.0|host|hostname|\$)', evidence):
            return False, "local_config_variable"

        # Filter out internal service URLs (no dot in hostname = not a public domain)
        url_match = re.search(r'http://([^/:"\s]+)', evidence)
        if url_match:
            hostname = url_match.group(1)
            if '.' not in hostname:
                return False, "internal_service_hostname"

        # Filter out license/spec URLs in non-JSON files too
        if re.search(r'(?:license|licence|spdx)', evidence, re.IGNORECASE):
            return False, "license_url"

        # Filter out XML namespaces: {http://...} or xmlns="http://..."
        if re.search(r'(?:\{http://|xmlns\s*=\s*["\']http://)', evidence):
            return False, "xml_namespace"

        # Filter out URL validation / checking code (string literal used to test against)
        # e.g.: startsWith("http://"), .includes("http://"), === "http://", url.match("http://")
        if re.search(r'(?:startsWith|endsWith|includes|indexOf|match|test|search|replace|split)\s*\(\s*["\']http://', evidence):
            return False, "url_validation_code"

        # Filter out error messages / validation messages about URLs
        # e.g.: "must start with http://", "URL must be a valid URL starting with http://"
        if re.search(r'(?:must\s+(?:start|begin)|starting\s+with|invalid|expected|should\s+(?:start|begin)|format)\s*.*http://', evidence, re.IGNORECASE):
            return False, "url_validation_message"

        # Filter out console.error / console.log messages containing http://
        if re.search(r'console\.(?:error|warn|log|info)\s*\(.*http://', evidence):
            return False, "console_log_message"

        # Filter out string comparison / assignment of bare "http://" literal
        # e.g.: protocol === "http://", scheme = "http://", "must start with http://"
        if re.search(r'(?:["\']http://["\']|["\']https?://["\'])', evidence):
            return False, "protocol_string_literal"

        # Filter out SPARQL/RDF prefixes: PREFIX xxx: <http://...>
        if re.search(r'(?:PREFIX\s+\w*:\s*<http://|@prefix\s+)', evidence, re.IGNORECASE):
            return False, "sparql_rdf_prefix"

        # Filter out bundled/minified JS assets
        if re.search(r'(?:bundle|\.min\.|dist/|assets/scripts/|vendor\.)', filepath, re.IGNORECASE):
            return False, "bundled_js_asset"

        # Filter out description strings containing http:// links (documentation, not code)
        if re.search(r'(?:"description"|"summary"|"help"|"info"|"readme"|"text"|"message"|"detail"|"comment")\s*[:=]', evidence, re.IGNORECASE):
            return False, "description_string_with_link"

        # Filter out Python description= / help= keyword args with URLs
        if re.search(r'(?:description|help|message|detail|label|title|placeholder)\s*=\s*["\'].*http://', evidence, re.IGNORECASE):
            return False, "description_kwarg_with_link"

        # Filter out string concatenation/interpolation building URLs from variables
        # e.g.: `http://${host}:${port}`, "http://" + host
        if re.search(r'http://["\']?\s*\+\s*\w|http://\$\{|http://["\']?\s*\.\s*concat', evidence):
            return False, "dynamic_url_construction"

        # Filter out dictionary/object literal values — data, not HTTP connections
        # e.g.: 'source': 'http://...', "website": "http://...", "/RegistryName": "http://..."
        if re.search(r'["\'][^"\']*["\']\s*:\s*["\']http://', evidence):
            return False, "dict_value_not_connection"

        # Filter out http:// URLs used as dictionary KEYS (namespace maps, etc.)
        # e.g.: "http://www.opengis.net/wfs/2.0": {
        if re.search(r'["\']http://[^"\']+["\']\s*:', evidence):
            return False, "url_as_dict_key"

        # Filter out hardcoded URL strings assigned to variables or returned (reference data)
        # e.g.: return 'http://ws.audioscrobbler.com', BASE_URL = "http://..."
        if re.search(r'(?:return\s+|=\s*)["\']http://[^"\']+["\']', evidence):
            # Only keep if it's clearly making a connection (fetch, request, etc.)
            if not re.search(r'(?:fetch|request|axios|urllib|http\.get|http\.post|\.open\()', evidence):
                return False, "url_string_assignment"

        # Filter out docstrings / triple-quoted strings containing http://
        if re.search(r'(?:"""|\'\'\')', evidence):
            return False, "docstring_with_url"

        # Filter out string literals that are clearly documentation/help text
        # (long natural language strings with http:// in them)
        if re.search(r'(?:format|normalise|normalize|canonical|variant|convert|parse)\s.*http://', evidence, re.IGNORECASE):
            return False, "documentation_text_with_url"

        # Filter out security tool examples (nikto, nmap, etc.)
        if re.search(r'(?:nikto|nmap|burp|zap|sqlmap|metasploit|hydra)\s.*http://', evidence, re.IGNORECASE):
            return False, "security_tool_example"

        # Remaining http:// URLs to actual external services are real issues
        return True, "insecure_http_to_external"

    elif vid == "SESSION_ID_IN_URL":
        # Filter out README/documentation content
        if re.search(r'"(?:Readme|ReadmeCN|description)"', evidence, re.IGNORECASE):
            return False, "readme_content"

        # Filter out template placeholders
        if re.search(r'<UUID>|<session_id>|\{session_id\}|\$\{', evidence, re.IGNORECASE):
            return False, "template_placeholder"

        # Filter out comments
        if re.match(r'^\s*(?://|#|\*)', evidence):
            return False, "comment"

        # Filter out JSON data files
        if re.search(r'\.json$', filepath, re.IGNORECASE):
            return False, "json_data_file"

        # Filter out constructor/function calls where session_id is just a parameter
        # e.g.: McpSession(endpoint_url=..., session_id=session_id) — not a URL
        if re.search(r'(?:\w+\s*\(|new\s+\w+\s*\().*session_id\s*=', evidence) and not re.search(r'\?.*session_id=', evidence):
            return False, "constructor_parameter"

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|conftest|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Actual session ID in URL construction (query string)
        if re.search(r'\?.*(?:sessionId|session_id|sid)=', evidence):
            return True, "session_id_in_url_construction"

        # session_id appended to URL path
        if re.search(r'(?:url|path|endpoint|route).*(?:sessionId|session_id|sid)=\$?\{?\w', evidence):
            return True, "session_id_in_url_construction"

        return False, "no_real_session_leak"

    return False, "unknown_id"

**Veri positivi stimati**: ~10-15%