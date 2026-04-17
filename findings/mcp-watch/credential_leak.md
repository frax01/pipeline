### Credential leak
**Finding originali**: 646.447

1. critical
private containsHardcodedCredentials(line: string): boolean {
    const patterns = [
      // Enhanced API key patterns
      /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][a-zA-Z0-9]{15,}["']/i,
      /sk-[a-zA-Z0-9]{20,}/, // OpenAI
      /ghp_[a-zA-Z0-9]{36}/, // GitHub
      /xoxb-[a-zA-Z0-9-]{50,}/, // Slack
      /AKIA[a-zA-Z0-9]{16}/, // AWS
      /ya29\.[a-zA-Z0-9_-]{50,}/, // Google OAuth
      /AIza[a-zA-Z0-9_-]{35}/, // Google API
      /pk_[a-zA-Z0-9]{24}/, // Stripe
      /sk_[a-zA-Z0-9]{24}/, // Stripe Secret
      /dckr_pat_[a-zA-Z0-9_-]+/, // Docker
      /["'][a-zA-Z0-9+/]{40,}={0,2}["']/, // Base64-like
      /["']eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["']/, // JWT
    ];

    return (
      patterns.some((pattern) => pattern.test(line)) &&
      !this.isExampleCredential(line)
    );
  }

2. high
private containsPlaintextStorage(line: string): boolean {
    const fileWriteOps = [
      /writeFileSync\s*\(/,
      /writeFile\s*\(/,
      /createWriteStream\s*\(/,
      /\.write\s*\(/,
      /appendFileSync\s*\(/,
      /outputFileSync\s*\(/,
    ];

    const hasFileWrite = fileWriteOps.some((op) => op.test(line));
    if (!hasFileWrite) return false;

    const credentialIndicators = [
      /\b(?:token|key|secret|password|auth|credential|apiKey)\b/i,
      /['"`](?:api[-_]?key|secret|token|password|auth)['"`]\s*:/i,
      /process\.env\.[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD)/i,
    ];

    const hasCredentialData = credentialIndicators.some((indicator) =>
      indicator.test(line)
    );
    if (!hasCredentialData) return false;

    const encryptionMentioned = [
      /\b(?:encrypt|cipher|hash|crypto|bcrypt|scrypt)\b/i,
      /\.encrypt\(/,
      /CryptoJS\./,
      /crypto\./,
    ];

    return !encryptionMentioned.some((enc) => enc.test(line));
  }

3. high
private containsInsecureCredentialPermissions(line: string): boolean {
    return (
      /chmod\s+[0-9]*[4-7][4-7][4-7]/.test(line) &&
      /(?:key|token|secret|password|credential)/i.test(line)
    );
  }



**Finding dopo filtro**: 784

| PLAINTEXT_STORAGE | 434 |
| HARDCODED_CREDENTIALS | 339 |
| INSECURE_CREDENTIAL_PERMISSIONS | 11 |

# ═══════════════════════════════════════════════════════════════════════════
#  CATEGORY 1: CREDENTIAL-LEAK
# ═══════════════════════════════════════════════════════════════════════════

# Provider-specific patterns that almost certainly indicate real credentials
CREDENTIAL_PROVIDER_PATTERNS = [
    # AI / LLM
    (re.compile(r'sk-ant-api03-[a-zA-Z0-9\-_]{48,85}'),           "Anthropic API Key"),
    (re.compile(r'sk-proj-[a-zA-Z0-9\-_]{40,}'),                  "OpenAI Project Key"),
    (re.compile(r'sk-[a-zA-Z0-9]{40,60}'),                        "OpenAI Legacy Key"),
    (re.compile(r'sess-[a-zA-Z0-9]{40,}'),                        "OpenAI Session Key"),
    (re.compile(r'hf_[a-zA-Z0-9]{34,}'),                          "Hugging Face Token"),

    # Cloud Providers
    (re.compile(r'AKIA[A-Z0-9]{16}'),                              "AWS Access Key ID"),
    (re.compile(r'ASIA[A-Z0-9]{16}'),                              "AWS Temporary Key"),
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'),                       "Google API Key"),
    (re.compile(r'ya29\.[a-zA-Z0-9_\-]{50,}'),                    "Google OAuth Token"),

    # Git / CI/CD
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'),                          "GitHub PAT (classic)"),
    (re.compile(r'gho_[a-zA-Z0-9]{36}'),                          "GitHub OAuth Token"),
    (re.compile(r'ghu_[a-zA-Z0-9]{36}'),                          "GitHub User Token"),
    (re.compile(r'ghs_[a-zA-Z0-9]{36}'),                          "GitHub Server Token"),
    (re.compile(r'ghr_[a-zA-Z0-9]{36}'),                          "GitHub Refresh Token"),
    (re.compile(r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'),   "GitHub PAT (fine-grained)"),
    (re.compile(r'glpat-[a-zA-Z0-9\-_]{20,}'),                    "GitLab PAT"),

    # Messaging / SaaS
    (re.compile(r'xoxb-[0-9]{10,}-[0-9A-Za-z\-]+'),               "Slack Bot Token"),
    (re.compile(r'xoxp-[0-9]{10,}-[0-9A-Za-z\-]+'),               "Slack User Token"),
    (re.compile(r'xoxs-[0-9]{10,}-[0-9A-Za-z\-]+'),               "Slack Session Token"),
    (re.compile(r'xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+'),    "Slack App Token"),

    # Payments
    (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Secret Key (live)"),
    (re.compile(r'sk_test_[a-zA-Z0-9]{24,}'),                     "Stripe Secret Key (test)"),
    (re.compile(r'pk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Publishable (live)"),
    (re.compile(r'pk_test_[a-zA-Z0-9]{24,}'),                     "Stripe Publishable (test)"),
    (re.compile(r'rk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Restricted Key"),
    (re.compile(r'whsec_[a-zA-Z0-9]{32,}'),                       "Stripe Webhook Secret"),

    # Email / Communication
    (re.compile(r'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'), "SendGrid API Key"),
    (re.compile(r'SK[a-f0-9]{32}'),                                "Twilio API Key"),

    # Infrastructure / DevOps
    (re.compile(r'dckr_pat_[a-zA-Z0-9_\-]{24,}'),                 "Docker PAT"),
    (re.compile(r'npm_[a-zA-Z0-9]{36}'),                           "npm Token"),
    (re.compile(r'pypi-AgEIcH[a-zA-Z0-9\-_]{50,}'),               "PyPI API Token"),
    (re.compile(r'vercel_[a-zA-Z0-9]{24,}'),                       "Vercel API Token"),
    (re.compile(r'npl_[a-zA-Z0-9]{24,}'),                          "Netlify PAT"),
    (re.compile(r'sbp_[a-f0-9]{40}'),                              "Supabase Service Key"),

    # Databases (connection URIs with credentials)
    (re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"<>]{5,}"), "MongoDB URI with creds"),
    (re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^\s'\"<>]{5,}"),   "PostgreSQL URI with creds"),
    (re.compile(r"mysql://[^:]+:[^@]+@[^\s'\"<>]{5,}"),             "MySQL URI with creds"),
    (re.compile(r"redis://[^:]+:[^@]+@[^\s'\"<>]{5,}"),             "Redis URI with creds"),

    # Private Keys
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Private Key Header"),

    # JWT (only with 3 segments, each 10+ chars)
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]{10,}'), "JWT Token"),

    # Generic high-confidence assignment (api_key = "longRandomValue")
    (re.compile(
        r'(?:api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token)'
        r'\s*[:=]\s*["\']([a-zA-Z0-9\-_./+]{20,})["\']',
        re.IGNORECASE
    ), "Generic API Key Assignment"),
]

# Evidence patterns that are NEVER real credentials
CREDENTIAL_FALSE_POSITIVE_PATTERNS = [
    # Hashes / checksums
    re.compile(r'"(?:sha256?|sha384|sha512|md5|hash|checksum|digest|fileSha256|commit_sha|sha|etag)"'
               r'\s*:\s*"[a-fA-F0-9]{32,}"', re.IGNORECASE),
    re.compile(r'"(?:sha256?|sha384|sha512|md5|hash|checksum|digest|fileSha256|commit_sha|sha)"'
               r'\s*:\s*"', re.IGNORECASE),

    # Blockchain / Ethereum addresses
    re.compile(r'0x[a-fA-F0-9]{40}'),
    re.compile(r'"(?:address|source|from|to|contractAddress|sender|receiver|owner)"\s*:\s*"0x', re.IGNORECASE),

    # Google API discovery schema refs
    re.compile(r'"\$ref"\s*:\s*"Google[A-Z]'),
    re.compile(r'"id"\s*:\s*"Google(?:Cloud|Devtools|Iam|Api|Monitoring|Storage|Compute)', re.IGNORECASE),

    # Long CamelCase identifiers (class names, not secrets)
    re.compile(r'"[A-Z][a-zA-Z]{30,}"'),

    # __name() wrapper from bundled JS
    re.compile(r'__name\s*\('),

    # Example / placeholder credentials
    re.compile(r'(?:your[-_]?(?:api[-_]?key|token|secret)|example|demo|placeholder|'
               r'xxx{3,}|yyy{3,}|123456|abcdef{2,}|replace[-_]?me|change[-_]?me|'
               r'dummy|fake|mock|sample|insert[-_]?here|insert[-_]?your|'
               r'key[-_]?here|token[-_]?example|secret[-_]?placeholder|TODO|FIXME)',
               re.IGNORECASE),

    # AWS example keys
    re.compile(r'AKIAIOSFODNN7EXAMPLE'),

    # Template variables (not hardcoded)
    re.compile(r'\$\{[^}]+\}'),
    re.compile(r'\{\{[^}]+\}\}'),
    re.compile(r'<[A-Z_]{3,}>'),

    # Environment variable reads (not hardcoded)
    re.compile(r'process\.env\.\w+'),
    re.compile(r'os\.environ\b'),
    re.compile(r'os\.getenv\b'),

    # Pure hex strings in non-credential context (checksums, tx hashes)
    re.compile(r'^"?[a-fA-F0-9]{40,128}"?,?$'),

    # Base64 strings that are actually just long ASCII text
    re.compile(r'"[a-zA-Z]{40,}"'),  # All-alpha, no mixed case typical of secrets

    # Test file paths
    re.compile(r'(?:test|spec|mock|fixture|__test__|__mock__|\.test\.|\.spec\.)', re.IGNORECASE),
]


def filter_credential_finding(finding: dict) -> tuple[bool, str]:
    """
    Returns (keep, reason).
    For HARDCODED_CREDENTIALS: re-test evidence against provider-specific patterns.
    For PLAINTEXT_STORAGE / INSECURE_CREDENTIAL_PERMISSIONS: keep with lighter filter.
    """
    vid = finding.get("id", "")
    evidence = finding.get("evidence", "") or ""
    filepath = finding.get("file", "") or ""

    if vid == "HARDCODED_CREDENTIALS":
        # Filter out test files — credentials in tests are intentional fixtures
        if re.search(r'(?:test|spec|mock|fixture|__test__|__mock__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Filter out third-party / vendored code (not the server's own code)
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build|__pycache__|\.tox|\.eggs)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Filter out JSON data files (openapi.json, config examples, etc.)
        if re.search(r'\.(?:json|yaml|yml)$', filepath, re.IGNORECASE):
            return False, "data_config_file"

        # Filter out documentation files
        if re.search(r'\.(?:md|rst|txt|html|htm)$', filepath, re.IGNORECASE):
            return False, "documentation_file"

        # Filter out docs/ directories (client-side search keys, etc.)
        if re.search(r'(?:^|/)docs?/', filepath, re.IGNORECASE):
            return False, "docs_directory"

        # Filter out well-known example JWTs (jwt.io default tokens)
        if re.search(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkw', evidence):
            return False, "jwt_io_example_token"

        # Filter out public/client-side API keys (analytics, search, Firebase)
        # These are DESIGNED to be embedded in frontend code, not secrets
        if re.search(
            r'(?:amplitude|analytics|telemetry|tracking|segment|mixpanel|'
            r'algolia|search[_-]?(?:key|api)|gtag|ga[_-]?(?:key|id|token)|'
            r'google[_-]?analytics|measurement[_-]?id)',
            evidence, re.IGNORECASE
        ):
            return False, "public_client_side_key"

        # Firebase API keys are public by design (used in frontend firebase config)
        if re.search(r'(?:firebase|FIREBASE)', evidence) and re.search(r'AIza', evidence):
            return False, "firebase_public_key"

        # First check if it's a known false positive pattern
        for fp_pattern in CREDENTIAL_FALSE_POSITIVE_PATTERNS:
            if fp_pattern.search(evidence):
                return False, "false_positive_pattern"

        # Then check if it matches a provider-specific pattern
        for pattern, provider in CREDENTIAL_PROVIDER_PATTERNS:
            if pattern.search(evidence):
                # Extra check: for Generic API Key Assignment, verify entropy
                if provider == "Generic API Key Assignment":
                    m = pattern.search(evidence)
                    if m and m.group(1):
                        ent = shannon_entropy(m.group(1))
                        if ent < 3.5:
                            return False, "low_entropy_generic"
                return True, f"provider:{provider}"

        # Didn't match any provider pattern = likely false positive from
        # the overly broad Base64-like or generic pattern in mcp-watch
        return False, "no_provider_match"

    elif vid == "PLAINTEXT_STORAGE":
        # This rule has 3 conditions already (write + credential keyword + no encryption)
        # Still produces FPs with logging/debug writes. Filter out:

        # Filter out third-party / vendored code
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build|__pycache__)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Filter out documentation files
        if re.search(r'\.(?:md|rst|txt|html|htm)$', filepath, re.IGNORECASE):
            return False, "documentation_file"

        # Filter out docs/ directories
        if re.search(r'(?:^|/)docs?/', filepath, re.IGNORECASE):
            return False, "docs_directory"

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|__test__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        fp_indicators = [
            r'sys\.stderr\.write',
            r'console\.',
            r'log\(',
            r'logger\.',
            r'logging\.',
            r'debug\(',
            r'print\(',
            r'\.write\s*\(\s*["\']',  # Writing string literals, not variables with secrets
            r'stderr',
            r'keyboard\.write',       # HID/keyboard, not credential storage
            r'f\.write\s*\(\s*f"',    # f-string write (benchmark, report, etc.)
            r'\.writeFile\s*\(',      # Node writeFile with hardcoded content
        ]
        for pattern in fp_indicators:
            if re.search(pattern, evidence, re.IGNORECASE):
                return False, "logging_not_storage"

        # The "write" must be writing an actual credential variable, not just any data
        has_credential_var = bool(re.search(
            r'(?:password|passwd|secret|token|api_key|apikey|credentials?|private_key)\b',
            evidence, re.IGNORECASE
        ))
        if not has_credential_var:
            return False, "write_without_credential_variable"

        return True, "plaintext_storage_confirmed"

    elif vid == "INSECURE_CREDENTIAL_PERMISSIONS":
        # Already quite specific (chmod + credential keyword), keep
        # But filter out docs/test files
        if re.search(r'\.(?:md|rst|txt|html|htm)$', filepath, re.IGNORECASE):
            return False, "documentation_file"
        if re.search(r'(?:^|/)docs?/', filepath, re.IGNORECASE):
            return False, "docs_directory"
        if re.search(r'(?:test|spec|mock|fixture|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"
        return True, "insecure_perms_confirmed"

    return False, "unknown_id"

**Veri positivi confermati dopo analisi LLM**: 516

{"server_name": "graphitiMCP", "file": "mcp_server/.env",
 "evidence": "OPENAI_API_KEY=sk-dZcsMXB34134r2YM759SWuTrfm1gHvHHWIgFBILK5OcGtiKJ"}

{"server_name": "mcp_py_exam", "file": ".env",
"evidence": "GOOGLE_API_KEY=AIzaSyDy6v56upofdlScaivq7NRW_Fh1KSmxjAM"}

{"server_name": "mcp-github-agent", "file": ".env",
 "evidence": "GITHUB_TOKEN=ghp_[REDACTED]"}

**Possibili falsi positivi da verificare:**
{
    "server_name": "docs-mcp",
    "github_url": "https://github.com/penysho/docs-mcp",
    "language": "nodejs",
    "id": "INSECURE_CREDENTIAL_PERMISSIONS",
    "category": "credential-leak",
    "description": "Credentials with world-readable permissions",
    "file": "package.json",
    "line": 9,
    "evidence": "\"build\": \"tsc && chmod 755 dist/index.js && cp credentials.json dist/ && cp token.json dist/\",",
    "source": "Trail of Bits research",
    "filter_confidence": "insecure_perms_confirmed"
},