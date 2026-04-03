"""
Credential Re-Filter for MCP Watch results.

Reads the existing credential-leak JSON files produced by mcp-watch
and re-evaluates every finding using:
  1. Provider-specific regex patterns (style GitGuardian/GitHub Advanced Security)
  2. Shannon entropy analysis (reject low-entropy strings)
  3. Context-aware exclusions (hashes, blockchain addresses, API schema refs, etc.)

Usage:
  python credential_refilter.py                         # uses default paths
  python credential_refilter.py --input <dir>           # custom input dir
  python credential_refilter.py --input <dir> --output <dir>

Input:  analysisAllData/0_tool_mcp_watch/credential-leak/
Output: pipeline/new_mcp_watch/  (credential_leak_refiltered.json + stats)
"""

import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import re
import math
import argparse
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone


# ── Paths ────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = SCRIPT_DIR.parent / "analysisAllData" / "0_tool_mcp_watch" / "credential-leak"
DEFAULT_OUTPUT = SCRIPT_DIR


# ═══════════════════════════════════════════════════════════════════════════
#  1. PROVIDER-SPECIFIC PATTERNS
# ═══════════════════════════════════════════════════════════════════════════
#
# Each entry: (compiled_regex, provider_label, min_entropy)
# min_entropy=0 means "the prefix alone is proof enough, skip entropy check"

PROVIDER_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # ── AI / LLM ──
    (re.compile(r'sk-ant-api03-[a-zA-Z0-9\-_]{48,85}'),           "Anthropic API Key",        0),
    (re.compile(r'sk-proj-[a-zA-Z0-9\-_]{40,}'),                  "OpenAI Project Key",       0),
    (re.compile(r'sk-[a-zA-Z0-9]{40,60}'),                        "OpenAI Legacy Key",        3.5),
    (re.compile(r'sess-[a-zA-Z0-9]{40,}'),                        "OpenAI Session Key",       0),
    (re.compile(r'hf_[a-zA-Z0-9]{34,}'),                          "Hugging Face Token",       0),

    # ── Cloud Providers ──
    (re.compile(r'AKIA[A-Z0-9]{16}'),                              "AWS Access Key ID",        3.0),
    (re.compile(r'ASIA[A-Z0-9]{16}'),                              "AWS Temporary Key",        3.0),
    (re.compile(r'(?:aws).{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]'),    "AWS Secret Access Key",    4.0),
    (re.compile(r'AIza[a-zA-Z0-9_\-]{35}'),                       "Google API Key",           0),
    (re.compile(r'ya29\.[a-zA-Z0-9_\-]{50,}'),                    "Google OAuth Token",       0),
    (re.compile(r'[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'), "Google OAuth Client ID", 0),
    (re.compile(r'az[a-z]{2,4}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), "Azure Key", 0),

    # ── Git / CI/CD ──
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'),                          "GitHub PAT (classic)",     0),
    (re.compile(r'gho_[a-zA-Z0-9]{36}'),                          "GitHub OAuth Token",       0),
    (re.compile(r'ghu_[a-zA-Z0-9]{36}'),                          "GitHub User Token",        0),
    (re.compile(r'ghs_[a-zA-Z0-9]{36}'),                          "GitHub Server Token",      0),
    (re.compile(r'ghr_[a-zA-Z0-9]{36}'),                          "GitHub Refresh Token",     0),
    (re.compile(r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'),   "GitHub PAT (fine-grained)",0),
    (re.compile(r'glpat-[a-zA-Z0-9\-_]{20,}'),                    "GitLab PAT",               0),
    (re.compile(r'glrt-[a-zA-Z0-9\-_]{20,}'),                     "GitLab Runner Token",      0),
    (re.compile(r'GR1348941[a-zA-Z0-9\-_]{20,}'),                 "GitLab Pipeline Token",    0),

    # ── Messaging / SaaS ──
    (re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'), "Slack Bot Token",       0),
    (re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'), "Slack User Token",      0),
    (re.compile(r'xoxs-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}'), "Slack Session Token", 0),
    (re.compile(r'xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-zA-Z0-9]{64}'), "Slack App Token",    0),
    (re.compile(r'xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'), "Slack Access Token",    0),
    (re.compile(r'(?:https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)'), "Slack Webhook URL", 0),
    (re.compile(r'[0-9]{17,20}\.[a-zA-Z0-9_\-]{6,7}\.[a-zA-Z0-9_\-]{27,}'), "Discord Bot Token", 3.5),
    (re.compile(r'(?:https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+)'), "Discord Webhook URL", 0),

    # ── Payments ──
    (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Secret Key (live)",  0),
    (re.compile(r'sk_test_[a-zA-Z0-9]{24,}'),                     "Stripe Secret Key (test)",  0),
    (re.compile(r'pk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Publishable (live)", 0),
    (re.compile(r'pk_test_[a-zA-Z0-9]{24,}'),                     "Stripe Publishable (test)", 0),
    (re.compile(r'rk_live_[a-zA-Z0-9]{24,}'),                     "Stripe Restricted Key",     0),
    (re.compile(r'whsec_[a-zA-Z0-9]{32,}'),                       "Stripe Webhook Secret",     0),
    (re.compile(r'sq0atp-[a-zA-Z0-9\-_]{22,}'),                   "Square Access Token",       0),
    (re.compile(r'sq0csp-[a-zA-Z0-9\-_]{43,}'),                   "Square OAuth Secret",       0),

    # ── Email / Communication ──
    (re.compile(r'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'), "SendGrid API Key",        0),
    (re.compile(r'key-[a-zA-Z0-9]{32}'),                           "Mailgun API Key",         3.5),
    (re.compile(r'SK[a-f0-9]{32}'),                                "Twilio API Key",          3.0),

    # ── Infrastructure / DevOps ──
    (re.compile(r'dckr_pat_[a-zA-Z0-9_\-]{24,}'),                 "Docker PAT",              0),
    (re.compile(r'npm_[a-zA-Z0-9]{36}'),                           "npm Token",               0),
    (re.compile(r'pypi-AgEIcH[a-zA-Z0-9\-_]{50,}'),               "PyPI API Token",          0),
    (re.compile(r'v1\.[a-f0-9]{40}'),                              "Vercel Token",            3.0),
    (re.compile(r'vercel_[a-zA-Z0-9]{24,}'),                       "Vercel API Token",        0),
    (re.compile(r'npl_[a-zA-Z0-9]{24,}'),                          "Netlify PAT",             0),
    (re.compile(r'(?:heroku)[a-zA-Z0-9\-_]{0,20}[\'"][0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}[\'"]'), "Heroku API Key", 0),
    (re.compile(r'FLWSECK_TEST-[a-zA-Z0-9]{32,}'),                "Flutterwave Secret Key",  0),
    (re.compile(r'FLWPUBK_TEST-[a-zA-Z0-9]{32,}'),                "Flutterwave Public Key",  0),

    # ── Databases / BaaS ──
    (re.compile(r'sbp_[a-f0-9]{40}'),                              "Supabase Service Key",    0),
    (re.compile(r"mongodb(?:\+srv)?://[^\s'\"<>]{10,}"),            "MongoDB Connection URI",  0),
    (re.compile(r"postgres(?:ql)?://[^\s'\"<>]{10,}"),              "PostgreSQL Connection URI",0),
    (re.compile(r"mysql://[^\s'\"<>]{10,}"),                        "MySQL Connection URI",    0),
    (re.compile(r"redis://[^\s'\"<>]{10,}"),                        "Redis Connection URI",    0),
    (re.compile(r"amqp://[^\s'\"<>]{10,}"),                         "AMQP Connection URI",     0),

    # ── Auth / Identity ──
    (re.compile(r'(?:Bearer\s+)[a-zA-Z0-9\-_.~+/]{20,}'),         "Bearer Token",            4.0),

    # ── Private Keys (multiline won't work line-by-line, but catch the header) ──
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Private Key Header", 0),

    # ── JWT (only flag if it looks real — high entropy in payload) ──
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]{10,}'), "JWT Token", 3.5),

    # ── Generic high-confidence: assignment of long random string to sensitive var ──
    # Only matches: apiKey = "actualRandomValue" (not variable refs, not short)
    (re.compile(
        r'''(?:api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token)'''
        r'''\s*[:=]\s*["']([a-zA-Z0-9\-_./+]{20,})["']''',
        re.IGNORECASE
    ), "Generic API Key Assignment", 4.0),
]


# ═══════════════════════════════════════════════════════════════════════════
#  2. CONTEXT-AWARE FALSE POSITIVE FILTERS
# ═══════════════════════════════════════════════════════════════════════════

# Patterns in evidence that are NEVER real credentials
FALSE_POSITIVE_PATTERNS: list[re.Pattern] = [
    # Hashes / checksums / digests in data files
    re.compile(r'"(?:sha256?|sha384|sha512|md5|hash|checksum|digest|fileSha256|commit_sha|sha|spentTxId|paper_id)"'
               r'\s*:\s*"[a-fA-F0-9]{32,}"', re.IGNORECASE),

    # Blockchain / Ethereum addresses (0x prefix + 40 hex)
    re.compile(r'0x[a-fA-F0-9]{40}'),

    # Blockchain / long hex constants clearly labeled as addresses
    re.compile(r'"(?:address|source|from|to|contractAddress|sender|receiver|owner)"\s*:\s*"0x', re.IGNORECASE),

    # Google API discovery schema refs ($ref: "GoogleCloud...")
    re.compile(r'"\$ref"\s*:\s*"Google[A-Z]'),

    # Google API class/type IDs in "id" fields
    re.compile(r'"id"\s*:\s*"Google(?:Cloud|Devtools|Iam|Api|Monitoring|Storage|Compute)', re.IGNORECASE),

    # Long CamelCase identifiers (class names, not secrets)
    re.compile(r'"[A-Z][a-zA-Z]{30,}"'),

    # __name(...) wrapper from bundled JS (minified code)
    re.compile(r'__name\s*\('),

    # Example / placeholder credentials
    re.compile(r'(?:your[-_]?(?:api[-_]?key|token|secret)|example|demo|placeholder|'
               r'xxx{3,}|yyy{3,}|123456|abcdef{2,}|replace[-_]?me|change[-_]?me|'
               r'dummy|fake|mock|sample|insert[-_]?here|insert[-_]?your|'
               r'key[-_]?here|token[-_]?example|secret[-_]?placeholder|TODO|FIXME)',
               re.IGNORECASE),

    # AWS presigned URL parameters (not leaked keys, just S3 signed URLs)
    re.compile(r'X-Amz-(?:Algorithm|Credential|Signature|Date|Expires)', re.IGNORECASE),
    re.compile(r'AWSAccessKeyId=', re.IGNORECASE),  # presigned URL v2 syntax

    # AWS example/documentation keys
    re.compile(r'AKIAIOSFODNN7EXAMPLE'),
    re.compile(r'AKIAIOSFODNN7REALKEY'),  # common test fixture

    # Template variables: ${...}, {{...}}, <...>
    re.compile(r'\$\{[^}]+\}'),
    re.compile(r'\{\{[^}]+\}\}'),
    re.compile(r'<[A-Z_]{3,}>'),  # <YOUR_API_KEY>

    # process.env references (reading from env, not hardcoded)
    re.compile(r'process\.env\.\w+'),
    re.compile(r'os\.environ\b'),
    re.compile(r'os\.getenv\b'),

    # Comments (lines starting with // or # after trim)
    re.compile(r'^\s*(?://|#)\s'),

    # govinfo / bulk data URLs
    re.compile(r'govinfo\.gov/bulkdata'),

    # Pure hex strings in non-credential contexts (data files)
    # These get caught by the entropy check anyway, but explicitly:
    re.compile(r'"[a-f0-9]{64}"'),  # SHA-256 hex

    # Sui/Cetus/blockchain package IDs (long hex with 0x prefix)
    re.compile(r"0x[a-f0-9]{64}"),

    # Boolean-like values that happen to have credential keywords in key name
    re.compile(r':\s*(?:true|false|null)\s*[,}]?\s*$', re.IGNORECASE),

    # Supabase demo/local development JWT (well-known token shared in docs)
    re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZS1kZW1v'),

    # Supabase anon key JWT (public by design, protected by RLS)
    re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*cm9sZSI6ImFub24[A-Za-z0-9_-]*'),  # role":"anon" in base64

    # JWT "John Doe" / sub=1234567890 example tokens (jwt.io / RFC 7519)
    re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJzdWIiOiIxMjM0NTY3ODkw'),

    # Binance official documentation example keys
    re.compile(r'vmPUZE6mv9SD5VNHk4HlWFsOr6aKE2zvsw0MuIgwCIPy6utIco14y7Ju91duEh8A'),
    re.compile(r'NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j'),

    # Placeholder PostgreSQL/MySQL URIs with obvious fake credentials
    re.compile(r'(?:postgresql|mysql|postgres)://(?:postgres|dbuser|user|admin|root):(?:password|dbpass|pass|secret|123456)@localhost', re.IGNORECASE),

    # Synthetic/sequential placeholder keys (sk-abc123def456...)
    re.compile(r'sk-abc\d+[a-z]+\d+[a-z]+\d+'),

    # evdev keyboard input simulation (EV_KEY = keyboard key, not credential)
    re.compile(r'EV_KEY'),
]

# Files/paths that almost never contain real hardcoded credentials
FALSE_POSITIVE_FILE_PATTERNS: list[re.Pattern] = [
    re.compile(r'\.test\.[jt]sx?$'),
    re.compile(r'\.spec\.[jt]sx?$'),
    re.compile(r'__tests__/'),
    re.compile(r'test[s]?/'),
    re.compile(r'fixture[s]?/'),
    re.compile(r'mock[s]?/'),
    re.compile(r'\.snap$'),
    re.compile(r'\.lock$'),
    re.compile(r'package-lock\.json$'),
    re.compile(r'yarn\.lock$'),
    re.compile(r'\.min\.js$'),
    re.compile(r'swagger\.json$'),
    re.compile(r'openapi.*\.json$', re.IGNORECASE),
    re.compile(r'discovery.*\.json$', re.IGNORECASE),
    # Virtual environments and installed dependencies
    re.compile(r'(?:^|/)venv/'),
    re.compile(r'(?:^|/)\.venv/'),
    re.compile(r'(?:^|/)node_modules/'),
    re.compile(r'site-packages/'),
    # Minified JS libraries
    re.compile(r'jquery[^/]*\.js$', re.IGNORECASE),
    # Security scan result/demo files
    re.compile(r'(?:result-demo|last_results|security.*report)\.json$', re.IGNORECASE),
    # Lighthouse performance logs
    re.compile(r'logs/.*lighthouse.*\.json$', re.IGNORECASE),
]


# ═══════════════════════════════════════════════════════════════════════════
#  3. SHANNON ENTROPY
# ═══════════════════════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_alternating_placeholder(s: str) -> bool:
    """
    Detect placeholder tokens with alternating letter/number patterns.
    Examples: A1bC2dE3fH4iJ5kL6mN7o, xK9mL2pQ3rN4sT5vW6x
    These are structured sequences that fool entropy checks.
    """
    if len(s) < 16:
        return False

    # Strip common prefixes
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "sk_live_", "sk_test_"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break

    if len(s) < 12:
        return False

    # Check if the string follows a repeating [letter][digit] or [letter][digit][letter] pattern
    # Count transitions between character types
    transitions = 0
    for i in range(1, len(s)):
        prev_is_alpha = s[i - 1].isalpha()
        curr_is_alpha = s[i].isalpha()
        if prev_is_alpha != curr_is_alpha:
            transitions += 1

    # A truly alternating pattern has transitions/(len-1) close to 1.0
    # Real random strings have ~0.5 transition rate
    transition_rate = transitions / (len(s) - 1)
    if transition_rate < 0.55:
        return False

    # Additionally check for alphabetical progression in the letters
    letters = [c.lower() for c in s if c.isalpha()]
    if len(letters) < 6:
        return False

    # Count how many consecutive letter pairs are in alphabetical order (wrapping)
    alpha_order_count = 0
    for i in range(len(letters) - 1):
        diff = (ord(letters[i + 1]) - ord(letters[i])) % 26
        if 1 <= diff <= 4:  # within 4 letters forward in alphabet
            alpha_order_count += 1

    alpha_order_rate = alpha_order_count / (len(letters) - 1)
    # Real tokens: ~0.2-0.3 alphabetical adjacency
    # Fake alternating: ~0.5+ alphabetical adjacency
    return alpha_order_rate > 0.45


def extract_secret_value(evidence: str) -> str:
    """Try to extract the actual secret value from the evidence line."""
    # Try to find a quoted string that looks like the secret
    # Pattern: after = or : find a quoted value
    m = re.search(r'''[:=]\s*["']([a-zA-Z0-9\-_./+]{8,})["']''', evidence)
    if m:
        return m.group(1)

    # Try to find any long alphanumeric string
    candidates = re.findall(r'[a-zA-Z0-9\-_./+]{20,}', evidence)
    if candidates:
        # Return the longest one
        return max(candidates, key=len)

    return evidence


# ═══════════════════════════════════════════════════════════════════════════
#  4. CORE CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

def classify_finding(finding: dict) -> dict | None:
    """
    Evaluate a single finding. Returns an enriched finding dict if it's
    a true positive, or None if it's a false positive.
    """
    evidence = finding.get("evidence", "")
    file_path = finding.get("file", "")
    original_id = finding.get("id", "")

    if not evidence:
        return None

    # ── Step 1: Check file-level false positives ──
    for fp_file in FALSE_POSITIVE_FILE_PATTERNS:
        if fp_file.search(file_path):
            return None

    # ── Step 2: Check evidence-level false positives ──
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp.search(evidence):
            return None

    # ── Step 3: Try provider-specific patterns ──
    for pattern, provider, min_entropy in PROVIDER_PATTERNS:
        m = pattern.search(evidence)
        if m:
            matched_text = m.group(0)

            # Entropy check if required
            if min_entropy > 0:
                # For patterns with capture group, use the group
                secret_part = m.group(1) if m.lastindex and m.lastindex >= 1 else matched_text
                # Strip known prefixes for entropy calc
                for prefix in ("sk-", "sk-proj-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
                               "AKIA", "ASIA", "AIza", "ya29.", "xoxb-", "xoxp-",
                               "sk_live_", "sk_test_", "pk_live_", "pk_test_",
                               "SG.", "npm_", "dckr_pat_", "hf_", "Bearer "):
                    if secret_part.startswith(prefix):
                        secret_part = secret_part[len(prefix):]
                        break

                entropy = shannon_entropy(secret_part)
                if entropy < min_entropy:
                    return None
            else:
                secret_part = matched_text
                entropy = shannon_entropy(secret_part)

            # Check for alternating placeholder patterns (e.g. A1bC2dE3f)
            if is_alternating_placeholder(matched_text):
                return None

            result = {**finding}
            result["matched_provider"] = provider
            result["matched_pattern"] = matched_text[:80] + ("..." if len(matched_text) > 80 else "")
            result["entropy"] = round(entropy, 3)
            result["confidence"] = "high" if min_entropy == 0 else "medium"
            result["refilter_id"] = f"CREDENTIAL_{provider.upper().replace(' ', '_')}"
            return result

    # ── Step 4: For PLAINTEXT_STORAGE and INSECURE_CREDENTIAL_PERMISSIONS ──
    #    These are structural findings, not pattern-based. Apply lighter filtering.
    if original_id == "INSECURE_CREDENTIAL_PERMISSIONS":
        # This one is already quite precise, keep it
        result = {**finding}
        result["matched_provider"] = "Permission Issue"
        result["matched_pattern"] = ""
        result["entropy"] = 0
        result["confidence"] = "medium"
        result["refilter_id"] = "INSECURE_CREDENTIAL_PERMISSIONS"
        return result

    if original_id == "PLAINTEXT_STORAGE":
        # Filter out common false positives for PLAINTEXT_STORAGE
        plaintext_fp = [
            re.compile(r'sys\.stderr\.write'),          # logging, not file write
            re.compile(r'sys\.stdout\.write'),           # logging
            re.compile(r'console\.(?:log|error|warn)'),  # logging
            re.compile(r'proc\.stdin\.write'),            # stdin pipe, not file
            re.compile(r'socket\.write'),                 # network write
            re.compile(r'res\.write'),                    # HTTP response
            re.compile(r'response\.write'),               # HTTP response
            re.compile(r'stream\.write.*(?:log|debug|info|warn|error)', re.IGNORECASE),
            re.compile(r'\.write\s*\(\s*[\'"]'),          # writing a literal string
            re.compile(r'stderr\.write.*(?:error|warning|token\s+expired|syntax)', re.IGNORECASE),
            # Writing to spec/test files
            re.compile(r'writeFile.*(?:\.spec\.|\.test\.|mock|fixture|\.md)', re.IGNORECASE),
            re.compile(r'writeFileSync.*(?:\.spec\.|\.test\.|mock|fixture)', re.IGNORECASE),
            # Streamlit UI output
            re.compile(r'st\.write'),
            # S3-style .write() with Bucket/Key as parameters (not credentials)
            re.compile(r'\.write\s*\(.*\b(?:Bucket|Key)\b.*\.read\s*\(', re.IGNORECASE),
        ]

        for pfp in plaintext_fp:
            if pfp.search(evidence):
                return None

        # Keep the rest — these could be real plaintext credential writes
        result = {**finding}
        result["matched_provider"] = "Plaintext Storage"
        result["matched_pattern"] = ""
        result["entropy"] = 0
        result["confidence"] = "low"
        result["refilter_id"] = "PLAINTEXT_CREDENTIAL_STORAGE"
        return result

    # ── Step 5: Nothing matched → false positive ──
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  5. MAIN PROCESSING
# ═══════════════════════════════════════════════════════════════════════════

def load_input_files(input_dir: Path) -> list[dict]:
    """Load all credential-leak JSON files from the input directory."""
    all_findings = []
    for json_file in sorted(input_dir.glob("credential_leak_*.json")):
        print(f"  Loading {json_file.name}...")
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings = data.get("findings", [])
            severity = data.get("severity", "unknown")
            # Tag each finding with its original severity
            for finding in findings:
                if "severity" not in finding:
                    finding["severity"] = severity
            all_findings.extend(findings)
            print(f"    -> {len(findings)} findings (severity: {severity})")
        except Exception as e:
            print(f"    -> ERROR: {e}")
    return all_findings


def process_findings(findings: list[dict]) -> tuple[list[dict], dict]:
    """Process all findings and return (true_positives, stats)."""
    true_positives = []
    stats = {
        "total_input": len(findings),
        "total_output": 0,
        "false_positives_removed": 0,
        "by_provider": Counter(),
        "by_confidence": Counter(),
        "by_severity": Counter(),
        "by_original_id": Counter(),
        "original_id_breakdown": {},
    }

    # Track per original_id stats
    per_id_input = Counter()
    per_id_output = Counter()

    for i, finding in enumerate(findings):
        if i > 0 and i % 100000 == 0:
            print(f"  Processed {i:,}/{len(findings):,} "
                  f"({len(true_positives):,} kept, {i - len(true_positives):,} removed)")

        per_id_input[finding.get("id", "unknown")] += 1

        result = classify_finding(finding)
        if result is not None:
            true_positives.append(result)
            stats["by_provider"][result["matched_provider"]] += 1
            stats["by_confidence"][result["confidence"]] += 1
            stats["by_severity"][result.get("severity", "unknown")] += 1
            per_id_output[finding.get("id", "unknown")] += 1

    stats["total_output"] = len(true_positives)
    stats["false_positives_removed"] = len(findings) - len(true_positives)

    # Build per-ID breakdown
    for orig_id in sorted(per_id_input.keys()):
        inp = per_id_input[orig_id]
        out = per_id_output.get(orig_id, 0)
        stats["original_id_breakdown"][orig_id] = {
            "input": inp,
            "output": out,
            "removed": inp - out,
            "removal_rate": round((1 - out / inp) * 100, 2) if inp > 0 else 0,
        }

    return true_positives, stats


def save_results(true_positives: list[dict], stats: dict, output_dir: Path):
    """Save filtered results and stats."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Main results file (grouped by confidence) ──
    output = {
        "refilter_date": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_input": stats["total_input"],
            "total_output": stats["total_output"],
            "false_positives_removed": stats["false_positives_removed"],
            "removal_rate_percent": round(
                (stats["false_positives_removed"] / stats["total_input"] * 100)
                if stats["total_input"] > 0 else 0, 2
            ),
        },
        "findings_by_confidence": {
            "high": [],
            "medium": [],
            "low": [],
        },
    }

    for tp in true_positives:
        confidence = tp.get("confidence", "low")
        output["findings_by_confidence"][confidence].append(tp)

    for conf in output["findings_by_confidence"]:
        output["findings_by_confidence"][conf].sort(
            key=lambda x: x.get("entropy", 0), reverse=True
        )

    results_file = output_dir / "credential_leak_refiltered.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)
    print(f"\n  Results saved to: {results_file}")

    # ── Stats file ──
    stats_output = {
        "refilter_date": datetime.now(timezone.utc).isoformat(),
        "summary": output["summary"],
        "by_provider": dict(stats["by_provider"].most_common()),
        "by_confidence": dict(stats["by_confidence"].most_common()),
        "by_severity": dict(stats["by_severity"].most_common()),
        "original_id_breakdown": stats["original_id_breakdown"],
        "counts_by_confidence": {
            k: len(v) for k, v in output["findings_by_confidence"].items()
        },
    }

    stats_file = output_dir / "credential_leak_refilter_stats.json"
    with open(stats_file, "w", encoding="utf-8") as f:
        json.dump(stats_output, f, indent=4, ensure_ascii=False)
    print(f"  Stats saved to:   {stats_file}")


def main():
    parser = argparse.ArgumentParser(description="Re-filter MCP Watch credential-leak findings")
    parser.add_argument("--input", "-i", type=str, default=None,
                        help="Input directory with credential_leak_*.json files")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output directory (default: same as script)")
    args = parser.parse_args()

    input_dir = Path(args.input) if args.input else DEFAULT_INPUT
    output_dir = Path(args.output) if args.output else DEFAULT_OUTPUT

    print(f"=== Credential Re-Filter ===")
    print(f"  Input:  {input_dir}")
    print(f"  Output: {output_dir}")
    print()

    if not input_dir.exists():
        print(f"ERROR: Input directory does not exist: {input_dir}")
        sys.exit(1)

    # Load
    print("Loading input files...")
    findings = load_input_files(input_dir)
    print(f"\nTotal findings loaded: {len(findings):,}")
    print()

    if not findings:
        print("No findings to process.")
        return

    # Process
    print("Processing findings...")
    true_positives, stats = process_findings(findings)

    print(f"\n{'=' * 60}")
    print(f"  INPUT:   {stats['total_input']:>10,} findings")
    print(f"  OUTPUT:  {stats['total_output']:>10,} true positives")
    print(f"  REMOVED: {stats['false_positives_removed']:>10,} false positives "
          f"({stats['false_positives_removed'] / stats['total_input'] * 100:.1f}%)")
    print(f"{'=' * 60}")

    if stats["by_provider"]:
        print(f"\n  By provider:")
        for provider, count in stats["by_provider"].most_common(20):
            print(f"    {provider:<35} {count:>8,}")

    if stats["by_confidence"]:
        print(f"\n  By confidence:")
        for conf, count in stats["by_confidence"].most_common():
            print(f"    {conf:<35} {count:>8,}")

    print(f"\n  By original ID (input -> output):")
    for orig_id, breakdown in stats["original_id_breakdown"].items():
        print(f"    {orig_id:<40} {breakdown['input']:>8,} -> {breakdown['output']:>8,} "
              f"(removed {breakdown['removal_rate']:.1f}%)")

    # Save
    print()
    save_results(true_positives, stats, output_dir)
    print("\nDone.")


if __name__ == "__main__":
    main()
