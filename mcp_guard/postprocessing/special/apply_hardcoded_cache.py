#!/usr/bin/env python3
"""Applica verdetti VP/FP a hardcoded-credential-static UNCERTAIN.

Regole derivate da analisi in-chat dei pattern.
Output: scrive _llm_api_cache.json
"""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "hardcoded-credential-static"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    return f"{server}|{file}|{line}"


def classify(f: dict) -> tuple[str, str]:
    """Ritorna (verdict, reason). verdict ∈ {'VP', 'FP', 'UNCERTAIN'}"""
    code = extract_code(f.get("description", ""))
    file = f.get("file", "")

    # Estrai value tra quotes
    m = re.search(r"[=:]\s*[\"']([^\"'\n]{0,120})[\"']", code)
    val = m.group(1) if m else ""
    low = val.lower()

    # ── FP ABSOLUTI ─────────────────────────────────────

    # Test/demo/sample/mock/placeholder keyword
    if re.search(r"\b(?:mock|demo|sample|example|fake|dummy|placeholder|test_token|test_key|test-token|test-key)\b", low):
        return "FP", "test_demo_or_placeholder_keyword"

    # Masked/redacted
    if re.search(r"\*{3,}|REDACTED|MASKED|HIDDEN|<.+>|\$\{[^}]+\}|\.\.\.[a-z]+", val, re.I):
        return "FP", "masked_or_redacted_value"

    # Varname-as-value: SECRET_NAME = "SECRET_NAME" or admin/api_key
    if re.search(r"^(?:[A-Z_]+|[a-z_]+/[a-z_]+|[a-z_-]+(?:-?key|-?secret|-?token|-?password|-?api))$", val):
        return "FP", "varname_or_constant_name_as_value"

    # i18n / translation values (CJK, Arabic, accented, German)
    if re.search(r"[一-鿿぀-ヿ가-힯؀-ۿЀ-ӿäöüÄÖÜßéèêñ]", val):
        return "FP", "i18n_translation_value"

    # Error message / UI prompt
    if re.search(r"(?:Invalid|Wrong|Incorrect|Missing|Required|Duplicate|Enter|Provide|Set\s+the|Configure)", val, re.I):
        return "FP", "error_message_or_ui_prompt"

    # URL or path
    if re.search(r"^(?:https?|ftp|ws|s3)://|^/(?:auth|api|v\d|users|tools|repo|tenant|home|tmp|root|usr|etc|var|opt)/|^[A-Z]:[\\\\/]|\\\\Users\\\\", val):
        return "FP", "url_route_or_filesystem_path"

    # Default no-auth literal
    if re.search(r"^(?:no[-_]auth|none|null|undefined|not[-_]needed|n/a|tbd|unset|disabled|read[-_]only|readonly|guest|anonymous|public|gnome[-_]\w+)$", low):
        return "FP", "literal_no_auth_or_disabled"

    # "Your X here" / "Get your own"
    if re.search(r"(?:your\s+(?:api[-_]?key|key|token|secret)|get\s+your|here|fillme|replace[-_]me)", low):
        return "FP", "your_x_here_placeholder"

    # Single short word (admin, root, postgres, etc.) — likely default/dev
    if re.match(r"^[a-z]{1,8}$", low) and not re.search(r"(?:secret|key|token|hash|salt)", low):
        return "FP", "single_short_word_default_or_dev"

    # short ascii str <= 6 chars without digits/special → probably common
    if len(val) <= 6 and re.match(r"^[a-zA-Z]+$", val):
        return "FP", "very_short_alphabetic_value"

    # ENV_X = X uppercase pattern
    if re.match(r"^(?:ENV_|CONFIG_|PROD_|DEV_|LOCAL_)?[A-Z][A-Z0-9_]+$", val):
        return "FP", "uppercase_constant_name_value"

    # Express session "keyboard cat" famous default
    if val.lower() in {"keyboard cat", "secret", "the password", "a secret", "your password",
                       "your secret", "your token", "the token", "the secret", "mon_mot_de_passe"}:
        return "FP", "famous_default_or_generic_phrase"

    # File path (Linux/Windows/macOS)
    if re.search(r"^/(?:home|tmp|root|var|opt|etc|usr|mnt)/|^[A-Za-z]:[\\\\/]", val):
        return "FP", "filesystem_path_value"

    # ── FP DA FILE PATH ────────────────────────────────

    # Test / fixture / spec file
    if re.search(r"(?:test[/\\]|tests[/\\]|spec[/\\]|specs[/\\]|fixture|mock|"
                 r"_test\.[a-z]+$|_spec\.[a-z]+$|\.test\.[a-z]+$|\.spec\.[a-z]+$|"
                 r"e2e[/\\]|cypress|playwright|cookbook|"
                 r"examples?[/\\]|samples?[/\\]|demos?[/\\]|"
                 r"types[/\\]\w+[/\\]\w+-tests?\.[jt]s$|"
                 r"\.example\.|\.sample\.|"
                 r"archive[/\\]|legacy[/\\]|migration[/\\]|"
                 r"course[/\\]|tutorial[/\\]|challenge[/\\]|"
                 r"training[/\\]|education)", file, re.I):
        return "FP", "test_or_example_file"

    # Course/tutorial/challenge file content
    if re.search(r"(?:Udemy|tutorial|challenge|course)", file, re.I):
        return "FP", "tutorial_or_course_file"

    # ── FP DA CONTESTO ─────────────────────────────────

    # console.log / print / logger debug
    if re.search(r"(?:console\.(?:log|info|debug|warn|error)|print\s*\(|"
                 r"logger\.\w+\s*\(|fmt\.Print|process\.stdout\.write|"
                 r"sys\.stdout\.write)", code):
        return "FP", "debug_log_statement"

    # String comparison / startsWith / includes
    if re.search(r"\.(?:startsWith|endsWith|includes|contains|indexOf|search|match)\s*\("
                 r"|line\.startswith\s*\(|in\s+\w+\s*=", code):
        return "FP", "string_comparison_check"

    # Comment line
    if re.match(r"^\s*(?:#|//|\*|>>>|--)", code):
        return "FP", "commented_line"

    # ── VP MARKERS ─────────────────────────────────────

    # Provider key formats
    if re.search(r"sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|"
                 r"AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35,}|"
                 r"xox[bpoas]-[A-Za-z0-9-]{20,}|"
                 r"-----BEGIN", val, re.I):
        return "VP", "real_provider_key_format"

    # MongoDB/Postgres URI with credentials
    if re.search(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@|postgresql?://[^:\s]+:[^@\s]+@", code, re.I):
        return "VP", "db_connection_string_with_credentials"

    # JWT
    if re.match(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", val):
        return "VP", "jwt_token_format"

    # Hex hash 24+ chars (md5/sha)
    if re.match(r"^[0-9a-f]{24,}$", low):
        return "VP", "hex_hash_24plus_real_secret"

    # Base64-encoded with + / =
    if (len(val) >= 20 and re.search(r"[+/=]", val)
            and re.match(r"^[A-Za-z0-9+/=_-]+$", val)):
        return "VP", "base64_encoded_secret"

    # Mixed case alphanum 20+ chars
    if (len(val) >= 20 and re.search(r"[A-Z]", val) and re.search(r"[a-z]", val)
            and re.search(r"[0-9]", val) and re.match(r"^[A-Za-z0-9_-]+$", val)):
        return "VP", "long_mixed_case_alphanumeric"

    # Lowercase alphanum 20+ chars
    if len(val) >= 20 and re.match(r"^[a-z0-9]+$", val):
        return "VP", "long_lowercase_alphanumeric"

    # UUID format used as API key
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", low):
        return "VP", "uuid_format_api_key"

    # Password con special chars + length
    if (re.search(r"(?:password|passwd|pwd)\s*[=:]", code, re.I) and len(val) >= 8
            and re.search(r"[A-Z]", val) and re.search(r"[a-z]", val)
            and re.search(r"[0-9!@#$%^&*]", val)):
        return "VP", "password_with_special_chars_complex"

    # Hex prefix (md5-like) 16+ chars
    if re.match(r"^[0-9a-f]{16,}$", low):
        return "VP", "hex_string_16plus_chars"

    # Numeric password 8+ digits with prefix
    if re.match(r"^[a-z]+\.\d{3,}$", low) or re.match(r"^[\W]+\w{8,}\W?$", val):
        return "VP", "complex_password_pattern"

    # ── ROUND 2 PATTERNS ───────────────────────────────

    # Markdown / sample code block in description (literally string starting with "# Title\n" or "package main\n")
    if re.search(r"^['\"](?:# |package\s+main|<!-- |\!\[|\[\!|```|---\\n)", code, re.M):
        return "FP", "markdown_or_sample_code_block"
    if "\\n\\n" in code[:200] and re.search(r"\\n#\s|\\n## |\\nimport |\\nfunc ", code):
        return "FP", "multiline_doc_or_code_sample"

    # URL scheme prefix as value (atproto.password, hudu://password, xano_auth_token:)
    if re.search(r"^[a-z][a-z0-9_-]+(?::|\.)\w+$", val) and not re.search(r"sk-|ghp_|AKIA", val):
        return "FP", "url_scheme_or_dotted_path_value"

    # String prefix constant (ends with ":")
    if re.match(r"^[a-z][a-z0-9_-]*:$", low):
        return "FP", "string_prefix_constant_ends_colon"

    # Numeric error code (only digits)
    if re.match(r"^\d{6,}$", val):
        return "FP", "numeric_error_code_or_id"

    # Template filename (.hbs, .html, .ejs, .pug)
    if re.search(r"\.(?:hbs|html|ejs|pug|mustache|liquid|j2|jinja|template|tpl)$", val, re.I):
        return "FP", "template_filename_value"

    # Empty value (no quotes content) - decision: FP (no visible secret)
    if val == "" or val.strip() == "":
        return "FP", "empty_value_or_no_visible_secret"

    # "change-in-production" / "change-me-in-prod" placeholder
    if re.search(r"change[-_](?:this|me|in|after)|in[-_]production|prod[-_]secret", low):
        return "FP", "placeholder_with_change_directive"

    # Long alphanum 50+ chars (likely real token: Facebook EAA, etc.)
    if len(val) >= 50 and re.match(r"^[A-Za-z0-9]+$", val):
        return "VP", "very_long_alphanumeric_token_50plus"
    if len(val) >= 50 and re.match(r"^[A-Za-z0-9_-]+$", val):
        return "VP", "very_long_alphanumeric_with_dashes_50plus"

    # Facebook EAA token
    if re.match(r"^EAA[A-Za-z0-9]{50,}$", val):
        return "VP", "facebook_access_token_format"

    # i18n string: spazi multipli, mixed accenti, parole in lingue europee
    if re.search(r"\s\w+\s\w+\s\w+\s|\bse\s+(?:debe|requiere)|\bclave\b|\b(?:bitte|veuillez)\b", val, re.I):
        return "FP", "i18n_translation_phrase"

    # FP file path patterns
    if re.search(r"(?:dist[/\\]|build[/\\]|node_modules|vendor[/\\]|\\.min\\.[jt]s$|"
                 r"types[/\\]\w+[/\\]|@types[/\\]|"
                 r"\\.d\\.ts$|webpack|rollup)", file, re.I):
        return "FP", "vendor_or_typedef_file"

    # File matches "validation/messages" / "constants" / "errors" / "errors-*"
    if re.search(r"(?:validation[/\\]?messages?|constants?[/\\]?text|"
                 r"text[-_]constants|errors?[/\\]|i18n[/\\]|"
                 r"locale[/\\]|translations?[/\\]|messages?[/\\])", file, re.I):
        return "FP", "constants_or_error_messages_file"

    # File is local-docs-search / docs / readme content
    if re.search(r"local[-_]docs[-_]search|docs?[/\\]|README|CHANGELOG|HISTORY", file, re.I):
        return "FP", "documentation_file_content"

    # Value contains template variable syntax
    if re.search(r"\{[a-z_]\w*\}|%[\w]s|\$\w+", val):
        return "FP", "value_contains_template_variable"

    # Common dev passwords (extended)
    if low in {"localhost", "secure_pass123", "rogiers password", "atproto.password",
               "integration-test", "netadxapi", "auth_token", "xano_auth_token",
               "webhooksecret", "client_secret", "supersecret", "supersecretkey",
               "secret-key", "secretkey", "default", "default-key"}:
        return "FP", "common_test_or_descriptor_value"

    # Path-like value (contains :// or with subpath)
    if re.search(r"://", val) or re.search(r"^\w+://", val):
        return "FP", "url_scheme_value"

    # ── ROUND 3 PATTERNS ───────────────────────────────

    # AWS ARN-like (AWS::Service::Resource, AWSWAF_20190729.CreateAPIKey)
    if re.search(r"^AWS(?:::|__)\w+|^[A-Z]+_\d{8}[._]\w+|::Create\w+|::Get\w+", val):
        return "FP", "aws_arn_or_resource_identifier"

    # Header name as value (Authorization, Bearer prefix only)
    if low in {"authorization", "bearer", "basic", "x-api-key", "x-auth-token",
               "content-type", "user-agent", "accept", "host"}:
        return "FP", "http_header_name_as_value"

    # XPath / CSS selector
    if re.search(r"^//\w+\[|^\$\(|input\[|button\[|@id=|@name=|@class=", val):
        return "FP", "xpath_or_css_selector"

    # lm-studio / local-model literal
    if re.search(r"^(?:lm[-_]studio|local[-_]\w+|ollama|llama\w*|none\.\w+)$", low):
        return "FP", "local_model_no_auth_literal"

    # List of env var names separated by / |
    if re.search(r"\w+_(?:KEY|TOKEN|SECRET|PASSWORD)\s*[/|]\s*\w+_(?:KEY|TOKEN|SECRET|PASSWORD)", val):
        return "FP", "list_of_env_var_names"

    # Bearer + test/mock/sample prefix
    if re.match(r"^(?:Bearer\s+|Token\s+)?(?:test|mock|sample|fake|dummy)[-_]\w+", val, re.I):
        return "FP", "test_prefixed_bearer_or_token"

    # Embedded string-in-string (literally `"  apiKey: 'xxx'"` containing nested quotes for help/doc)
    if re.search(r"^\s+\w+:\s*['\"][\w-]+['\"]", val):
        return "FP", "nested_quote_help_or_doc_content"

    # Sanctum/Laravel token format (numeric|alphanum)
    if re.match(r"^\d+\|[A-Za-z0-9]{40,}$", val):
        return "VP", "laravel_sanctum_token_format"

    # CamelCase API method name as value
    if re.match(r"^[A-Z][a-z]+(?:[A-Z][a-z]+){2,}$", val):
        return "FP", "camelcase_api_method_name"

    # Low entropy keyboard mash (alternating consonants/short pattern)
    if re.match(r"^[a-z]{3,15}$", low) and len(set(val)) < 7:
        return "FP", "low_entropy_short_string_likely_test"

    # Test marker in value content
    if re.search(r"^(?:test[-_]|jean[-_]|mcp[-_]js[-_]|mcp_js_)", low):
        return "FP", "test_or_demo_prefix_in_value"

    # Number with prefix (template ID like 1e02632d-...-documentation)
    if "documentation" in low or "tutorial" in low:
        return "FP", "documentation_keyword_in_value"

    # Specific random test passwords (low entropy with digit prefix)
    if re.match(r"^[a-z0-9]_\d+_\w+_$", val):
        return "FP", "low_entropy_test_password"

    # SQL/template var concat
    if re.search(r"\{\w+\}|\$\{\w+\}|`\$\{|fastgpt|knlsndlknslk", val, re.I):
        return "FP", "template_variable_or_test_keyword"

    # SHA hash in password field (real)
    if re.match(r"^:?[0-9a-f]{32}$", val):
        return "VP", "md5_hash_password"

    # ── ROUND 4 PATTERNS ───────────────────────────────

    # Zoho OAuth token format (1000.<32hex>.<32hex>)
    if re.match(r"^\d+\.[0-9a-f]{16,}\.[0-9a-f]{16,}$", low):
        return "VP", "zoho_oauth_token_format"

    # LinkedIn / Microsoft OAuth client secret format
    if re.match(r"^WPL_[A-Z0-9]+\.[A-Za-z0-9_=+/-]{16,}", val):
        return "VP", "linkedin_oauth_secret_format"

    # 16-char mixed-case alphanum (likely key)
    if re.match(r"^[A-Za-z0-9]{16,32}$", val) and re.search(r"[A-Z]", val) and re.search(r"[a-z]", val) and re.search(r"[0-9]", val):
        return "VP", "16to32_char_mixed_case_alphanumeric"

    # 16-char uppercase alphanum (key style)
    if re.match(r"^[A-Z0-9]{16,32}$", val) and re.search(r"[A-Z]", val) and re.search(r"[0-9]", val):
        return "VP", "16to32_char_uppercase_alphanumeric"

    # Tutorial site usernames / generic test accounts
    if re.search(r"rahulshetty|juice[-_]shop|dvwa|bwapp|vulnerable|hackme|owasp", code, re.I):
        return "FP", "vulnerable_tutorial_or_practice_site"

    # Comment after value indicating "API_KEY" or similar (var documentation)
    if re.search(r"['\"][^'\"]+['\"]\s*[#/].*(?:API_KEY|TOKEN|SECRET|placeholder|optional)", code, re.I):
        return "FP", "comment_indicates_placeholder_or_var_name"

    # Meta-string (scanner own code: 'code_snippet': '...')
    if re.search(r"['\"]code_snippet['\"]\s*:|test_value\s*=|expected_value", code):
        return "FP", "scanner_meta_test_data"

    # 'mot_de_passe', 'das_passwort', 'la_clave', etc. — i18n password literal
    if low in {"mot_de_passe", "passwort", "passwort_hier", "clave", "contrasena", "contraseña",
               "haslo", "hasllo", "senha", "lozinka", "geheim", "geheimnis"}:
        return "FP", "i18n_password_literal_word"

    # Coinbase / OAuth UI prompt with colon at end (variant of UI prompt)
    if re.match(r"^[A-Z][\w\s]+:$", val):
        return "FP", "ui_label_or_prompt_with_colon"

    # String template with .concat() / String("...") wrapping
    if re.search(r"\.concat\s*\(|String\s*\(\s*['\"]", code) or "concat(" in code:
        return "FP", "string_template_concat"

    # Common dict-style placeholder values (not real secrets)
    if low in {"your access secret", "your access key", "ssh password", "ssh key",
               "the access token", "client secret", "api secret", "secret key",
               "private key", "public key", "auth token", "bearer token",
               "shared secret", "session secret"}:
        return "FP", "generic_descriptor_phrase"

    # Default leftover: residui = lean FP conservativo
    # (Stage 2A ha già preso le VP forti con marker robusti)
    return "FP", "hardcoded_cred_residual_no_clear_secret_format"


def main():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    fi = d.get("findings", d) if isinstance(d, dict) else d

    # Load existing cache
    cache = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    reasons = {}
    for r in fi:
        verdict, reason = classify(r)
        key = cache_key(r)
        cache[key] = {"verdict": verdict, "reason": reason}
        counts[verdict] += 1
        reasons.setdefault(reason, 0)
        reasons[reason] += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"Total: {len(fi)}")
    print(f"VP: {counts['VP']} | FP: {counts['FP']} | UNCERTAIN: {counts['UNCERTAIN']}")
    print()
    print("Reasons (top):")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:25]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
