"""
Stage 2B classifier per UNCERTAIN NPX mcp-check.

Logica:
- invalid_arguments UNCERTAIN: tutti FP (server validano correttamente "test"/input fuzz)
- other_errors UNCERTAIN: maggior parte FP (env/auth/validation server),
  VP solo per bug runtime reali (JS errors, undefined in URL, JSON Schema bugs).
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _server_short(url):
    return (url or "").replace("https://github.com/", "")


# VP set per other_errors: server con bug runtime reali
OTHER_ERRORS_VP_SERVERS = {
    "@ericxstone/crypto-earn-mcp",         # Custom types JSON Schema serialization bug
    "@huangchen1989/image-to-matlab-mcp",  # Failed to parse URL from test (no validation)
    "@llmready/mcp",                       # Failed to parse URL from test (no validation)
    "@mseep/bruno-mcp",                    # DEP0040 deprecation warning treated as error
    "bruno-mcp",                           # Stesso problema bruno-mcp DEP0040
    "@pony683/mcp-server-flomo",           # Failed to parse URL from (no validation)
    "@undefined0_0/jira-mcp",              # Failed to parse URL from undefined/... (undefined bug)
    "chip-mcp",                            # Failed to parse URL from undefined
    "mcp-server-rss3",                     # Method undefined not found
    "prompt-flow-mcp",                     # JS runtime: Cannot use 'in' operator on undefined
}


def classify_invalid_arguments(entry):
    """tool_invocation/invalid_arguments: tutti server validano input → FP."""
    return ("FP", "server_correctly_validates_test_input")


def classify_other_errors(entry):
    server = _server_short(entry.get("server_url", ""))
    if server in OTHER_ERRORS_VP_SERVERS:
        return ("VP", "runtime_bug_or_missing_input_validation")
    # default FP per UNCERTAIN residui (env/auth/external/validation correcta)
    msgs = " ".join(e.get("message", "") for e in entry.get("errors", []))
    # bug reali aggiuntivi catch-all
    if re.search(r"Cannot (read|set) propert(y|ies) of (undefined|null)", msgs):
        return ("VP", "js_runtime_undefined_property")
    if re.search(r"Cannot use 'in' operator", msgs):
        return ("VP", "js_runtime_in_operator_on_undefined")
    if re.search(r"Failed to parse URL from (undefined|test|$)", msgs):
        return ("VP", "url_parse_missing_validation")
    if re.search(r"Custom types cannot be represented in JSON Schema", msgs):
        return ("VP", "json_schema_serialization_bug")
    if re.search(r"DeprecationWarning.*punycode.*Use.*node.*trace-deprecation", msgs, re.S):
        return ("VP", "deprecation_warning_treated_as_error")
    if re.search(r"Method undefined not found", msgs):
        return ("VP", "undefined_method_name_bug")
    return ("FP", "env_auth_or_correct_validation")


CLASSIFIERS = {
    "tool_invocation/invalid_arguments": classify_invalid_arguments,
    "tool_invocation/other_errors": classify_other_errors,
}


def main():
    for cat_key, fn in CLASSIFIERS.items():
        phase, cat = cat_key.split("/")
        unc_path = HERE / phase / cat / "filtered" / "llm_analysis" / "uncertain.json"
        cache_path = HERE / phase / cat / "filtered" / "llm_analysis" / "_llm_api_cache.json"
        if not unc_path.exists():
            print(f"  SKIP {cat_key}: no uncertain.json")
            continue
        data = json.load(open(unc_path, "r", encoding="utf-8"))
        entries = data.get("entries", [])
        cache = {}
        if cache_path.exists():
            cache = json.load(open(cache_path, "r", encoding="utf-8"))
        n_vp = n_fp = 0
        for e in entries:
            server = _server_short(e.get("server_url", ""))
            key = f"{server}|{cat_key}"
            verdict, reason = fn(e)
            cache[key] = {"verdict": verdict, "reason": reason}
            if verdict == "VP":
                n_vp += 1
            else:
                n_fp += 1
        cache_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  {cat_key}: VP={n_vp} FP={n_fp}  -> {cache_path.relative_to(HERE)}")


if __name__ == "__main__":
    main()
