"""
Stage 2A — 3-bucket classifier for data-exfiltration findings.

Buckets:
  HC-FP  → high-confidence False Positive  (regole molto specifiche, FP certo)
  HC-VP  → high-confidence True Positive   (regole molto specifiche, VP certo)
  UNCERTAIN → giudizio semantico richiesto  (va analizzato dall'LLM in chat)

Output (in llm_analysis/):
  hc_fp.json      — FP certi (nessuna chiamata LLM)
  hc_vp.json      — VP certi (nessuna chiamata LLM)
  uncertain.json  — da analizzare con LLM in chat

Logica:
  - UNUSED_SENSITIVE_PARAMETER  → tutti FP (parametri Python interni, non MCP schema)
  - MAGIC_PARAMETER_INJECTION tools_list → tutti FP (registrazione tool, non schema)
  - MAGIC_PARAMETER_INJECTION system_prompt → FP se JS minificato o security tool
  - CONVERSATION_EXFILTRATION_TRIGGER → VP se description dice "ENTIRE conversation"
  - DATA_EXFILTRATION → VP se UserPromptSubmit hook invia a backend esterno
  - DATA_EXFILTRATION → FP per pattern noti (Ollama, ComfyUI, hook, bundle, ecc.)
  - Resto → UNCERTAIN
"""

from __future__ import annotations
import io, json, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC  = HERE / "data_exfiltration_filtered.json"
OUT  = HERE / "llm_analysis"

# ─── HC-FP rules ─────────────────────────────────────────────────────────────

# Pattern Ollama / embedding locale
OLLAMA_PAT = re.compile(
    r'json=\{"model":\s*\w+,\s*"prompt":\s*\w+'         # {"model": X, "prompt": Y}
    r'|EMBED_URL|embed_url|ollama_url'
    r'|api/embeddings',
    re.IGNORECASE,
)

# ComfyUI: localhost o variabile workflow (non dati utente)
COMFYUI_PAT = re.compile(
    r'127\.0\.0\.1:8188|localhost:8188'
    r'|json=\{"prompt":\s*workflow\}'       # ComfyUI: "prompt" = workflow ComfyUI, non testo utente
    r'|/prompt.*json.*\bworkflow\b'
)

# Hook/metodo di plugin framework (definizione, non chiamata HTTP)
PLUGIN_HOOK_PAT = re.compile(
    r'async def (prompt|resource)_(pre|post)_fetch'
    r'|async def (pre|post)_(prompt|resource)_fetch'
    r'|def prompt_pre_fetch|def prompt_post_fetch'
)

# Bundle/JS minificato (webpack, rollup, esbuild, playwright trace, js-yaml residui)
BUNDLED_JS_PAT = re.compile(
    r'self\.webpackChunk'
    r'|import\{r,j as e'
    r'|FAILSAFE_SCHEMA.*JSON_SCHEMA.*CORE_SCHEMA'    # js-yaml minificato
    r'|`:``\}var [a-z][A-Za-z]+='                   # bundle js-yaml/rollup
    r'|\}var [a-z][A-Za-z]+={dump:'                 # bundle con dump:
)

# Chiamata protocollo MCP standard (prompts/get, prompts/list)
MCP_PROTOCOL_PAT = re.compile(r'"prompts/(get|list)"')

# Metodo di cache (non HTTP)
CACHE_METHOD_PAT = re.compile(r'cache\.get_or_fetch')

# Wrapper API interno (ohFetch)
INTERNAL_WRAP_PAT = re.compile(r'\bohFetch\(')

# Codice seed/template con chiave placeholder
SEED_CODE_PAT = re.compile(
    r"your-api-key|api\.example\.com"
    r"|code:\s*[\"']async function generateText",
    re.IGNORECASE,
)

# OpenRouter / servizi LLM pubblici noti (non esfiltra dati utente)
OPENROUTER_PAT = re.compile(r'openrouter\.ai|openai\.com/v1|anthropic\.com')

# Dati meteo/finanziari/infrastruttura (non dati utente)
WEATHER_FINANCE_PAT = re.compile(r'history\.json.*q.*dt|premiumFetch|coinId=')

# Harvest/scraper npm, non esfiltra conversazione
NPM_HARVEST_PAT = re.compile(r'harvester\.fetch\(|npm_example')

# Benchmark/valutazione (non esfiltra conversazione utente)
BENCHMARK_PAT = re.compile(r'evaluate_alpaca|args\.url.*json.*prompt')

# File di test/trace Playwright (artefatto di test, non codice di produzione)
PLAYWRIGHT_TRACE_PAT = re.compile(r'playwright-report[/\\]trace')

# Chiamata di attore interno Cloudflare (actor.local)
CF_ACTOR_PAT = re.compile(r'actor\.local')

# Configurazione dimensione contesto LLM (non esfiltra)
CTX_SIZE_PAT = re.compile(r'contextSize')

# Codice commentato
COMMENTED_PAT = re.compile(r'^\s*#')

# Definizione di funzione (non una chiamata HTTP) — es. "function fetch(payload: ..."
FUNC_DEF_PAT = re.compile(r'^\s*(async\s+)?function\s+\w+\s*\(.*?(payload|context).*?\)')

# Servizio di redazione (riceve testo per sanificarlo, non lo esfiltra)
REDACTION_NAMES = {"redaction-compliance-MCP"}

# Security-tool che analizza system_prompt per rilevare rischi (FP)
SECURITY_TOOL_NAMES = {"secure.mcp"}


def hc_fp_data_exfil(f: dict) -> tuple[bool, str]:
    """Regole HC-FP per DATA_EXFILTRATION (http_exfiltration_payload)."""
    name = f.get("server_name", "")
    path = (f.get("file") or "").lower()
    ev   = f.get("evidence", "")

    if COMMENTED_PAT.match(ev):
        return True, "hc_fp:commented_out_code"
    if FUNC_DEF_PAT.match(ev):
        return True, "hc_fp:function_definition_not_http_call"
    if OLLAMA_PAT.search(ev):
        return True, "hc_fp:ollama_or_embedding_api_call"
    if COMFYUI_PAT.search(ev):
        return True, "hc_fp:comfyui_localhost_workflow"
    if PLUGIN_HOOK_PAT.search(ev):
        return True, "hc_fp:mcp_gateway_plugin_hook_method"
    if BUNDLED_JS_PAT.search(ev):
        return True, "hc_fp:bundled_minified_js"
    if MCP_PROTOCOL_PAT.search(ev):
        return True, "hc_fp:mcp_standard_protocol_call"
    if CACHE_METHOD_PAT.search(ev):
        return True, "hc_fp:cache_method_not_http"
    if INTERNAL_WRAP_PAT.search(ev):
        return True, "hc_fp:internal_api_wrapper"
    if SEED_CODE_PAT.search(ev):
        return True, "hc_fp:seed_or_template_code"
    if OPENROUTER_PAT.search(ev):
        return True, "hc_fp:known_llm_provider_api_call"
    if WEATHER_FINANCE_PAT.search(ev):
        return True, "hc_fp:weather_or_financial_data_api"
    if NPM_HARVEST_PAT.search(ev):
        return True, "hc_fp:npm_metadata_harvester"
    if BENCHMARK_PAT.search(ev):
        return True, "hc_fp:benchmark_evaluation_call"
    if CF_ACTOR_PAT.search(ev):
        return True, "hc_fp:cloudflare_internal_actor"
    if CTX_SIZE_PAT.search(ev):
        return True, "hc_fp:llm_context_size_config"
    if name in REDACTION_NAMES:
        return True, "hc_fp:redaction_service_receives_text"
    # File di trace Playwright (artefatti di test)
    if PLAYWRIGHT_TRACE_PAT.search(path):
        return True, "hc_fp:playwright_test_trace_artifact"
    return False, ""


def hc_fp(f: dict) -> tuple[bool, str]:
    vid  = f.get("id", "")
    conf = f.get("filter_confidence", "")
    name = f.get("server_name", "")
    ev   = f.get("evidence", "")
    path = (f.get("file") or "").lower()

    # --- UNUSED_SENSITIVE_PARAMETER → tutti FP ---
    # conversation_history / full_context sono parametri Python interni,
    # non campi nell'inputSchema di un tool MCP.
    # I file di test (test_cascade.py) hanno pytest fixture, non magic param.
    if vid == "UNUSED_SENSITIVE_PARAMETER":
        if conf == "unused_magic:full_context" and "test" in path:
            return True, "hc_fp:pytest_fixture_not_magic_param"
        if conf == "unused_magic:conversation_history":
            return True, "hc_fp:standard_python_function_param"
        return True, "hc_fp:unused_sensitive_internal_param"

    # --- MAGIC_PARAMETER_INJECTION: tools_list → tutti FP ---
    # def register_tools(server, tools_list) è pattern di registrazione tool interno,
    # non un magic parameter nello schema JSON esposto all'LLM.
    if vid == "MAGIC_PARAMETER_INJECTION" and conf == "magic_param_in_schema:tools_list":
        return True, "hc_fp:tools_list_registration_function_param"

    # --- MAGIC_PARAMETER_INJECTION: system_prompt in tool schema ---
    if vid == "MAGIC_PARAMETER_INJECTION" and conf == "magic_param:system_prompt_in_tool_schema":
        # Minified/bundled JS
        if BUNDLED_JS_PAT.search(ev) or "webpackChunk" in ev:
            return True, "hc_fp:system_prompt_in_minified_js"
        # Security tool che analizza le chiamate tool per valutarne il rischio
        if name in SECURITY_TOOL_NAMES:
            return True, "hc_fp:security_tool_analyzes_system_prompt"
        # Altrimenti → UNCERTAIN (potrebbe essere un vero magic param)

    # --- DATA_EXFILTRATION: http_exfiltration_payload ---
    if vid == "DATA_EXFILTRATION" and conf == "http_exfiltration_payload":
        ok, r = hc_fp_data_exfil(f)
        if ok:
            return True, r

    return False, ""


# ─── HC-VP rules ─────────────────────────────────────────────────────────────

# Pattern: tool description istruisce LLM a estrarre l'INTERA conversazione
ENTIRE_CONV_PAT = re.compile(
    r'ENTIRE conversation|entire conversation|ENTIRE CONVERSATION'
    r'|extracted from the ENTIRE'
    r'|from all messages in the conversation',
    re.IGNORECASE,
)

# Pattern: hook UserPromptSubmit che invia dati sessione a backend esterno
USER_PROMPT_SUBMIT_PAT = re.compile(r'UserPromptSubmit', re.IGNORECASE)
SESSION_DATA_PAT = re.compile(r'CLAUDE_SESSION_ID|session_id.*CLAUDE|session_id.*fetch', re.IGNORECASE)
EXTERNAL_BACKEND_PAT = re.compile(r'BACKEND_URL|api/events.*POST|fetch.*api.*events', re.IGNORECASE)


def hc_vp(f: dict) -> tuple[bool, str]:
    vid  = f.get("id", "")
    conf = f.get("filter_confidence", "")
    ev   = f.get("evidence", "")

    # CONVERSATION_EXFILTRATION_TRIGGER → VP se la description istruisce
    # l'LLM a estrarre l'intera conversazione
    if vid == "CONVERSATION_EXFILTRATION_TRIGGER":
        if ENTIRE_CONV_PAT.search(ev):
            return True, "hc_vp:tool_description_extracts_entire_conversation"

    # DATA_EXFILTRATION → VP se c'è un hook UserPromptSubmit che invia
    # dati di sessione Claude a un backend esterno
    if vid == "DATA_EXFILTRATION" and conf == "http_exfiltration_payload":
        if USER_PROMPT_SUBMIT_PAT.search(ev) and (
            SESSION_DATA_PAT.search(ev) or EXTERNAL_BACKEND_PAT.search(ev)
        ):
            return True, "hc_vp:user_prompt_submit_hook_exfiltrates_session"

    return False, ""


# ─── main ───────────────────────────────────────────────────────────────────

def classify(f: dict) -> tuple[str, str]:
    ok, r = hc_fp(f)
    if ok: return "HC-FP", r
    ok, r = hc_vp(f)
    if ok: return "HC-VP", r
    return "UNCERTAIN", "needs_llm_judgment"


def main() -> None:
    with io.open(SRC, encoding="utf-8") as fh:
        src = json.load(fh)
    findings = src["findings"]

    hc_fp_list, hc_vp_list, unc_list = [], [], []
    for f in findings:
        bucket, reason = classify(f)
        enriched = dict(f, llm_bucket=bucket, bucket_reason=reason)
        if   bucket == "HC-FP":    hc_fp_list.append(enriched)
        elif bucket == "HC-VP":    hc_vp_list.append(enriched)
        else:                       unc_list.append(enriched)

    OUT.mkdir(exist_ok=True)

    def dump(path: Path, items: list, meta: dict) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**meta, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    base_meta = {
        "category": src["category"],
        "original_total": src.get("original_total"),
        "filter_kept_total": src.get("kept_total"),
    }

    dump(OUT / "hc_fp.json",     hc_fp_list, {**base_meta, "bucket": "HC-FP"})
    dump(OUT / "hc_vp.json",     hc_vp_list, {**base_meta, "bucket": "HC-VP"})
    dump(OUT / "uncertain.json", unc_list,   {**base_meta, "bucket": "UNCERTAIN"})

    total = len(findings)
    print(f"{'─'*50}")
    print(f"  Total filtered:   {total:4d}")
    print(f"  HC-FP  (certo):   {len(hc_fp_list):4d}  ({len(hc_fp_list)/total*100:.1f}%)")
    print(f"  HC-VP  (certo):   {len(hc_vp_list):4d}  ({len(hc_vp_list)/total*100:.1f}%)")
    print(f"  UNCERTAIN (LLM):  {len(unc_list):4d}  ({len(unc_list)/total*100:.1f}%)")
    print(f"{'─'*50}")

    from collections import Counter
    print("\nHC-FP reasons:")
    for r, c in Counter(x["bucket_reason"] for x in hc_fp_list).most_common():
        print(f"  {c:3d}  {r}")
    print("\nHC-VP reasons:")
    for r, c in Counter(x["bucket_reason"] for x in hc_vp_list).most_common():
        print(f"  {c:3d}  {r}")
    print("\nUNCERTAIN findings:")
    for x in unc_list:
        print(f"  {x['server_name']:40s}  {x['id']}  {x.get('filter_confidence','')}")


if __name__ == "__main__":
    main()
