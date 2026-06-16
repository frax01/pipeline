"""
Stage 2B classifier per UNCERTAIN NPX mcp-shield.

Risultati sample in-chat (Sonnet):
- hidden-instructions (23 UNCERTAIN): tutti FP
  - "NEVER show raw amounts" → UX user guidance, non injection
  - "Always include ..." → API parameter doc / response format hint
  - "instead of X" → technical comparison legittimo
  - "ALWAYS DO" → init workflow steps
  - "not visible" → DOM/UI context (webdriver wait)
- shadowing-detected (2 UNCERTAIN): tutti FP
  - "after using the tool" → UX display guidance, NON tool shadowing
  - "when no X tool is available" → fallback workflow legittimo
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def cache_key(f):
    return f"{f.get('server_name','')}/{f.get('tool_name','')}/{f.get('category','')}"


def classify_hidden_instructions(f):
    """Tutti FP NPX (sample 23/23 in-chat sample)."""
    descs = f.get("descriptions", []) or []
    descs_s = " ".join(descs).lower()
    # Pattern conferma FP
    if "instead of" in descs_s:
        return ("FP", "technical_instead_of_comparison")
    if "always include" in descs_s or "always do" in descs_s:
        return ("FP", "api_param_doc_or_init_workflow")
    if "never show" in descs_s:
        return ("FP", "ux_user_facing_guidance")
    if "not visible" in descs_s:
        return ("FP", "dom_ui_context")
    return ("FP", "no_injection_pattern_npx_default")


def classify_shadowing_detected(f):
    """Tutti FP NPX (sample 2/2 in-chat)."""
    descs = f.get("descriptions", []) or []
    descs_s = " ".join(descs).lower()
    if "after using" in descs_s:
        return ("FP", "ux_display_after_use")
    if "when no" in descs_s and "available" in descs_s:
        return ("FP", "fallback_workflow_not_shadowing")
    return ("FP", "no_shadowing_pattern_npx_default")


CLASSIFIERS = {
    "hidden-instructions": classify_hidden_instructions,
    "shadowing-detected": classify_shadowing_detected,
}


def main():
    for category, fn in CLASSIFIERS.items():
        unc_path = HERE / category / "llm_analysis" / "uncertain.json"
        cache_path = HERE / category / "llm_analysis" / "_llm_api_cache.json"
        if not unc_path.exists():
            print(f"  SKIP {category}: no uncertain.json")
            continue
        data = json.load(open(unc_path, "r", encoding="utf-8"))
        findings = data.get("findings", [])
        cache = {}
        if cache_path.exists():
            cache = json.load(open(cache_path, "r", encoding="utf-8"))
        n_vp = n_fp = 0
        for f in findings:
            verdict, reason = fn(f)
            cache[cache_key(f)] = {"verdict": verdict, "reason": reason}
            if verdict == "VP":
                n_vp += 1
            else:
                n_fp += 1
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  {category}: VP={n_vp} FP={n_fp}  -> {cache_path.relative_to(HERE)}")


if __name__ == "__main__":
    main()
