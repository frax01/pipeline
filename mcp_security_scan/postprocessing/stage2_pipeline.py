"""
Pipeline LLM per i finding di mcp-security-scan (post-stage1_filter.py).

Funziona sulle cartelle <categoria>/filtered/<cat>_filtered.json già prodotte
da stage1_filter.py (Stage 1).

Flusso:
    Stage 2A (HC rules)  — solo per categorie con has_hc=True (rug-pull, dangerous-capabilities)
                           → hc_vp.json / hc_fp.json / uncertain.json
    Stage 2B (LLM/cache) — classifica UNCERTAIN
                           → vp.json / fp.json / audit.json

Per le categorie senza HC rules (piccole + input-validation) si usa direttamente
--cache-only: la cache è pre-popolata con verdetti in-chat (Sonnet).

Uso:
    python -X utf8 stage2_pipeline.py --category rug-pull --hc-only
    python -X utf8 stage2_pipeline.py --category dangerous-capabilities --hc-only
    python -X utf8 stage2_pipeline.py --category prompt-injection --cache-only
    python -X utf8 stage2_pipeline.py --category all --cache-only
    python -X utf8 stage2_pipeline.py --category dangerous-capabilities --merge

Output in <categoria>/filtered/llm_analysis/:
    hc_vp.json / hc_fp.json / uncertain.json   (solo con --hc-only, categorie HC)
    vp.json / fp.json / audit.json              (con --cache-only o --merge)
    _llm_api_cache.json                         (cache verdetti)

Categorie disponibili:
    prompt-injection, path-traversal, sensitive-file-access, data-leak,
    remote-access-control, indirect-prompt-injection, sensitive-resource-exposure,
    input-validation, rug-pull, dangerous-capabilities
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY CATEGORIE
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES: dict[str, dict] = {
    "prompt-injection": {
        "filename": "prompt_injection_filtered.json",
        "description": "Prompt Injection nelle tool description (P-02)",
        "has_hc": False,
    },
    "path-traversal": {
        "filename": "path_traversal_filtered.json",
        "description": "Path Traversal confermato via probe attivo (R-01)",
        "has_hc": False,
    },
    "sensitive-file-access": {
        "filename": "sensitive_file_access_filtered.json",
        "description": "Accesso a file sensibili confermato via probe (R-02)",
        "has_hc": False,
    },
    "data-leak": {
        "filename": "data_leak_filtered.json",
        "description": "Token/credenziali esposti nel response (A-03)",
        "has_hc": False,
    },
    "remote-access-control": {
        "filename": "remote_access_control_filtered.json",
        "description": "Accesso remoto attivabile via tool (RC-01)",
        "has_hc": False,
    },
    "indirect-prompt-injection": {
        "filename": "indirect_prompt_injection_filtered.json",
        "description": "Prompt injection indiretta via risorse esterne (P-03)",
        "has_hc": False,
    },
    "sensitive-resource-exposure": {
        "filename": "sensitive_resource_exposure_filtered.json",
        "description": "Esposizione di risorse sensibili (R-03)",
        "has_hc": False,
    },
    "input-validation": {
        "filename": "input_validation_filtered.json",
        "description": "Command injection / path traversal confermati da fuzzing (X-02)",
        "has_hc": False,
    },
    "rug-pull": {
        "filename": "rug_pull_filtered.json",
        "description": "Instabilità tool description tra due chiamate (X-03)",
        "has_hc": True,
    },
    "dangerous-capabilities": {
        "filename": "dangerous_capabilities_filtered.json",
        "description": "Tool con capacità pericolose (exec, shell, write/delete file) (X-01)",
        "has_hc": True,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _server_short(url: str) -> str:
    """Rimuove prefisso GitHub. Per URL non-GitHub ritorna l'URL completo."""
    return (url or "").replace("https://github.com/", "")


def _cache_key(f: dict) -> str:
    """Cache key: server_short (un finding per server per categoria)."""
    return _server_short(f.get("server_url", ""))


def _parse_details(det_str) -> object:
    """Prova a parsare il campo details come JSON."""
    if isinstance(det_str, (list, dict)):
        return det_str
    if not det_str or not isinstance(det_str, str):
        return det_str
    try:
        return json.loads(det_str)
    except (json.JSONDecodeError, TypeError):
        return det_str


# ══════════════════════════════════════════════════════════════════════════════
#  HC RULES
# ══════════════════════════════════════════════════════════════════════════════

# ── rug-pull ─────────────────────────────────────────────────────────────────

def hc_rules_rug_pull(finding: dict) -> tuple[str | None, str]:
    """
    HC rules per rug-pull (X-03).

    Regola principale: se una delle due liste (before/after) è vuota,
    è una startup race condition (il server non aveva ancora registrato i tool
    alla prima chiamata) → FP.

    Ritorna: ("VP"/"FP"/None, reason)
      None = UNCERTAIN → da classificare via LLM
    """
    details = _parse_details(finding.get("details", ""))

    if isinstance(details, list) and details:
        for diff in details:
            if not isinstance(diff, dict):
                continue
            before = diff.get("before", [])
            after = diff.get("after", [])
            b_empty = (len(before) == 0)
            a_empty = (len(after) == 0)
            # XOR: esattamente uno dei due è vuoto → startup race
            if b_empty or a_empty:
                return "FP", "startup_race_condition"
        # Entrambi non vuoti: vero diff → controllo se solo ordering o reale
        # Se i nomi sono gli stessi in ordine diverso → FP
        all_before = []
        all_after = []
        for diff in details:
            if isinstance(diff, dict):
                all_before.extend(t.get("name", "") for t in diff.get("before", []))
                all_after.extend(t.get("name", "") for t in diff.get("after", []))
        if set(all_before) == set(all_after) and len(all_before) == len(all_after):
            return "FP", "ordering_only_no_content_change"
        # Vero diff: tool aggiunti/rimossi o description cambiate
        return "VP", "real_tool_set_or_description_change"

    if isinstance(details, str):
        dl = details.lower()
        if "changed" in dl or "differ" in dl or "added" in dl or "removed" in dl:
            return None, "text_diff_uncertain"
        return None, "uncertain_text"

    return None, "uncertain_empty"


# ── dangerous-capabilities ───────────────────────────────────────────────────

# Pattern per tool CHIARAMENTE OFFENSIVI / exploit framework
_DC_EXPLICIT_OFFENSE = re.compile(
    r'\b(reverse.?shell|bind.?shell|mimikatz|metasploit|meterpreter|'
    r'privilege.?escal|lateral.?movement|exfiltrat|c2.?server|'
    r'command.?and.?control|payload.?inject|backdoor)\b',
    re.I
)

# Pattern FP: descrizione ONLY read-only (search, get, list, ecc.)
_DC_READONLY_DESC = re.compile(
    r'^(retrieve|search|query|look.?up|get|list|view|show|display|check|'
    r'inspect|browse|fetch|read|scan|monitor|watch|describe|find|'
    r'analyze|analyse|report|status|info|summary|parse|extract|'
    r'count|stat|metric|audit|log|trace|stream|subscribe|listen)\b',
    re.I
)

# Descrizioni che indicano esecuzione comandi ESPLICITA
_DC_EXEC_DESC = re.compile(
    r'\b(execut(e|es|ing)\s+(a\s+)?(command|shell|script|bash|code|query|sql|statement)|'
    r'run\s+(a\s+)?(shell|command|script|bash|arbitrary)|'
    r'runs?\s+(shell|bash|commands?)\b|'
    r'execute\s+arbitrary|'
    r'spawn\s+(a\s+)?(process|command|shell)|'
    r'eval(uate)?\s+(code|expression|script))\b',
    re.I
)

# Descrizioni che indicano operazioni su file OS (non AI model)
_DC_FILE_OPS_DESC = re.compile(
    r'\b(delet(e|es|ing)\s+(a\s+)?(file|director|folder)|'
    r'remov(e|es|ing)\s+(a\s+)?(file|director|folder)|'
    r'writ(e|es|ing)\s+(to\s+)?(a\s+)?(file|disk|filesystem|path)|'
    r'creat(e|es|ing)\s+(a\s+)?(file|director))\b',
    re.I
)

# Tool che gestiscono AI model (rm = remove model, non file OS) → FP
_DC_AI_MODEL_MGMT = re.compile(
    r'\b(model|ollama|llm|embedding|weight|checkpoint|artifact)\b',
    re.I
)

# Descrizioni che indicano operazioni SSH/exec remoto
_DC_SSH_EXEC_DESC = re.compile(
    r'\b(execut(e|es|ing)\s+(a\s+)?(command|script|bash)\s+(on|over|via|through|in)\s+(remote|ssh|the\s+server|a\s+container|kubernetes|pod|docker)|'
    r'ssh\s+(exec|command|into|session)|'
    r'run\s+(commands?\s+(on|over|via)\s+(remote|ssh|container|kubernetes|pod)))\b',
    re.I
)

# Descrizioni che indicano install/deploy REALE (non solo analisi)
_DC_REAL_INSTALL_DESC = re.compile(
    r'\b(install(s|ing)?\s+(package|dependency|dependencies|library|plugin|hook|extension|software|tool)|'
    r'deploy(s|ing)?\s+(a\s+)?(service|container|app|application)|'
    r'npm\s+(install|run|exec)|pip\s+install|'
    r'apt.get|brew\s+install|yarn\s+(install|add))\b',
    re.I
)

# Descrizioni che indicano SOLO analisi/raccomandazione install (FP)
_DC_ANALYZE_INSTALL_DESC = re.compile(
    r'\b(detect(s|ing)?\s+(the\s+)?(tech\s+stack|mcp|framework|language)|'
    r'recommend(s|ing)?\s+(mcp|package|tool|server)|'
    r'analyz(e|es|ing)\s+(your|the)\s+(repo|project|codebase)|'
    r'suggest(s|ing)?\s+(package|tool|server|mcp)|'
    r'generat(e|es|ing)\s+(a\s+)?(config|configuration|\.env))\b',
    re.I
)

# Pattern for sudo/su operations → VP
_DC_SUDO_DESC = re.compile(r'\b(sudo|su\s|run\s+as\s+root|escalat(e|es)\s+privilege)\b', re.I)

# Pattern for database destructive operations → VP
_DC_DB_DESTROY_DESC = re.compile(
    r'\b(drop\s+(table|database|collection|index|schema)|truncate\s+(table|database|collection))\b',
    re.I
)


def hc_rules_dangerous_capabilities(finding: dict) -> tuple[str | None, str]:
    """
    HC rules per dangerous-capabilities (X-01).

    Analizza la lista di tool nel campo details (ogni tool ha già passato
    il filtro Stage 1 di stage1_filter.py).

    Ritorna: ("VP"/"FP"/None, reason)
      None = UNCERTAIN → da classificare via LLM
    """
    details = _parse_details(finding.get("details", ""))
    if not isinstance(details, list):
        return None, "details_not_list"

    vp_reasons = []
    fp_reasons = []

    for tool in details:
        if not isinstance(tool, dict):
            continue
        name = (tool.get("name") or "").lower().strip()
        desc = (tool.get("description") or "").lower().strip()
        filter_reason = tool.get("_filter_reason", "")

        # ── HC-VP ────────────────────────────────────────────────────────────

        # VP-1: linguaggio offensivo esplicito nella descrizione
        if _DC_EXPLICIT_OFFENSE.search(desc):
            vp_reasons.append(f"explicit_offense:{name}")
            continue

        # VP-2: descrizione indica esecuzione comandi ESPLICITA
        if _DC_EXEC_DESC.search(desc):
            vp_reasons.append(f"exec_desc:{name}")
            continue

        # VP-3: operazioni su file OS (delete/remove/write file)
        if _DC_FILE_OPS_DESC.search(desc):
            # Eccezione: se parla di AI model management, non di OS files
            if not _DC_AI_MODEL_MGMT.search(desc):
                vp_reasons.append(f"file_ops:{name}")
                continue

        # VP-4: SSH exec / esecuzione remota comandi
        if _DC_SSH_EXEC_DESC.search(desc):
            vp_reasons.append(f"ssh_exec:{name}")
            continue

        # VP-5: sudo / privilege escalation
        if _DC_SUDO_DESC.search(desc):
            vp_reasons.append(f"sudo_su:{name}")
            continue

        # VP-6: distruzione database (DROP/TRUNCATE)
        if _DC_DB_DESTROY_DESC.search(desc):
            vp_reasons.append(f"db_destroy:{name}")
            continue

        # VP-7: dangerous_name (exec/bash/terminal/shell) + descrizione NON read-only
        if "dangerous_name:" in filter_reason and not _DC_READONLY_DESC.match(desc):
            # Il nome indica esecuzione e la descrizione non è read-only → VP
            vp_reasons.append(f"dangerous_name_non_readonly:{name}")
            continue

        # VP-8: unconstrained param (code/script/sql/command/expression) + desc non read-only
        if "unconstrained_param:" in filter_reason:
            param = filter_reason.replace("unconstrained_param:", "").split(":")[0]
            if not _DC_READONLY_DESC.match(desc):
                vp_reasons.append(f"unconstrained_{param}:{name}")
                continue
            else:
                # read-only description + unconstrained param → FP (es. search tool)
                fp_reasons.append(f"unconstrained_{param}_readonly:{name}")
                continue

        # VP-9: install reale (non analisi/raccomandazione)
        if "install" in filter_reason and _DC_REAL_INSTALL_DESC.search(desc):
            if not _DC_ANALYZE_INSTALL_DESC.search(desc):
                vp_reasons.append(f"real_install:{name}")
                continue

        # ── HC-FP ────────────────────────────────────────────────────────────

        # FP-1: dangerous_name match ma descrizione è chiaramente read-only
        if "dangerous_name:" in filter_reason and _DC_READONLY_DESC.match(desc):
            fp_reasons.append(f"dangerous_name_readonly:{name}")
            continue

        # FP-2: install in descrizione ma tool analizza/raccomanda (non installa)
        if "install" in filter_reason and _DC_ANALYZE_INSTALL_DESC.search(desc):
            fp_reasons.append(f"analyze_not_install:{name}")
            continue

        # FP-3: delete/rm name ma gestisce AI model (non file OS)
        if ("write_file|delete_file|remove_file|rm" in filter_reason
                and _DC_AI_MODEL_MGMT.search(desc)):
            fp_reasons.append(f"ai_model_mgmt:{name}")
            continue

        # FP-4: payment/transaction tool (legit e-commerce tools)
        if "payment" in filter_reason:
            fp_reasons.append(f"payment_tool:{name}")
            continue

    if vp_reasons:
        return "VP", f"confirmed_dangerous:{';'.join(vp_reasons[:3])}"

    if fp_reasons and not vp_reasons:
        return "FP", f"false_positive:{';'.join(fp_reasons[:3])}"

    # Ancora UNCERTAIN: nessuna regola HC sufficiente
    if details:
        return None, f"uncertain_{len(details)}_tools"

    return "FP", "no_dangerous_tools"


HC_RULES: dict[str, object] = {
    "rug-pull": hc_rules_rug_pull,
    "dangerous-capabilities": hc_rules_dangerous_capabilities,
}


# ══════════════════════════════════════════════════════════════════════════════
#  LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_findings(cat: str) -> tuple[list, dict]:
    info = CATEGORIES[cat]
    path = HERE / cat / "filtered" / info["filename"]
    if not path.exists():
        raise FileNotFoundError(f"File sorgente non trovato: {path}")
    with io.open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("findings") or []
    meta = {
        "category": cat,
        "description": info["description"],
        "has_hc": info.get("has_hc", False),
        "total_in_file": data.get("total", len(findings)),
        "total_loaded": len(findings),
    }
    return findings, meta


# ══════════════════════════════════════════════════════════════════════════════
#  LLM / OLLAMA
# ══════════════════════════════════════════════════════════════════════════════

OLLAMA_PROMPT = """\
Sei un esperto di sicurezza MCP (Model Context Protocol).

Classifica il seguente finding come VP (Vero Positivo) o FP (Falso Positivo).

CATEGORIA:   {category}
SERVER:      {server}
VULN ID:     {vuln_id}
SEVERITY:    {severity}
FILTER:      {filter_reason}
DETAILS:
---
{details_snippet}
---

RISPONDI SOLO con questo JSON (nessun altro testo):
{{"verdict": "VP" o "FP", "reason": "spiegazione in italiano max 20 parole"}}"""


def _call_ollama(
    finding: dict,
    cat: str,
    model: str,
    ollama_url: str,
    dry_run: bool,
) -> dict | None:
    details_raw = finding.get("details", "")
    details_snippet = details_raw[:800] if isinstance(details_raw, str) else json.dumps(details_raw)[:800]

    prompt = OLLAMA_PROMPT.format(
        category=cat,
        server=_server_short(finding.get("server_url", ""))[:60],
        vuln_id=finding.get("id", "?"),
        severity=finding.get("severity", "?"),
        filter_reason=finding.get("_filter_reason", "?"),
        details_snippet=details_snippet,
    )

    if dry_run:
        print(f"  [DRY-RUN] Prompt:\n{prompt[:400]}\n...")
        return None

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        text = body.get("response", "").strip()
        # Estrai JSON dalla risposta
        m = re.search(r'\{[^}]+\}', text, re.DOTALL)
        if m:
            result = json.loads(m.group())
            verdict = result.get("verdict", "").upper()
            if verdict in ("VP", "FP"):
                return {"verdict": verdict, "reason": result.get("reason", "")}
        return {"verdict": "FP", "reason": f"parse_error: {text[:60]}"}
    except Exception as e:
        return {"verdict": "FP", "reason": f"ollama_error: {str(e)[:60]}"}


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def _out_dir(cat: str) -> Path:
    d = HERE / cat / "filtered" / "llm_analysis"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_json(path: Path, data: object) -> None:
    with io.open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"  -> {path.relative_to(HERE)}")


def _load_cache(out_dir: Path) -> dict:
    p = out_dir / "_llm_api_cache.json"
    if p.exists():
        with io.open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _save_cache(out_dir: Path, cache: dict) -> None:
    p = out_dir / "_llm_api_cache.json"
    with io.open(p, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2A — HC RULES
# ══════════════════════════════════════════════════════════════════════════════

def run_hc_only(cat: str, findings: list, meta: dict) -> None:
    hc_fn = HC_RULES.get(cat)
    if not hc_fn:
        print(f"  WARN: nessuna HC rule per '{cat}' — usa --cache-only")
        return

    out_dir = _out_dir(cat)
    hc_vp, hc_fp, uncertain = [], [], []
    reason_counter: Counter = Counter()

    for f in findings:
        verdict, reason = hc_fn(f)
        entry = dict(f, _hc_verdict=verdict, _hc_reason=reason)
        reason_counter[f"{verdict or 'UNCERTAIN'}:{reason}"] += 1
        if verdict == "VP":
            hc_vp.append(entry)
        elif verdict == "FP":
            hc_fp.append(entry)
        else:
            uncertain.append(entry)

    print(f"  HC: {len(hc_vp)} VP, {len(hc_fp)} FP, {len(uncertain)} UNCERTAIN")
    print("  Top reasons:")
    for r, c in reason_counter.most_common(10):
        print(f"    {c:4d}  {r}")

    _save_json(out_dir / "hc_vp.json",
               {"category": cat, "verdict": "true_positive", "total": len(hc_vp), "findings": hc_vp})
    _save_json(out_dir / "hc_fp.json",
               {"category": cat, "verdict": "false_positive", "total": len(hc_fp), "findings": hc_fp})
    _save_json(out_dir / "uncertain.json",
               {"category": cat, "total": len(uncertain), "findings": uncertain})


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2B — LLM / CACHE
# ══════════════════════════════════════════════════════════════════════════════

def run_llm_stage(
    cat: str,
    findings: list,
    meta: dict,
    *,
    cache_only: bool,
    model: str,
    ollama_url: str,
    no_cache: bool,
    dry_run: bool,
) -> None:
    out_dir = _out_dir(cat)
    has_hc = meta.get("has_hc", False)

    # Se la categoria ha HC rules, carica uncertain.json se esiste
    if has_hc:
        uncertain_path = out_dir / "uncertain.json"
        hc_vp_path = out_dir / "hc_vp.json"
        hc_fp_path = out_dir / "hc_fp.json"

        if not uncertain_path.exists():
            print(f"  WARN: uncertain.json non trovato — esegui --hc-only prima")
            print(f"  Classifico tutti i {len(findings)} finding via cache/LLM")
            to_classify = findings
            hc_vp_list, hc_fp_list = [], []
        else:
            with io.open(uncertain_path, encoding="utf-8") as fh:
                to_classify = json.load(fh).get("findings", [])
            hc_vp_list = json.load(io.open(hc_vp_path, encoding="utf-8")).get("findings", []) if hc_vp_path.exists() else []
            hc_fp_list = json.load(io.open(hc_fp_path, encoding="utf-8")).get("findings", []) if hc_fp_path.exists() else []
            print(f"  Da HC: {len(hc_vp_list)} VP, {len(hc_fp_list)} FP, {len(to_classify)} UNCERTAIN da classificare")
    else:
        to_classify = findings
        hc_vp_list, hc_fp_list = [], []

    # Carica cache
    cache = {} if no_cache else _load_cache(out_dir)

    vp_list, fp_list = list(hc_vp_list), list(hc_fp_list)
    audit_list = []
    n_cache_hit = 0
    n_new_calls = 0
    n_uncached = 0

    print(f"\n[Stage LLM] Classificazione ({len(to_classify)} finding)...")

    for idx, f in enumerate(to_classify, 1):
        key = _cache_key(f)
        cached = cache.get(key)

        if cached and not no_cache:
            verdict = cached["verdict"]
            reason = cached["reason"]
            source = "CACHE"
            n_cache_hit += 1
        elif cache_only:
            verdict = "FP"
            reason = "uncached_default_fp"
            source = "UNCACHED"
            n_uncached += 1
        else:
            result = _call_ollama(f, cat, model, ollama_url, dry_run)
            if result:
                verdict = result["verdict"]
                reason = result["reason"]
                cache[key] = {"verdict": verdict, "reason": reason}
                n_new_calls += 1
            else:
                verdict = "FP"
                reason = "dry_run_or_error"
                n_new_calls += 1
            source = "OLLAMA"

        label = f"[{idx:4d}/{len(to_classify)}]"
        server_s = _server_short(f.get("server_url", ""))[:50]
        print(f"  {label} {source:7s} {server_s:<50} -> {verdict}")

        entry = dict(f,
                     llm_verdict=verdict,
                     llm_reason=reason,
                     verdict_source=source,
                     final_verdict=verdict,
                     final_reason=reason)

        if verdict == "VP":
            vp_list.append(entry)
        else:
            fp_list.append(entry)
        audit_list.append(entry)

    # Aggiungi HC entries all'audit
    for f in hc_vp_list:
        audit_list.append(dict(f, final_verdict="VP", final_reason=f.get("_hc_reason", "hc_vp")))
    for f in hc_fp_list:
        audit_list.append(dict(f, final_verdict="FP", final_reason=f.get("_hc_reason", "hc_fp")))

    # Salva cache
    _save_cache(out_dir, cache)

    # Salva output
    _save_json(out_dir / "vp.json",
               {"category": cat, "description": meta["description"],
                "verdict": "true_positive", "total": len(vp_list), "findings": vp_list})
    _save_json(out_dir / "fp.json",
               {"category": cat, "description": meta["description"],
                "verdict": "false_positive", "total": len(fp_list), "findings": fp_list})
    _save_json(out_dir / "audit.json",
               {"category": cat, "total": len(audit_list), "findings": audit_list})

    print(f"\n  Riepilogo: {n_cache_hit} da cache, {n_new_calls} nuove chiamate, {n_uncached} non cachati")
    print(f"\n-- Risultati finali --")
    print(f"  Totale:          {len(audit_list)}")
    print(f"  Veri Positivi:   {len(vp_list):4d}  ({len(vp_list)/max(len(audit_list),1)*100:.1f}%)")
    print(f"  Falsi Positivi:  {len(fp_list):4d}  ({len(fp_list)/max(len(audit_list),1)*100:.1f}%)")

    if n_uncached:
        print(f"\n  ATTENZIONE: {n_uncached} finding non erano in cache → classificati come FP (default).")
        print(f"  Aggiungili alla cache in {out_dir / '_llm_api_cache.json'}")
        print(f"  e riesegui --cache-only per aggiornare i risultati.")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline LLM per mcp-security-scan")
    parser.add_argument("--category", default="all",
                        help="Categoria (o 'all'). Default: all")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache e riclassifica tutto")
    parser.add_argument("--cache-only", action="store_true",
                        help="Usa solo cache (non chiama Ollama)")
    parser.add_argument("--hc-only", action="store_true",
                        help="Solo Stage 2A (HC rules), non chiama LLM")
    parser.add_argument("--merge", action="store_true",
                        help="Stage 2A + 2B completo (HC + LLM/cache)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt senza chiamare Ollama")
    args = parser.parse_args()

    cats = list(CATEGORIES.keys()) if args.category == "all" else [args.category]

    for cat in cats:
        if cat not in CATEGORIES:
            print(f"Categoria '{cat}' non trovata. Disponibili: {list(CATEGORIES.keys())}")
            continue

        print(f"\n{'='*70}")
        print(f"  Categoria: {cat} ({CATEGORIES[cat]['description']})")
        print(f"  Has HC: {CATEGORIES[cat]['has_hc']}")
        print(f"{'='*70}")

        try:
            findings, meta = load_findings(cat)
        except FileNotFoundError as e:
            print(f"  ERRORE: {e}")
            continue

        print(f"  Finding caricati: {len(findings)}")

        if args.hc_only:
            if meta["has_hc"]:
                run_hc_only(cat, findings, meta)
            else:
                print(f"  INFO: '{cat}' non ha HC rules — usa --cache-only")

        elif args.cache_only or args.dry_run:
            run_llm_stage(cat, findings, meta,
                          cache_only=True,
                          model=args.model,
                          ollama_url=args.ollama_url,
                          no_cache=args.no_cache,
                          dry_run=args.dry_run)

        elif args.merge:
            if meta["has_hc"]:
                hc_out = HERE / cat / "filtered" / "llm_analysis" / "uncertain.json"
                if not hc_out.exists():
                    print(f"  Eseguo HC rules prima del merge...")
                    run_hc_only(cat, findings, meta)
            run_llm_stage(cat, findings, meta,
                          cache_only=False,
                          model=args.model,
                          ollama_url=args.ollama_url,
                          no_cache=args.no_cache,
                          dry_run=args.dry_run)

        else:
            parser.print_help()
            print(f"\n  Specifica --hc-only, --cache-only, o --merge")


if __name__ == "__main__":
    main()
