"""
Pipeline Stage 2A + 2B per i finding di mcp-shield.

Uso:
    python pipeline_mcp_shield.py --category hidden-instructions --hc-only
    python pipeline_mcp_shield.py --category hidden-instructions --merge
    python pipeline_mcp_shield.py --category all --merge

Stage 2A: regole HC (high-confidence) per categoria → HC-VP / HC-FP / UNCERTAIN
Stage 2B: Ollama llama3 per i finding UNCERTAIN → VP o FP

Output in <categoria>/llm_analysis/:
    hc_fp.json        FP certi da regole HC
    hc_vp.json        VP certi da regole HC
    uncertain.json    finding mandati a Ollama
    vp.json           VP finali (hc_vp + uncertain VP)
    fp.json           FP finali (hc_fp + uncertain FP)
    audit.json        log completo di tutti i finding

Parametri:
    --category        categoria da analizzare (o 'all')
    --severity        high | medium | both  (default: both)
    --model           modello Ollama (default: llama3)
    --ollama-url      URL Ollama (default: http://localhost:11434)
    --no-cache        ignora cache Ollama esistente
    --hc-only         esegui solo Stage 2A (senza Ollama)
    --dry-run         mostra prompt Ollama senza chiamare il server

Nota sulla triangolazione llm_risk:
    Ogni finding contiene llm_risk (HIGH/MEDIUM/LOW/NOT_AVAILABLE) proveniente
    dall'analisi LLM eseguita da mcp-shield durante la scansione. Viene usato
    come segnale aggiuntivo nelle regole HC: se llm_risk=HIGH il finding e'
    classificato HC-VP indipendentemente dal trigger; se llm_risk=LOW e il
    trigger e' solo "instead of", e' classificato HC-FP.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY CATEGORIE
#  file_prefix: prefisso dei file JSON di input (es. hidden_instructions)
#  severities: lista dei livelli di severity disponibili come file separati
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES: dict[str, dict] = {
    "hidden-instructions": {
        "file_prefix": "hidden_instructions",
        "severities": ["HIGH", "MEDIUM"],
    },
    "potential-exfiltration": {
        "file_prefix": "potential_exfiltration",
        "severities": ["HIGH", "MEDIUM"],
    },
    "sensitive-file-access": {
        "file_prefix": "sensitive_file_access",
        "severities": ["HIGH"],
    },
    "shadowing-detected": {
        "file_prefix": "shadowing_detected",
        "severities": ["HIGH"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER COMUNI
# ══════════════════════════════════════════════════════════════════════════════

def _desc_list(f: dict) -> list[str]:
    """Ritorna la lista normalizzata dei trigger descriptions."""
    return [d.strip() for d in (f.get("descriptions") or []) if d]


def _tool_desc(f: dict) -> str:
    return f.get("tool_description") or ""


def _llm_risk(f: dict) -> str:
    return (f.get("llm_risk") or "").upper()


_INSTEAD_OF_VARIANTS = frozenset({
    "instead of", "Instead of", "INSTEAD OF", "INSTEAD of",
    "instead of using", "Instead of using", "INSTEAD OF USING",
})


def _triggers_only_instead_of(descriptions: list[str]) -> bool:
    return bool(descriptions) and all(d in _INSTEAD_OF_VARIANTS for d in descriptions)


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-shield | CATEGORIA: hidden-instructions
#
#  mcp-shield rileva tool description che contengono frasi di istruzione nascosta.
#  Trigger phrases presenti in descriptions[] (totale HIGH+MEDIUM = 310 finding):
#
#    "instead of"      259  FP dominante: uso tecnico legittimo
#    "Instead of"        7
#    "INSTEAD OF"        7
#    "INSTEAD of"        4
#    "Always include"    9  ambiguo: istruzione operativa o inject?
#    "always include"    3
#    "ALWAYS include"    4
#    "ALWAYS DO"         2
#    "Always do"         1
#    "always do"         1
#    "not visible"       6  VP se riferito a istruzione nascosta all'utente
#    "hide this"         1  VP quasi certo
#    "<instructions>"    6  VP certo: tag injection
#    "Never show"        1  VP certo
#    "Ignore all instructions" 1  VP certo
#    "Do not mention"    2  VP certo
#    "<IMPORTANT>"       2  VP certo: tag injection
#
#  Logica:
#    - "instead of" + llm_risk=LOW  → HC-FP (~135 finding): uso tecnico legittimo
#    - "instead of" + contesto confronto tecnico nel testo → HC-FP aggiuntivi
#    - llm_risk=HIGH (da mcp-shield LLM) → HC-VP (triangolazione forte)
#    - tag XML nascosti, "Ignore all", "Never show", "hide this" → HC-VP
#    - resto → UNCERTAIN (inclusi "Always include/do", "not visible", MEDIUM ambigui)
# ══════════════════════════════════════════════════════════════════════════════

# HC-VP: tag XML di istruzione nascosta nella tool_description
# ESCLUSO: <instructions> accoppiato con <usecase> → struttura documentazione legittima
# (es. remarkable-mcp usa <usecase>/<instructions>/<examples> come JSDoc-style)
_HI_INJECTION_TAG_PAT = re.compile(
    r"</?IMPORTANT>|</?secret>|</?hidden>|</?system>|</?cmd>",
    re.IGNORECASE,
)

# <instructions> e' VP solo se NON accompagnato da <usecase> (= struttura docs legittima)
_HI_INSTRUCTIONS_TAG_PAT = re.compile(r"<instructions>", re.IGNORECASE)
_HI_USECASE_TAG_PAT = re.compile(r"<usecase>", re.IGNORECASE)

# HC-VP: pattern classici di prompt injection diretta
_HI_IGNORE_ALL_PAT = re.compile(
    r"[Ii]gnore\s+(?:all\s+)?(?:previous\s+)?instructions",
)

# HC-VP: tool shadowing — "NEVER use [altro tool], ALWAYS use [questo] instead"
# Pattern: condizionamento forte che sostituisce strumenti built-in con questo tool
# Esempio: "NEVER use Read or any file reading tool... ALWAYS use mdsel instead"
_HI_TOOL_SHADOW_PAT = re.compile(
    r"NEVER\s+use\s+(?:Read|Grep|Glob|Write|Edit|Bash)\b"
    r"|NEVER\s+use\s+any\s+file\s+(?:reading|writing)\s+tool"
    r"|ALWAYS\s+use\s+\S+\s+instead(?!\s+of\s)"
    r"|never\s+use\s+\w+\s+(?:tool|command)\s+for\s+\w",
    re.IGNORECASE,
)

_HI_NEVER_SHOW_PAT = re.compile(
    # "Never show" / "Do not mention" in contesto di istruzione AI nascosta
    # Escludi pattern UX come "Never show full wallet addresses" (dopo virgola/trattino)
    r"[Nn]ever\s+show\s+(?!full\s+\w+\s+address)"
    r"|[Dd]o\s+not\s+(?:mention|show|display|reveal)\s+(?:this|it|the\s+(?:tool|instruction|fact))",
)

_HI_HIDE_PAT = re.compile(
    # "not visible to user" in contesto di istruzione nascosta (non UI/DOM)
    # "hide this" puo' essere UI switcher → richiede contesto piu' specifico
    r"not\s+visible\s+to\s+(?:the\s+)?(?:user|humans?|operator)"
    r"|\bthis\s+(?:instruction|text|message|content)\s+(?:is\s+)?(?:hidden|not\s+visible)\b",
    re.IGNORECASE,
)

# HC-FP: "instead of" in contesto di confronto tecnico tra strumenti/metodi/sintassi
# Esempi: "use X instead of Y", "instead of creating from scratch", "instead of get_all",
#         "connect to emulator instead of Azure service", "USE INSTEAD OF GREP"
_HI_INSTEAD_OF_TECH_PAT = re.compile(
    r"\buse\s+\S+\s+instead\s+of\b"           # use X instead of Y
    r"|\bUSE\s+INSTEAD\s+OF\b"                # USE INSTEAD OF GREP (file-search)
    r"|\binstead\s+of\s+(?:using|creating|calling|modifying|"
    r"get_all|the\s+\w+|direct\b|creating\b|individual\b|separate\b)\b"
    r"|\binstead\s+of\s+\w+\s+(?:syntax|format|pattern|approach|method|linkage|"
    r"basename|service)\b"
    r"|\bsize\s+values\s+instead\s+of\b"      # "size values instead of data"
    r"|\bsegments?\s+instead\s+of\b"          # "add segment instead of creating steps"
    r"|\bpagination\s+instead\s+of\b"         # "pagination instead of get_all"
    r"|\bconnect\s+to\s+(?:the\s+)?(?:local\s+)?(?:emulator|Azure|service)\s+instead\s+of\b"
    r"|\binstead\s+of\s+(?:Azure|local)\s+service\b"  # "instead of Azure service"
    r"|\binstead\s+of\s+\w+\s+(?:on\s+disk|request|requests)\b",  # "basenames on disk"
    re.IGNORECASE,
)


def hc_rules_hidden_instructions(f: dict) -> tuple[str, str]:
    desc = _tool_desc(f)
    descriptions = _desc_list(f)
    lr = _llm_risk(f)

    # ── HC-VP ────────────────────────────────────────────────────────────────

    # tag XML nascosti nella tool_description → iniezione strutturata
    # Controlla PRIMA di llm_risk per catturare anche i casi con llm_risk LOW
    if _HI_INJECTION_TAG_PAT.search(desc):
        return "HC-VP", "hc_vp:hidden_instruction_xml_tags"

    # <instructions> + <usecase> → struttura docs legittima (es. remarkable-mcp)
    # Controlla FP PRIMA del VP e del check llm_risk HIGH
    if _HI_INSTRUCTIONS_TAG_PAT.search(desc) and _HI_USECASE_TAG_PAT.search(desc):
        return "HC-FP", "hc_fp:instructions_xml_paired_with_usecase_structural_docs"

    # <instructions> senza <usecase> → iniezione strutturata
    if _HI_INSTRUCTIONS_TAG_PAT.search(desc):
        return "HC-VP", "hc_vp:hidden_instruction_xml_tags"

    # triangolazione: mcp-shield LLM classificato HIGH, MA solo se il trigger
    # NON e' esclusivamente "instead of" (falso HIGH di shield possibile)
    if lr == "HIGH" and not _triggers_only_instead_of(descriptions):
        return "HC-VP", "hc_vp:shield_llm_risk_high"

    # prompt injection classica
    if _HI_IGNORE_ALL_PAT.search(desc):
        return "HC-VP", "hc_vp:ignore_all_instructions"

    # tool shadowing: forza uso di questo tool, vieta strumenti built-in
    if _HI_TOOL_SHADOW_PAT.search(desc):
        return "HC-VP", "hc_vp:tool_shadowing_forces_replacement"

    # tentativo di nascondere output o comportamento
    if _HI_NEVER_SHOW_PAT.search(desc):
        return "HC-VP", "hc_vp:never_show_or_do_not_mention"

    # istruzione esplicitamente nascosta o dichiarata non visibile
    if _HI_HIDE_PAT.search(desc):
        return "HC-VP", "hc_vp:hide_this_or_not_visible_to_user"

    # ── HC-FP ────────────────────────────────────────────────────────────────

    # solo trigger "instead of" (tutte varianti) + llm_risk LOW → FP certo
    if _triggers_only_instead_of(descriptions) and lr == "LOW":
        return "HC-FP", "hc_fp:instead_of_low_llm_risk"

    # solo trigger "instead of" + pattern tecnico legittimo nel testo
    if _triggers_only_instead_of(descriptions) and _HI_INSTEAD_OF_TECH_PAT.search(desc):
        return "HC-FP", "hc_fp:instead_of_technical_comparison"

    # solo trigger "instead of" + nessuna analisi LLM da mcp-shield (NOT_AVAILABLE /
    # NOT_COMPLETED) → VP patterns gia' esclusi sopra, "instead of" tecnico quasi certo
    if _triggers_only_instead_of(descriptions) and lr in ("NOT_AVAILABLE", "NOT_COMPLETED"):
        return "HC-FP", "hc_fp:instead_of_no_llm_analysis"

    # ── HC-FP: trigger non-instead_of con llm_risk LOW ───────────────────────
    # "not visible" + LOW: visibilita' DOM/HTTP, non istruzione nascosta
    # Confermati in-chat: HttpOnly cookies, DOM disabled, admin note, frame context
    if (all(d == "not visible" for d in descriptions)
            and lr == "LOW"):
        return "HC-FP", "hc_fp:not_visible_low_risk_dom_or_admin_context"

    # "Always include"/"always include"/"ALWAYS include"/"always do"/"Always do" + LOW:
    # parametro API obbligatorio o istruzione workflow, non injection
    # Confermati in-chat: API param (commons, appsflyer, memos), step instruction
    _always_low_triggers = {
        "Always include", "always include", "ALWAYS include",
        "always do", "Always do",
    }
    if (all(d in _always_low_triggers for d in descriptions)
            and lr == "LOW"
            and not _HI_INJECTION_TAG_PAT.search(desc)):
        return "HC-FP", "hc_fp:always_include_low_risk_api_or_workflow"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-shield | CATEGORIA: shadowing-detected
#
#  Trigger phrases (22 finding totali, solo HIGH):
#    "instead of using"        7  FP — confronto tecnico ("use API instead of Curl")
#    "before using other tool" 13  FP — init/sequencing ("call this first to initialize")
#    "after using the tool"    1  FP — istruzione UX ("show the link after using the tool")
#    "When this tool is available" + "This is VERY VERY" 1  VP — math-mcp, catturato da <IMPORTANT>
#
#  Risultato atteso: 1 HC-VP (math-mcp/subtract), 21 HC-FP, 0 UNCERTAIN.
#
#  Note:
#    - "before using other tool" NON è mai tool shadowing: è workflow sequencing legittimo.
#      mcp-shield lo flagga per via del testo "other tool" ma non c'è intercettazione.
#    - gohighlevel-mcp con llm_risk=HIGH: falso positivo del LLM di shield (ha visto
#      il codice JavaScript dell'event listener e lo ha interpretato come sospetto).
#    - math-mcp/subtract è già VP in hidden-instructions per i tag <IMPORTANT>; qui
#      ricompare perché la stessa description ha anche "When this tool is available"
#      che qualifica come tool shadowing esplicito.
# ══════════════════════════════════════════════════════════════════════════════

_SD_BEFORE_OTHER_TOOL_PAT = re.compile(
    r"before\s+(?:using|calling)\s+(?:any\s+)?other\s+tools?",
    re.IGNORECASE,
)

_SD_AFTER_TOOL_PAT = re.compile(
    r"after\s+using\s+(?:the\s+)?tool",
    re.IGNORECASE,
)


def hc_rules_shadowing_detected(f: dict) -> tuple[str, str]:
    desc = _tool_desc(f)
    descriptions = _desc_list(f)
    lr = _llm_risk(f)

    # ── HC-VP ────────────────────────────────────────────────────────────────

    # XML injection tags: math-mcp/subtract ha <IMPORTANT> + redirect email attacker
    if _HI_INJECTION_TAG_PAT.search(desc):
        return "HC-VP", "hc_vp:hidden_instruction_xml_tags"

    # ── HC-FP ────────────────────────────────────────────────────────────────

    # "before using other tool/tools" — init/sequencing legittimo, mai tool shadowing
    if _SD_BEFORE_OTHER_TOOL_PAT.search(desc):
        return "HC-FP", "hc_fp:before_using_other_tools_init_sequence"

    # "instead of using" — confronto tecnico (es. "use this window instead of Curl")
    # valido anche per llm_risk=HIGH (shield LLM sbagliato su codice JS OAuth)
    if _triggers_only_instead_of(descriptions):
        return "HC-FP", "hc_fp:instead_of_using_technical_comparison"

    # "after using the tool" — istruzione UX display, non shadowing
    if _SD_AFTER_TOOL_PAT.search(desc) and lr == "LOW":
        return "HC-FP", "hc_fp:after_using_tool_display_instruction"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-shield | CATEGORIA: potential-exfiltration
#
#  Trigger phrases (1621 finding totali, HIGH+MEDIUM):
#    Tutti nel formato "<nome_parametro> (<tipo>)" — es. "context (string)",
#    "metadata (object)", "notes (array)", "debug (boolean)", ecc.
#
#  mcp-shield flagga qualsiasi tool con un parametro chiamato context, metadata,
#  notes, note, debug, reasoning, details, feedback, annotation, ecc. anche quando
#  la tool description non contiene alcuna evidenza di esfiltrazione dati.
#
#  Analisi di tutti i 1621 finding:
#    - Nessun finding con llm_risk=HIGH nel gruppo HIGH severity (34 LOW, 34 MEDIUM)
#    - Solo 13 MEDIUM severity con llm_risk=HIGH, tutti FP (campi CRM, kubectl, memory)
#    - Nessuna descrizione contiene linguaggio di esfiltrazione esplicita (URL attaccante,
#      "send conversation to", "collect all", ecc.)
#    - Falsi positivi "sospetti" analizzati:
#        * librarian/record: "webhook" era in un esempio testuale, non nel comportamento
#        * mcp-memento/checkpoint_context: "entire conversation" = salva localmente
#        * ccusage-mcp-server/send-usage: invia conteggi token a spreadsheet, non dati convo
#
#  Risultato: 1621 HC-FP, 0 UNCERTAIN.
#
#  HC-FP: tutti i trigger matchano il pattern `<parola> (<tipo>)` = annotazione
#         schema parametro, non istruzione di esfiltrazione.
# ══════════════════════════════════════════════════════════════════════════════

_PE_PARAM_TYPE = r"(?:string|object|boolean|array|integer|number|unknown|null)"
_PE_PARAM_SCHEMA_PAT = re.compile(
    rf"^\w+\s+\({_PE_PARAM_TYPE}(?:,{_PE_PARAM_TYPE})*\)$",
    re.IGNORECASE,
)


def hc_rules_potential_exfiltration(f: dict) -> tuple[str, str]:
    descriptions = _desc_list(f)

    # Tutti i trigger sono annotazioni schema parametro: "<nome> (<tipo>)"
    # Avere un parametro "context" o "metadata" non è evidenza di esfiltrazione.
    if descriptions and all(_PE_PARAM_SCHEMA_PAT.match(d) for d in descriptions):
        return "HC-FP", "hc_fp:parameter_schema_annotation_not_exfiltration"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-shield | CATEGORIA: sensitive-file-access
#
#  Trigger phrases (3094 finding totali, solo HIGH severity):
#    token/Token/TOKEN   ~1423  credenziali API, crypto token, LLM token — quasi tutti FP
#    ..                   640   path traversal in schema params / doc — tutti FP
#    credentials          361   credential manager, API wrapper — quasi tutti FP
#    API key/api_key      311   configurazione chiavi API — tutti FP
#    password             221   device management, DB access — quasi tutti FP
#    secret               174   secret manager (GCP, Azure, Saturn) — quasi tutti FP
#    .env/config/mcp.json  96   deployment e config tools — tutti FP
#    Read file/content     89   file reading legittimo — tutti FP
#    ~/.ssh                 8   SSH manager (legge ~/.ssh/config) — tutti FP
#    .cursor/               8   accesso config IDE Cursor — tutti FP
#
#  llm_risk=HIGH (26 finding): analizzati manualmente — 3 VP + 23 FP
#    VP: sec-mimikatz-mcp (dcsync, token_elevate), sec-rubeus-mcp (s4u)
#    FP: tutti gli altri (crypto token, credential manager, API key, SSH manager, ecc.)
#
#  PATTERN VP:
#    I soli VP sono wrapper di offensive tool (mimikatz, rubeus) con linguaggio esplicito
#    di attacco: DCSync, LSASS, WDigest, Kerberoasting, token elevation, credential dump.
#    Questi tool NON gestiscono le credenziali per conto dell'utente — le estraggono
#    in modo non autorizzato da sistemi altrui.
#
#  PATTERN FP:
#    Tutti gli altri trigger appaiono in tool che gestiscono legittimamente risorse
#    sensibili: SSH manager, secret manager, credential vault, API wrapper.
#    Avere un parametro "token" o "credentials" non è evidenza di furto.
#
#  Risultato atteso: ~14 HC-VP (attack tools), ~3080 HC-FP, 0 UNCERTAIN.
# ══════════════════════════════════════════════════════════════════════════════

# Linguaggio da offensive tool — indica strumenti di attacco reali, non gestione legittima
_SFA_ATTACK_PAT = re.compile(
    r"DCSync|LSASS|WDigest|sekurlsa|lsadump"
    r"|Kerberoast|AS-REP\s+[Rr]oast|kerberoasting"
    r"|Kerberos\s+(?:delegation\s+abuse|preauthentication)"
    r"|NTLM\s+hash|credential\s+dump"
    r"|Elevate\s+to\s+SYSTEM\s+token|impersonate\s+another\s+user"
    r"|S4U2(?:Self|Proxy)"
    r"|mimikatz|rubeus"
    r"|Extract\s+\w+\s+credentials\s+from\s+LSASS"
    r"|Dump\s+(?:LSA|Windows\s+Vault)\s+(?:secrets|credentials)"
    r"|privilege\s+escalation.*delegation"
    r"|replicate\s+AD\s+credentials"
    r"|pass-the-hash|pass\s+the\s+hash",
    re.IGNORECASE,
)


def hc_rules_sensitive_file_access(f: dict) -> tuple[str, str]:
    desc = _tool_desc(f)

    # ── HC-VP ────────────────────────────────────────────────────────────────
    # Offensive tool wrappers: mimikatz, rubeus e simili con linguaggio di attacco
    if _SFA_ATTACK_PAT.search(desc):
        return "HC-VP", "hc_vp:offensive_tool_credential_attack"

    # ── HC-FP ────────────────────────────────────────────────────────────────
    # Tutto il resto: credential manager, secret manager, API wrapper, SSH tool,
    # crypto token, config reader, file reader — nessuna evidenza di furto credentials.
    return "HC-FP", "hc_fp:legitimate_credential_or_file_management"


# ══════════════════════════════════════════════════════════════════════════════
#  DISPATCHER — mappa categoria → funzione regole HC
# ══════════════════════════════════════════════════════════════════════════════

HC_RULES: dict[str, callable] = {
    "hidden-instructions":   hc_rules_hidden_instructions,
    "shadowing-detected":    hc_rules_shadowing_detected,
    "potential-exfiltration": hc_rules_potential_exfiltration,
    "sensitive-file-access": hc_rules_sensitive_file_access,
}


# ══════════════════════════════════════════════════════════════════════════════
#  CARICAMENTO INPUT
#  Ogni categoria ha file separati per severity: <prefix>_HIGH.json, _MEDIUM.json
#  --severity: high | medium | both (default)
# ══════════════════════════════════════════════════════════════════════════════

def load_findings(cat: str, severity: str) -> tuple[list, dict]:
    """
    Carica i finding dalle file HIGH e/o MEDIUM della categoria.
    Ritorna (findings, meta) dove meta contiene i totali per severity.
    """
    cfg = CATEGORIES[cat]
    prefix = cfg["file_prefix"]
    available = cfg["severities"]
    cat_dir = HERE / cat

    if severity == "both":
        to_load = available
    elif severity.upper() in available:
        to_load = [severity.upper()]
    else:
        raise ValueError(
            f"Severity '{severity}' non disponibile per '{cat}'. "
            f"Disponibili: {', '.join(available)}"
        )

    findings = []
    meta: dict = {"by_severity": {}}

    for sev in to_load:
        fname = cat_dir / f"{prefix}_{sev}.json"
        if not fname.exists():
            print(f"  [WARN] File non trovato: {fname}")
            continue
        with io.open(fname, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data.get("findings", [])
        meta["by_severity"][sev] = len(items)
        findings.extend(items)

    meta["total_loaded"] = len(findings)
    return findings, meta


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2A — classificazione HC
# ══════════════════════════════════════════════════════════════════════════════

def run_stage2a(cat: str, findings: list) -> tuple[list, list, list]:
    fn = HC_RULES.get(cat)
    if fn is None:
        raise ValueError(
            f"Nessuna regola HC per la categoria '{cat}'. "
            f"Aggiungi hc_rules_{cat.replace('-','_')}() e registrala in HC_RULES."
        )

    hc_fp, hc_vp, unc = [], [], []
    for f in findings:
        bucket, reason = fn(f)
        enriched = dict(f, hc_bucket=bucket, hc_reason=reason)
        if   bucket == "HC-FP": hc_fp.append(enriched)
        elif bucket == "HC-VP": hc_vp.append(enriched)
        else:                   unc.append(enriched)
    return hc_fp, hc_vp, unc


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2B — classificazione Ollama (llama3)
# ══════════════════════════════════════════════════════════════════════════════

OLLAMA_PROMPT = """\
Sei un esperto di sicurezza informatica MCP (Model Context Protocol).

Devi classificare questo finding come VP (Vero Positivo) o FP (Falso Positivo).

CONTESTO: mcp-shield ha rilevato una potenziale istruzione nascosta/manipolativa
in una tool description di un server MCP.

SERVER: {server_name}
TOOL: {tool_name}
CATEGORIA: {category}
TRIGGER RILEVATO: {trigger}
RISK STATICO: {static_risk}
RISK LLM SHIELD: {llm_risk}

TOOL DESCRIPTION (troncata):
---
{tool_description}
---

CLASSIFICAZIONE:
- VP se: la tool description contiene istruzioni nascoste che tentano di
  manipolare il modello LLM (ridirezione comportamento, nascondere output,
  ignorare istruzioni precedenti, shadowing di altri tool, urgenza artificiale)
- FP se: il trigger e' usato in contesto tecnico legittimo (confronto tra
  strumenti, best practices, documentazione API, esempi d'uso)

RISPONDI SOLO con questo JSON (nessun altro testo):
{{"verdict": "VP" o "FP", "reason": "breve spiegazione in italiano (max 20 parole)"}}"""


def _build_ollama_prompt(f: dict) -> str:
    td = _tool_desc(f)[:600]
    triggers = ", ".join(_desc_list(f)) or "n/a"
    return OLLAMA_PROMPT.format(
        server_name=f.get("server_name", ""),
        tool_name=f.get("tool_name", ""),
        category=f.get("category", ""),
        trigger=triggers,
        static_risk=f.get("risk", ""),
        llm_risk=f.get("llm_risk", ""),
        tool_description=td,
    )


def _call_ollama(ollama_url: str, model: str, prompt: str) -> dict:
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{ollama_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    text = body.get("message", {}).get("content", "").strip()
    m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"verdict": "UNCERTAIN", "reason": f"parse_error:{text[:80]}"}


def check_ollama(ollama_url: str, model: str) -> bool:
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        available = [m["name"].split(":")[0] for m in tags.get("models", [])]
        model_base = model.split(":")[0]
        if model_base not in available:
            print(f"ATTENZIONE: modello '{model}' non trovato in Ollama.")
            print(f"  Disponibili: {', '.join(available) or 'nessuno'}")
            print(f"  Esegui: ollama pull {model}")
            return False
        return True
    except urllib.error.URLError as e:
        print(f"ERRORE: impossibile connettersi a Ollama su {ollama_url}: {e}")
        print("  Assicurati che Ollama sia in esecuzione (ollama serve)")
        return False


def _cache_path(out_dir: Path) -> Path:
    return out_dir / "_llm_api_cache.json"


def _load_cache(out_dir: Path) -> dict:
    p = _cache_path(out_dir)
    if p.exists():
        try:
            with io.open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def _save_cache(out_dir: Path, cache: dict) -> None:
    with io.open(_cache_path(out_dir), "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


def _cache_key(f: dict) -> str:
    return f"{f.get('server_name','')}/{f.get('tool_name','')}/{f.get('category','')}"


def run_stage2b(unc: list, out_dir: Path, args) -> list:
    if not unc:
        return []

    cache = {} if args.no_cache else _load_cache(out_dir)
    results = []
    new_calls = 0
    n = len(unc)

    for i, f in enumerate(unc):
        key = _cache_key(f)
        if key in cache and not args.no_cache:
            vd = cache[key]
            print(f"  [{i+1}/{n}] CACHED  {f.get('server_name','')[:30]:30s}  → {vd.get('verdict','?')}")
        else:
            prompt = _build_ollama_prompt(f)
            if args.dry_run:
                print(f"  [{i+1}/{n}] DRY-RUN {f.get('server_name','')[:30]:30s}")
                print(f"    PROMPT: {prompt[:200]}...")
                vd = {"verdict": "DRY_RUN", "reason": "dry_run"}
            else:
                try:
                    vd = _call_ollama(args.ollama_url, args.model, prompt)
                    new_calls += 1
                    cache[key] = vd
                    _save_cache(out_dir, cache)
                    print(f"  [{i+1}/{n}] OLLAMA  {f.get('server_name','')[:30]:30s}"
                          f"  → {vd.get('verdict','?'):2s}  {vd.get('reason','')[:55]}")
                except Exception as e:
                    print(f"  [{i+1}/{n}] ERRORE  {f.get('server_name','')}: {e}")
                    vd = {"verdict": "ERROR", "reason": str(e)[:80]}

        results.append(dict(f,
                            llm_verdict=vd.get("verdict"),
                            llm_reason=vd.get("reason"),
                            verdict_source=f"ollama:{args.model}"))

    print(f"  Ollama: {new_calls} nuove chiamate, {n - new_calls} da cache")
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  SALVATAGGIO bucket intermedi
# ══════════════════════════════════════════════════════════════════════════════

def save_buckets(cat: str, meta: dict, hc_fp: list, hc_vp: list,
                 unc: list, out_dir: Path) -> None:
    base = {
        "category": cat,
        "total_loaded": meta.get("total_loaded"),
        "by_severity": meta.get("by_severity", {}),
    }

    def dump(path: Path, items: list, bucket: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**base, "bucket": bucket, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    dump(out_dir / "hc_fp.json",    hc_fp, "HC-FP")
    dump(out_dir / "hc_vp.json",    hc_vp, "HC-VP")
    dump(out_dir / "uncertain.json", unc,  "UNCERTAIN")


# ══════════════════════════════════════════════════════════════════════════════
#  MERGE finale → vp.json / fp.json / audit.json
# ══════════════════════════════════════════════════════════════════════════════

def run_merge(cat: str, meta: dict, hc_fp: list, hc_vp: list,
              unc_classified: list, out_dir: Path) -> None:
    vp_final, fp_final, audit = [], [], []

    for f in hc_vp:
        rec = dict(f, final_verdict="VP", verdict_source="hc_rule",
                   final_reason=f.get("hc_reason", ""))
        vp_final.append(rec); audit.append(rec)

    for f in hc_fp:
        rec = dict(f, final_verdict="FP", verdict_source="hc_rule",
                   final_reason=f.get("hc_reason", ""))
        fp_final.append(rec); audit.append(rec)

    for f in unc_classified:
        v = f.get("llm_verdict", "")
        if v not in ("VP", "FP"):
            v = "FP"  # default conservativo per verdetti non parsati
        rec = dict(f, final_verdict=v, final_reason=f.get("llm_reason", ""))
        (vp_final if v == "VP" else fp_final).append(rec)
        audit.append(rec)

    base = {
        "category": cat,
        "total_loaded": meta.get("total_loaded"),
        "by_severity": meta.get("by_severity", {}),
        "pipeline_stage": "stage2_hc+ollama",
    }

    def dump(path: Path, items: list, verdict: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**base, "verdict": verdict, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    dump(out_dir / "vp.json", vp_final, "true_positive")
    dump(out_dir / "fp.json", fp_final, "false_positive")
    with io.open(out_dir / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"category": cat, "total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    if total == 0:
        print("\n  [WARN] Nessun finding nel merge.")
        return

    print(f"\n  ── Risultati finali ──────────────────────────────")
    print(f"  Totale:          {total:4d}")
    print(f"  Veri Positivi:   {len(vp_final):4d}  ({len(vp_final)/total*100:.1f}%)")
    print(f"  Falsi Positivi:  {len(fp_final):4d}  ({len(fp_final)/total*100:.1f}%)")
    print(f"  ─────────────────────────────────────────────────")


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

def run_category(cat: str, args) -> None:
    out_dir = HERE / cat / "llm_analysis"
    out_dir.mkdir(exist_ok=True)

    print(f"\n{'═'*60}")
    print(f"  Categoria: {cat}  |  Severity: {args.severity}")
    print(f"{'═'*60}")

    # Carica finding
    try:
        findings, meta = load_findings(cat, args.severity)
    except ValueError as e:
        print(f"  [ERRORE] {e}")
        return

    print(f"  Finding caricati: {meta['total_loaded']}")
    for sev, cnt in meta.get("by_severity", {}).items():
        print(f"    {sev}: {cnt}")

    # ── Stage 2A ─────────────────────────────────────────────────────────────
    print(f"\n[Stage 2A] Regole HC...")
    hc_fp, hc_vp, unc = run_stage2a(cat, findings)
    save_buckets(cat, meta, hc_fp, hc_vp, unc, out_dir)

    total = len(findings)
    print(f"  HC-FP:     {len(hc_fp):4d}  ({len(hc_fp)/total*100:.1f}%)")
    print(f"  HC-VP:     {len(hc_vp):4d}  ({len(hc_vp)/total*100:.1f}%)")
    print(f"  UNCERTAIN: {len(unc):4d}  ({len(unc)/total*100:.1f}%)")

    if unc:
        print(f"\n  UNCERTAIN finding ({len(unc)}):")
        for f in unc:
            triggers = ", ".join(_desc_list(f)) or "n/a"
            lr = f.get("llm_risk", "?")
            print(f"    [{lr:13s}]  {f.get('server_name','')[:35]:35s}  [{triggers}]")

    if hc_vp:
        print(f"\n  HC-VP finding ({len(hc_vp)}):")
        for f in hc_vp:
            print(f"    {f.get('server_name','')[:40]:40s}  {f.get('tool_name','')[:30]}  [{f.get('hc_reason','')}]")

    if args.hc_only:
        print(f"\n[{cat}] --hc-only: skip Stage 2B.")
        return

    # ── Stage 2B ─────────────────────────────────────────────────────────────
    if unc:
        if not args.dry_run and not check_ollama(args.ollama_url, args.model):
            print("  Ollama non raggiungibile. Usa --dry-run per vedere i prompt.")
            return
        print(f"\n[Stage 2B] Ollama ({args.model})...")
        unc_classified = run_stage2b(unc, out_dir, args)
    else:
        print("\n[Stage 2B] Nessun finding UNCERTAIN, skip Ollama.")
        unc_classified = []

    # ── Merge ─────────────────────────────────────────────────────────────────
    print("\n[Merge] Produzione vp.json / fp.json / audit.json...")
    run_merge(cat, meta, hc_fp, hc_vp, unc_classified, out_dir)

    all_fp_reasons = (
        [f.get("hc_reason", "") for f in hc_fp]
        + [f.get("llm_reason", "") for f in unc_classified if f.get("llm_verdict") == "FP"]
    )
    if all_fp_reasons:
        print("\n  FP per motivo:")
        for r, c in Counter(all_fp_reasons).most_common(10):
            print(f"    {c:3d}  {r}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline Stage 2A+2B mcp-shield: HC rules + Ollama llama3 per finding UNCERTAIN"
    )
    parser.add_argument("--category", default="all",
                        help=f"Categoria: {', '.join(CATEGORIES)}, o 'all' (default: all)")
    parser.add_argument("--severity", default="both",
                        choices=["high", "medium", "both"],
                        help="Filtra per severity: high | medium | both (default: both)")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache Ollama e riclassifica tutto da zero")
    parser.add_argument("--hc-only", action="store_true",
                        help="Esegui solo Stage 2A (senza Ollama)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt Ollama senza chiamare il server")
    parser.add_argument("--merge", action="store_true",
                        help="Alias per eseguire Stage 2A + 2B + merge (default senza --hc-only)")

    args = parser.parse_args()

    cats = list(CATEGORIES.keys()) if args.category == "all" else [args.category]

    for cat in cats:
        if cat not in CATEGORIES:
            print(f"[ERRORE] Categoria sconosciuta: '{cat}'. "
                  f"Disponibili: {', '.join(CATEGORIES)}")
            continue
        run_category(cat, args)


if __name__ == "__main__":
    main()
