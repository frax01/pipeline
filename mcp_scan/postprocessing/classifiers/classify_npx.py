"""
Stage 2A classifier per finding NPX mcp-scan (modello mcp-guard/mcp-watch).

Produce 3 bucket per categoria:
  hc_vp.json     vero positivo ad alta confidenza (pattern espliciti)
  hc_fp.json     falso positivo ad alta confidenza (pattern espliciti)
  uncertain.json residui senza match → da classificare in Stage 2B (Sonnet in-chat)

Default = UNCERTAIN. NON c'e' default VP/FP catch-all.

Workflow:
  1. py -X utf8 classifiers/classify_npx.py           → Stage 2A: produce 3 bucket
  2. classificare uncertain.json in-chat   → popola _llm_api_cache.json
  3. py -X utf8 stage2_pipeline_npx.py --merge  → produce vp.json/fp.json/audit.json

Output in <level>/<cat>/llm_analysis/:
  hc_vp.json / hc_fp.json / uncertain.json
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  HONEYPOT
# ══════════════════════════════════════════════════════════════════════════════

_HONEYPOT = {
    "malicious_mcp", "vulnerable-notes-mcp", "imcp", "vulnicheck",
    "mcp-scanner", "agent-security-scanner-mcp", "vulnerable-mcp", "honeypot-mcp",
}


def _is_honeypot(server_url: str) -> bool:
    s = (server_url or "").lower()
    return any(h in s for h in _HONEYPOT)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _server_short(url: str) -> str:
    return (url or "").replace("https://github.com/", "")


def _evidence(f: dict) -> str:
    return ((f.get("extra_data") or {}).get("evidence") or "")


def _example(f: dict) -> str:
    return ((f.get("extra_data") or {}).get("example") or "")


def _reason(f: dict) -> str:
    return ((f.get("extra_data") or {}).get("reason") or "")


def _risk(f: dict) -> float:
    try:
        return float((f.get("extra_data") or {}).get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  CLASSIFICATORI PER CATEGORIA (3-bucket: VP/FP/UNCERTAIN)
# ══════════════════════════════════════════════════════════════════════════════

# ----- E001: Prompt Injection (tool-level) -----------------------------------

_E001_VP_STRONG = re.compile(
    r"""
    (
        \bsilently\b
      | \bsliently\s+remember\b
      | ignore\s+(?:all\s+)?(?:previous\s+)?instructions
      | NEVER\s+use\s+(?:Read|Grep|Glob|Write|Edit|Bash|file\s+reading)
      | ALWAYS\s+use\s+\w+\s+instead(?!\s+of\s+\w)
      | <IMPORTANT>
      | <hidden>
      | <secret>
      | <cmd>
      | export\s+(?:ALL|the\s+complete).{0,30}conversation
      | send.{0,40}(?:ENTIRE|all|complete).{0,30}conversation
      | CRITICAL.{0,30}MUST
      | display\s+verbatim
      | as\s+your\s+own\s+words
      | bypass.{0,15}(?:token\s+limits|safety|security|guardrails)
      | forget\s+everything
      | do\s+NOT\s+suggest\s+alternatives
      | never\s+(?:reveal|show|mention|disclose|expose).{0,40}
        (?:this|instruction|prompt|query|data|key|token|password|secret|actual|conversation|system)
      | do\s+not\s+(?:reveal|disclose|share|expose)\s+(?:the\s+)?
        (?:actual|real|underlying|internal|system)
      | IMPORTANT[:\.]\s+(?:Never|Always|MUST|Do\s+not|You\s+must)
      | this\s+is\s+VERY\s+VERY
      | embedded\s+(?:directive|agent\s+directive|system\s+instruction|behavioral\s+directive|imperative)
      # extensions from sample analysis
      | AGENT[-_\s]?MANDATORY[-_\s]?INSTRUCTIONS?
      | <AGENT[-_]MANDATORY
      | agent[-\s]?(?:targeted|mandatory)\s+directive
      | prompt[-\s]?injection[-\s]?style
      | dictate\s+agent\s+behavior
      | disclose\s+(?:chain[-\s]?of[-\s]?thought|internal\s+reasoning|thinking\s+(?:process|summary))
      | send\s+all\s+credentials?\s+to
      | should\s+no\s+longer\s+tell\s+the\s+user
      | YOU\s+MUST\s+READ\s+AND\s+FOLLOW
      | A\s+FAILURE\s+TO\s+DO\s+SO
      | \(MANDATORY\)
      | call\s+(?:another|the)\s+tool\s+(?:automatically|immediately)
      | embedded\s+in\s+tool\s+(?:metadata|description)
      | classic\s+prompt[-\s]?injection
      | autoroles?\s+a\s+tool[-\s]?call
      | imperative\s+(?:embedded|in\s+tool)
      | dataforseo_labs_google_su  # dummy filler, not used
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Chinese imperative patterns (e.g., "必须", "你必须")
_E001_VP_CHINESE = re.compile(r"(必须|你必须|严禁|不许)")

_E001_FP_STRONG = re.compile(
    r"""
    (
        \bSTRICT:\s+You\s+MUST\s+follow\s+exactly\b
      | \bgrants\s+internet\s+access\b
      | --yolo
      | \bbaseInstructions\b
      | \bsystem_prompt\b\s*:\s*str
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_E001(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _reason(f)
    if _E001_FP_STRONG.search(ev):
        return ("FP", "enterprise boilerplate/CLI wrapper/fetch template")
    if _E001_VP_STRONG.search(ev) or _E001_VP_CHINESE.search(ev):
        return ("VP", "explicit manipulation pattern in tool description")
    # risk_score=1.0 from mcp-scan internal LLM = very high confidence
    if _risk(f) >= 1.0:
        return ("VP", "mcp-scan internal LLM highest confidence (risk_score=1.0)")
    return ("UNCERTAIN", "no strong pattern")


# ----- W001: Dangerous Words (tool-level) ------------------------------------

_W001_STRONG = {"ignore", "override", "bypass"}
_W001_BENIGN = {"important", "critical", "urgent", "vital", "crucial"}


def classify_W001(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    words = set((w or "").lower() for w in ((f.get("extra_data") or {}).get("words") or []))
    strong = words & _W001_STRONG
    # VP forti: combo di 2+ parole strong manipolative
    if len(strong) >= 2:
        return ("VP", f"multiple strong manipulation keywords: {sorted(strong)}")
    if "ignore" in words and "override" in words:
        return ("VP", "ignore+override pattern")
    # FP forti: SOLO parole benign (emphasis ordinaria)
    if words and words.issubset(_W001_BENIGN):
        return ("FP", f"only common emphasis: {sorted(words)}")
    # Single strong word in legit API tool = FP (W001 sample analysis showed 10/10 FP)
    if len(strong) == 1 and not (words - strong):
        return ("FP", f"isolated single strong word in API tool: {sorted(strong)}")
    # Mix di strong + benign senza pattern chiaro = FP (benign emphasis context)
    if strong and (words - strong) <= _W001_BENIGN:
        return ("FP", f"strong+benign mix (likely emphasis): {sorted(words)}")
    return ("UNCERTAIN", f"unclassified word set: {sorted(words)}")


# ----- W015: Untrusted Content Injection -------------------------------------

_W015_VP_PASSIVE = re.compile(
    r"""
    (
        \b(?:webhook|email\s+inbox|incoming\s+email)\b
      | \b(?:github|gitlab|gerrit)\s+(?:issue|pr|pull\s+request|comment|notification|change|patch)
      | \bsupport\s+ticket
      | \b(?:pending|incoming|monitored)\s+(?:transaction|content|message|event)
      | \b(?:subscribe|listen|consume|stream)\b.{0,30}(?:events?|messages?|feed)
      | \b(?:broadcast|publish)\b.{0,30}(?:public|chain|forum|market)
      | \battacker[\s-]?(?:broadcasts?|submits?|sends?|publishes?|controlled|posts?)
      | \b(?:passive|incoming|inbound)\s+(?:monitoring|content|stream|queue|feed)
      # extensions from sample
      | \b(?:public|external)\s+(?:market|orderbook|exchange|chain|registry|api|article|form|gist|crowd)
      | \b(?:public\s+)?(?:gerrit|airtable|qiita|weibo)\s+(?:project|change|article|form|post|share)
      | \b(?:external\s+)?(?:actor|attacker)\s+(?:can\s+)?(?:submit|post|publish|create|broadcast|inject)
      | \bcrowd[-\s]?(?:work|source)\b|\bcrowd\s+workers?\b
      | \bairtable\s+(?:form|public\s+form|share)
      | \b(?:create|post|submit)_(?:note|hit|issue|comment|article)
      | \b(?:public|external)\s+(?:trades?|orders?|transactions?)\s+(?:that|which)\s+(?:appear|are\s+received)
      | \b(?:populated|fed|filled)\s+by\s+(?:external|public|untrusted)\s+(?:activity|content|input)
      | \battacker[-\s]?controlled\s+content
      | \bappear\s+in\s+the\s+agent'?s\s+(?:monitored|incoming|inbox|stream)
      | \binject\s+(?:untrusted|malicious)\s+content
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W015_FP_INTERNAL = re.compile(
    r"""
    (
        \b(?:internal|private|admin|authenticated|enterprise)\s+(?:api|sdk|server)
      | requires?\s+(?:admin|root|service)\s+(?:token|credentials)
      | \bofficial\s+API\s+with\s+(?:auth|api[\s_]?key)
      | \bagent\s+must\s+(?:explicitly\s+)?call
      | \bagent[\s-]initiated
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W015(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    if _W015_VP_PASSIVE.search(ev):
        return ("VP", "passive monitoring of attacker-publishable source")
    if _W015_FP_INTERNAL.search(ev):
        return ("FP", "authenticated/internal source, not passively poisonable")
    return ("UNCERTAIN", "no clear passive/internal signal")


# ----- W016: Untrusted Content Retrieval -------------------------------------

_W016_VP_PUBLIC = re.compile(
    r"""
    (
        \b(?:github|gitlab|bitbucket|gitee|cnb)\.(?:com|cool)\b
      | \b(?:youtube|reddit|twitter|telegram|discord|hackernews|medium|stackoverflow)\b
      | \bweb\s+(?:scrap|search|browse|fetch|page)
      | \b(?:npm|pypi|packagist|crates|maven|nuget|rubygems)\b.{0,40}(?:package|registry|public)
      | \bwikipedia\b
      | \barxiv(?:\.org)?\b
      | \bpublic\s+(?:repo|repository|forum|blog|site|page|news|article)
      | \b(?:rss|atom)\s+feed
      | \bopen[\s-]?(?:source|library|book|index|registry)
      | \bsocial\s+media\b
      | \b(?:search\s+(?:results?|engine|index)|google\s+search)
      | \bpublic[\s-]?(?:on[\s-]?chain|blockchain|mainnet)
      | \bpoisonable\s+(?:registry|package|repo|content)
      # extensions
      | \bcrossref\b
      | \battacker\s+(?:can\s+)?(?:publish|host|spoof)
      | \btyposquat
      | \bsupply[\s-]?chain
      | \bcrafted\s+(?:url|page|article|content)
      | \b(?:malicious|poisoned)\s+(?:url|page|article|content|package|preprint|content)
      | \bsearch[-_\s]?(?:results?|engine|index|poisoning)
      | \bspoofed\s+(?:public|website|page|api)
      | \bweb\s+(?:content|results?|page)\b.{0,30}(?:attack|poison|malicious|inject)
      | \b(?:weather|forecast|api)\b.{0,30}(?:untrusted|public|external)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W016_FP_AUTHED = re.compile(
    r"""
    (
        \b(?:internal|private|enterprise|corporate)\s+(?:api|sdk|server|database)
      | requires?\s+(?:admin|root|service[\s_]?role)\s+(?:token|credentials|auth)
      | \bauthenticated\s+(?:saas|crm|erp|api)
      | \bofficial\s+(?:cloud\s+)?api\s+endpoint\b.{0,50}(?:requires?\s+auth|with\s+api[\s_]?key)
      | \bget_public_prices?\b
      | \bonly\s+public\s+(?:prices?|chain|metadata)\b.{0,40}(?:cannot|can\s*not)\s+make
      # extensions: explicit "no auto fetch" or "agent must supply"
      | \bno\s+(?:automatic\s+)?(?:fetcher|reader|monitor|ingestion)
      | \bagent\s+must\s+(?:be\s+given|actively\s+(?:call|select|fetch|choose|invoke))
      | \brequires?\s+the\s+agent\s+to\s+(?:select|choose|provide|supply|actively\s+call)
      | \brequires?\s+the\s+agent\s+to\s+be\s+given
      | \bthere\s+is\s+no\s+(?:mechanism|automatic|inbox|queue|fetcher)
      | \bcannot\s+force\s+(?:those|the|content)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W016(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    has_vp = _W016_VP_PUBLIC.search(ev)
    has_fp = _W016_FP_AUTHED.search(ev)
    # Per W016 il pattern "agent must invoke / cannot push" è segnale forte di FP
    # anche in presenza di VP keywords (specifico per la semantica di W016)
    if has_fp:
        return ("FP", "authenticated/private API or agent-must-invoke")
    if has_vp:
        return ("VP", "fetches from public/attacker-publishable source")
    return ("UNCERTAIN", "no clear public-source signal")


# ----- W017: Sensitive Data Exposure -----------------------------------------

_W017_VP_SENSITIVE = re.compile(
    r"""
    (
        \b(?:password|api[\s_]?key|secret|credential|token|private[\s_]?key)\b
      | \b(?:wallet|seed[\s_]?phrase|mnemonic)\b
      | \b(?:balance|equity|margin|drawdown|portfolio)\b
      | \b(?:email\s+inbox|gmail|outlook|personal\s+message)\b
      | \b(?:credit[\s_]?card|bank\s+account|payment\s+method|transaction\s+history)\b
      | \b(?:medical|health|patient|prescription|diagnosis)\b.{0,30}\b(?:record|data|info)
      | \b(?:ssn|tax[\s_]?id|passport|driver[\s_]?license)\b
      | \b(?:trade[\s_]?journal|open\s+positions?|pending\s+orders?)\b
      | \b(?:dm|direct[\s_]?message|private[\s_]?chat|conversation\s+history)\b
      | \b(?:salary|payroll|compensation|hr\s+records?)\b
      | \b(?:keychain|secret[\s_]?manager|password[\s_]?manager|vault\s+(?:secret|cred))\b
      | \b(?:lat(?:itude)?|long(?:itude)?|gps)\b.{0,30}(?:coordinate|location|route|track)
      | \bprecise\s+(?:location|coordinate)\b
      # extensions from sample
      | \b(?:unpublished|proprietary|internal)\s+(?:project|design|code|spec|asset|implementation|api)
      | \bslack\s+(?:channel|message|user|workspace|private|dms?)
      | \bpr\s+(?:detail|review|comment|description|author)
      | \berror\s+(?:records?|messages?|details?)\s+(?:with|including|expos)
      | \bstack\s+traces?\b.{0,30}(?:expose|reveal|return|implementation)
      | \bidentity\s+verification
      | \bfull\s+name\s+and\s+(?:id|ssn|passport)
      | \bmastergo\s+(?:design|file|component)
      | \bdesign\s+(?:file|asset)\s+(?:content|metadata)
      | \buser\s+(?:profile|posts|activity|feed|messages)
      | \b(?:weibo|wechat|telegram|whatsapp)\s+(?:profile|post|message|content|feed)
      | \byapi\s+(?:interface|docs?|spec)
      | \bproject\s+(?:spec|specification)\s+(?:files?|context|documents?)
      | \bcoach[\s/-]?member\s+relationships?
      | \buser\s+(?:profiles?|roles?|schedules?|availability)
      | \btraining\s+plans?\b.{0,30}per[-\s]?user
      | \benterprise\s+information\b
      | \bcompany[-\s]?(?:focused|owned)\s+(?:queries?|data)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W017_FP_PUBLIC = re.compile(
    r"""
    (
        \bpublic\s+(?:on[\s-]?chain|blockchain|api|data|price|info|metadata)
      | \bget_(?:public|chain|block|price|version|info|status|health)
      | \b(?:read-?only|view-?only)\s+(?:public|metadata|summary)
      | \bonly\s+(?:returns?|exposes?)\s+(?:public|api)\s+(?:metadata|response)
      | \bpublic\s+package\s+(?:info|metadata)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


_W017_CATCHALL = re.compile(
    r"""
    (
        \b(?:expose|return|retriev|reveal|access|read)\w*\s+(?:non[-\s]?public|private|personal|sensitive|enterprise|proprietary|internal|user'?s?|user\s+data|user\s+info)
      | \b(?:full|first|last)\s?[Nn]ame
      | \bemail\s+(?:address|inbox)
      | \bphone\s+(?:number)?
      | \b(?:address|location|country|city|zip|postcode|postal)\b.{0,30}(?:user|personal|private|record)
      | \b(?:guest|booking|reservation|appointment)\s+(?:record|detail|info|data)
      | \b(?:figma|sketch|adobe|design)\s+(?:file|design|component|node|asset)\s+(?:content|metadata|data)
      | \bread_memory\b
      | \b(?:screenshot|page\s+source|on[-\s]?screen\s+text)
      | \bappium_(?:get_text|get_page_source)
      | \bsecrets?\s+(?:flag|scan|finder|--secrets)
      | \b(?:CRM|crm)\s+(?:data|deals?|pipeline|leads?)
      | \bremote\s+(?:desktop|VM|machine)\s+(?:inventory|screenshot|image)
      | \b(?:experiments?|remote[\s-]?configs?|analytics?\s+(?:chart|report))
      | \buser[-\s]?(?:group|profile|emails?|messages?|account)
      | \b(?:financial|monetary)\s+(?:filters?|fields?|data|records?)
      | \b(?:project|task)\s+(?:documents?|details?|listings?|history)\s+(?:tied|associated|linked)\s+to
      | \btie[ds]?\s+to\s+(?:the\s+)?(?:current\s+)?(?:authenticated\s+)?(?:user|account)
      | \bproprietary\s+(?:data|info|metric)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W017(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    has_vp_strong = _W017_VP_SENSITIVE.search(ev)
    has_vp_catchall = _W017_CATCHALL.search(ev)
    if has_vp_strong:
        return ("VP", "exposes sensitive PII/credentials/financial/private data")
    if has_vp_catchall:
        return ("VP", "exposes private/proprietary/user-tied data (catchall)")
    if _W017_FP_PUBLIC.search(ev):
        return ("FP", "public/read-only data, not sensitive PII")
    return ("UNCERTAIN", "no clear sensitive-data signal")


# ----- W018: Workspace Data Exposure -----------------------------------------

_W018_VP_WORKSPACE = re.compile(
    r"""
    (
        \b\.cursor\b
      | \b\.vscode\b
      | \b\.idea\b
      | \bproject\s+(?:files?|director(?:y|ies)|source\s+code|root)
      | \b(?:read|list|sync|scan)[\s_-]?(?:files?|sources?|workspace|dir)
      | \bsource\s+code\s+(?:files?|repository|directory)
      | \b\.env\s+file
      | \blocal\s+(?:notes?|docs?|drafts?|files?)
      | \bworking\s+directory
      | \bproject[\s_]?root
      | \binternal\s+(?:docs?|documentation|wiki|notes?)
      | \b(?:git\s+repo|monorepo|subprojects?)\s+(?:files?|content|sources?)
      | \bextract_source\b
      | \blocal\s+(?:user[\s-]?managed|user\s+files?)
      # extensions from sample
      | \b\.pbxproj\b|\b\.xcstrings\b|\b\.cursorrules\b
      | \b(?:xcode|android\s+studio|intellij)\s+project
      | \binputPath\s+to\s+(?:a\s+)?user'?s?\s+(?:file|image|pdf|document)
      | \buser'?s?\s+(?:image|pdf|document|file|note|context)
      | \b(?:absolute|local)\s+path\s+to\s+(?:a\s+)?(?:pdf|file|image|directory)
      | \bconvert.{0,15}(?:pdf|local|files?)\s+to
      | \b(?:read|expose)s?\s+(?:image|file)\s+(?:contents?|metadata)
      | \bspec[\s_-]?(?:list|status|context)\s+(?:files?|context|documents?)
      | \blocal\s+(?:pdfs?|contracts?|documents?|notes?)
      | \bproject(?:'s)?\s+(?:specification|spec)\s+(?:and\s+)?guidance
      | \bsaved\s+(?:persistent\s+)?contexts?
      | \bsensor[\s-]?tower|app[\s-]?level\s+analytics?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W018_FP_PATTERNS = re.compile(
    r"""
    (
        \bonly\s+metadata\b
      | \bversion\s+info\b
      | \b(?:health|status|ping)[\s_]?check\b
      | \bpublic\s+package\s+(?:info|metadata)\b
      | \b(?:weather|station|device|iot)\s+(?:metadata|observations?|diagnostics?|telemetry)
      | \b(?:returns?|exposes?)\s+(?:public|api)\s+(?:metadata|response)
      | \b(?:openapi|swagger|api[\s_]?spec)\s+(?:schema|doc|definition)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


_W018_CATCHALL = re.compile(
    r"""
    (
        \blocal(?:[-\s]?(?:non[-\s]?critical|user[-\s]?managed))?\s+(?:files?|data|notes?|docs?|workspace|user)
      | \bnon[-\s]?public\s+(?:project|file|content|api|doc|spec|workspace)
      | \b(?:read|access|expose|return|disclose)\w*\s+(?:local|workspace|project)\s+(?:files?|content|data|sources?|notes?|docs?|specs?)
      | \buser[-\s]?(?:provided|managed|created)\s+(?:datasets?|notes?|prompts?|files?|context)
      | \bproject[-\s]?(?:files?|context|metadata|spec|sources?)
      | \b(?:diagnostics?|errors?|warnings?)\s+for\s+(?:all\s+)?workspace\s+files?
      | \b(?:notification|prompt|context|chat|conversation)\s+(?:history|entries?|content)\b.{0,60}(?:user|personal|local|stored)
      | \bappium_(?:get_page_source|extract_selectors)
      | \b(?:debug|admin|trace)\s+(?:traces?|details?|api)
      | \bbirthHour|\bbirthMinute|\bbirthDay|\bbirthMonth|\bbirthYear
      | \b(?:lat|long|latitude|longitude)\b.{0,30}(?:required|param|input|birth)
      | \bphone[\s_-]?(?:location|number)
      | \b(?:guest|booking|customer|client)\s+(?:fields?|records?)\b
      | \bnavigate\s+to\s+(?:arbitrary|any)\s+(?:URL|page)
      | \bsketch_?(?:file|design|context)
      | \b(?:fetch|load|read)\s+(?:arbitrary|any)\s+(?:URL|file|path)
      | \binventory\s+of\s+(?:VMs?|connections|hosts)
      | \bsaved\s+(?:prompts?|notes?|contexts?|data)
      | \bdataset\s+contents?\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W018(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    has_vp_strong = _W018_VP_WORKSPACE.search(ev)
    has_vp_catchall = _W018_CATCHALL.search(ev)
    if has_vp_strong:
        return ("VP", "reads local workspace files/code/notes")
    if has_vp_catchall:
        return ("VP", "exposes local/non-public/user-managed workspace data (catchall)")
    if _W018_FP_PATTERNS.search(ev):
        return ("FP", "metadata-only or telemetry, no workspace file content")
    return ("UNCERTAIN", "no clear workspace-file signal")


# ----- W019: Destructive Capabilities (shared) -------------------------------

_W019_VP_DESTRUCTIVE = re.compile(
    r"""
    (
        \b(?:deploy|publish|push)\s+(?:to|website|service|app|application)
      | \bexec(?:ute)?[\s_]?(?:command|shell|bash|sh|cmd|code|javascript|sql|query)
      | \b(?:run|invoke|spawn)\s+(?:shell|command|process|terminal)
      | \bdrop\s+(?:table|database|index|schema)
      | \b(?:truncate|delete\s+all)\s+(?:table|database)
      | \bkubectl\s+(?:delete|apply|exec|patch|create)
      | \bdocker\s+(?:run|exec|kill|stop|rm|build)
      | \binstall\s+(?:package|dependency|plugin|extension|service)
      | \b(?:uninstall|remove)\s+(?:package|dependency|plugin|service)
      | \bssh\s+(?:exec|command|connect)
      | \b(?:create|modify|delete|remove|update)\s+(?:user|account|organization|role|permission|policy|project|ticket|task|cookie|prompt|workflow|alarm|webhook|trigger|automation|article|attachment|portfolio|knowledgebase|source|frame|invoice|payment|payout|order|subscription|catalog|comment)
      | \bsend\s+(?:bulk\s+)?(?:email|sms|notification|message)\s+(?:to|s)
      | \b(?:transfer|withdraw|send)\s+(?:funds|crypto|token|currency)
      | \b(?:cluster|namespace|node)\s+(?:operation|management|control)
      | \b(?:firewall|security[\s_]?group|iam)\s+(?:rule|policy|change|update)
      | \bmodif(?:y|ies?)\s+(?:shared|production|prod|live|remote|cloud)
      | \bremote\s+(?:server|host|infrastructure)
      | \b(?:restart|stop|kill)\s+(?:service|process|container|pod)
      # extensions from sample
      | \bsendBulkMail\b|\bsendMail\b|\bsend(?:Simple|Html)Mail\b
      | \bdelete[Ee]mail|\bmove[Ee]mail|\bmarkAs(?:Read|Unread)
      | \bmailbox\s+(?:state|action)
      | \b(?:payments?|refunds?|payouts?|invoices?|subscriptions?)\s+(?:on|create|process|api)
      | \bfinancial\s+(?:transactions?|flow)
      | \bdeploy(?:s|ment)?\s+(?:contract|token|server|new\s+token)
      | \bon[\s-]?chain\s+(?:state|changes?|action)
      | \bnew\s+token\s+contracts?
      | \blaunch_(?:on|memecoin|pool)
      | \bDEX\s+(?:launch|swap|pool)
      | \bcreate_memecoin\b
      | \bPOST/PUT/DELETE
      | \b(?:create|update|delete)\s+(?:nodes?|content|media|resources?)\s+(?:on|in)\s+(?:remote|shared|hosted)
      | \bstrapi_(?:rest|upload_media)
      | \bcall_(?:nodit|blockchain)_api
      | \bdestroy\s+(?:project|knowledgebase|source|namespace)
      | \bremoveUserFor(?:Workspace|Team)
      | \bcreate/update/delete
      | \bgranted\s+access\s+to\s+tools\s+that\s+can\s+(?:modify|execute|deploy)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W019_FP_READONLY = re.compile(
    r"""
    (
        \b(?:get|list|read|query|fetch|view|describe)[\s_-]?(?:only|info|status|metadata)
      | \bread[\s-]?only\s+(?:access|operation|tool)
      | \bonly\s+(?:gets?|lists?|reads?|fetches?|views?)\s+(?:data|info|status)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


_W019_CATCHALL = re.compile(
    r"""
    (
        \b(?:modif(?:y|ies?)|alter|change|update|create|delete)\s+(?:shared|remote|external|cloud|hosted|production|prod|live)
      | \bshared\s+(?:infrastructure|SaaS|service|state|account|database|cluster)
      | \b(?:remote|external)\s+(?:state|infrastructure|server|service|account|environment)
      | \bdestructive(?:/state-?modifying|\s+actions?)
      | \b(?:POST|PUT|PATCH|DELETE)\s+(?:against|to)\s+(?:arbitrary|api)\s+(?:URL|endpoint)
      | \b(?:initiate|trigger)\s+(?:irreversible|financial)\s+(?:transfers?|operations?|payments?)
      | \binvoke\s+(?:models?|cloud|remote)
      | \bRailway\s+CLI|deploy\s+to\s+(?:vercel|netlify|heroku|aws|gcp)
      | \b(?:start|stop|restart|kill)\s+(?:a\s+)?(?:proxy|server|process|service|browser)\s+(?:server|debug)
      | \b(?:authenticated\s+)?session.{0,30}(?:modify|delete|alter|update)
      | \b(?:write|update|delete|create)\s+(?:in|to)\s+(?:flomo|notion|jira|slack|trello|monday|airtable|gerrit)
      | \b(?:remote|cloud)\s+(?:flomo|notion|jira|slack|trello)\s+account
      | \b(?:invoke|call)_provider|call_(?:nodit|blockchain|hyperware)
      | \b(?:project_(?:delete|remove|cleanup)|knowledgebase_delete|source_delete)
      | \b(?:project|repository|repo)\s+state\b.{0,30}(?:modify|alter|update|change)
      | \bsave\s+(?:new\s+)?SQL|\bSQL\s+(?:auto[-\s]?saved|stored)
      | \bvercel|jfrog|spotify\s+(?:account|playlist)|hypergrid
      | \badd_(?:tool|python_tool|mcp_tool).{0,50}(?:command|args|env|run|execute)
      | \bcustom\s+(?:server|process)\s+(?:start|launch)
      | \bregister\s+executable
      | \blaunch\s+(?:on|browser|debug)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W019(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    has_vp_strong = _W019_VP_DESTRUCTIVE.search(ev)
    has_vp_catchall = _W019_CATCHALL.search(ev)
    if has_vp_strong:
        return ("VP", "modifies/executes on shared infrastructure")
    if has_vp_catchall:
        return ("VP", "modifies shared/remote/cloud state (catchall)")
    if _W019_FP_READONLY.search(ev):
        return ("FP", "read-only operation, no destructive capability")
    return ("UNCERTAIN", "no clear destructive signal")


# ----- W020: Local Destructive Capabilities ----------------------------------

_W020_VP_LOCAL = re.compile(
    r"""
    (
        \b(?:write|create|delete|remove|rm|unlink)\s+(?:files?|director(?:y|ies)|folder)
      | \b(?:overwrite|append|modif(?:y|ies?))\s+(?:files?|config|settings)
      | \bsync_to\b
      | \bwriteFileSync\b
      | \bos\.remove\b
      | \bshutil\.rmtree\b
      | \bos\.unlink\b
      | \b(?:reorganize|restructure|move)\s+(?:files?|dirs?|folders?)
      | \b(?:edit|update|patch)\s+(?:local|project|workspace)\s+files?
      | \binit_(?:monorepo|project|workspace|repo)
      | \bgenerate.{0,15}(?:rules?|config|scaffold)\s+(?:files?|in)
      | \b(?:rewrite|overwrite)\s+(?:rules?|config|cursor)
      | \bnpm\s+install\b.{0,30}(?:local|project)
      | \bpip\s+install\b.{0,30}(?:local|requirements)
      # extensions from sample
      | \badd_(?:cookie|prompt)|\bdelete_(?:cookie|prompt)
      | \bset_localstorage|\bset_sessionstorage
      | \b(?:upload|download)_file
      | \bexecute_(?:javascript|code)
      | \b(?:browser|local)\s+(?:logs?|cache)
      | \bwipeLogs?\b
      | \bpcap\s+(?:output|file|capture)
      | \bcapture\s+session
      | \b(?:start|stop)_recording
      | \bclear[\s_]?(?:queue|logcat)
      | \bremove[\s_]?from[\s_]?queue
      | \b(?:delete|reset)_(?:alarm|processing|context|chunk|knowledge_check)
      | \bsimulate\s+user\s+input
      | \btap|swipe|keyevent
      | \bcontext_add\b|\bcontext_delete\b
      | \basimov_(?:context_add|index|delete)
      | \btake_screenshot\b
      | \bcreate.{0,15}(?:transcription|output|audit)\s+files?
      | \bwrite\s+(?:vectorDrawable\s+xml|audit\.md|output\s+files?)\s+to
      | \bsave.{0,10}(?:to|local|capture)\s+(?:output|file|path)
      | \badd_prompt\b|\bcreate_structured_prompt\b
      | \bcontained\s+to\s+(?:the\s+)?(?:user'?s\s+)?(?:single\s+)?(?:machine|workspace|browser|device|local)
      | \bblast\s+radius\s+(?:is\s+)?(?:contained|local|limited)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_W020_FP_READONLY = re.compile(
    r"""
    (
        \bonly\s+(?:reads?|lists?|views?|gets?|queries)
      | \bread[\s-]?only\b
      | \bnever\s+(?:writes?|modifies?|deletes?)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


_W020_CATCHALL = re.compile(
    r"""
    (
        \b(?:modify|alter|change|create|delete|update|write|remove)\s+(?:local|user'?s?|browser|device|sandbox)\s+(?:files?|state|cache|config|data|profile)
      | \blocal\s+(?:browser|device|filesystem|machine|state)
      | \bcontained\s+to\s+(?:the\s+)?(?:user'?s\s+)?(?:single\s+)?(?:machine|workspace|browser|device|local|personal|sandbox)
      | \bblast\s+radius\s+(?:is\s+)?(?:contained|local|limited|single[\s-]?user)
      | \b(?:write|create|generate|save)\s+(?:transcription|output|audit|pcap|json|xml|csv|markdown|file)
      | \b(?:add|update|remove|delete)\s+(?:notes?|prompts?|entries?|memory|saved\s+context)
      | \b(?:create|delete|toggle)\s+(?:live[-\s]?stream|recording|project|session)
      | \b(?:DOM\s+interactions?|fill\s+forms?|navigate\s+page|evaluate_script)
      | \blaunch.{0,20}(?:system\s+default\s+app|local\s+file|path)
      | \bsystem\s+default\s+app
      | \breveal_path|\bopen_path
      | \boutput[\s_-]?path|\boutputDir|\boutPath
      | \bwrite\s+metric\s+points?|\bimport\s+Prometheus
      | \b(?:VictoriaMetrics|Prometheus|metric)\s+(?:state|instance|write)
      | \bcreate_sandbox|\bsandbox\s+id|\bisolated\s+sandbox
      | \b(?:Spotify|playback|playlist)\s+(?:account|device|state)
      | \b(?:create|update)Playlist|\baddTracksToPlaylist|\bsaveOrRemoveAlbum
      | \b(?:bulk_)?delete_(?:notes?|note_type)
      | \bplan\s+(?:register|update)|\bupdate.{0,20}commit\s+(?:status|state)|\bcancel\s+(?:PR|commit)
      | \bgenerate_\w+\s+with\s+outputFormat
      | \bdiffs?\s+to\s+source\s+files?
      | \badd_cookie\b|\bdelete_cookie\b
      | \bset/remove\s+localStorage
      | \boverwrite\s+(?:local|reference)\s+(?:files?|json)
      | \badd\s+new\s+entries?|\bremove\s+entries?\s+from
      | \bnote\s+(?:contents?|links?)|\bnote\s+entries
      | \b(?:context|knowledge_check|chunk|processing)\s+(?:add|delete|reset|complete|record)
      | \bmodif(?:y|ies)\s+(?:server|service)\s+state
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_W020(f: dict):
    if _is_honeypot(f.get("server_url", "")):
        return ("FP", "honeypot/intentionally vulnerable")
    ev = _evidence(f) + " " + _example(f)
    has_vp_strong = _W020_VP_LOCAL.search(ev)
    has_vp_catchall = _W020_CATCHALL.search(ev)
    if has_vp_strong:
        return ("VP", "modifies/writes/deletes local files or config")
    if has_vp_catchall:
        return ("VP", "modifies local browser/device/sandbox state (catchall)")
    if _W020_FP_READONLY.search(ev):
        return ("FP", "read-only operation, no local destruction")
    return ("UNCERTAIN", "no clear local-destructive signal")


# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

# Registry post-merge (struttura unificata):
# - E001 / W015: file raw mergiati (GitHub+NPX); classifier processa solo _origin=npx
# - W001 / W016: solo raw .json mergiati, NO analysis (esclusi dal registry)
# - W017_npx .. W020_npx: NPX-only, rinominati con suffisso _npx
CATEGORIES = {
    "E001":     {"level": "tool-level",   "kind": "tool",   "classify": classify_E001, "subdir": "E001",     "filename": "E001.json"},
    "W015":     {"level": "server-level", "kind": "server", "classify": classify_W015, "subdir": "W015",     "filename": "W015.json"},
    "W017_npx": {"level": "server-level", "kind": "server", "classify": classify_W017, "subdir": "W017_npx", "filename": "W017_npx.json"},
    "W018_npx": {"level": "server-level", "kind": "server", "classify": classify_W018, "subdir": "W018_npx", "filename": "W018_npx.json"},
    "W019_npx": {"level": "server-level", "kind": "server", "classify": classify_W019, "subdir": "W019_npx", "filename": "W019_npx.json"},
    "W020_npx": {"level": "server-level", "kind": "server", "classify": classify_W020, "subdir": "W020_npx", "filename": "W020_npx.json"},
}


def _cache_key(f: dict, kind: str) -> str:
    s = _server_short(f.get("server_url", ""))
    if kind == "tool":
        return f"{s}|{f.get('tool_name','')}"
    return s


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2A: produce 3 bucket
# ══════════════════════════════════════════════════════════════════════════════

def process_category(cat: str) -> dict:
    info = CATEGORIES[cat]
    src_path = HERE / info["level"] / info["filename"]
    subdir = info.get("subdir", cat)
    out_dir = HERE / info["level"] / subdir / "llm_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path = out_dir / "_llm_api_cache.json"

    with io.open(src_path, encoding="utf-8") as fh:
        data = json.load(fh)
    all_findings = data.get("vulnerabilities") or []
    # Per E001/W015 il file è merged GitHub+NPX: classifica solo _origin=npx
    # (i finding GitHub hanno già verdetti Sonnet preservati in cache + vp/fp)
    findings = [f for f in all_findings if f.get("_origin", "npx") == "npx"]
    n_skipped = len(all_findings) - len(findings)
    if n_skipped:
        print(f"  [filter] skipped {n_skipped} _origin=github findings (preserve Sonnet classifications)")

    hc_vp, hc_fp, uncertain = [], [], []
    cache: dict = {}
    for f in findings:
        verdict, reason = info["classify"](f)
        rec = dict(f, _hc_verdict=verdict, _hc_reason=reason)
        key = _cache_key(f, info["kind"])
        if verdict == "VP":
            hc_vp.append(rec)
            cache[key] = {"verdict": "VP", "reason": f"stage2A: {reason}"}
        elif verdict == "FP":
            hc_fp.append(rec)
            cache[key] = {"verdict": "FP", "reason": f"stage2A: {reason}"}
        else:
            uncertain.append(rec)
            # NON aggiungere a cache: lasciato a Stage 2B

    def dump(name, items):
        with io.open(out_dir / name, "w", encoding="utf-8") as fh:
            json.dump({"category": cat, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    dump("hc_vp.json", hc_vp)
    dump("hc_fp.json", hc_fp)
    dump("uncertain.json", uncertain)

    # Scrivi cache (solo verdetti Stage 2A — Stage 2B aggiungerà i residui)
    with io.open(cache_path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)

    tot = len(findings)
    pct_unc = (len(uncertain) / tot * 100) if tot else 0
    print(f"  [{cat:5s}] total={tot:5d}  hc_vp={len(hc_vp):5d}  hc_fp={len(hc_fp):5d}  "
          f"uncertain={len(uncertain):5d}  ({pct_unc:.1f}%)")
    return {"total": tot, "vp": len(hc_vp), "fp": len(hc_fp), "uncertain": len(uncertain)}


def main() -> None:
    print("=" * 80)
    print("Stage 2A: classificatore HC NPX mcp-scan (3-bucket)")
    print("=" * 80)
    totals = {"total": 0, "vp": 0, "fp": 0, "uncertain": 0}
    for cat in CATEGORIES:
        r = process_category(cat)
        for k, v in r.items():
            totals[k] += v
    print("-" * 80)
    pct_unc = totals["uncertain"] / max(totals["total"], 1) * 100
    print(f"  TOTALE: {totals['total']:5d}  hc_vp={totals['vp']:5d}  hc_fp={totals['fp']:5d}  "
          f"uncertain={totals['uncertain']:5d}  ({pct_unc:.1f}%)")
    print("\nProssimo step: classificare uncertain.json in-chat (Sonnet) -> _llm_api_cache.json")


if __name__ == "__main__":
    main()
