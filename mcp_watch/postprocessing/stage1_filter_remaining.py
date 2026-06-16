"""
Stage 1 filter for the 4 mcp-watch categories not covered by filter_all_categories.py:

  1. tool-poisoning         (HIDDEN_TOOL_INSTRUCTIONS only, DECEPTIVE_TOOL_NAMING ignored)
  2. prompt-injection       (TOOL_DESCRIPTION_INJECTION only, RETRIEVAL_AGENT_DECEPTION ignored)
  3. tool-mutation          (DYNAMIC_TOOL_MUTATION only, TOOL_NAME_COLLISION ignored)
  4. access-control         (EXCESSIVE_PERMISSIONS only, CONSENT_FATIGUE_RISK ignored)

All these scanners produce massive false-positive noise due to over-broad regex rules. The
filter here is a WHITELIST: only findings matching hand-picked "high risk" patterns survive.

Usage:
  python -X utf8 filter_remaining_categories.py
  python -X utf8 filter_remaining_categories.py --category tool-poisoning

Output: <cat>/filtered/<cat>_filtered.json

Rationale: almost all surviving findings still end up as FP at Stage 2 (HC rules), but
the explicit filter makes the pipeline uniform with the other 5 categories.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPT_DIR = Path(__file__).resolve().parent


# ══════════════════════════════════════════════════════════════════════════════
#  COMMON: path classifiers
# ══════════════════════════════════════════════════════════════════════════════

_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|e2e)(?:/|$)|"
    r"(?:[._-])(?:test|spec)\.(?:ts|tsx|js|jsx|mjs|cjs|py)$|"
    r"conftest\.py$",
    re.IGNORECASE,
)
_THIRD_PARTY_PATH = re.compile(
    r"/node_modules/|/venv/|/\.venv/|/env/lib/|/site-packages/|/vendor/|"
    r"/medenv/|/menv/|/dist/|/build/|/out/|"
    r"/\.next/|/\.nuxt/|/\.svelte-kit/|"
    r"\.min\.(?:js|css)$|\.bundle\.(?:js|css)$",
    re.IGNORECASE,
)
_DOC_PATH = re.compile(
    r"\.(?:md|mdx|rst|txt|adoc)$|"
    r"(?:^|/)(?:docs?|examples?|samples?|guides?|plans?|tutorials?|recipes?|cookbook|rfcs?)/",
    re.IGNORECASE,
)
# Files clearly designed as intentional vulnerabilities / test fixtures
_INTENTIONAL_VULN_PATH = re.compile(
    r"bad_mcps/|"
    r"(?:^|/)(?:vuln|vulnerable|attack|injection|poison|malicious)[-_][a-z]+/|"
    r"inject[_-]bender|"
    r"honeymcp|"
    r"(?:^|/)injection-dataset",
    re.IGNORECASE,
)

# Security scanners / pattern databases — servers that intentionally contain
# injection strings in data, scripts, README, or tests because that IS their
# product. Any match is definitionally FP.
_SECURITY_SCANNER_SERVERS = {
    "vulnicheck",
    "agentshield", "AgentShield", "ZugaShield",
    "mcp-scanner", "mcpscanner",
    "mcpscc",
    "MCP-Security-Agent",
    "MUSUBIX",
    "wundr",
    "tool-scan",
    "openapi-directory-mcp",
    "bellwether",
    "mcp-preflight",
    "mighty-security",
    "mcp-inject-bender",
    "secure-mcp-gateway",
    "ranavibe",
    "valora.ai",
    "agentscore-mcp",
    "agent-security-scanner-mcp",
    "agentic-deployment-engine",
    "mpak",
    "astrbot",
    "claude-flow",
    "MCP-allthetools", "mcp-allthetools",
    "mcp-server-all",
    "skill-scanner",
    "community-rules",
    "HoneyMCP",
    "aws-pentest-mcp",
    "Shrike-Security", "shrike-mcp",
    "IMCP",
}

# LLM model catalog files — these contain model descriptions that legitimately
# mention roleplay, jailbreak finetunes, etc. as metadata, not as injections.
_MODEL_CATALOG_PATH = re.compile(
    r"(?:^|/)(?:models?|modelList|model-list|model_list)\.(?:js|ts|mjs|json|py)$|"
    r"/language-models?/|/llm-models?/",
    re.IGNORECASE,
)


def path_is_noise(path: str) -> str | None:
    """Return a rejection reason if the path matches known noise, else None."""
    if not path:
        return None
    p = path.replace("\\", "/")
    if _THIRD_PARTY_PATH.search(p):
        return "third_party"
    if _TEST_PATH.search(p):
        return "test_fixture"
    if _DOC_PATH.search(p):
        return "documentation"
    if _INTENTIONAL_VULN_PATH.search(p):
        return "intentional_vuln_path"
    return None


def is_valid_finding(finding: dict) -> bool:
    vid = finding.get("id", "")
    return isinstance(vid, str) and 0 < len(vid) < 50 and vid.isupper() and "_" in vid


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY 1: tool-poisoning / HIDDEN_TOOL_INSTRUCTIONS
# ══════════════════════════════════════════════════════════════════════════════

_TP_ACT_AS_ONLY = re.compile(r"act\s+as\s+(?:a|an|if|the)\b", re.I)
_TP_INJECTION_STRONG = re.compile(
    r"ignore\s+(previous|all|above|prior)\s+(instructions?|commands?|prompts?)|"
    r"system\s*:\s*you\s+are\s+now|"
    r"forget\s+(everything|all|previous|prior)",
    re.I,
)
_TP_SYSTEM_BRACKETS = re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[JAILBREAK\]", re.I)
# `# type: ignore[override]` mypy annotation matches the [OVERRIDE] regex
_TP_MYPY_IGNORE = re.compile(r"#\s*type:\s*ignore\[override\]")
# `[Admin]` / `[System]` as human-readable tool label prefix (not injection)
_TP_ADMIN_LABEL = re.compile(
    r'(?:description\s*[:=]\s*[\'"`])\s*\[(?:Admin|ADMIN|System|SYSTEM)\]\s+(?:[A-Z]|\w)',
    re.IGNORECASE,
)


def filter_tool_poisoning(f: dict) -> tuple[bool, str]:
    """HIDDEN_TOOL_INSTRUCTIONS — almost entirely FP by design of scanner."""
    if f.get("id") != "HIDDEN_TOOL_INSTRUCTIONS":
        return False, "not_hidden_tool_instructions"

    path = f.get("file", "") or ""
    ev = f.get("evidence", "") or ""
    sname = f.get("server_name", "") or ""

    if _TP_MYPY_IGNORE.search(ev):
        return False, "mypy_type_ignore_override"

    reason = path_is_noise(path)
    if reason:
        return False, reason

    if sname in _SECURITY_SCANNER_SERVERS:
        return False, "security_scanner_server"

    # "act as a/if" only → English phrase, not injection
    if _TP_ACT_AS_ONLY.search(ev) and not (
        _TP_INJECTION_STRONG.search(ev) or _TP_SYSTEM_BRACKETS.search(ev)
    ):
        return False, "act_as_english_phrase"

    # [ADMIN]/[SYSTEM] as tool label prefix in real description (not payload)
    if _TP_SYSTEM_BRACKETS.search(ev) and _TP_ADMIN_LABEL.search(ev):
        return False, "admin_label_prefix"

    return True, "kept"


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY 2: prompt-injection / TOOL_DESCRIPTION_INJECTION
# ══════════════════════════════════════════════════════════════════════════════

_PI_SIMULATE_ACT_AS = re.compile(
    r"simulate\s+(?:being|a)|act\s+as\s+(?:a|an|if|the)\b|pretend\s+(?:that|you)",
    re.I,
)
_PI_INJECTION_STRONG = re.compile(
    r"ignore\s+(previous|above|all|prior)\s+(instructions?|commands?|prompts?)|"
    r"forget\s+(everything|all|previous|prior)|"
    r"you\s+are\s+now\s+(?:a|an|my)|"
    r"disregard\s+(?:the|any|all)|"
    r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[JAILBREAK\]",
    re.I,
)
# role-related keyword: "new role" in DB/API schemas
_PI_NEW_ROLE_BENIGN = re.compile(
    r'description\s*[:=]\s*[\'"`]?\s*[\'"`]?\s*New\s+role\s*:\s*[\'"`]?(?:admin|user|editor|viewer|member|guest)',
    re.I,
)
# "simulate a transaction/click/key press" — wallet/UI simulator tool description
_PI_SIMULATE_BENIGN = re.compile(
    r"simulate\s+a\s+(?:transaction|transfer|swap|mint|burn|stake|"
    r"key\s+press|click|mouse|keyboard|"
    r"description|database|query|request|response|api|message|"
    r"switch|network|hub|router|port|device|session|connection|"
    r"function|tool|user|environment|operation|event|call|"
    r"battle|game|scenario|webhook|webhook|timeout|error|failure|build)",
    re.I,
)


def filter_prompt_injection(f: dict) -> tuple[bool, str]:
    """TOOL_DESCRIPTION_INJECTION — nearly all FP."""
    if f.get("id") != "TOOL_DESCRIPTION_INJECTION":
        return False, "not_tool_description_injection"

    path = f.get("file", "") or ""
    ev = f.get("evidence", "") or ""
    sname = f.get("server_name", "") or ""

    reason = path_is_noise(path)
    if reason:
        return False, reason

    if sname in _SECURITY_SCANNER_SERVERS:
        return False, "security_scanner_server"

    if _MODEL_CATALOG_PATH.search(path.replace("\\", "/")):
        return False, "llm_model_catalog"

    # "New role: admin/user/editor" — obvious DB/API schema, not injection
    if _PI_NEW_ROLE_BENIGN.search(ev):
        return False, "db_role_enum_schema"

    # "simulate a transaction/click/key press" → benign tool description
    if _PI_SIMULATE_BENIGN.search(ev) and not _PI_INJECTION_STRONG.search(ev):
        return False, "simulate_benign_action"

    # Only act_as / simulate / pretend trigger + no strong injection → benign
    if _PI_SIMULATE_ACT_AS.search(ev) and not _PI_INJECTION_STRONG.search(ev):
        return False, "act_as_simulate_english"

    # [ADMIN]/[SYSTEM] as label prefix
    if _TP_SYSTEM_BRACKETS.search(ev) and _TP_ADMIN_LABEL.search(ev):
        return False, "admin_label_prefix"

    # type: ignore[override]
    if _TP_MYPY_IGNORE.search(ev):
        return False, "mypy_type_ignore_override"

    return True, "kept"


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY 3: tool-mutation / DYNAMIC_TOOL_MUTATION
# ══════════════════════════════════════════════════════════════════════════════

# Runtime mutation context indicators: push/splice inside event handlers,
# setInterval/setTimeout, after server.connect, onMessage handlers. These are
# the ONLY contexts where rug-pull actually happens.
_TM_RUNTIME_INDICATORS = re.compile(
    r"setInterval|setTimeout|setImmediate|"
    r"on[A-Z]\w+\s*:\s*(?:async\s+)?\(|"
    r"addEventListener|\.on\s*\(\s*['\"`]message['\"`]|"
    r"process\.on\s*\(|socket\.on\s*\(|"
    r"after\s*server\.connect|after\s+initialization|"
    r"runtime\s+modif|dynamic\s+update|hot[_-]?reload|"
    r"await\s+pollForUpdates|pollMutation",
    re.I,
)
# Clear init / register / setup contexts → benign push
_TM_INIT_CONTEXTS = re.compile(
    r"(?:init(?:ialize|ialization)?|register|setup|configure|create|add|load|build|list)[_-]?(?:tools?|plugins?|handlers?|registry)|"
    r"for\s+(?:const|let|var)?\s*\w+\s+of\s+|"
    r"forEach\s*\(|"
    r"\.map\s*\(|\.reduce\s*\(|\.filter\s*\(",
    re.I,
)
_TM_ASSIGNMENT_IDX = re.compile(r"tools?\[[^\]]+\]\s*=")
_TM_PUSH_OPS = re.compile(r"\btools?\.(push|splice|pop|shift|unshift)\b")


def filter_tool_mutation(f: dict) -> tuple[bool, str]:
    """DYNAMIC_TOOL_MUTATION — huge noise due to any tools.push()."""
    if f.get("id") != "DYNAMIC_TOOL_MUTATION":
        return False, "not_dynamic_tool_mutation"

    path = f.get("file", "") or ""
    ev = f.get("evidence", "") or ""

    reason = path_is_noise(path)
    if reason:
        return False, reason

    # Comparison/equality checks (not mutation)
    if re.search(r"tool\[\w+\]\s*==", ev) or re.search(r"tools?\[\d+\]\[", ev):
        return False, "equality_or_index_read"

    # Explicit init/register/load contexts are benign
    if _TM_INIT_CONTEXTS.search(ev):
        return False, "init_or_register_context"

    # Variable name ending with "Tools" / "tools" in assignment (typically array building)
    # e.g. "categoriesTools[category].push(tool)"
    if re.search(r"\w+(?:Tools|_tools)\[[^\]]*\]\s*\.push\b", ev):
        return False, "category_buckets_build"

    # Only keep if the line shows a runtime indicator OR index assignment to tools[]
    has_push = bool(_TM_PUSH_OPS.search(ev))
    has_assign = bool(_TM_ASSIGNMENT_IDX.search(ev))
    has_runtime = bool(_TM_RUNTIME_INDICATORS.search(ev))

    if has_runtime and (has_push or has_assign):
        return True, "runtime_mutation_indicator"

    if has_assign:
        # tools["x"] = ... is potentially suspicious; keep for HC to decide
        return True, "tools_index_assignment"

    # All other push/splice in init code → FP
    return False, "benign_array_push"


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY 4: access-control / EXCESSIVE_PERMISSIONS
# ══════════════════════════════════════════════════════════════════════════════

# WHITELIST: only these patterns indicate real privilege escalation / over-permission.
_AC_HIGH_VALUE_PATS = [
    (re.compile(r'"Action"\s*:\s*"\*"'),                     "iam_wildcard_action"),
    (re.compile(r'"Resource"\s*:\s*"\*"'),                   "iam_wildcard_resource"),
    (re.compile(r'\bUSER\s+root\b'),                          "dockerfile_user_root"),
    (re.compile(r'\bchmod\s+777\b'),                          "chmod_777"),
    (re.compile(r'\bchown\s+root\b'),                         "chown_root"),
    (re.compile(r'privileged\s*:\s*true', re.I),              "k8s_privileged_true"),
    (re.compile(r'hostNetwork\s*:\s*true', re.I),             "k8s_host_network"),
    (re.compile(r'hostPID\s*:\s*true', re.I),                 "k8s_host_pid"),
    (re.compile(r'runAsUser\s*:\s*0\b'),                      "k8s_run_as_root"),
    (re.compile(r'allowPrivilegeEscalation\s*:\s*true', re.I), "k8s_privilege_escalation"),
    (re.compile(r'verbs\s*:\s*\[\s*["\']\*["\']\s*\]'),       "k8s_wildcard_verbs"),
    (re.compile(r'resources\s*:\s*\[\s*["\']\*["\']\s*\]'),   "k8s_wildcard_resources"),
    (re.compile(r'\bAdministratorAccess\b'),                  "iam_administrator_access"),
    (re.compile(r'\bPowerUserAccess\b'),                      "iam_power_user_access"),
    (re.compile(r'GRANT\s+ALL\s+PRIVILEGES', re.I),           "sql_grant_all_privileges"),
    (re.compile(r'GRANT\s+ALL\s+ON', re.I),                   "sql_grant_all_on"),
    (re.compile(r'\b--privileged\b'),                         "docker_privileged_flag"),
    (re.compile(r'capabilities?\s*:\s*(?:add|all|\{).*SYS_ADMIN|CAP_SYS_ADMIN'), "linux_cap_sys_admin"),
]


def filter_access_control(f: dict) -> tuple[bool, str]:
    """EXCESSIVE_PERMISSIONS — whitelist only real over-permission patterns."""
    if f.get("id") != "EXCESSIVE_PERMISSIONS":
        return False, "not_excessive_permissions"

    path = f.get("file", "") or ""
    ev = f.get("evidence", "") or ""

    reason = path_is_noise(path)
    if reason:
        return False, reason

    # Comments / print strings / logs
    ev_stripped = ev.lstrip()
    if ev_stripped.startswith(("#", "//", "/*", "*", ">>>", "--")):
        return False, "comment_or_repl"

    # Security tools that scan for / describe these patterns
    if re.search(r"CommandPattern\s*\(|pattern\s*=\s*r?[\'\"]", ev):
        return False, "pattern_definition_not_usage"

    # Error message strings
    if re.search(r'(?:error|warning|info|describe|example|log|msg|message)\s*[:=]\s*[\'"]', ev, re.I):
        # Keep only if a high-value pattern sits OUTSIDE the string value
        pass

    for pat, name in _AC_HIGH_VALUE_PATS:
        if pat.search(ev):
            return True, f"high_value:{name}"

    return False, "no_high_value_pattern"


# ══════════════════════════════════════════════════════════════════════════════
#  DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

CATEGORY_CONFIG = {
    "tool-poisoning": {
        "filter_fn": filter_tool_poisoning,
        "source_files": ["tool_poisoning_critical.json", "tool_poisoning_high.json"],
        "target_id": "HIDDEN_TOOL_INSTRUCTIONS",
    },
    "prompt-injection": {
        "filter_fn": filter_prompt_injection,
        "source_files": ["prompt_injection_high.json"],
        "target_id": "TOOL_DESCRIPTION_INJECTION",
    },
    "tool-mutation": {
        "filter_fn": filter_tool_mutation,
        "source_files": ["tool_mutation_high.json"],
        "target_id": "DYNAMIC_TOOL_MUTATION",
    },
    "access-control": {
        "filter_fn": filter_access_control,
        "source_files": ["access_control_high.json"],
        "target_id": "EXCESSIVE_PERMISSIONS",
    },
}


def process_category(base_dir: Path, category: str, cfg: dict) -> dict:
    cat_dir = base_dir / category
    if not cat_dir.exists():
        print(f"  [SKIP] {category}/ not found")
        return {}

    filter_fn = cfg["filter_fn"]
    target_id = cfg["target_id"]

    all_kept = []
    stats_by_id = defaultdict(lambda: {"original": 0, "kept": 0, "rejected": 0,
                                        "reject_reasons": Counter()})
    total_original = 0
    total_kept = 0

    for fname in cfg["source_files"]:
        jf = cat_dir / fname
        if not jf.exists():
            continue

        print(f"  Processing {fname}...")
        with io.open(jf, encoding="utf-8") as fh:
            data = json.load(fh)

        for finding in data.get("findings", []):
            if not is_valid_finding(finding):
                continue
            if finding.get("id") != target_id:
                continue

            vid = finding["id"]
            stats_by_id[vid]["original"] += 1
            total_original += 1

            keep, reason = filter_fn(finding)
            if keep:
                finding["filter_confidence"] = reason
                all_kept.append(finding)
                stats_by_id[vid]["kept"] += 1
                total_kept += 1
            else:
                stats_by_id[vid]["rejected"] += 1
                stats_by_id[vid]["reject_reasons"][reason] += 1

    filtered_dir = cat_dir / "filtered"
    filtered_dir.mkdir(exist_ok=True)

    out_file = filtered_dir / f"{category.replace('-', '_')}_filtered.json"
    output_data = {
        "category": category,
        "filter": "remaining_categories_whitelist",
        "filtered_at": datetime.now(timezone.utc).isoformat(),
        "original_total": total_original,
        "kept_total": total_kept,
        "rejection_rate": f"{((total_original - total_kept) / total_original * 100) if total_original else 0:.1f}%",
        "findings": all_kept,
    }
    with io.open(out_file, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2, ensure_ascii=False)

    stats_file = filtered_dir / f"{category.replace('-', '_')}_filter_stats.json"
    stats_data = {
        "category": category,
        "filtered_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "original": total_original,
            "kept": total_kept,
            "rejected": total_original - total_kept,
        },
        "by_vulnerability_id": {
            vid: {
                "original": info["original"],
                "kept": info["kept"],
                "rejected": info["rejected"],
                "top_reject_reasons": dict(info["reject_reasons"].most_common(15)),
            }
            for vid, info in sorted(stats_by_id.items())
        },
    }
    with io.open(stats_file, "w", encoding="utf-8") as fh:
        json.dump(stats_data, fh, indent=2, ensure_ascii=False)

    print(f"    -> {total_kept:,} kept / {total_original:,} original")
    return {"category": category, "original": total_original, "kept": total_kept}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", type=Path, default=SCRIPT_DIR)
    ap.add_argument("--category", default="all",
                    choices=list(CATEGORY_CONFIG) + ["all"])
    args = ap.parse_args()

    base = args.input
    cats = list(CATEGORY_CONFIG) if args.category == "all" else [args.category]

    print("=" * 70)
    print("MCP-Watch: Remaining-Categories Stage 1 Filter")
    print("=" * 70)

    results = []
    for cat in cats:
        print(f"\n-- {cat} --")
        r = process_category(base, cat, CATEGORY_CONFIG[cat])
        if r:
            results.append(r)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for r in results:
        pct = (r["original"] - r["kept"]) / r["original"] * 100 if r["original"] else 0
        print(f"  {r['category']:25s} {r['kept']:>7,} kept / {r['original']:>9,} ({pct:.1f}% rejected)")


if __name__ == "__main__":
    main()
