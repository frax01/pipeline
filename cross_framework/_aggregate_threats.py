#!/usr/bin/env python3
"""Aggrega VP per threat type cross-framework."""
import json
import sys
from pathlib import Path
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
BASE = Path(__file__).parent
# Dopo il merge per-tool i dati stanno in <repo>/*/postprocessing/...: la root e' il parent.
REPO = BASE.parent

# Map (framework, category) → threat type
THREAT_MAP = {
    # Command Injection
    ("mcp-guard", "command-injection-static"): "command-injection",
    ("mcp-guard", "command-injection-fuzzing"): "command-injection",
    ("mcp-guard", "command-execution-fuzzing"): "command-injection",
    # Code Injection
    ("mcp-guard", "code-injection-static"): "code-injection",
    ("mcp-guard", "code-injection-fuzzing"): "code-injection",
    # Input Validation generic (mcp-watch + mcp-security-scan covers SSRF/CMD/PATH)
    ("mcp-watch", "input-validation"): "input-validation-mixed",
    ("mcp-security-scan", "input-validation"): "input-validation-mixed",
    # SQL Injection
    ("mcp-guard", "sql-injection-static"): "sql-injection",
    # Path Traversal
    ("mcp-guard", "path-traversal-static"): "path-traversal",
    ("mcp-guard", "path-traversal-fuzzing"): "path-traversal",
    ("mcp-guard", "protocol-path-traversal"): "path-traversal",
    ("mcp-security-scan", "path-traversal"): "path-traversal",
    # SSRF
    ("mcp-guard", "ssrf-static"): "ssrf",
    # Credential Leak
    ("mcp-guard", "hardcoded-credential-static"): "credential-leak",
    ("mcp-watch", "credential-leak"): "credential-leak",
    # Sensitive Info Disclosure
    ("mcp-guard", "sensitive-info-disclosed-fuzzing"): "sensitive-info-disclosure",
    ("mcp-guard", "information-disclosure-fuzzing"): "sensitive-info-disclosure",
    ("mcp-guard", "protocol-information-disclosure"): "sensitive-info-disclosure",
    ("mcp-security-scan", "sensitive-resource-exposure"): "sensitive-info-disclosure",
    # Data Exfiltration
    ("mcp-watch", "data-exfiltration"): "data-exfiltration",
    ("mcp-security-scan", "data-leak"): "data-exfiltration",
    # Prompt Injection / Tool Poisoning
    ("mcp-guard", "prompt-injection-static"): "prompt-injection",
    ("mcp-watch", "prompt-injection"): "prompt-injection",
    ("mcp-watch", "tool-poisoning"): "prompt-injection",
    ("mcp-shield", "hidden-instructions"): "prompt-injection",
    ("mcp-scan", "tool-level"): "prompt-injection",
    ("mcp-security-scan", "prompt-injection"): "prompt-injection",
    ("mcp-security-scan", "indirect-prompt-injection"): "prompt-injection",
    # Tool Shadowing
    ("mcp-shield", "shadowing-detected"): "tool-shadowing",
    # Insecure Deserialization
    ("mcp-guard", "insecure-deserialization-static"): "insecure-deserialization",
    # Dangerous Capabilities
    ("mcp-guard", "dangerous-tool-handler-static"): "dangerous-capabilities",
    ("mcp-security-scan", "dangerous-capabilities"): "dangerous-capabilities",
    # Sensitive File Access
    ("mcp-shield", "sensitive-file-access"): "sensitive-file-access",
    ("mcp-security-scan", "sensitive-file-access"): "sensitive-file-access",
    # Tool Mutation / Rug Pull
    ("mcp-watch", "tool-mutation"): "tool-mutation",
    ("mcp-security-scan", "rug-pull"): "tool-mutation",
    # Steganographic
    ("mcp-watch", "steganographic-attack"): "steganographic-attack",
    # Access Control
    ("mcp-watch", "access-control"): "access-control",
    ("mcp-security-scan", "remote-access-control"): "access-control",
    # Untrusted Content
    ("mcp-scan", "server-level"): "untrusted-content",
    # Protocol Violation (real security)
    ("mcp-guard", "protocol-invalid-jsonrpc-version"): "protocol-violation",
    ("mcp-guard", "protocol-missing-id"): "protocol-violation",
    ("mcp-watch", "protocol-violation"): "protocol-violation",
    ("tool_fuzzing", "protocol-fuzzing"): "protocol-violation",
    # Server Crash / Resilience
    ("mcp-check", "tool_invocation/panic_or_crash"): "server-crash",
    ("tool_fuzzing", "server-crash-fuzzing"): "server-crash",
    # Auth Issues
    ("mcp-check", "handshake/unauthorized_or_auth_missing"): "auth-issues",
    ("mcp-check", "tool_invocation/unauthorized_or_auth_missing"): "auth-issues",
    # Protocol Compliance (mcp-check rest)
    ("mcp-check", "handshake/schema_violation"): "protocol-compliance",
    ("mcp-check", "handshake/other_errors"): "protocol-compliance",
    ("mcp-check", "handshake/method_not_found"): "protocol-compliance",
    ("mcp-check", "handshake/invalid_arguments"): "protocol-compliance",
    ("mcp-check", "tool_discovery/schema_violation"): "protocol-compliance",
    ("mcp-check", "tool_discovery/other_errors"): "protocol-compliance",
    ("mcp-check", "tool_discovery/method_not_found"): "protocol-compliance",
    ("mcp-check", "tool_discovery/warnings"): "protocol-compliance",
    ("mcp-check", "tool_invocation/schema_violation"): "protocol-compliance",
    ("mcp-check", "tool_invocation/other_errors"): "protocol-compliance",
    ("mcp-check", "tool_invocation/method_not_found"): "protocol-compliance",
    ("mcp-check", "tool_invocation/invalid_arguments"): "protocol-compliance",
    ("mcp-check", "tool_invocation/warnings"): "protocol-compliance",
}

FRAMEWORK_DIRS = {
    "mcp_guard": "mcp-guard",
    "mcp_watch": "mcp-watch",
    "mcp_scan": "mcp-scan",
    "mcp_shield": "mcp-shield",
    "mcp_security_scan": "mcp-security-scan",
    "mcp_check": "mcp-check",
    "fuzzing": "tool_fuzzing",
}


def get_fw_cat(path):
    parts = list(path.parts)
    fw = None
    fw_idx = -1
    for i, p in enumerate(parts):
        if p in FRAMEWORK_DIRS:
            fw = FRAMEWORK_DIRS[p]
            fw_idx = i
            break
    if not fw:
        return None, "?"
    # salta il livello 'analysis/' introdotto dal merge per-tool
    start = fw_idx + 1
    if start < len(parts) and parts[start] == "postprocessing":
        start += 1
    # Try with 'filtered' separator
    try:
        fidx = parts.index("filtered", fw_idx)
        cat = "/".join(parts[start:fidx])
        return fw, cat
    except ValueError:
        pass
    # Fallback: 'llm_analysis' separator (mcp-shield)
    try:
        lidx = parts.index("llm_analysis", fw_idx)
        cat = "/".join(parts[start:lidx])
        return fw, cat
    except ValueError:
        return fw, "?"


def main():
    threat_counts = defaultdict(lambda: defaultdict(int))
    threat_examples = defaultdict(list)
    threat_servers = defaultdict(set)
    unmapped = defaultdict(int)

    for vp_file in REPO.rglob("vp.json"):
        if "llm_analysis" not in vp_file.parts:
            continue
        fw, cat = get_fw_cat(vp_file)
        if not fw:
            continue
        threat = THREAT_MAP.get((fw, cat))
        if not threat:
            unmapped[(fw, cat)] += 1
            continue
        try:
            with open(vp_file, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        fis = d.get("findings") or d.get("entries") or []
        if not isinstance(fis, list):
            continue
        for fi in fis:
            if not isinstance(fi, dict):
                continue
            server = fi.get("server_url") or fi.get("github_url") or ""
            threat_counts[threat][fw] += 1
            threat_servers[threat].add(server)
            key = (threat, fw)
            if len(threat_examples[key]) < 3:
                ex = {
                    "server_url": server,
                    "tool_name": fi.get("tool_name", "") or fi.get("protocol_type", ""),
                    "file": fi.get("file", ""),
                    "evidence": (fi.get("evidence") or fi.get("description") or fi.get("exception_message") or "")[:250],
                    "reason": fi.get("_hc_reason") or fi.get("_llm_reason") or "-",
                    "category": cat,
                }
                threat_examples[key].append(ex)

    # Save
    out = {
        "threat_counts": {t: dict(fws) for t, fws in threat_counts.items()},
        "threat_examples": {f"{k[0]}|{k[1]}": v for k, v in threat_examples.items()},
        "threat_unique_servers": {t: len(s) for t, s in threat_servers.items()},
        "unmapped": {f"{k[0]}|{k[1]}": v for k, v in unmapped.items()},
    }
    with open(BASE / "_threat_aggregation.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    # Print summary
    print("=== THREAT AGGREGATION ===\n")
    sorted_threats = sorted(threat_counts.items(), key=lambda x: -sum(x[1].values()))
    grand_total = 0
    for threat, fws in sorted_threats:
        total = sum(fws.values())
        grand_total += total
        n_servers = len(threat_servers[threat])
        print(f"\n{threat:30}  TOTAL VP: {total:>6}  unique_servers: {n_servers:>5}")
        for fw, c in sorted(fws.items(), key=lambda x: -x[1]):
            print(f"   {c:>6}  {fw}")
    print(f"\n  GRAND TOTAL VP: {grand_total:,}")

    if unmapped:
        print("\n=== UNMAPPED (skipped) ===")
        for (fw, cat), c in unmapped.items():
            print(f"  {fw} | {cat}")


if __name__ == "__main__":
    main()
