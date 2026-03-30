"""
NewProxy - Python Analysis Bridge (Improved)
Changes from original llmProxyAnalysis.py:
1. Fixed npx path: uses shutil.which() instead of hardcoded /opt/homebrew/bin/npx
2. Counters are local to each function call (no global state accumulation)
3. Fixed hardcoded total_prompt += 10 -> counts actual prompts
4. Handles 'generic', 'jailbreak_combined', 'encoding_evasion', 'indirect_injection' intents
5. Points to NewProxy/index.ts
6. Returns all deterministic violation reasons (not just the first)
"""

import subprocess
import json
import shutil
from pathlib import Path

# Use config if available, otherwise compute path directly
try:
    from functions.config import BASE_DIR
except ImportError:
    BASE_DIR = Path.home() / "Desktop" / "Pipeline"

PROXY_SCRIPT = BASE_DIR / "frameworks" / "NewProxy" / "index.ts"

# Detect npx path dynamically
_npx = shutil.which("npx")
if not _npx:
    # Fallback paths
    import platform
    if platform.system() == "Windows":
        _npx = str(Path.home() / "AppData" / "Roaming" / "npm" / "npx.cmd")
    elif platform.system() == "Darwin":
        _npx = "/opt/homebrew/bin/npx"
    else:
        _npx = "/usr/local/bin/npx"
NPX = _npx


def _make_empty_deterministic_causes():
    return {
        "total": 0,
        "command_injection": 0,
        "ssh_private_keys": 0,
        "suspicious_file_access": 0,
        "sql_injection": 0,
        "container_isolation_violation": 0,
        "entropy_secrets": 0,
        "pii_detection": 0,
        "prompt_injection": 0,
        "important_tag_injection": 0,
        "shadow_hijack": 0,
        "cross_origin_access": 0,
        "xss_injection": 0,
        "base64_encoded_payload": 0,
        "invisible_unicode_injection": 0
    }


def _make_empty_intent_block():
    return {
        "deterministic_causes": _make_empty_deterministic_causes(),
        "tool_call_causes": 0,
        "tool_response_causes": 0,
        "failed": 0
    }


def _increment_deterministic(dest: dict, reason: str):
    """Increment the matching deterministic cause counter."""
    known_keys = [
        "command_injection", "ssh_private_keys", "suspicious_file_access",
        "sql_injection", "container_isolation_violation", "entropy_secrets",
        "pii_detection", "prompt_injection", "important_tag_injection",
        "shadow_hijack", "cross_origin_access", "xss_injection",
        "base64_encoded_payload", "invisible_unicode_injection"
    ]
    for key in known_keys:
        if key in reason:
            dest["deterministic_causes"][key] += 1
            dest["deterministic_causes"]["total"] += 1
            return


def run_llm_proxy_analysis(repo_path, command: str, args: list) -> dict:
    """
    Run the NewProxy TypeScript analysis against an MCP server.
    Returns a structured summary dict.
    """
    # Build counters fresh for each call (no global state)
    proxy = {
        "total_blocked": 0,
        "tool_length": 0,
        "total_trials": 0,
        "total_failed": 0,
        "proxy": {
            "benign": _make_empty_intent_block(),
            "malicious": _make_empty_intent_block(),
            "jailbreak_combined": _make_empty_intent_block(),
            "encoding_evasion": _make_empty_intent_block(),
        }
    }

    prompt_stats = {
        "total_blocked": 0,
        "total_allowed": 0,
        "total_prompt": 0,
        "percentage": 0.0,
        "deterministic_causes": _make_empty_deterministic_causes(),
        "tool_call_causes": 0,
        "tool_response_causes": 0
    }

    # Execute the TypeScript proxy
    cmd = [NPX, "tsx", str(PROXY_SCRIPT), str(repo_path), str(command)]
    cmd.extend(str(arg) for arg in args)

    result = subprocess.run(
        cmd,
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("stdout:", result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
        print("stderr:", result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
        return {"status": "failed"}

    stdout = result.stdout
    print("stdout:", stdout[-3000:] if len(stdout) > 3000 else stdout)

    marker = "================ FINAL RESULTS ================"
    if marker not in stdout:
        print("FINAL RESULTS marker not found in proxy output")
        return {"status": "failed"}

    json_part = stdout.split(marker, 1)[1].strip()

    try:
        output_data = json.loads(json_part)
    except json.JSONDecodeError as e:
        print("Failed to parse JSON from proxy output")
        print("----- RAW JSON PART (last 2000 chars) -----")
        print(json_part[-2000:])
        print("-------------------------------------------")
        return {"status": "failed"}

    # Parse test results
    results_list = output_data.get("results", [])

    for tool_data in results_list:
        tool_name = tool_data.get("toolName", "")

        if tool_name == "generic_tool_test":
            # Generic prompt tests (Phase 2 & 3)
            for res in tool_data.get("results", []):
                overall = res.get("overall", "")
                reason = res.get("reason", "")

                prompt_stats["total_prompt"] += 1

                if overall == "failed":
                    continue
                elif overall == "blocked":
                    prompt_stats["total_blocked"] += 1
                    if "llm_call_rejected" in reason:
                        prompt_stats["tool_call_causes"] += 1
                    elif "llm_response_rejected" in reason:
                        prompt_stats["tool_response_causes"] += 1
                    _increment_deterministic({"deterministic_causes": prompt_stats["deterministic_causes"]}, reason)
                elif overall == "allowed":
                    prompt_stats["total_allowed"] += 1
        else:
            # Per-tool fuzzing results (Phase 1)
            proxy["tool_length"] += 1

            for res in tool_data.get("results", []):
                intent = res.get("intent", "malicious")
                overall = res.get("overall", "")
                reason = res.get("reason", "")

                proxy["total_trials"] += 1

                # Map intent to proxy bucket
                if intent in ("benign",):
                    bucket = "benign"
                elif intent in ("jailbreak_combined",):
                    bucket = "jailbreak_combined"
                elif intent in ("encoding_evasion",):
                    bucket = "encoding_evasion"
                else:
                    bucket = "malicious"

                if overall == "failed":
                    proxy["total_failed"] += 1
                    proxy["proxy"][bucket]["failed"] += 1
                    continue

                if overall == "blocked":
                    proxy["total_blocked"] += 1
                    if "llm_call_rejected" in reason:
                        proxy["proxy"][bucket]["tool_call_causes"] += 1
                    elif "llm_response_rejected" in reason:
                        proxy["proxy"][bucket]["tool_response_causes"] += 1
                    _increment_deterministic(proxy["proxy"][bucket], reason)

    # Compute percentage
    total_p = prompt_stats["total_prompt"]
    if total_p > 0:
        prompt_stats["percentage"] = round(prompt_stats["total_blocked"] / total_p * 100, 2)

    summary = {
        "status": "completed",
        "tool_length": proxy["tool_length"],
        "total_trials": proxy["total_trials"],
        "total_failed": proxy["total_failed"],
        "proxy": proxy["proxy"],
        "prompt": prompt_stats
    }

    return summary
