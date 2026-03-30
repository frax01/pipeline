import subprocess
import json
from pathlib import Path
from functions.config import PROXY_SCRIPT

#PROXY_SCRIPT = Path.home() / "Desktop" / "Pipeline" / "llmProxy.ts"

proxy = {
    "total_blocked": 0,
    "tool_length": 0,
    "total_trials": 0,
    "total_failed": 0,
    "proxy": {
        "benign": {
          "deterministic_causes": {
            "total": 0,
            "command_injection": 0,
            "ssh_private_keys": 0,
            "suspicious_file_access": 0,
            "sql_injection": 0,
            "container_isolation_violation": 0,
            "entropy_secrets": 0,
            "pii_detection": 0
          },
          "tool_call_causes": 0,
          "tool_response_causes": 0,
          "failed": 0
        },
        "malicious": {
          "deterministic_causes": {
            "total": 0,
            "command_injection": 0,
            "ssh_private_keys": 0,
            "suspicious_file_access": 0,
            "sql_injection": 0,
            "container_isolation_violation": 0,
            "entropy_secrets": 0,
            "pii_detection": 0
          },
          "tool_call_causes": 0,
          "tool_response_causes": 0,
          "failed": 0
        }
    }
}

prompt = {
    "total_blocked": 0,
    "total_allowed": 0,
    "total_prompt": 0,
    "percentage": 0.0,
    "deterministic_causes": {
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
        "xss_injection": 0
    },
    "tool_call_causes": 0,
    "tool_response_causes": 0
}

def run_llm_proxy_analysis(repo_path: Path, command: str, args: list[str]) -> dict:
    cmd = [
        "/opt/homebrew/bin/npx",
        "ts-node",
        str(PROXY_SCRIPT),
        str(repo_path),
        str(command)
    ]
    cmd.extend(str(arg) for arg in args)
    result = subprocess.run(
        cmd,
        cwd=Path.home() / "Desktop" / "Pipeline",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)
        return {
            "status": "failed"
        }
    full_stdout = result.stdout
    print("stdout:", full_stdout)

    stdout = result.stdout

    marker = "================ FINAL RESULTS ================"

    if marker not in stdout:
        raise RuntimeError("❌ FINAL RESULTS marker not found in proxy output")

    json_part = stdout.split(marker, 1)[1].strip()

    #json_part = result.stdout.strip()

    try:
        llama3_data = json.loads(json_part)
        #print("llama3_data:", llama3_data)
    except json.JSONDecodeError as e:
        print("❌ Failed to parse JSON from proxy output")
        print("----- RAW JSON PART -----")
        print(json_part)
        print("-------------------------")
        raise e

    # llama3_data = lista di tool
    # ===============================
    prompt["total_prompt"] += 10
    for tool in llama3_data:
        if tool["toolName"] == "generic_tool_test":
            results = tool.get("results", [])
            for res in results:
                intent = res.get("intent")
                overall = res.get("overall")
                reason = res.get("reason", "")

                # -----------------------
                # FAILED → non conta come blocked
                # -----------------------
                if overall == "failed":
                    continue

                # -----------------------
                # BLOCKED
                # -----------------------
                if overall == "blocked":
                    prompt["total_blocked"] += 1

                    if "llm_call_rejected" in reason:
                        prompt["tool_call_causes"] += 1
                    elif "llm_response_rejected" in reason:
                        prompt["tool_response_causes"] += 1
                    # deterministic reason
                    if "sql_injection" in reason:
                        prompt["deterministic_causes"]["sql_injection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "command_injection" in reason:
                        prompt["deterministic_causes"]["command_injection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "container_isolation_violation" in reason:
                        prompt["deterministic_causes"]["container_isolation_violation"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "entropy_secrets" in reason:
                        prompt["deterministic_causes"]["entropy_secrets"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "pii_detection" in reason:
                        prompt["deterministic_causes"]["pii_detection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "ssh_private_keys" in reason:
                        prompt["deterministic_causes"]["ssh_private_keys"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "suspicious_file_access" in reason:
                        prompt["deterministic_causes"]["suspicious_file_access"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "prompt_injection" in reason:
                        prompt["deterministic_causes"]["prompt_injection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "important_tag_injection" in reason:
                        prompt["deterministic_causes"]["important_tag_injection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "shadow_hijack" in reason:
                        prompt["deterministic_causes"]["shadow_hijack"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "cross_origin_access" in reason:
                        prompt["deterministic_causes"]["cross_origin_access"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                    elif "xss_injection" in reason:
                        prompt["deterministic_causes"]["xss_injection"] += 1
                        prompt["deterministic_causes"]["total"] += 1
                elif overall == "allowed":
                    prompt["total_allowed"] += 1
        else:
            proxy["tool_length"] += 1

            for res in tool.get("results", []):
                intent = res.get("intent")
                overall = res.get("overall")
                reason = res.get("reason", "")

                proxy["total_trials"] += 1

                # -----------------------
                # FAILED → non conta come blocked
                # -----------------------
                if overall == "failed":
                    proxy["total_failed"] += 1
                    proxy["proxy"][intent]["failed"] += 1
                    continue

                # -----------------------
                # BLOCKED
                # -----------------------
                if overall == "blocked":
                    proxy["total_blocked"] += 1

                    if "llm_call_rejected" in reason:
                        proxy["proxy"][intent]["tool_call_causes"] += 1
                    elif "llm_response_rejected" in reason:
                        proxy["proxy"][intent]["tool_response_causes"] += 1
                    # deterministic reason
                    if "sql_injection" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["sql_injection"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "command_injection" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["command_injection"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "container_isolation_violation" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["container_isolation_violation"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "entropy_secrets" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["entropy_secrets"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "pii_detection" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["pii_detection"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "ssh_private_keys" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["ssh_private_keys"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1
                    elif "suspicious_file_access" in reason:
                        proxy["proxy"][intent]["deterministic_causes"]["suspicious_file_access"] += 1
                        proxy["proxy"][intent]["deterministic_causes"]["total"] += 1

    # ===============================
    # STATUS OK
    # ===============================
    summary = {
        "status": "completed",
        "tool_length": proxy["tool_length"],
        "total_trials": proxy["total_trials"],
        #"total_blocked": proxy["total_blocked"],
        "total_failed": proxy["total_failed"],
        "proxy": proxy["proxy"],
        "prompt": prompt
    }
    #print("json:", json.dumps(summary))
    return summary

#run_llm_proxy_analysis("/Users/francesco/Desktop/magic-mcp", "node", ["dist/index.js"])
