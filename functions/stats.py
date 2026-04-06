import math
from typing import Any
import json

def normalize_category(title: str) -> str:
    return (
        title.strip()
        .lower()
        .replace(" ", "-")
        .replace("_", "-")
    )

def _mcp_guard_category_key(analysis_type: str) -> str:
    mapping = {
        "static": "categories_static",
        "dynamic": "categories_dynamic",
        "fuzzing": "categories_fuzzing",
        "protocol": "categories_protocol",
    }
    return mapping.get(analysis_type)

def update_framework_categories(existing_data: dict, result: dict, name: str) -> None:
    if name == "mcp-shield":
        tools = result.get("tools", {})

        for tool in tools.values():
            if tool.get("status") != "vulnerable":
                continue

            cat_block = tool.get("category", {})
            for cat_name, items in cat_block.items():
                if isinstance(items, dict):
                    existing_data["tools"]["vulnerable"]["static-analysis"]["categories"][cat_name] = (
                        existing_data["tools"]["vulnerable"]["static-analysis"]["categories"].get(cat_name, 0) + len(items)
                    )
                    # Collect descriptions per category (as dict with counts)
                    desc_block = existing_data["tools"]["vulnerable"]["static-analysis"].setdefault("descriptions", {})
                    desc_counts = desc_block.setdefault(cat_name, {})
                    for instance in items.values():
                        desc = instance.get("description", "") if isinstance(instance, dict) else ""
                        if desc:
                            desc_counts[desc] = desc_counts.get(desc, 0) + 1
        return
    
    if name == "mcp-guard":
        cat_block = result.get("category")
        if not isinstance(cat_block, dict):
            return

        for category_name, vulns in cat_block.items():
            if not isinstance(vulns, dict):
                continue

            normalized_cat = normalize_category(category_name)

            for vuln in vulns.values():
                analysis_type = vuln.get("type")
                severity = vuln.get("severity")

                if not analysis_type:
                    continue  # oppure raise, se vuoi essere strict

                category_key = _mcp_guard_category_key(analysis_type)
                if not category_key:
                    continue  # type sconosciuto → ignora

                # inizializza bucket
                categories = existing_data.setdefault(category_key, {})
                categories[normalized_cat] = categories.get(normalized_cat, 0) + 1

                # total vulnerabilities
                existing_data["vulnerabilities"]["total"] += 1

                # severity counts
                if severity:
                    counts = existing_data["vulnerabilities"].setdefault("counts", {})
                    counts[severity] = counts.get(severity, 0) + 1

        return
    
    if name == "mcp-watch":
    # Caso 1: payload diretto con lista di vulnerabilità
        vulns = result.get("vulnerabilities")
        if isinstance(vulns, list):
            print("0")
            for v in vulns:
                title = v.get("title")
                severity = v.get("severity")

                if not title:
                    continue

                cat = normalize_category(title)
                existing_data["categories"][cat] = existing_data["categories"].get(cat, 0) + 1
                existing_data["vulnerabilities"]["total"] += 1

                # opzionale: se la severity è qui, aggiorna anche counts
                if severity:
                    counts = existing_data["vulnerabilities"].setdefault("counts", {})
                    counts[severity] = counts.get(severity, 0) + 1
            return

        # Caso 2: payload già aggregato (mcp_summary.json)
        cat_block = result.get("category")
        if isinstance(cat_block, dict):
            for cat_name, items in cat_block.items():
                if not isinstance(items, dict):
                    continue

                for item in items.values():
                    # Increment category count
                    existing_data["categories"][cat_name] = (
                        existing_data["categories"].get(cat_name, 0) + 1
                    )
                    
                    # Increment total vulnerabilities
                    existing_data["vulnerabilities"]["total"] += 1
                    
                    # Extract severity from each item and update counts
                    severity = item.get("severity") if isinstance(item, dict) else None
                    if severity:
                        counts = existing_data["vulnerabilities"].setdefault("counts", {})
                        counts[severity] = counts.get(severity, 0) + 1
    
    if name == "mcp-scan":
        # ── Tool-level vulnerabilities ──
        tools = result.get("tools", {})
        for tool in tools.values():
            if tool.get("status") != "vulnerable":
                continue

            cat_block = tool.get("category", {})
            extra_block = tool.get("extra_data", {})
            if isinstance(cat_block, dict):
                for issue_code, cat_value in cat_block.items():
                    cat = normalize_category(cat_value)
                    
                    # Global categories (mixed)
                    existing_data["categories"][cat] = (
                        existing_data["categories"].get(cat, 0) + 1
                    )
                    existing_data["vulnerabilities"]["total"] += 1
                    
                    # Tool specific categories
                    tool_vulns = existing_data["tool_vulnerabilities"]
                    cat_map = tool_vulns.setdefault("categories", {})
                    cat_map[cat] = cat_map.get(cat, 0) + 1
                    tool_vulns["total"] += 1

                    # Track issue codes (e.g. W001, E001)
                    ic_map = tool_vulns.setdefault("issue_codes", {})
                    ic_map[issue_code] = ic_map.get(issue_code, 0) + 1

                    # Track severity from extra_data
                    issue_extra = extra_block.get(issue_code, {}) if isinstance(extra_block, dict) else {}
                    severity = issue_extra.get("severity")
                    if severity:
                        counts = existing_data["vulnerabilities"].setdefault("counts", {})
                        counts[severity] = counts.get(severity, 0) + 1
                        tool_counts = tool_vulns.setdefault("counts", {})
                        tool_counts[severity] = tool_counts.get(severity, 0) + 1

                    # Extract trigger words from W001
                    words = issue_extra.get("words", [])
                    if words and isinstance(words, list):
                        tw_map = tool_vulns.setdefault("trigger_words", {})
                        for word in words:
                            tw_map[word] = tw_map.get(word, 0) + 1

        # ── Server-level issues (from snyk-agent-scan) ──
        server_issues = result.get("server_issues", {})
        if isinstance(server_issues, dict):
            for code, issue_data in server_issues.items():
                cat = normalize_category(issue_data.get("category", "unknown"))
                
                # Global categories (mixed)
                existing_data["categories"][cat] = (
                    existing_data["categories"].get(cat, 0) + 1
                )
                existing_data["vulnerabilities"]["total"] += 1
                
                # Server specific categories
                srv_vulns = existing_data["server_vulnerabilities"]
                cat_map = srv_vulns.setdefault("categories", {})
                cat_map[cat] = cat_map.get(cat, 0) + 1
                srv_vulns["total"] += 1

                # Track issue codes (e.g. W015, W016)
                ic_map = srv_vulns.setdefault("issue_codes", {})
                ic_map[code] = ic_map.get(code, 0) + 1

                # Track severity counts
                severity = issue_data.get("severity")
                if severity:
                    counts = existing_data["vulnerabilities"].setdefault("counts", {})
                    counts[severity] = counts.get(severity, 0) + 1
                    srv_counts = srv_vulns.setdefault("counts", {})
                    srv_counts[severity] = srv_counts.get(severity, 0) + 1

        # ── Tool Toxic flows ──
        toxic_flows = result.get("toxic_flows")
        if isinstance(toxic_flows, dict):
            for tf_code, items in toxic_flows.items():
                cat = normalize_category(items)
                
                # Global
                existing_data["categories"][cat] = (
                    existing_data["categories"].get(cat, 0) + 1
                )
                existing_data["vulnerabilities"]["total"] += 1
                
                # Tool specific
                tool_vulns = existing_data["tool_vulnerabilities"]
                cat_map = tool_vulns.setdefault("categories", {})
                cat_map[cat] = cat_map.get(cat, 0) + 1
                tool_vulns["total"] += 1

                # Track toxic flow codes (TF001, TF002)
                ic_map = tool_vulns.setdefault("issue_codes", {})
                ic_map[tf_code] = ic_map.get(tf_code, 0) + 1
        return

    if name == "mcp-security-scan":
        categories = result.get("categories", {})
        for cat_name, count in categories.items():
            cat = normalize_category(cat_name)
            existing_data["categories"][cat] = (
                existing_data["categories"].get(cat, 0) + count
            )
            existing_data["vulnerabilities"]["total"] += count

        # Update passed categories
        categories_passed = result.get("categories_passed", {})
        passed_block = existing_data.setdefault("categories_passed", {})
        for cat_name, count in categories_passed.items():
            cat = normalize_category(cat_name)
            passed_block[cat] = passed_block.get(cat, 0) + count

        # Update severity counts
        severity_data = result.get("severity", {}).get("counts", {})
        for sev, count in severity_data.items():
            counts = existing_data["vulnerabilities"].setdefault("counts", {})
            counts[sev] = counts.get(sev, 0) + count

        # Update findings stats
        findings = result.get("findings", {})
        existing_data["findings"]["total"] += findings.get("total", 0)
        existing_data["findings"]["passed"] += findings.get("passed", 0)
        existing_data["findings"]["failed"] += findings.get("failed", 0)
        if existing_data["findings"]["total"] > 0:
            existing_data["findings"]["percentage_passed"] = round(
                (existing_data["findings"]["passed"] / existing_data["findings"]["total"]) * 100, 2
            )
        return

    if name == "mcp-validator":
        tests = result.get("tests", {})
        existing_data["tests"]["total"] += tests.get("total", 0)
        existing_data["tests"]["passed"] += tests.get("passed", 0)
        existing_data["tests"]["failed"] += tests.get("failed", 0)
        
        # update success rate
        if existing_data["tests"]["total"] > 0:
            existing_data["tests"]["success_rate"] = round(
                (existing_data["tests"]["passed"] / existing_data["tests"]["total"]) * 100, 2
            )
            
        compliance = result.get("compliance", {})
        is_compliant = compliance.get("status", False)
        
        if is_compliant:
            existing_data["compliance"]["compliant"] += 1
        else:
            existing_data["compliance"]["non_compliant"] += 1
            
        total_runs = existing_data["total"] # Use the framework total count
        if total_runs > 0:
             existing_data["compliance"]["percentage_compliant"] = round(
                (existing_data["compliance"]["compliant"] / total_runs) * 100, 2
            )
        return

    if name == "mcp-check":
        suites = result.get("suites", {})
        for suite_name, suite_data in suites.items():
            # Initialize suite if not exists (dynamic)
            if suite_name not in existing_data.get("suites", {}):
                existing_data["suites"][suite_name] = {"passed": 0, "failed": 0, "warnings": 0, "total": 0}
            
            existing_data["suites"][suite_name]["passed"] += suite_data.get("passed", 0)
            existing_data["suites"][suite_name]["failed"] += suite_data.get("failed", 0)
            existing_data["suites"][suite_name]["warnings"] += suite_data.get("warnings", 0)
            existing_data["suites"][suite_name]["total"] += suite_data.get("total", 0)
            
            # Aggregate errors as message:count
            errors = suite_data.get("errors")
            if errors:
                error_counts = existing_data.setdefault("errors", {})
                for err in errors:
                    msg = err.get("message", "Unknown error")
                    error_counts[msg] = error_counts.get(msg, 0) + 1
            
            # Aggregate warnings as message:count
            warning_list = suite_data.get("warning_list")
            if warning_list:
                warning_counts = existing_data.setdefault("warnings", {})
                for warn in warning_list:
                    msg = warn.get("message", "Unknown warning")
                    warning_counts[msg] = warning_counts.get(msg, 0) + 1
        
        summary = result.get("summary", {})
        existing_data["tests"]["total"] += summary.get("total", 0)
        existing_data["tests"]["passed"] += summary.get("passed", 0)
        existing_data["tests"]["failed"] += summary.get("failed", 0)
        existing_data["tests"]["skipped"] += summary.get("skipped", 0)
        existing_data["tests"]["warnings"] += summary.get("warnings", 0)
        if existing_data["tests"]["total"] > 0:
            existing_data["tests"]["success_rate"] = round(
                (existing_data["tests"]["passed"] / existing_data["tests"]["total"]) * 100, 2
            )
        return
    
    # Caso 1: payload diretto con lista di vulnerabilità
    #vulns = result.get("vulnerabilities")
    #if isinstance(vulns, list):
    #    print("0")
    #    for v in vulns:
    #        title = v.get("title")
    #        severity = v.get("severity")
    #        if not title:
    #            continue
    #        cat = normalize_category(title)
    #        existing_data["categories"][cat] = existing_data["categories"].get(cat, 0) + 1
    #        existing_data["vulnerabilities"]["total"] += 1
    #        # opzionale: se la severity è qui, aggiorna anche counts
    #        if severity:
    #            counts = existing_data["vulnerabilities"].setdefault("counts", {})
    #            counts[severity] = counts.get(severity, 0) + 1
    #    return
    #
    ## Caso 2: payload già aggregato (mcp_summary.json)
    #cat_block = result.get("category")
    #if isinstance(cat_block, dict):
    #    for cat_name, items in cat_block.items():
    #        if not isinstance(items, dict):
    #            continue
    #        count = len(items)
    #        existing_data["categories"][cat_name] = (
    #            existing_data["categories"].get(cat_name, 0) + count
    #        )
    #        # 🔴 QUESTO ERA IL PEZZO CHE MANCAVA
    #        existing_data["vulnerabilities"]["total"] += count

def safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        if isinstance(x, bool):
            return int(x)
        if isinstance(x, (int,)):
            return int(x)
        if isinstance(x, float):
            if math.isnan(x) or math.isinf(x):
                return default
            return int(x)
        s = str(x).strip()
        if not s:
            return default
        return int(float(s))
    except Exception:
        return default

def update_framework_severity(existing_data: dict, result: dict, name: str) -> None:
    if name == "mcp-shield":
        tools = result.get("tools")
        if not isinstance(tools, dict):
            return

        static_counts = (
            existing_data
            .setdefault("tools", {})
            .setdefault("vulnerable", {})
            .setdefault("static-analysis", {})
            .setdefault("counts", {})
        )

        for tool in tools.values():
            if tool.get("status") != "vulnerable":
                continue

            risk = tool.get("risk")
            if not risk:
                continue

            static_counts[risk] = static_counts.get(risk, 0) + 1

        return

    if name == "mcp-scan":
        return
    
    if name == "mcp-security-scan":
        return
    
    if name=="mcp-guard":
        return
    
    if name == "mcp-watch":
        return  # severity counts handled in update_framework_categories
    
    sev_block = result.get("severity")
    if not isinstance(sev_block, dict):
        return

    sev_counts = sev_block.get("counts")
    if not isinstance(sev_counts, dict):
        return

    global_counts = existing_data["vulnerabilities"].setdefault("counts", {})

    for severity, count in sev_counts.items():
        global_counts[severity] = global_counts.get(severity, 0) + int(count)

def update_safe_vulnerable_tools(framework_block: dict, server_fw_payload: dict) -> None:
    """
    Solo per mcp-scan e mcp-shield.
    Cerca vari pattern nel payload:
      - payload["tools"] = {"safe": x, "vulnerable": y}
      - payload["safe_tools"], payload["vulnerable_tools"]
    """
    tools_block = framework_block.get("tools")
    if not isinstance(tools_block, dict):
        return

    safe_add = 0
    vuln_add = 0

    if isinstance(server_fw_payload.get("tools"), dict):
        safe_add = safe_int(server_fw_payload["tools"].get("safe"), 0)
        vuln_add = safe_int(server_fw_payload["tools"].get("vulnerable"), 0)
    else:
        safe_add = safe_int(server_fw_payload.get("safe_tools"), 0)
        vuln_add = safe_int(server_fw_payload.get("vulnerable_tools"), 0)

    tools_block["safe"] = safe_int(tools_block.get("safe"), 0) + safe_add
    tools_block["vulnerable"]["total"] += vuln_add
    #tools_block["vulnerable"] = safe_int(tools_block.get("vulnerable"), 0) + vuln_add

    total = tools_block["safe"] + tools_block["vulnerable"]["total"]
    if total > 0:
        tools_block["percentage_of_vulnerability"]["safe"] = round(tools_block["safe"] / tools_block["total"], 4)
        tools_block["percentage_of_vulnerability"]["vulnerable"] = round(tools_block["vulnerable"]["total"] / tools_block["total"], 4)
    else:
        tools_block.setdefault("percentage_of_vulnerability", {})
        tools_block["percentage_of_vulnerability"]["safe"] = 0.0
        tools_block["percentage_of_vulnerability"]["vulnerable"] = 0.0

    return safe_add + vuln_add

def update_framework_tools(framework_block: dict, server_fw_payload: dict, name: str) -> int:
    tools_block = framework_block["tools"]

    tools_payload = server_fw_payload.get("tools")
    if not isinstance(tools_payload, dict):
        return 0

    added = 0

    for tool_data in tools_payload.values():
        status = tool_data.get("status")
        if status == "safe":
            tools_block["safe"] += 1
            added += 1
        elif status == "vulnerable":
            if name == "mcp-shield":
                tools_block["vulnerable"]["total"] += 1
            else:
                tools_block["vulnerable"] += 1
            added += 1
    vuln_tools = tools_block["vulnerable"]["total"] if name == "mcp-shield" else tools_block["vulnerable"]
    tools_block["total"] = tools_block["safe"] + vuln_tools
    if tools_block["total"] > 0:
        tools_block["percentage_of_vulnerability"]["safe"] = round(
            tools_block["safe"] / tools_block["total"] * 100, 2
        )
        tools_block["percentage_of_vulnerability"]["vulnerable"] = round(
            vuln_tools / tools_block["total"] * 100, 2
        )
    return added


def extract_tool_count(fw_data: dict) -> tuple[int, int]:
    tools = fw_data.get("tools", {})
    if not tools:
        return 0, 0

    safe = 0
    vulnerable = 0

    for tool_name, tool_data in tools.items():
        if not isinstance(tool_data, dict):
            continue

        status = tool_data.get("status")

        if status == "safe":
            safe += 1
        elif status == "vulnerable":
            vulnerable += 1

    return safe, vulnerable

def update_analysis_types(framework_block: dict, result: dict) -> None:
    """Update analysis_types counters based on analyses_completed from mcp-guard scan."""
    analyses = result.get("analyses_completed", {})
    if not analyses:
        return

    at = framework_block.setdefault("analysis_types", {})
    fw_total = framework_block.get("total", 0)

    for atype in ("static", "fuzzing", "dynamic", "protocol"):
        bucket = at.setdefault(atype, {"total": 0, "percentage": 0.0})
        if analyses.get(atype, False):
            bucket["total"] += 1
        if fw_total > 0:
            bucket["percentage"] = round(
                (bucket["total"] / fw_total) * 100, 2
            )

def get_error_category(message: str) -> str:
    """Map error message to a logical category for folder organization."""
    if not isinstance(message, str): return "other_errors"
    msg = message.lower()
    if "connection refused" in msg or "econnrefused" in msg: return "connection_refused"
    if "timeout" in msg or "timed out" in msg: return "timeout"
    if "method not found" in msg or "32601" in msg: return "method_not_found"
    if "invalid arguments" in msg or "32602" in msg: return "invalid_arguments"
    if "unauthorized" in msg or "authentication failed" in msg or "api key" in msg or "token" in msg: return "unauthorized_or_auth_missing"
    if "not connected" in msg or "transport not connected" in msg: return "not_connected"
    if "invalid schemas" in msg or "invalid input" in msg or "output schema" in msg: return "schema_violation"
    if "panic recovered" in msg or "runtime error" in msg: return "panic_or_crash"
    if "enoent" in msg or "no such file" in msg: return "file_not_found"
    if "osascript" in msg or "applescript" in msg: return "macos_specific_failed"
    if "docker" in msg: return "docker_missing"
    return "other_errors"

def update_framework_check_stats(framework_block: dict, result: dict) -> None:
    """Update suites, tests, and reorganized errors for mcp-check."""
    # Aggiorna suites
    res_suites = result.get("suites", {})
    if res_suites:
        fw_suites = framework_block.setdefault("suites", {})
        er_root = framework_block.setdefault("errors_reorganized", {})
        
        for suite_name, suite_data in res_suites.items():
            s_block = fw_suites.setdefault(suite_name, {"passed": 0, "failed": 0, "warnings": 0, "total": 0})
            s_block["passed"] += suite_data.get("passed", 0)
            s_block["failed"] += suite_data.get("failed", 0)
            s_block["warnings"] += suite_data.get("warnings", 0)
            s_block["total"] = s_block["passed"] + s_block["failed"] + s_block["warnings"]
            
            # Reorganized errors
            errors = suite_data.get("errors", [])
            if errors:
                suite_er = er_root.setdefault(suite_name, {})
                for err in errors:
                    msg = err.get("message", "Unknown error")
                    category = get_error_category(msg)
                    suite_er[category] = suite_er.get(category, 0) + 1

    # Aggiorna tests (summary)
    summary = result.get("summary", {})
    test_stats = summary.get("testStatistics", {})
    if test_stats:
        fw_tests = framework_block.setdefault("tests", {
            "total": 0, "passed": 0, "failed": 0, "skipped": 0, "warnings": 0,
            "success_rate": 0.0, "average_failed_per_server": 0.0
        })
        for key in ["total", "passed", "failed", "skipped", "warnings"]:
            fw_tests[key] += test_stats.get(key, 0)
        
        if fw_tests["total"] > 0:
            fw_tests["success_rate"] = round((fw_tests["passed"] / fw_tests["total"]) * 100, 2)
        
        fw_total_servers = framework_block.get("total", 0)
        if fw_total_servers > 0:
            fw_tests["average_failed_per_server"] = round(fw_tests["failed"] / fw_total_servers, 2)

    # Aggiorna errors (flat map per compatibilità)
    res_errors = result.get("errors", {}) # Se mcp-check lo fornisce a quel livello
    if res_errors:
        fw_errors = framework_block.setdefault("errors", {})
        for err_msg, count in res_errors.items():
            fw_errors[err_msg] = fw_errors.get(err_msg, 0) + count

def update_framework(existing_data: dict, result: dict, name: str, server_language: str):
    total_servers = existing_data.get("total", 0)
    existing_data[name]["total"] += 1
    if total_servers > 0:
        existing_data[name]["percentage"] = round(
            (existing_data[name]["total"] / total_servers) * 100.0, 2
        )
    else:
        existing_data[name]["percentage"] = 0.0

    # Ensure languages dict exists and language is counted
    langs = existing_data[name].setdefault("languages", {})
    langs[server_language] = langs.get(server_language, 0) + 1
    update_framework_categories(existing_data[name], result, name)
    update_framework_severity(existing_data[name], result, name)
    
    if name == "mcp-guard":
        update_analysis_types(existing_data[name], result)
    elif name == "mcp-check":
        update_framework_check_stats(existing_data[name], result)
        
    recompute_framework_probabilities(existing_data[name], total_servers, name)
    finalize_percentage_of_vulnerability(existing_data[name], name)

    if name in ("mcp-scan", "mcp-shield"):
        update_framework_tools(existing_data[name], result, name)
        existing_data[name]["tools"]["average_per_server"] = (
            existing_data[name]["tools"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
    if name == "scanorama":
        # Calcolo tools totali
        tools_list = result.get("scanorama", [])
        if isinstance(tools_list, list):
            existing_data[name]["tools"]["total"] += len(tools_list)
            
            # Calcolo injection
            injection_count = 0
            for tool in tools_list:
                if tool.get("injectionType") == "Injection":
                    injection_count += 1
            existing_data[name]["injections"]["total"] += injection_count

        existing_data[name]["tools"]["average_per_server"] = (
            existing_data[name]["tools"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
        existing_data[name]["injections"]["average_per_server"] = (
            existing_data[name]["injections"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
    if name == "mcp-shield":
        existing_data[name]["tools"]["vulnerable"]["average_vulnerable_per_server"] = (
            existing_data[name]["tools"]["vulnerable"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
    if name == "mcp-scan":
        existing_data[name]["tools"]["average_vulnerable_per_server"] = (
            existing_data[name]["tools"]["vulnerable"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )

def update_framework_npx(existing_data: dict, result: dict, name: str, server_language: str = "unknown"):
    total_servers = existing_data.get("total", 0)  
    existing_data[name]["total"] += 1

    # Ensure languages dict exists and language is counted
    langs = existing_data[name].setdefault("languages", {})
    langs[server_language] = langs.get(server_language, 0) + 1

    if total_servers > 0:
        existing_data[name]["percentage"] = round(
            (existing_data[name]["total"] / total_servers) * 100.0, 2
        )
    else:
        existing_data[name]["percentage"] = 0.0

    update_framework_categories(existing_data[name], result, name)
    update_framework_severity(existing_data[name], result, name)
    if name == "mcp-guard":
        update_analysis_types(existing_data[name], result)
    recompute_framework_probabilities(existing_data[name], total_servers, name)
    finalize_percentage_of_vulnerability(existing_data[name], name)
    if name in ("mcp-scan", "mcp-shield"):
        update_framework_tools(existing_data[name], result, name)
        existing_data[name]["tools"]["average_per_server"] = (
            existing_data[name]["tools"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
    if name == "scanorama":
        # Calcolo tools totali
        tools_list = result.get("scanorama", [])
        if isinstance(tools_list, list):
            existing_data[name]["tools"]["total"] += len(tools_list)

            # Calcolo injection
            injection_count = 0
            for tool in tools_list:
                if tool.get("injectionType") == "Injection":
                    injection_count += 1
            existing_data[name]["injections"]["total"] += injection_count

        existing_data[name]["tools"]["average_per_server"] = (
            existing_data[name]["tools"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
        existing_data[name]["injections"]["average_per_server"] = (
            existing_data[name]["injections"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )

    if name == "mcp-shield":
        existing_data[name]["tools"]["vulnerable"]["average_vulnerable_per_server"] = (
            existing_data[name]["tools"]["vulnerable"]["total"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )
    if name == "mcp-scan":
        existing_data[name]["tools"]["average_vulnerable_per_server"] = (
            existing_data[name]["tools"]["vulnerable"] / existing_data[name]["total"]
            if existing_data[name]["total"] else 0.0
        )

def finalize_percentage_of_vulnerability(analysis: dict, name: str) -> None:
    if name == "mcp-shield":
        static_analysis = (
            analysis
            .get("tools", {})
            .get("vulnerable", {})
            .get("static-analysis", {})
        )

        categories = static_analysis.get("categories", {})
        total_vulns = sum(categories.values())

        if total_vulns <= 0:
            static_analysis["percentage_of_vulnerability"] = {}
            return

        static_analysis["percentage_of_vulnerability"] = {
            cat: round((count / total_vulns) * 100, 2)
            for cat, count in categories.items()
        }
        return
    
    if name == "mcp-check":
        # mcp-check doesn't use vulnerability categories
        return
    
    if name == "mcp-guard":
        merged_categories = {}

        for key in (
            "categories_static",
            "categories_dynamic",
            "categories_fuzzing",
            "categories_protocol",
        ):
            for cat, count in analysis.get(key, {}).items():
                merged_categories[cat] = merged_categories.get(cat, 0) + count

        total_vulns = analysis.get("vulnerabilities", {}).get("total", 0)

        if not merged_categories or total_vulns <= 0:
            analysis["percentage_of_vulnerability"] = {}
            analysis.pop("percentage_of_vulnerability_grouped", None)
            return

        # Main percentages (4 decimals)
        analysis["percentage_of_vulnerability"] = {
            cat: round((count / total_vulns) * 100, 4)
            for cat, count in merged_categories.items()
        }
        
        # Grouped percentages (aggregate sensitive info, 4 decimals)
        grouped = {}
        for cat, count in merged_categories.items():
            if cat.startswith("sensitive-information-disclosed"):
                grouped["sensitive-information-disclosed"] = grouped.get("sensitive-information-disclosed", 0) + count
            else:
                grouped[cat] = grouped.get(cat, 0) + count
                
        # Remove and re-add to ensure it's at the end
        analysis.pop("percentage_of_vulnerability_grouped", None)
        analysis["percentage_of_vulnerability_grouped"] = {
            cat: round((count / total_vulns) * 100, 4)
            for cat, count in grouped.items()
        }
        return


    categories = analysis.get("categories", {})
    total_vulns = analysis.get("vulnerabilities", {}).get("total", 0)

    if not categories or total_vulns <= 0:
        analysis["percentage_of_vulnerability"] = {}
    else:
        analysis["percentage_of_vulnerability"] = {
            cat: round((count / total_vulns) * 100, 2)
            for cat, count in categories.items()
        }

    # Additional nested percentages for mcp-scan
    if name == "mcp-scan":
        for sub in ("server_vulnerabilities", "tool_vulnerabilities"):
            sub_block = analysis.get(sub, {})
            sub_cats = sub_block.get("categories", {})
            sub_total = sub_block.get("total", 0)
            
            if not sub_cats or sub_total <= 0:
                sub_block["percentage_of_vulnerability"] = {}
            else:
                sub_block["percentage_of_vulnerability"] = {
                    cat: round((count / sub_total) * 100, 2)
                    for cat, count in sub_cats.items()
                }
    return

def recompute_framework_probabilities(framework_block: dict, total_servers: int, name: str) -> None:
    if name == "mcp-shield":
        static_analysis = (
            framework_block
            .get("tools", {})
            .get("vulnerable", {})
            .get("static-analysis", {})
        )

        counts = static_analysis.get("counts", {})
        prob = static_analysis.setdefault("percentage_of_severity", {})

        total_v = sum(safe_int(v, 0) for v in counts.values())

        if total_v <= 0:
            for sev in counts.keys():
                prob[sev] = 0.0
            return

        for sev, c in counts.items():
            prob[sev] = round(safe_int(c, 0) / total_v, 6)

        return  # ⬅️ NON cade nella logica legacy
    
    if name == "mcp-check":
        # mcp-check doesn't track vulnerabilities, it tracks test results
        # No vulnerability-based probability calculations needed
        return
            
    if name == "scanorama" or name == "mcp-validator":
        return
    
    # percentage_of_vulnerability
    total_v = safe_int(framework_block["vulnerabilities"].get("total"), 0)
    framework_block["vulnerabilities"]["average_per_server"] = round((total_v / total_servers) if total_servers else 0.0, 6)
    
    if name == "mcp-scan":
        total_sv = safe_int(framework_block["server_vulnerabilities"].get("total"), 0)
        framework_block["server_vulnerabilities"]["average_per_server"] = round((total_sv / total_servers) if total_servers else 0.0, 6)
        
        total_tv = safe_int(framework_block["tool_vulnerabilities"].get("total"), 0)
        framework_block["tool_vulnerabilities"]["average_per_server"] = round((total_tv / total_servers) if total_servers else 0.0, 6)

    # severity percentage_of_severity
    counts = framework_block.get("vulnerabilities", {}).get("counts", {})
    prob = framework_block.get("vulnerabilities", {}).setdefault("percentage_of_severity", {})
    if total_v <= 0:
        # azzera o lascia come 0
        for sev in list(counts.keys()):
            prob[sev] = 0.0
    else:
        for sev, c in counts.items():
            prob[sev] = round(safe_int(c, 0) / total_v, 6)

    if name == "mcp-scan":
        srv_counts = framework_block.get("server_vulnerabilities", {}).get("counts", {})
        srv_prob = framework_block.get("server_vulnerabilities", {}).setdefault("percentage_of_severity", {})
        if total_sv <= 0:
            for sev in list(srv_counts.keys()):
                srv_prob[sev] = 0.0
        else:
            for sev, c in srv_counts.items():
                srv_prob[sev] = round(safe_int(c, 0) / total_sv, 6)
                
        tool_counts = framework_block.get("tool_vulnerabilities", {}).get("counts", {})
        tool_prob = framework_block.get("tool_vulnerabilities", {}).setdefault("percentage_of_severity", {})
        if total_tv <= 0:
            for sev in list(tool_counts.keys()):
                tool_prob[sev] = 0.0
        else:
            for sev, c in tool_counts.items():
                tool_prob[sev] = round(safe_int(c, 0) / total_tv, 6)

def update_summary_llm_risk(summary: dict, llm_result: dict, type: str, total_servers: int, server_language: str, tool_length: int) -> None:
    if type == "static":
        llm_counts = llm_result.get("overallRisk", {})
        target = summary["mcp-shield"]["tools"]["vulnerable"]["llm-description-analysis"]

        for level in ("LOW", "MEDIUM", "HIGH"):
            target[level] += llm_counts.get(level, 0)
    else:
        proxy_data = llm_result.get("proxy", {})
        summ = summary["proxy"]
        summ["total_server"] += 1
        if total_servers > 0:
            summ["percentage"] = (summ["total_server"] / total_servers) * 100.0
        summ["languages"][server_language] = summ["languages"].get(server_language, 0) + 1
        summ["total_tools"] += tool_length
        summ["total_trials"] += llm_result.get("total_trials", 0)
        summ["total_failed"] += llm_result.get("total_failed", 0)

        # All 14 deterministic cause keys
        DET_KEYS = [
            "total", "command_injection", "ssh_private_keys", "suspicious_file_access",
            "sql_injection", "container_isolation_violation", "entropy_secrets",
            "pii_detection", "prompt_injection", "important_tag_injection",
            "shadow_hijack", "cross_origin_access", "xss_injection",
            "base64_encoded_payload", "invisible_unicode_injection"
        ]

        # All 4 intent buckets
        INTENT_KEYS = ["benign", "malicious", "jailbreak_combined", "encoding_evasion"]

        summary_proxy = summ["tool_blocked"]

        # Aggregate tool_blocked across all intents
        total_blocked = 0
        for intent in INTENT_KEYS:
            src = proxy_data.get(intent, {})
            dst = summary_proxy.get(intent, {})
            if not dst:
                continue

            # Deterministic causes
            src_det = src.get("deterministic_causes", {})
            dst_det = dst.get("deterministic_causes", {})
            for key in DET_KEYS:
                dst_det[key] = dst_det.get(key, 0) + src_det.get(key, 0)

            # LLM causes
            dst["tool_call_causes"] = dst.get("tool_call_causes", 0) + src.get("tool_call_causes", 0)
            dst["tool_response_causes"] = dst.get("tool_response_causes", 0) + src.get("tool_response_causes", 0)

            total_blocked += dst_det.get("total", 0) + dst.get("tool_call_causes", 0) + dst.get("tool_response_causes", 0)

        summary_proxy["total"] = total_blocked
        if summ["total_tools"] > 0:
            summary_proxy["percentage"] = (summary_proxy["total"] / summ["total_tools"]) * 100.0

        # ===============================
        # PROMPT BLOCKED (prompt-level)
        # ===============================
        prompt_data = llm_result.get("prompt", {})
        summary_prompt = summ["prompt"]

        summary_prompt["total_prompt"] += prompt_data.get("total_prompt", 0)
        summary_prompt["total_blocked"] += prompt_data.get("total_blocked", 0)
        summary_prompt["total_allowed"] += prompt_data.get("total_allowed", 0)

        summary_prompt["tool_call_causes"] += prompt_data.get("tool_call_causes", 0)
        summary_prompt["tool_response_causes"] += prompt_data.get("tool_response_causes", 0)

        # deterministic causes
        det_src = prompt_data.get("deterministic_causes", {})
        det_dst = summary_prompt["deterministic_causes"]

        for key in DET_KEYS:
            det_dst[key] = det_dst.get(key, 0) + det_src.get(key, 0)
