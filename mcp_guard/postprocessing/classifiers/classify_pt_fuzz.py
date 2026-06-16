#!/usr/bin/env python3
"""Classifica path-traversal-fuzzing UNCERTAIN."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "path-traversal-fuzzing"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    payload = f.get("payload", "")
    if payload:
        return f"{server}|{CAT}|{payload[:40]}"
    return f"{server}|{f.get('file', '')}|?"


def classify(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # ── VP: actual /etc/passwd content leaked ──

    if re.search(r"root:x:0:0:|daemon:x:1:1:|nobody:x:|"
                 r"/usr/sbin/nologin|/bin/(?:bash|sh|false|nologin)|"
                 r"\bbin:x:|\bsys:x:|\bsync:x:", response):
        return "VP", "etc_passwd_content_leaked"

    # /etc/shadow content
    if re.search(r"\$[156y]\$[A-Za-z0-9./]{8,}\$|\$argon2|\$pbkdf2", response):
        return "VP", "shadow_hash_format_leaked"

    # Windows boot.ini / SAM / system32 content
    if re.search(r"\[boot loader\]|\[operating systems\]|"
                 r"WINDOWS\\system32\\config\\SAM|"
                 r"NT AUTHORITY\\SYSTEM", response):
        return "VP", "windows_system_file_content_leaked"

    # SSH known_hosts / authorized_keys content
    if re.search(r"ssh-rsa\s+AAAA|ssh-ed25519\s+AAAA|ecdsa-sha2-nistp", response):
        return "VP", "ssh_key_content_leaked"

    # AWS credentials file format
    if re.search(r"\[default\]\s*\\?\\?n.*aws_access_key_id|"
                 r"\[profile\s+\w+\].*aws_secret", response, re.I):
        return "VP", "aws_credentials_file_leaked"

    # ENOTDIR / Error reading + /etc/passwd → server tried but blocked at last step
    if re.search(r"ENOTDIR.*?/etc/passwd|"
                 r"Error\s+reading\s+(?:directory|path)\s*:?\s*/etc/passwd|"
                 r"Project\s+structure\s*\([^)]*(?:\.\./|/etc/)[^)]*\)\s*:.*?Error", response, re.I):
        return "VP", "server_attempted_traversal_confirmed_by_fs_error"

    # ── FP: payload echoed without leak ──

    # Stored as project/draft/snapshot/config metadata
    if re.search(r"(?:Saved\s+local\s+snapshot|"
                 r"Project\s+structure|projectPath|currentProject|"
                 r"['\"]projectPath['\"]\s*:|['\"]currentProject['\"]\s*:|"
                 r"['\"]gateway_url['\"]\s*:|['\"]kvUrl['\"]\s*:|"
                 r"['\"]baseUrl['\"]\s*:|['\"]targetUrl['\"]\s*:|"
                 r"['\"]publicEndpoint['\"]\s*:|['\"]postal_code['\"]\s*:|"
                 r"['\"]hostname['\"]\s*:|['\"]server['\"]\s*:|"
                 r"['\"]connection['\"]\s*:\s*\{[^}]*['\"]server['\"])"
                 r".*?(?:file:///|\.\./|/etc/)", response, re.S):
        return "FP", "payload_stored_as_metadata_or_config"

    # Portainer / app config display
    if re.search(r"(?:Portainer|App|Service|Tool)\s+Configuration:|"
                 r"['\"]url['\"]\s*:\s*['\"]file:///|"
                 r"['\"]endpoint['\"]\s*:\s*['\"]file:///", response):
        return "FP", "config_display_with_payload_url"

    # PlantUML / Mermaid / diagram with payload as title/label
    if re.search(r"@startuml|@enduml|@startgantt|"
                 r"```mermaid|graph\s+[TBLR]D|"
                 r"title.*?(?:file:///|\.\./|/etc/)", response):
        return "FP", "diagram_with_payload_in_title_or_label"

    # Search engine response (algolia/elastic/solr)
    if re.search(r"['\"]hits['\"]\s*:\s*\[|nbHits|exhaustive|"
                 r"Found\s+\d+\s+(?:result|recipe|insight|match|item)s?\s+(?:for|matching)", response):
        return "FP", "search_engine_query_result"

    # Task list / journal / notes with payload as title
    if re.search(r"Task\s+List\s*\(|"
                 r"Journal\s+Tags\s*\(|"
                 r"['\"]tags?['\"]\s*:\s*\[",  response):
        return "FP", "task_list_or_journal_with_payload_as_label"

    # CJK echo of payload
    if re.search(r"最近添加|关键词|标题|创建时间|"
                 r"허용된|디렉토리|"
                 r"プロジェクト|タスク|"
                 r"未配置|未设置", response):
        return "FP", "cjk_label_response_with_payload"

    # Path normalized: server prepended cwd to payload
    if re.search(r"['\"]filePath['\"]\s*:\s*['\"]/home/tecnico/|"
                 r"['\"]filePath['\"]\s*:\s*['\"][A-Z]:\\\\Users\\\\|"
                 r"/home/tecnico/Desktop/.*?(?:file:|/etc/)|"
                 r"\\\\Users\\\\\\w+\\\\.*?(?:file:|\\.\\.)", response):
        return "FP", "payload_prepended_with_test_vm_cwd"

    # Tool execution failed (EEXIST, EACCES, ENOENT non-leak)
    if re.search(r"(?:Tool\s+'?[\w_-]+'?\s+(?:execution\s+)?failed|"
                 r"EEXIST|EACCES|EPERM|EISDIR|ENOTDIR\s+(?:open|stat)|"
                 r"already\s+exists|file\s+already\s+exists|"
                 r"is\s+a\s+directory|not\s+a\s+directory|"
                 r"no\s+such\s+file\s+or\s+directory)", response):
        return "FP", "filesystem_error_no_leak"

    # SQL syntax error (DB rejected)
    if re.search(r"SQL(?:ite)?\s+error|unrecognized\s+token|syntax\s+error|"
                 r"sql\s+logic\s+error|database\s+error", response, re.I):
        return "FP", "sql_syntax_error"

    # Network error
    if re.search(r"getaddrinfo|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|"
                 r"NetworkError|fetch\s+failed", response):
        return "FP", "network_error"

    # Validation error / API rejection
    if re.search(r"Invalid\s+(?:address|format|number|hash|input|argument|parameter|"
                 r"symbol|path|URL|accession)|"
                 r"validation\s+(?:error|failed)|"
                 r"MCP\s+error\s+-32\d{3}|"
                 r"Unrecognized\s+(?:argument|format)|"
                 r"Bad\s+(?:request|input)", response, re.I):
        return "FP", "validation_or_api_rejection"

    # LLM/AI explanation of payload concept
    if re.search(r"(?:The\s+(?:file|command|path)\s+(?:`|')?\.\.|"
                 r"The\s+SAM\s+\(Security\s+Account\s+Manager\)|"
                 r"The\s+_etc/passwd_\s+file|"
                 r"Comprendre\s+le\s+fichier\s+SAM|"
                 r"fichier\s+SAM\s+dans\s+Windows|"
                 r"(?:critical|essential)\s+(?:text\s+)?file\s+in\s+Linux|"
                 r"represents\s+an\s+attempt\s+to\s+access|"
                 r"is\s+a\s+(?:critical|fundamental|important)\s+component)", response, re.I):
        return "FP", "llm_explanation_of_path_concept"

    # HTTP error 4xx/5xx
    if re.search(r"HTTP\s+[45]\d{2}|status\s+code\s+[45]\d{2}|"
                 r"Request\s+failed\s+with\s+status|"
                 r"\b(?:401|403|404|405|500|502|503)\s+(?:Not\s+Found|Unauthorized|"
                 r"Forbidden|Method\s+Not\s+Allowed|Internal|Bad)", response):
        return "FP", "http_error_status"

    # Successfully connected with payload as host
    if re.search(r"Successfully\s+connected\s+to\s+\w+\s+at\s+(?:\.\./|file:///|/etc/)|"
                 r"connected\s+to\s+(?:file:///|\.\./|/etc/)", response):
        return "FP", "payload_as_connection_host_label"

    # Comparison/Report with payload as subject
    if re.search(r"(?:Comparison|Analysis|Report|Summary)\s+for\s+(?:\.\./|file:///|/etc/)|"
                 r"Generated\s+(?:a\s+)?\w+.*?for\s+(?:file:///|/etc/)", response):
        return "FP", "comparison_or_report_with_payload"

    # Domain Model / Component / Plan generated
    if re.search(r"Component\s+Generation|Domain\s+Model:|"
                 r"Research\s+plan\s+created\s+for|"
                 r"Generated\s+(?:a\s+)?complete", response):
        return "FP", "code_or_doc_generated_with_payload"

    # Cached response with payload
    if re.search(r"Cached\s+response\s+for|Cache\s+miss\s+for|"
                 r"['\"]message['\"]\s*:\s*['\"]Cached", response):
        return "FP", "cache_response_with_payload"

    # Wallet/blockchain validation rejection
    if re.search(r"Invalid\s+(?:address|wallet|signature|public\s+key|nft|erc\d+|"
                 r"contract|hash|chain|network|gas)|"
                 r"ENS\s+name|Failed\s+to\s+resolve\s+ENS", response, re.I):
        return "FP", "blockchain_validation_error"

    # Tool list / schema response
    if re.search(r"['\"]tools['\"]\s*:\s*\[|"
                 r"['\"]inputSchema['\"]\s*:|"
                 r"['\"]description['\"]\s*:\s*['\"]", response):
        return "FP", "tool_list_or_schema_response"

    # Default: residual fuzzing senza secret reale → FP
    return "FP", "pt_fuzzing_residual_no_traversal_evidence"


def main():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    fi = d.get("findings", d) if isinstance(d, dict) else d

    cache = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    reasons = {}
    for r in fi:
        v, reason = classify(r)
        cache[cache_key(r)] = {"verdict": v, "reason": reason}
        counts[v] += 1
        reasons.setdefault(reason, 0)
        reasons[reason] += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"Total: {len(fi)}")
    print(f"VP: {counts['VP']} | FP: {counts['FP']} | UNCERTAIN: {counts['UNCERTAIN']}")
    print()
    print("Reasons:")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:20]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
