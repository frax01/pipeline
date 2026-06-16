import platform
from functions.config import NPM, MCP_WATCH_DIR, TIMEOUT_SECONDS
from collections import defaultdict
from functions.helper import run_process, failure
import re

def parse_mcp_watch(text):
    severity_summary = {}
    in_severity_summary = False

    categories = {}
    category_counters = defaultdict(int)
    total_vulns = 0

    current_severity = None
    current_category = None
    current_id = None
    current_location = None
    current_source = None
    current_evidence = None
    current_title = None


    for line in text.splitlines():
        line = line.strip()

        # Detect start of severity summary
        if "Summary by Severity" in line:
            in_severity_summary = True
            continue
        
        # Exit severity summary section
        if in_severity_summary and line == "":
            in_severity_summary = False
            continue
        
        # Parse severity summary lines
        if in_severity_summary:
            m = re.search(r"(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(\d+)", line, re.IGNORECASE)
            if m:
                sev = m.group(1).lower()
                count = int(m.group(2))
                severity_summary[sev] = count
            continue

        # Title / description (prima riga del finding)
        m = re.match(r"^\d+\.\s*⚡\s*(.+)$", line)
        if m:
            current_title = m.group(1).strip()
            continue

        # Severity
        if "Severity:" in line:
            value = line.split("Severity:", 1)[1].strip().lower()
            if not value or value not in ("critical", "high", "medium", "low"):
                current_severity = None
                continue
            current_severity = value
            total_vulns += 1
            continue

        # Category
        if re.match(r"^\s*📂\s*Category:", line):
            value = line.split("Category:", 1)[1].strip().lower()
            if not value:
                current_category = None
                continue
            current_category = value
            categories.setdefault(current_category, {})
            continue

        # ID
        if "ID:" in line:
            current_id = line.split("ID:", 1)[1].strip()
            continue

        # Location
        if "Location:" in line:
            current_location = line.split("Location:", 1)[1].strip()
            continue

        # Source
        if "Source:" in line:
            current_source = line.split("Source:", 1)[1].strip()
            continue

        # Evidence
        if "Evidence:" in line:
            current_evidence = line.split("Evidence:", 1)[1].strip()
            continue

        # Quando abbiamo tutto → registra finding
        if current_severity and current_category and current_id:
            category_counters[current_category] += 1
            idx = str(category_counters[current_category])

            categories[current_category][idx] = {
                "title": current_title,
                "id": current_id,
                "severity": current_severity,
                "source": current_source,
                "location": current_location,
                "evidence": current_evidence
            }

            # reset per prossimo finding
            current_severity = None
            current_category = None
            current_id = None
            current_location = None
            current_source = None
            current_evidence = None
            current_title = None

    # Percentuali
    percentage_of_vulnerability = {
        f"{k}": round((len(v) / total_vulns) * 100, 2)
        for k, v in categories.items()
    }

    return {
        "mcp-watch": {
            "status": "completed",
            "total-vulnerabilities": total_vulns,
            "category": categories,
            "percentage_of_vulnerability": percentage_of_vulnerability,
            "severity": {
                "counts": severity_summary,
                "percentage_of_severity": {
                    k: round(v / total_vulns, 6) if total_vulns > 0 else 0.0
                    for k, v in severity_summary.items()
                }
            }
        }
    }

def execute_mcp_watch(server_url: str, server_language: str):
    if server_language.lower() not in ("nodejs", "python"):
        return failure("mcp-watch")
    npm_command = NPM
    if platform.system() in ("Darwin", "Linux"):
        npm_command = "npm"
        
    is_github_url = server_url.startswith("http") or server_url.startswith("git@")
    
    if is_github_url:
        cmd_watch_new = [npm_command, "run", "scan:github", server_url]
        try:
            stdout, stderr, elapsed, code = run_process(
                cmd=cmd_watch_new,
                cwd=str(MCP_WATCH_DIR),
                timeout=TIMEOUT_SECONDS,
                framework_name="MCP Watch"
            )
            return parse_mcp_watch(stdout)
        except TimeoutError:
            return failure("mcp-watch")
    else:
        # Treat server_url as npm package name
        import os
        import tempfile
        import tarfile
        import subprocess
        import shutil
        
        temp_dir = tempfile.mkdtemp(prefix="mcp_watch_npm_")
        try:
            pack_process = subprocess.run(
                [npm_command, "pack", server_url],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if pack_process.returncode != 0:
                print(f"npm pack failed for {server_url}: {pack_process.stderr}")
                return failure("mcp-watch")
                
            tgz_files = [f for f in os.listdir(temp_dir) if f.endswith(".tgz")]
            if not tgz_files:
                print(f"No .tgz file found after npm pack for {server_url}")
                return failure("mcp-watch")
                
            tgz_path = os.path.join(temp_dir, tgz_files[0])
            
            with tarfile.open(tgz_path, "r:gz") as tar:
                # Add filter='data' to tar.extractall for safe extraction on python 3.12+ 
                # but fallback to no filter for older python versions.
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=temp_dir, filter='data')
                else:
                    tar.extractall(path=temp_dir)
                
            extracted_dir = os.path.join(temp_dir, "package")
            if not os.path.exists(extracted_dir):
                extracted_dir = temp_dir
                
            cmd_watch_new = [npm_command, "run", "scan:local", extracted_dir]
            
            try:
                stdout, stderr, elapsed, code = run_process(
                    cmd=cmd_watch_new,
                    cwd=str(MCP_WATCH_DIR),
                    timeout=TIMEOUT_SECONDS,
                    framework_name="MCP Watch"
                )
                return parse_mcp_watch(stdout)
            except TimeoutError:
                return failure("mcp-watch")
                
        except Exception as e:
            print(f"MCP Watch NPM package handling error: {e}")
            return failure("mcp-watch")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)