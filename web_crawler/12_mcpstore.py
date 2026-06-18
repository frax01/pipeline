import requests
import math
import re
from openpyxl import Workbook

BASE_API = "https://mcpstore.co/api"
PER_PAGE = 100
OUTPUT_FILE = "12_mcpstore.xlsx"

HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (MCP-Research)"
}

# =========================
# UTILS
# =========================

def normalize_github_url(url: str) -> str:
    if not url:
        return ""
    m = re.match(r"(https://github\.com/[^/]+/[^/]+)", url)
    return m.group(1) if m else ""

# =========================
# 1️⃣ TOTAL COUNT
# =========================

r = requests.get(f"{BASE_API}/total-count", headers=HEADERS, timeout=30)
r.raise_for_status()

total = r.json().get("count", 0)
pages = math.ceil(total / PER_PAGE)

print(f"[+] Server totali: {total}")
print(f"[+] Pagine da scaricare: {pages}")

# =========================
# 2️⃣ RACCOLTA SERVER
# =========================

repos = set()

for page in range(1, pages + 1):
    print(f"[+] Pagina {page}/{pages}")

    r = requests.get(
        f"{BASE_API}/servers",
        params={
            "page": page,
            "per_page": PER_PAGE
            # puoi aggiungere:
            # "category": "hosted",
            # "sort_by": "popular"
        },
        headers=HEADERS,
        timeout=30
    )
    r.raise_for_status()

    data = r.json()
    servers = data.get("servers", [])

    for srv in servers:
        gh = (
            srv.get("data_url")
            or srv.get("github")
            or srv.get("github_url")
        )

        gh = normalize_github_url(gh)
        if gh:
            repos.add(gh)

print(f"[✓] Repository GitHub unici: {len(repos)}")

# =========================
# 3️⃣ SALVA EXCEL
# =========================

wb = Workbook()
ws = wb.active
ws.title = "MCP Store Servers"

ws.append(["github_repo"])

for repo in sorted(repos):
    ws.append([repo])

wb.save(OUTPUT_FILE)

print(f"[✓] Excel salvato in {OUTPUT_FILE}")
