import requests
import re
from openpyxl import Workbook

README_URL = "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md"

def main():
    print("[+] Scarico README awesome-mcp-servers")
    r = requests.get(README_URL, timeout=20)
    r.raise_for_status()
    text = r.text

    # Regex per link GitHub a repo
    github_repos = set(
        re.findall(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text)
    )

    print(f"[+] Trovati {len(github_repos)} repository")

    wb = Workbook()
    ws = wb.active
    ws.title = "Awesome MCP Servers"
    ws.append(["GitHub Repository"])

    for repo in sorted(github_repos):
        ws.append([repo])

    output = "awesome_mcp_servers.xlsx"
    wb.save(output)

    print(f"[✓] Excel salvato in: {output}")

if __name__ == "__main__":
    main()
