import requests
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# =========================
# CONFIG
# =========================
URL = "https://github.com/modelcontextprotocol/servers"
OUTPUT_XLSX = "01_modelcontextprotocol.xlsx"

# =========================
# FETCH PAGE
# =========================
headers = {
    "User-Agent": "Mozilla/5.0"
}

response = requests.get(URL, headers=headers)
response.raise_for_status()

soup = BeautifulSoup(response.text, "html.parser")

# =========================
# EXTRACT GITHUB REPO LINKS
# =========================
github_links = set()

for a in soup.find_all("a", href=True):
    href = a["href"]

    # Link relativi ai repo GitHub
    if href.startswith("/"):
        full_url = urljoin("https://github.com", href)
    else:
        full_url = href

    # Filtra solo repository GitHub veri
    if (
        full_url.startswith("https://github.com/")
        and full_url.count("/") >= 4
        and not any(x in full_url for x in ["/issues", "/pull", "/actions", "/wiki"])
    ):
        github_links.add(full_url)

# =========================
# SAVE TO EXCEL
# =========================
df = pd.DataFrame(sorted(github_links), columns=["repo_url"])
df.to_excel(OUTPUT_XLSX, index=False)

print(f"[OK] Salvati {len(df)} repository in {OUTPUT_XLSX}")
