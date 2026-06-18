import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from openpyxl import Workbook


BASE_URL = "https://www.pulsemcp.com"
LISTING_URL = BASE_URL + "/servers?page={}"


HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; MCP-Research/1.0)"
}


def get_server_pages(page_num):
    url = LISTING_URL.format(page_num)


    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Timeout o errore su pagina {page_num}: {e}")
        return []   # NON crashare


    soup = BeautifulSoup(r.text, "html.parser")


    links = []
    for a in soup.select('a[href^="/servers/"]'):
        href = a.get("href")
        if href and href.count("/") == 2:
            links.append(urljoin(BASE_URL, href))


    return list(set(links))


def get_github_repo(server_url):
    try:
        r = requests.get(server_url, headers=HEADERS, timeout=20)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"      [!] Errore rete su {server_url}: {e}")
        return None


    soup = BeautifulSoup(r.text, "html.parser")


    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True).lower()
        href = a["href"]


        if "github" in text or "github.com" in href:
            if href.startswith("http"):
                return href


    return None




def main():
    wb = Workbook()
    ws = wb.active
    ws.title = "PulseMCP Servers"
    ws.append(["Server Page", "GitHub Repository"])


    visited_servers = set()
    page = 70


    while True:
        print(f"[+] Scansione pagina {page}")
        servers = get_server_pages(page)


        if not servers:
            print("[!] Nessun server trovato, fine paginazione")
            break


        for server_url in servers:
            if server_url in visited_servers:
                continue


            visited_servers.add(server_url)
            print(f"    ↳ Server: {server_url}")


            github = get_github_repo(server_url)
            ws.append([server_url, github or "NOT FOUND"])


            time.sleep(0.5)  # cortesia verso il sito


        page += 1


    output = "05_pulsemcp.xlsx"
    wb.save(output)
    print(f"\n[✓] Excel salvato in: {output}")


if __name__ == "__main__":
    main()
