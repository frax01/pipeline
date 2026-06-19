import asyncio
import aiohttp
from bs4 import BeautifulSoup
from openpyxl import Workbook

BASE_URL = "https://mcp.so"
SERVERS_URL = "https://mcp.so/servers?page={}"

HEADERS = {"User-Agent": "Mozilla/5.0"}

CONCURRENCY = 5
sem = asyncio.Semaphore(CONCURRENCY)

failed_servers = []


async def fetch(session, url):
    async with sem:
        try:
            async with session.get(url, headers=HEADERS) as resp:
                if resp.status != 200:
                    failed_servers.append((url, f"HTTP {resp.status}"))
                    return None
                return await resp.text()
        except Exception as e:
            failed_servers.append((url, f"Exception: {e}"))
            return None


async def get_server_detail_links(session, page_number):
    url = SERVERS_URL.format(page_number)
    html = await fetch(session, url)

    if not html:
        failed_servers.append((url, "Empty page"))
        return []

    soup = BeautifulSoup(html, "html.parser")

    # Trova la griglia dei server
    grid = soup.select_one("div.grid.gap-4.grid-cols-1.sm\\:grid-cols-2.lg\\:grid-cols-3.xl\\:grid-cols-4")
    if not grid:
        return []

    servers = []
    a_tags = grid.find_all("a", href=True)

    for a in a_tags:
        href = a["href"]
        if href.startswith("/server/"):
            servers.append(BASE_URL + href)

    # Stampa quanti server trovati nella pagina
    print(f"Pagina {page_number}: trovati {len(servers)} server")

    return servers


async def extract_repo_link(session, detail_url):
    html = await fetch(session, detail_url)
    if not html:
        failed_servers.append((detail_url, "Empty detail"))
        return ("Unknown", detail_url, None)

    soup = BeautifulSoup(html, "html.parser")

    # Nome server
    h1 = soup.find("h1")
    name = h1.text.strip() if h1 else "Unknown"

    # Cerca la div che contiene "Visit Server"
    container = soup.select_one("div.flex.flex-wrap.items-start.gap-4.mt-8")
    if not container:
        failed_servers.append((detail_url, "Visit Server container missing"))
        return (name, detail_url, None)

    # Dentro ci sono div .px-8 con il link
    repo_link = None
    for div in container.select("div.flex.items-center.gap-2.px-8 a"):
        if "Visit Server" in div.text:
            repo_link = div.get("href")
            break

    if repo_link:
        print(f"SERVER FOUND → {repo_link}")  # stampa link github
    else:
        failed_servers.append((detail_url, "GitHub repo missing"))

    return (name, detail_url, repo_link)


def save_failed_servers():
    if not failed_servers:
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "Failed Servers"
    ws.append(["URL", "Error"])

    for url, err in failed_servers:
        ws.append([url, err])

    wb.save("03_mcpso_failed.xlsx")


async def main():
    TOTAL_PAGES = 274

    wb = Workbook()
    ws = wb.active
    ws.title = "MCP Servers"
    ws.append(["Name", "Detail Page", "Repository Link"])

    async with aiohttp.ClientSession() as session:

        all_detail_urls = set()

        # Primo giro: tutte le pagine
        for page in range(1, TOTAL_PAGES + 1):
            links = await get_server_detail_links(session, page)
            all_detail_urls.update(links)

        print("\n===================================")
        print(f"Totale server trovati: {len(all_detail_urls)}")
        print("===================================\n")

        # Secondo giro: dettagli server
        tasks = [extract_repo_link(session, url) for url in all_detail_urls]
        results = await asyncio.gather(*tasks)

        # salva sul file
        for row in results:
            ws.append(row)

        wb.save("03_mcpso.xlsx")
        save_failed_servers()


if __name__ == "__main__":
    asyncio.run(main())
