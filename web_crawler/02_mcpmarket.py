import asyncio
import aiohttp
from openpyxl import Workbook

API_URL = "https://mcpmarket.com/api/search?q=&offset={}&limit=48"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

CONCURRENCY = 10
sem = asyncio.Semaphore(CONCURRENCY)

failed_requests = []


async def fetch_json(session, url):
    async with sem:
        try:
            async with session.get(url, headers=HEADERS) as resp:
                print(f"[FETCH] {url} -> {resp.status}")

                if resp.status != 200:
                    failed_requests.append((url, f"HTTP {resp.status}"))
                    return None

                data = await resp.json()
                print(f"data keys: {list(data.keys())}")
                return data

        except Exception as e:
            failed_requests.append((url, f"Exception {e}"))
            return None


async def scrape_all_servers():
    servers = []
    offset = 0

    async with aiohttp.ClientSession() as session:
        while True:
            url = API_URL.format(offset)
            data = await fetch_json(session, url)

            if not data or "tools" not in data:
                print("[STOP] Nessun dato — struttura JSON inattesa")
                break

            batch = data["tools"]
            print(f"[BATCH] offset={offset}  count={len(batch)}")

            if not batch:
                print("[STOP] Batch vuoto → finito")
                break

            for s in batch:
                name = s.get("name", "Unknown")
                slug = s.get("slug", "")
                detail_url = f"https://mcpmarket.com/server/{slug}"
                github = s.get("owner", {}).get("url")
                author = s.get("owner", {}).get("name")
                desc = s.get("description", "").strip()
                stars = s.get("github_stars", 0)

                servers.append([
                    name, detail_url, github, author, desc, stars
                ])

            # 🔥 La chiave corretta è pagination → hasMore
            pagination = data.get("pagination", {})
            has_more = pagination.get("hasMore", False)

            if not has_more:
                print("[STOP] hasMore = false → completato")
                break

            offset += 48

    return servers


def save_excel(servers):
    wb = Workbook()
    ws = wb.active
    ws.title = "MCPMarket Servers"

    ws.append(["Name", "Detail URL", "GitHub Owner URL", "Author", "Description", "GitHub Stars"])

    for row in servers:
        ws.append(row)

    wb.save("02_mcpmarket.xlsx")
    print("✔ File salvato: 02_mcpmarket.xlsx")


def save_failed():
    if not failed_requests:
        print("\n🎉 Nessun errore")
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "Failed"

    ws.append(["URL", "Error"])

    for url, err in failed_requests:
        ws.append([url, err])

    wb.save("02_mcpmarket_failed.xlsx")
    print(f"✔ File errori salvato: 02_mcpmarket_failed.xlsx ({len(failed_requests)} errori)")


async def main():
    print("\n=======================================")
    print("   SCARICO TUTTI I SERVER MCPMarket   ")
    print("=======================================\n")

    servers = await scrape_all_servers()

    print(f"\n[TOTAL] Server totali: {len(servers)}\n")

    save_excel(servers)
    save_failed()


if __name__ == "__main__":
    asyncio.run(main())
