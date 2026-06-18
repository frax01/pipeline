# web_crawler — Raccolta degli URL dei server MCP

Insieme di scraper che raccolgono gli URL dei repository di server MCP dalle
varie **directory pubbliche** (MCP marketplace, awesome-list, registri npm/Docker,
ecc.). L'output di ogni scraper è un Excel di URL GitHub; tutti gli output
confluiscono poi nella deduplica in [`../hashAnalysis/`](../hashAnalysis/) che
produce il dataset finale `0.0. All servers unified (69104).xlsx`.

## Pipeline di raccolta (ordine logico)

```
web_crawler/NN_*.py  (uno scraper per sorgente)  ──►  NN_*.xlsx per-sorgente
        │
        └──►  hashAnalysis/  (dedup per hash del contenuto)  ──►  dataset unico (69104)
```

## Scraper per sorgente

I numeri `NN_` corrispondono alle **fonti numerate nella tesi**. Ogni scraper
`NN_nome.py` salva il proprio output in `NN_nome.xlsx`. Le poche fonti che
richiedono più di uno script usano un suffisso (stesso numero).

| # tesi | Script | Sorgente |
|--------|--------|----------|
| 1 | `01_modelcontextprotocol.py` | github.com/modelcontextprotocol/servers |
| 2 | `02_mcpmarket.py` | mcpmarket.com (API JSON) |
| 3 | `03_mcpso.py` | mcp.so |
| 4 | `04_smithery.py` | registry.smithery.ai (richiede `SMITHERY_API_KEY`) |
| 5 | `05_pulsemcp.py` | pulsemcp.com |
| 6 | `06_glama.py` | glama.ai (via sitemap XML) |
| 7 | `07_cursor.py` | cursor.directory (Playwright) |
| 8 | `08_awesome_mcp.py` | punkpeye/awesome-mcp-servers (README) |
| 9 | `09_mcpservers_org.py` + `09_mcpservers_org_missing.py` | mcpservers.org/all (scrape principale + recupero link mancanti, stesso `.xlsx`) |
| 9 | `09_mcpservers_org_playwright.py` | mcpservers.org/all (implementazione alternativa Playwright) |
| 10 | `10_docker_catalog.py` | hub.docker.com/mcp/explore (Selenium + readme) |
| 11 | `11_mcpget.py` | mcp-get.com |
| 12 | `12_mcpstore.py` | mcpstore.co (API JSON) |
| 13 | `13_mcpworld.py` | mcpworld.com (API, con ripresa) |
| 14 | `14_mcprepository_collect.py` → `14_mcprepository_resolve.py` | mcprepository.com (pipeline 2 passi: raccogli URL → risolvi link GitHub) |
| 15 | `15_aibase.py` | mcp.aibase.com |
| 16 | `16_github_search.py` | github.com/search (richiede `GITHUB_TOKEN`) |
| 17 | `17_npm.py` | registry npm |
| 18 | — | npx-runnable: **non** uno scraper qui, è la pipeline npx (vedi `../npm_runner/`) |

## Come eseguire

### Tutti in un colpo

```bash
python run_all.py            # esegue in sequenza tutti gli scraper
python run_all.py --list     # elenca gli scraper senza eseguirli
python run_all.py --only 01,06,14   # solo alcuni (per numero-fonte)
python run_all.py --skip 13,17      # tutti tranne questi
```
`run_all.py` lancia ogni scraper come sottoprocesso isolato, **continua anche se
uno fallisce** e stampa un riepilogo finale. Gli scraper che richiedono una chiave
(`04`, `16`) vengono **saltati** con un avviso se la relativa env var non è
impostata. È un'esecuzione sequenziale e alcune fonti sono molto lunghe.

### Uno scraper alla volta

Ogni scraper è indipendente e si lancia anche da solo:
```bash
pip install -r ../requirements.txt      # requests, beautifulsoup4, openpyxl, aiohttp, pandas, playwright, selenium
python 01_modelcontextprotocol.py
python 02_mcpmarket.py
# ... e così via per ogni sorgente
```
Ognuno salva il suo `NN_nome.xlsx` con gli URL trovati. Gli `.xlsx` di output e i
file dati (es. `sitemap_test.xml`) **non sono versionati** (vedere `.gitignore`).

Per le fonti multi-script l'ordine conta:
```bash
python 09_mcpservers_org.py            # crea 09_mcpservers_org.xlsx
python 09_mcpservers_org_missing.py    # lo aggiorna con i link mancanti

python 14_mcprepository_collect.py     # crea 14_mcprepository_servers.xlsx
python 14_mcprepository_resolve.py     # legge quello e crea 14_mcprepository_github.xlsx
```

### Chiavi richieste (variabili d'ambiente)

Le chiavi **non** sono hardcoded nel codice:

| Scraper | Variabile | Note |
|---------|-----------|------|
| `04_smithery.py` | `SMITHERY_API_KEY` | token API del registry Smithery |
| `16_github_search.py` | `GITHUB_TOKEN` | PAT GitHub (necessario per volumi alti di ricerca) |

```bash
export SMITHERY_API_KEY=...   # solo per 04_smithery.py
export GITHUB_TOKEN=...        # solo per 16_github_search.py
```

## Origine

La sorgente originale degli scraper resta su Google Drive
([cartella](https://drive.google.com/drive/folders/1bA82n0ILw7H2Jq1_g0bbcGXR3a5_1JfN));
qui sono tutti versionati e rinominati secondo la numerazione della tesi.
