# web_crawler — Raccolta degli URL dei server MCP

Insieme di scraper che raccolgono gli URL dei repository di server MCP dalle
varie **directory pubbliche** (MCP marketplace, awesome-list, registri npm/Docker,
ecc.). L'output di ogni scraper è un Excel di URL GitHub; tutti gli output
confluiscono poi nella deduplica in [`../hashAnalysis/`](../hashAnalysis/) che
produce il dataset finale `0.0. All servers unified (69104).xlsx`.

## Pipeline di raccolta (ordine logico)

```
web_crawler/*.py  (uno scraper per sorgente)  ──►  Excel per-sorgente
        │
        └──►  hashAnalysis/  (dedup per hash del contenuto)  ──►  dataset unico (69104)
```

## Scraper per sorgente

| Script | Sorgente raccolta |
|--------|-------------------|
| `01_ModelContextProtocolServer.py` | github.com/modelcontextprotocol/servers |
| `02_mcpMarketServer.py` | mcpmarket.com (API JSON) |
| `03_mcpSoServer.py` | mcp.so |
| `04_newSmithery.py` | smithery.ai |
| `05_pulseMcpServer.py` | pulsemcp.com |
| `07_importCursor.py` | cursor.directory |
| `08_awesomeMcpServer.py` | punkpeye/awesome-mcp-servers (README) |
| `09_Awesome2.py` | altra awesome-list MCP |
| `11_mcpDockerServer.py`, `dockerMcpServer.py` | Docker MCP catalog |
| `13_McpGet.py` | mcp-get.com |
| `mcpStoreMcpServer.py` | mcp.store |
| `npmMcpServer.py` | registro npm |
| `importMcpServerFromGithub.py` | ricerca GitHub |
| `aibase.py` | aibase.com |
| `mcpworld.py` | mcpworld |
| `glama_scraper/` | glama.ai (via sitemap XML) |
| `mcp_store/`, `mcp_repository/` | varianti scraping GitHub link |

## Come eseguire

Ogni scraper è indipendente e si lancia da solo:
```bash
pip install -r ../requirements.txt      # requests, beautifulsoup4, openpyxl, aiohttp, pandas
python 01_ModelContextProtocolServer.py
python 02_mcpMarketServer.py
# ... e così via per ogni sorgente
```
Ognuno salva un `.xlsx` con gli URL trovati. Gli `.xlsx` di output e i file dati
(es. `sitemap_test.xml`) **non sono versionati** (vedere `.gitignore`).

## Set completo degli script

Per leggerezza in questo repo sono inclusi gli scraper principali. Il set
**completo** (tutti gli script + sottocartelle) è su Google Drive; per scaricarlo
in un colpo, mantenendo la struttura:

```bash
pip install gdown
gdown --folder https://drive.google.com/drive/folders/1bA82n0ILw7H2Jq1_g0bbcGXR3a5_1JfN -O web_crawler
```
