# tool_fuzzing findings (4 categorie)

**Numeri aggiornati 2026-05-06 post blind-review** (vedi `analysisAllData/UPDATED_NUMBERS_2026-05-06.md`).

Pipeline: 117.724 raw → Stage 1 (`filter_fuzzing.py`) → 17.841 → Stage 2A (HC) → Stage 2B → **776 VP / 17.065 FP**.

## Summary 4 categorie

| Categoria | Raw | Filtered | VP | FP | FP rate% (blind n=50) | Nota |
|-----------|----:|---------:|---:|---:|----------------------:|------|
| protocol-fuzzing | 103.394 | 3.511 | **775** | 2.736 | 2.1 | -787 vs precedente |
| server-error-fuzzing | 10.944 | 10.944 | 0 | 10.944 | 0 | Tutti FP (resilience ≠ security) |
| transport-failure-fuzzing | 3.385 | 3.385 | 0 | 3.385 | 0 | Tutti FP (transport noise) |
| server-crash-fuzzing | 1 | 1 | 1 | 0 | 0 | 1 VP (Python AttributeError) |
| **Totale** | **117.724** | **17.841** | **776** | **17.065** | | |

## Categorie

### protocol-fuzzing (775 VP)

Probe runtime: invia richieste JSON-RPC malformate per ogni protocol type MCP.

VP = server processa richieste malformate su protocol type security-relevant:
- `GenericJSONRPCRequest`: server processa metodi arbitrari (`unknown/method`, `custom/method`)
- `CreateMessageRequest`: server processa LLM call malformato
- `ReadResourceRequest`: server accetta resource read malformato (NON URI standard)

FP HC nuove (post 2026-05-06):
- `InitializeRequest` con success rate ≥80% = comportamento corretto (initialize è metodo valido, NON malformed)
- `ReadResourceRequest` con URI standard (file:///tmp/test.txt, resource://server/data, https://example.com/resource) = compliance test, NO security signal

### server-crash-fuzzing (1 VP)

1 server con Python `AttributeError` runtime crash → bug reale, VP.

### server-error-fuzzing (0 VP)

10.944 finding tutti FP. HC rules security-first:
- VP solo se input malicious accettato come `inputs_successful` o dangerous tool con 100% failure (DoS)
- Default FP (resilience issue ≠ security)

### transport-failure-fuzzing (0 VP)

3.385 finding tutti FP. HC rules:
- VP solo se "Failed to send" + 100% failure (server crash)
- Default FP (transport noise)

## Limiti tool_fuzzing

**Schema povero**: NO response body nei finding raw. Detection limitata a:
- DoS (tool/server crashed)
- Protocol violation (server accept malformed)
- Python crash (rare)

NON utile per: SAST findings, hidden instructions, hardcoded creds, injection vulns.

**Bug noto fix (2026-05-06)**: `_SE_EXTERNAL_SERVER` regex matchava `github` in URL `https://github.com/...` → tutti server flag esterni. Fix: applicare a `server_name`, NON `server_url`.

## Output finali

Per ogni categoria in `analysisAllData/0_tool_fuzzing/<cat>/filtered/llm_analysis/`:
- `vp.json` — VP finali
- `fp.json` — FP finali
- `audit.json` — log completo
- `_llm_api_cache.json` — cache verdetti

## Riferimenti

- Pipeline source: `analysisAllData/0_tool_fuzzing/pipeline_fuzzing.py`
- Filter source: `analysisAllData/0_tool_fuzzing/filter_fuzzing.py`
- Updated numbers: `analysisAllData/UPDATED_NUMBERS_2026-05-06.md`
- Analysis guide: `analysisAllData/0_tool_fuzzing/ANALYSIS_GUIDE.md`
