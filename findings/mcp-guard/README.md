# mcp-guard findings (19 categorie)

**Numeri aggiornati 2026-05-06 post blind-review** (vedi `analysisAllData/UPDATED_NUMBERS_2026-05-06.md`).

Pipeline: 96.500 raw → Stage 1 (`filter_mcp_guard.py`) → 28.125 → Stage 2A (HC) → Stage 2B (cache) → **5.774 VP / 22.959 FP** (post round 4 fix 2026-05-07).

## Summary 19 categorie

### Static (9)

| Categoria | Raw | Filtered | VP | FP | FP rate% (blind n=50) |
|-----------|----:|---------:|---:|---:|----------------------:|
| ssrf-static | 44.063 | 832 | 717 | 115 | 0.0 |
| hardcoded-credential-static | 18.438 | 4.701 | 650 | 4.051 | 2.8 |
| sql-injection-static | 4.886 | 2.689 | 2.375 | 314 | 6.9 |
| dangerous-tool-handler-static | 3.991 | 2.961 | 989 | 1.972 | 4.3 |
| path-traversal-static | 4.740 | 3.697 | 23 | 3.674 | <5 (post round 4) |
| prompt-injection-static | 2.016 | 435 | 16 | 420 | 0.0 |
| insecure-deserialization-static | 814 | 591 | 31 | 560 | 33.3 |
| code-injection-static | 318 | 241 | 184 | 57 | 0.0 |
| command-injection-static | 107 | 58 | 21 | 37 | 0.0 |

### Fuzzing (6)

| Categoria | Raw | Filtered | VP | FP | FP rate% (blind n=50) |
|-----------|----:|---------:|---:|---:|----------------------:|
| command-injection-fuzzing | 1.743 | 1.743 | 221 | 1.522 | 10.3 |
| path-traversal-fuzzing | 2.183 | 2.182 | 441 | 1.741 | ~10 (post round 2) |
| command-execution-fuzzing | 2.375 | 2.375 | 2 | 2.350 | 0 |
| code-injection-fuzzing | 538 | 538 | 36 | 488 | ~5 (post round 3) |
| information-disclosure-fuzzing | 1.360 | 1.360 | 4 | 1.334 | <5 (post round 4) |
| sensitive-info-disclosed-fuzzing | 5.626 | 3.120 | 1 | 3.119 | 0 |

### Protocol (4)

| Categoria | Raw | Filtered | VP | FP |
|-----------|----:|---------:|---:|---:|
| protocol-information-disclosure | 13 | 13 | 4 | 9 |
| protocol-path-traversal | 14 | 1 | 1 | 0 |
| protocol-missing-id | 79 | 79 | 0 | 79 |
| protocol-invalid-jsonrpc-version | 509 | 509 | 58 | 451 |

## Top categorie per VP

1. **sql-injection-static** (2.375 VP, 6.9% FP rate) — più grande pool VP, precision alta
2. **path-traversal-fuzzing** (1.106 VP, 33.3% FP rate)
3. **dangerous-tool-handler-static** (989 VP, 4.3% FP rate)
4. **information-disclosure-fuzzing** (770 VP, 62% FP rate ⚠️)
5. **ssrf-static** (717 VP, 0% FP rate)
6. **hardcoded-credential-static** (650 VP, 2.8% FP rate ✅ post-fix)
7. **command-injection-fuzzing** (221 VP, 10.3% FP rate)

## Categorie problematiche (FP rate ≥ 30%)

- `sensitive-info-disclosed-fuzzing` (75% FP) — signal weak strutturalmente
- `information-disclosure-fuzzing` (62% FP) — stack trace ambigui
- `path-traversal-fuzzing` (33% FP) — distinguere echo da exploit reale
- `insecure-deserialization-static` (33% FP) — sample piccolo
- `command-execution-fuzzing` (50% FP, ma pool=2) — già fixato a 2 VP

## ID di vulnerabilità per categoria

Vedere CLAUDE.md sezione "Post-processing mcp-guard" per dettagli completi su:
- HC rules per ogni categoria
- Pattern VP/FP riconosciuti
- Bug noti e fix applicati

## Output finali

Per ogni categoria in `analysisAllData/0_tool_mcp_guard/<cat>/filtered/llm_analysis/`:
- `vp.json` — VP finali (HC-VP + Stage2B-VP)
- `fp.json` — FP finali (HC-FP + Stage2B-FP)
- `audit.json` — log completo classificazione
- `_llm_api_cache.json` — cache verdetti

## Limitazioni note

**SAST regex-only**: pattern syntactic VP non sempre = vulnerability reale. Senza data-flow tracking, alcuni `cursor.execute(f"... {var}")` flag VP anche con `var` da fonte fidata (es. `sqlite_master` query).

**Fuzzing categorie**: signal weak quando server returns error con payload echo (NO actual exploitation). Categorie `path-traversal-fuzzing`, `information-disclosure-fuzzing`, `sensitive-info-disclosed-fuzzing` da considerare per spostamento Core → Appendice nel report tesi.

## Riferimenti

- Pipeline source: `analysisAllData/0_tool_mcp_guard/pipeline_mcp_guard.py`
- Filter source: `analysisAllData/0_tool_mcp_guard/filter_mcp_guard.py`
- Blind classifier: `analysisAllData/blind_classifier.py`
- Updated numbers report: `analysisAllData/UPDATED_NUMBERS_2026-05-06.md`
- Disagreement report: `analysisAllData/spot_check_all/_disagreement_report.md`
- Analysis guide: `analysisAllData/0_tool_mcp_guard/ANALYSIS_GUIDE.md`
