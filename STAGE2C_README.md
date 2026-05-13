# Stage 2C — Auto Audit (`stage2c_auto_audit.py`)

Classificazione automatica VP-C / VP-L / VP-D / FP dei finding già filtrati dalla pipeline (Stage 1 + 2A + 2B). Riapplica la stessa euristica del `MANUAL_AUDIT_REPORT.md` sui medesimi **1.122 finding** (Top 100 multi-source per meta-categoria) ma in modo riproducibile, scalabile e auditabile.

## Sample size: 1.122 finding

Il sample è organizzato per **meta-categoria** (allineata alla §5.1 di THREAT_ANALYSIS_REPORT.md), ognuna delle quali può raccogliere finding da **multiple sorgenti vp.json** (cross-framework).

**Distribuzione**:

| Meta-cat | Sources | Size |
|----------|---------|-----:|
| 1. sql-injection | mcp-guard/sql-injection-static | 100 |
| 2. dangerous-capabilities | mcp-security-scan + mcp-guard/dangerous-tool-handler | 50 + 50 |
| 3. credential-leak | mcp-watch + mcp-guard/hardcoded-credential | 50 + 50 |
| 4. ssrf | mcp-guard/ssrf-static | 100 |
| 5. untrusted-content | mcp-scan/server-level (W015) | 100 |
| 6. path-traversal | mcp-guard/static + fuzzing + mcp-security-scan | 23 + 72 + 5 |
| 7. command-injection | mcp-guard/static + fuzzing + execution-fuzzing | 21 + 77 + 2 |
| 8. code-injection | mcp-guard/static + fuzzing | 64 + 36 |
| 9. input-validation | mcp-watch + mcp-security-scan | 50 + 50 |
| 10. protocol-violation | mcp-watch + mcp-guard/invalid-jsonrpc-version | 79 + 21 |
| 11. prompt-injection | mcp-scan + mcp-guard + mcp-shield/hidden-instructions | 36 + 16 + 4 |
| 12. insecure-deserialization | mcp-guard (ALL) | 31 |
| 13. sensitive-file-access | mcp-shield + mcp-security-scan (ALL) | 11 + 5 |
| 14. sensitive-info-disclosure | 3 mcp-guard sources (ALL) | 4 + 1 + 4 |
| 15. access-control | mcp-watch (ALL) | 7 |
| 16. data-exfiltration | mcp-watch (ALL) | 2 |
| 17. tool-shadowing | mcp-shield (ALL) | 1 |
| **TOTALE** | | **1.122** |

## Cosa fa

Per ogni finding del sample:

1. **Carica** la metadata da `vp.json` (server_url, file, line, evidence, tool_name)
2. **Fetcha** il file sorgente reale da `raw.githubusercontent.com` (cache locale persistente)
3. **Estrae** un context window di ±30 righe attorno alla riga del finding
4. **Costruisce** un prompt strutturato con:
   - Taxonomia esplicita VP-C/VP-L/VP-D/FP
   - Metadata del finding + repo description
   - Context source code con riga del finding marcata `>>`
5. **Chiama** Claude API (`claude-sonnet-4-5` di default) con `tool_use` per output JSON validato
6. **Se confidence < 70**: re-prompt con file completo e best-guess calibrato (no estimates)
7. **Cache** ogni verdetto in `stage2c_cache/llm_verdicts.json` (riprese idempotenti)
8. **Aggrega** in report Markdown + JSON strutturato + comparison vs ground truth manuale

## Setup

Variabili d'ambiente richieste:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

# Opzionale: GITHUB_TOKEN per evitare rate limit GitHub API (60 req/h non auth, 5000/h con token)
export GITHUB_TOKEN="ghp_..."
```

Dipendenze: **nessuna installazione pip** (solo `urllib` stdlib). Compatibile con Python ≥ 3.9.

## Esecuzione

### Tutti i 1.122 finding del sample MANUAL_AUDIT

```bash
py -X utf8 stage2c_auto_audit.py --all
```

Tempo stimato: 30-60 minuti con `--concurrency 5`. Costo Claude API: ~$6-10 totali (Sonnet 4.5 con prompt caching).

### Una sola categoria

```bash
py -X utf8 stage2c_auto_audit.py --category sql-injection
py -X utf8 stage2c_auto_audit.py --category credential-leak --limit 10
```

### Solo rigenerare i report dalla cache

Utile dopo aver modificato la logica di reporting senza re-spendere API:

```bash
py -X utf8 stage2c_auto_audit.py --all --report-only
```

### Dry-run (preview del sample senza chiamare API)

```bash
py -X utf8 stage2c_auto_audit.py --all --dry-run
```

### Opzioni complete

| Flag | Default | Descrizione |
|------|---------|-------------|
| `--all` | — | Processa tutti i 1.122 finding del sample |
| `--category XXX` | — | Filtra una sola categoria (substring match su chiave) |
| `--limit N` | — | Massimo N finding totali (per test) |
| `--model MODEL` | `claude-sonnet-4-5` | Modello Claude da usare |
| `--concurrency N` | 5 | Worker paralleli |
| `--report-only` | — | Rigenera solo i report dalla cache esistente |
| `--dry-run` | — | Stampa il sample senza chiamare API |

## Output

```
stage2c_cache/
├── github/                          # File sorgenti cachati (uno per finding)
└── llm_verdicts.json                # Verdetti LLM cachati (idempotenti)

stage2c_output/
├── verdicts.json                    # Verdetti finali strutturati (riproducibili)
├── auto_audit_report.md             # Report Markdown analogo a MANUAL_AUDIT_REPORT
└── comparison_vs_manual.md          # Confronto totali auto vs ground truth manuale
```

### Struttura di un verdetto in `verdicts.json`

```json
{
  "finding_key": "a3f7c2...",
  "category": "1.sql-injection",
  "server_url": "https://github.com/JexinSam/mssql_mcp_server",
  "file": "src/mssql_mcp_server/server.py",
  "line": 82,
  "tool_name": "",
  "evidence_excerpt": "Static analysis found... cursor.execute(f\"SELECT TOP 100 * FROM {table}\")",
  "github_file_available": true,
  "verdict": "VP-C",
  "confidence": 95,
  "reasoning": "table = parts[0] from URI in read_resource() handler, no validation. pyodbc supports stacked queries on MSSQL...",
  "key_quote": "cursor.execute(f\"SELECT TOP 100 * FROM {table}\")",
  "tainted_source": "MCP resource URI path component",
  "mitigation_present": false,
  "needs_more_context": false,
  "reprompted": false,
  "model": "claude-sonnet-4-5",
  "timestamp": 1747059612
}
```

## Garanzia di precisione (no stime, no ipotesi)

Lo script è progettato per produrre **numeri concreti**, non statistiche stimate:

- **Re-prompting con full file** se `confidence < 70`: il modello rilegge il file completo (fino a 30KB) e ricalibra. Se ancora incerto, dà un best-guess esplicito con confidence reale.
- **Marker `needs_more_context: true`** se la classificazione richiederebbe analisi di file aggiuntivi (caller, README, altri tool dello stesso server). Questi finding sono ancora classificati con la migliore evidenza disponibile, ma il flag permette di identificarli per follow-up manuale.
- **Marker `github_file_available: false`** se il file non è raggiungibile (repo private, branch diverso, file rimosso). In quel caso il verdetto è basato solo sulla `evidence` originale.
- **Verdetto `ERROR`** se la chiamata API fallisce dopo retry esponenziale. Questi finding sono visibili nel report e non sporcano le statistiche dei verdetti reali.
- **Cache idempotente**: ogni finding viene classificato esattamente UNA volta; rilanciare lo script non altera i verdetti già emessi (utile per riproducibilità della tesi).

## Confronto con MANUAL_AUDIT_REPORT.md

Lo script genera automaticamente `comparison_vs_manual.md` con il confronto totale-per-totale per ogni categoria. L'**aggregate agreement** misura quanto i conteggi automatici coincidono con la classificazione manuale.

Aspettative basate su pre-esperimenti:
- Categorie ad alta confidenza (`untrusted-content`, `prompt-injection`, `credential-leak`): agreement ≥ 95%
- Categorie con molti VP-L by-design (`dangerous-capabilities`, `sql-injection`, `sensitive-file-access`): agreement 85-95%
- Categorie ambigue (`insecure-deserialization`, `path-traversal-static`): agreement 75-90%

Se l'agreement è alto, il valore metodologico è: **il sample manuale serve come ground truth, l'automatico permette di scalare a tutti i ~18.000 VP del dataset completo** mantenendo la stessa accuratezza.

## Costi & rate limit

- **Claude API**: ~$0.005-$0.010 per finding (Sonnet 4.5, context ±30 righe + re-prompt). Sul sample da 1.122: **$6-10 totali**. Sull'intero universo ~18k VP: **$100-200**.
- **GitHub raw**: nessun rate limit pratico (unauth ok per file <1MB).
- **GitHub API repos**: 60 req/h unauth → consigliato `GITHUB_TOKEN` per repos description (cache aiuta comunque).

## Limiti noti

1. **Intra-procedural data flow non automatizzato**: per verificare se i caller sono tutti hardcoded (caso `context-portal`) servirebbe AST parsing dei file Python/JS. Lo script lascia questi finding marcati `needs_more_context: true` con verdetto best-guess.
2. **Sample fisso ai 536 finding del MANUAL_AUDIT**: per estendere all'intero universo, modifica `SAMPLE_SCHEME` rimuovendo il limit (`None` invece di 50).
3. **Modello LLM**: la classificazione dipende dalla qualità di Claude. Sonnet 4.5 è raccomandato; Haiku 4.5 funziona ma con perdita di accuratezza ~5-10%.

## Estensione futura

Per ampliare a tutti i ~18.000 VP del dataset:

```python
# In stage2c_auto_audit.py, modifica SAMPLE_SCHEME:
"1.sql-injection": ("...", None),  # None = intero universo (2375 finding)
```

Ribattezza l'output dir (es. `stage2c_output_full/`) per non sovrascrivere il sample-MANUAL.
