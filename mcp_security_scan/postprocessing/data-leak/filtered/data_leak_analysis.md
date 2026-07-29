# data-leak (A-03) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Token passati nel response senza indirection. Lo scanner chiama upstream_access e cerca pattern come 'access_token', 'sk-', 'bearer'. Il filtro scarta errori che dicono 'token mancante' e tiene solo risposte con token reali.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 11 |
| Finding filtrati (tenuti) | 1 |
| Rimossi | 10 |
| Tasso di riduzione | 90.9% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `REJECTED:error_about_missing_credentials` | 5 |
| `REJECTED:error_response_no_leak` | 4 |
| `REJECTED:no_data_leak_evidence` | 1 |
| `KEPT:suspicious_result_content` | 1 |

## Server unici con vulnerabilita' reali: 1

## Esempi di finding tenuti (max 15)

### 1. [autodoc-ai-mcp-server](https://github.com/aisirij/autodoc-ai-mcp-server)

- **ID**: `A-03`
- **Severity**: `critical`
- **Filter reason**: `suspicious_result_content`
- **Details**: ```{"result": {"content": [{"type": "text", "text": "❌ Error: Unknown tool: upstream_access\n\n💡 **Troubleshooting Tips:**\n- Check that your project path exists and contains source files\n- Verify your OpenAI API key is valid and starts with \"sk-\"\n- Ensure you have write permissions to the output directory\n- For Java projects, make sure you have .java files in src/ directories\n- Check that your OpenAI account has available credits"}], "isError": true}, "jsonrpc": "2.0", "id": 1}```

## Interpretazione

I finding tenuti mostrano server che hanno esposto token o credenziali reali nel response. I finding scartati sono errori che dicono 'token mancante' (il server richiede config, non sta leakando token).

## Lista completa server vulnerabili

- https://github.com/aisirij/autodoc-ai-mcp-server
