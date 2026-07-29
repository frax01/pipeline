# indirect-prompt-injection (P-03) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Injection indiretta tramite risorse esterne (external://, http://). Lo scanner legge la risorsa e cerca pattern di injection nel contenuto.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 1 |
| Finding filtrati (tenuti) | 1 |
| Rimossi | 0 |
| Tasso di riduzione | 0.0% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `KEPT:kept` | 1 |

## Server unici con vulnerabilita' reali: 1

## Esempi di finding tenuti (max 15)

### 1. [clever-doc-mcp-server](https://github.com/LostInBrittany/clever-doc-mcp-server)

- **ID**: `P-03`
- **Severity**: `high`
- **Filter reason**: `kept`
- **Details**: ```[{"resource": {"uri": "https://www.clever-cloud.com/developers/llms.txt", "name": "Clever Cloud Documentation", "mimeType": "text/markdown"}, "suspicious": true, "exploited": false, "resource_read": {"result": {"contents": [{"uri": "https://www.clever-cloud.com/developers/llms.txt", "mimeType": "text/markdown", "text": "# Clever Cloud Documentation\n\n> Clever Cloud is a Platform-as-a-Service (PaaS) cloud provider, an automated hosting platform for developers. Deploy your app easily and launch dependencies without having to worry about the infrastructure set up.\n\n## API\n- [APIv4 Reference](https://www.clever.cloud/developers/api/v4/index.html.md): Reference documentation for the Clever Cloud APIv4 for billing, deployments, load balancers, logs, operators, etc.\n- [Clever Cloud API Overv... [troncato]```

## Interpretazione

Finding filtrati per la categoria `indirect-prompt-injection`.

## Lista completa server vulnerabili

- https://github.com/LostInBrittany/clever-doc-mcp-server
