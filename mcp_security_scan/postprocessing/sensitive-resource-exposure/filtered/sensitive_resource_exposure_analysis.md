# sensitive-resource-exposure (R-03) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Risorse con URI private:// o nomi sospetti (credential, secret, token, key, password) che espongono dati sensibili nel contenuto.

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

### 1. [octagon-mcp-server](https://github.com/OctagonAI/octagon-mcp-server)

- **ID**: `R-03`
- **Severity**: `high`
- **Filter reason**: `kept`
- **Details**: ```[{"resource": {"title": "Initialize the client with Octagon's API base and your API key", "description": "client = OpenAI(", "mimeType": "text/markdown", "uri": "octagon-docs://page/docs%3Ainitialize-the-client-with-octagons-api-base-and-your-api-key", "name": "docs:initialize-the-client-with-octagons-api-base-and-your-api-key"}, "resp": {"result": {"contents": [{"uri": "octagon-docs://page/docs%3Ainitialize-the-client-with-octagons-api-base-and-your-api-key", "mimeType": "text/markdown", "text": "# Initialize the client with Octagon's API base and your API key\nclient = OpenAI(\n    base_url=\"https://api.octagonai.co/v1\",\n    api_key=\"your-octagon-api-key\"  # Replace with your actual API key\n)"}]}, "jsonrpc": "2.0", "id": 1}}, {"resource": {"title": "Initialize the client with Octag... [troncato]```

## Interpretazione

Finding filtrati per la categoria `sensitive-resource-exposure`.

## Lista completa server vulnerabili

- https://github.com/OctagonAI/octagon-mcp-server
