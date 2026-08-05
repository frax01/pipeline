# Perche' e' calato il consenso cross-framework

- prima analisi : 11,841 server con VP
- rirun         : 11,487 server con VP

## Matrice di transizione (righe = prima, colonne = rirun)

| prima \ rirun | Tier 1 | Tier 2 | Tier 3 | assente | totale |
|---|---:|---:|---:|---:|---:|
| **Tier 1** | 0 | 12 | 5 | 1 | 18 |
| **Tier 2** | 1 | 726 | 2,170 | 135 | 3,032 |
| **Tier 3** | 0 | 261 | 5,589 | 2,941 | 8,791 |
| **assente** | 0 | 50 | 2,673 | 0 | 2,723 |

## Server che hanno perso la concordanza: **2,311**

(prima segnalati da >= 2 framework, ora da meno di 2)

Framework che il server aveva prima e ora non ha piu':

| framework | volte perso nei declassati | volte perso in totale |
|---|---:|---:|
| mcp-check | 2,064 | 4,634 |
| mcp-security-scan | 451 | 777 |
| mcp-guard | 121 | 343 |
| mcp-watch | 27 | 89 |
| tool_fuzzing | 2 | 2 |
| mcp-shield | 1 | 1 |

Di questi, **136** non hanno piu' alcun VP da nessun framework e **2,175** ne conservano uno solo.

Combinazioni di framework perse piu' frequenti:

| framework persi | server |
|---|---:|
| mcp-check | 1,749 |
| mcp-check, mcp-security-scan | 240 |
| mcp-security-scan | 178 |
| mcp-check, mcp-guard | 54 |
| mcp-guard | 28 |
| mcp-watch | 17 |
| mcp-check, mcp-guard, mcp-security-scan | 16 |
| mcp-guard, mcp-security-scan | 16 |
| mcp-guard, mcp-watch | 6 |
| mcp-check, mcp-watch | 3 |

## Server che hanno **guadagnato** concordanza: **311**

| framework | volte guadagnato |
|---|---:|
| mcp-check | 199 |
| mcp-guard | 102 |
| mcp-security-scan | 44 |
| mcp-watch | 25 |
| mcp-shield | 2 |

## Verifica: check e' peggiorato o ha solo coperto meno server?

Confronto a parita' di condizioni, sui soli server GitHub (npx esclusi: la prima
analisi li trattava in una run separata) analizzati **con successo in entrambe**
le run — cioe' presenti nel dataset e assenti dal ledger dei falliti:

| | prima | rirun |
|---|---:|---:|
| server GitHub analizzati con successo | 31.826 | 31.563 |
| di cui in comune fra le due run | 23.971 | 23.971 |
| con almeno un VP di check | 4.359 (18,2%) | **4.771 (19,9%)** |

**Sullo stesso insieme di server, la rirun trova PIU' problemi di conformita',
non meno (+412).** Il calo di 4.483 VP non e' quindi un peggioramento del tool:
e' turnover di copertura — solo 23.971 dei circa 31.800 server analizzati con
successo sono gli stessi nelle due run.

Il tasso di timeout e' praticamente invariato (91,3% dei falliti nella prima
analisi, 89,2% nella rirun): il collo di bottiglia di check e' strutturale e
identico, cambiano i server che riescono a partire.
