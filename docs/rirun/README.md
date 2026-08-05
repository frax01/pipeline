# Rirun 2026 — indice dei documenti

Seconda esecuzione completa dell'analisi di sicurezza dei 69.104 server MCP
(**luglio 2026**), messa a confronto con la prima (**maggio 2026**, archiviata in
`pipeline_DATI_BACKUP`).

Tutti i numeri sono verificati sui file. Gli script che li producono stanno in
`autorun/` e i comandi per rigenerare ogni documento sono in fondo.

---

## Da dove cominciare

| documento | cosa risponde |
|---|---|
| **[RECAP_RIRUN.md](RECAP_RIRUN.md)** | **il documento principale**: funnel, volumi, precisione, le 17 categorie, i punti da portare |
| [CONFRONTO_FINALE.md](CONFRONTO_FINALE.md) | le 17 categorie a confronto, con il tasso di conferma manuale |
| [CONFRONTO_RIRUN.md](CONFRONTO_RIRUN.md) | VP per tool e per categoria, e quali server cambiano fra le due run |
| [CONCORDANZA.md](CONCORDANZA.md) | perche' il consenso cross-framework crolla (e perche' non e' un peggioramento) |
| [MANUAL_RIRUN.md](MANUAL_RIRUN.md) | validazione manuale: 210 casi letti sul sorgente reale |
| [WATCH_FUNNEL.md](WATCH_FUNNEL.md) | il funnel di `mcp-watch` stadio per stadio, il tool che fa il 94% del volume |
| [RUGPULL.md](RUGPULL.md) | i server cambiano comportamento fra le due analisi? descrizioni riscritte; e perche' i tool aggiunti non sono misurabili |

---

## I risultati in una pagina

**Copertura.** 69.104 server, 7 framework. `mcp-scan` non e' piu' eseguibile
(l'endpoint di Invariant non ha piu' record DNS, la CLI ripiega su Snyk che
richiede una licenza): i suoi risultati sono stati **importati da maggio** e
marcati come tali.

**Volumi.** 24.225 VP contro 27.958. Ma i server con almeno un VP sono 11.487
contro 11.841 e solo **8.764 sono gli stessi**: l'ecosistema si e' mosso sotto i
piedi in due mesi (Jaccard 60%).

**Precisione.** La validazione manuale da' **49,7%** contro il 64,8% di maggio.
Il calo e' concentrato in quattro categorie e dipende in larga parte da un
criterio di giudizio, non da un cambiamento nei dati — il caso piu' netto e'
`credential-leak` (vedi RECAP §5.2).

**Consenso cross-framework.** Crolla (Tier 1 da 18 a 1), ma l'analisi mostra che
e' **turnover di raggiungibilita' dei server**, non un miglioramento della
sicurezza: a parita' di server analizzati con successo, `mcp-check` trova oggi
*piu* problemi di prima.

**Rug pull.** *Descrizioni cambiate*: su 3.961 server osservati due volte,
**1 caso confermato, 2 deboli, zero malevoli** — e tutte le capability nuove sono
dichiarate piu' forte, non nascoste. *Tool aggiunti*: *non misurabili* con questi
dati, perche' nessuna delle due analisi ha salvato un inventario completo dei
tool (vedi RUGPULL.md §6: una versione precedente sosteneva il contrario ed e'
stata ritirata).

---

## Due cose da sapere prima di citare i numeri

**1. La duplicazione in watch.** I worker di `mcp-watch` sono stati riavviati su
range sovrapposti e il merge dei 50 shard concatena senza deduplicare: **il 41,5%
dei suoi findings grezzi e il 39% dei suoi VP sono ripetizioni**. Tutti i valori
di luglio in questi documenti sono **deduplicati**; quelli di maggio sono gli
originali (la prima analisi ha ~0% di duplicati). La spiegazione completa sta in
un solo posto: **RECAP_RIRUN.md §2**.

> Conseguenza da non dimenticare: il "+72% di VP" di watch che compariva nelle
> versioni precedenti **non esiste** — deduplicato e' +5,0%.

**2. `mcp-scan` e' importato da maggio.** Per le categorie che dipendono da lui
(`Untrusted content`, e in parte `Sensitive info disclosure`, `Dangerous
capabilities`, `Prompt injection`) il confronto e' **a delta zero per
costruzione**: si sta confrontando lo stesso dato con se stesso.

---

## Rigenerare i documenti

```bash
python autorun/aggregato_finale.py --out docs/rirun/CONFRONTO_FINALE.md
python autorun/compare_vp.py --categorie --out docs/rirun/CONFRONTO_RIRUN.md
python autorun/analisi_concordanza.py --out docs/rirun/CONCORDANZA.md
python autorun/manual_audit_assembla.py
python autorun/rugpull_diff.py --json autorun/rugpull_cambi.json
python autorun/rugpull_verdetti.py --out autorun/rugpull_verdetti.json
python autorun/rugpull_nuovi.py --json autorun/rugpull_nuovi.json
```

`RECAP_RIRUN.md`, `WATCH_FUNNEL.md` e `RUGPULL.md` sono scritti a mano a partire
dagli output qui sopra.

---

## Lavoro rimasto aperto

- **`merge6.py` non deduplica**: rilanciando l'analisi la duplicazione di watch
  si ripresenta.
- **Densita' +38% per server in watch**: a parita' di server e senza duplicati,
  ogni server produce il 38% di findings in piu'. Le due cause candidate
  (repository cresciuti; bundle npx via `npm pack`) non sono state separate.
- **`security_scan` −50%** di findings grezzi: non investigato.
- **Riga "dopo Stage 2A"** in RECAP §1: non e' stato possibile risalire ai file
  da cui era ricavata, quindi e' l'unica non deduplicata.
- **Rug pull, terza passata — IN CORSO.** Ri-listing dal vivo di `tools/list`
  sui server della baseline di maggio: e' l'unico modo di ottenere un inventario
  **completo**, cosa che nessuna delle due analisi aveva salvato. Tunnel VPN
  tornato su, 9 VM raggiungibili, VM bonificate (crontab e processi orfani),
  script deployati e smoke test superato su .133 (6 server, 5 avviati).
  Da decidere: passata completa sui 5.948 server o campione casuale.
  Attenzione: il ri-listing misura i tool **spariti**, non quelli aggiunti
  (vedi RUGPULL.md §6).
