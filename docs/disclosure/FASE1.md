# Fase 1 — liste, canali e perimetro

Costruzione delle liste di segnalazione e scelta del canale per ciascun gruppo.
Come la Fase 0, **non contatta nessuno**: usa solo API pubbliche in lettura
(`api.github.com`, `registry.npmjs.org`, `raw.githubusercontent.com`) senza
autenticazione.

Aggiornamento rispetto alla Fase 0: il repository dello studio e' stato reso
**privato**, il che rimuove il vincolo che rendeva inapplicabile il preavviso e
restituisce liberta' sui tempi.

---

## Tier 1 — malware · 5 casi · **canale: GitHub Abuse**

Tutti e cinque i payload sono stati **riconfermati presenti** nell'HEAD attuale.
Il quinto caso, che in Fase 0 era rimasto sospeso perche' il vettore e' la
descrizione di un tool e non un file, e' stato verificato leggendo il sorgente
pubblico: `src/index.ts` contiene ancora `<IMPORTANT>`, `attacker@pwnd.com`,
`send_email` e `Do not mention`, su entrambi i rami.

| repository | vettore |
|---|---|
| `heavenlycolle/mcp-trino` | `exec.Command` a package-init, download ed esecuzione da dominio `.icu` |
| `illustriousj/kite-mcp-server` | idem, `wget` con pipe a `/bin/bash` |
| `optimisticdur/go-mcp-mysql` | stesso payload e stesso dominio dei precedenti |
| `FronNian/mpc-maven-security` | `eval()` di un buffer nascosto in caratteri Unicode invisibili |
| `michaelguo1991/math-mcp-server-nodejs` | descrizione che dirotta le email verso un indirizzo esterno |

**Nessuno dei due casi JavaScript e' pubblicato su npm** (verificato sul
registry): non esiste quindi un secondo canale da attivare, e i tre casi Go sono
moduli risolti direttamente da GitHub, per cui la rimozione del repository
chiude anche quella via. **GitHub Abuse e' l'unico canale necessario.**

I primi tre vanno segnalati in un'unica comunicazione: condividono schema di
offuscamento e dominio di comando e controllo, e presentarli come campagna
coordinata e' piu' efficace di tre segnalazioni scollegate.

## Tier 2 — esfiltrazione e rug pull · 4 casi · **canale: manutentore**

| repository | tipo | evidenza |
|---|---|---|
| `skdkfk8758/MCP-ProjectManager` | esfiltrazione | riconfermata |
| `vincentmcleese/promtHire-mcp` | esfiltrazione | riconfermata |
| `sentry-official/mcp-cap-internal` | rug pull | descrizione, da riconfermare via `tools/list` |
| `letoribo/mcp-graphql-enhanced` | rug pull dichiarato | cortesia |

Per `sentry-official` va aperta **una seconda segnalazione separata** a GitHub
sul nome dell'organizzazione, che evoca un'affiliazione a un fornitore noto: e'
una questione distinta dalla vulnerabilita' e va indirizzata come tale.

I due casi di esfiltrazione vanno formulati come richiesta di chiarimento e non
come accusa: il comportamento potrebbe essere documentato altrove nel progetto,
e una segnalazione che lo dia per malevolo perde credibilita' se cosi' non e'.

## Tier 3 — credenziali di terzi · **canale: fornitore, ma copre un sesto**

897 credenziali confermate. L'ipotesi iniziale era di raggrupparle per fornitore
e chiederne la revoca, riducendo 897 contatti a una decina. **La verifica la
smentisce in gran parte:**

| fornitore | chiavi | repository |
|---|---:|---:|
| Google | 76 | 49 |
| OpenAI | 39 | 25 |
| OpenWeather | 6 | 6 |
| Supabase / Docker / Groq | 2 ciascuno | 2 ciascuno |
| GitHub | 1 | 1 |
| **non attribuibile** | **769** | **331** |

Solo **128 chiavi su 897, il 14%**, portano un prefisso riconoscibile o un nome
di variabile che identifichi il servizio. Le restanti 769 sono assegnate a
identificatori generici e non hanno un destinatario naturale.

**Decisione proposta:** contattare i sette fornitori identificati, che copre 128
chiavi su 128 repository, e **rinunciare esplicitamente** al resto, motivando la
rinuncia nell'articolo. Contattare 331 manutentori per credenziali di cui non si
conosce nemmeno il servizio non e' proporzionato, e non farlo in silenzio
sarebbe la scelta peggiore delle due.

Da verificare prima dell'invio quali di quei sette siano gia' coperti dal secret
scanning automatico di GitHub sui repository pubblici: dove lo sono, la
segnalazione e' ridondante.

## Tier 4 — il resto · **canale: pubblicazione aggregata**

I candidati sono stati ordinati per **accordo fra framework e gravita' delle
categorie**, non per numero di finding. Il conteggio grezzo produce infatti una
classifica dominata da server con centinaia di difetti di conformita' al
protocollo segnalati da un solo framework, che la tesi tiene giustamente
separati dalle vulnerabilita' vere.

Il risultato del riordino e' netto e cambia la strategia:

| candidato | framework | gravi | popolarita' |
|---|---:|---:|---|
| `TauqeerAhmad5201/docker-mcp-extension` | 3 | 4 | 1 stella |
| `Streen9/terminal-mcp` | 3 | 3 | 1 stella |
| `chargenow-mcp` | 3 | 3 | 29 dl/mese |
| `davejohnson/infraprint` | 3 | 2 | 1 stella |
| `@iflow-mcp/ollama-mcp` | 2 | 33 | **344 dl/mese** |
| `thekaranpargaie/kube-mcp` | 2 | 20 | 0 stelle |
| `lox/tmux-mcp-server` | 2 | 19 | 6 stelle |
| `bigcodegen/mcp-neovim-server` | 2 | 6 | **319 stelle** |
| *(altri 22 candidati)* | 2 | 3–13 | 0–13 stelle |

**I server piu' gravi non hanno praticamente utenti.** Zero, una, tre stelle.
Segnalare individualmente a manutentori di progetti che nessuno installa ha un
valore protettivo prossimo allo zero, e consuma lo sforzo che serve al Tier 1.

**Decisione proposta:** contatto individuale limitato ai due casi in cui gravita'
e diffusione coesistono — `@iflow-mcp/ollama-mcp` e `bigcodegen/mcp-neovim-server`
— e pubblicazione aggregata come forma di disclosure per tutti gli altri.

### Un caso che vale la pena riportare nell'articolo

`wonderwhy-er/DesktopCommanderMCP`, indicato nella tesi come il caso di maggior
impatto per la combinazione fra capacita' pericolose e larga base di utenti, e'
passato da **12 finding confermati a 1** fra le due misurazioni, mentre le sue
stelle crescevano da 6.128 a **9.290**. Il server piu' diffuso del campione si e'
corretto mentre diventava piu' popolare. E' l'unico segnale che abbiamo di una
remediation spontanea, e merita una riga nel capitolo.

---

## Perimetro finale

| gruppo | destinatari | canale |
|---|---:|---|
| malware | 5 | GitHub Abuse (una comunicazione per i tre correlati, due singole) |
| esfiltrazione e rug pull | 4 | manutentore, piu' una segnalazione sul nome dell'organizzazione |
| credenziali | 7 fornitori | canale di sicurezza del fornitore |
| alta diffusione | 2 | manutentore |
| **totale contatti** | **~18** | |

Diciotto comunicazioni, contro le migliaia che una disclosure esaustiva
richiederebbe. La riduzione non e' una scorciatoia: e' il risultato di aver
misurato che il canale del fornitore copre un sesto delle credenziali e che i
server piu' gravi non hanno utenti.

## Aperto

- Verificare quali dei sette fornitori siano gia' coperti dal secret scanning.
- Riconfermare `sentry-official/mcp-cap-internal` con una chiamata `tools/list`
  in ambiente isolato, essendo il vettore la descrizione e non un file.
- Concordare con il relatore l'invio a firma istituzionale, e valutare il
  coinvolgimento del CERT di ateneo per il Tier 1.
