# MCP — Capabilities di Client e Server

## Indice
1. [Cos'è MCP in due righe](#1-cosè-mcp-in-due-righe)
2. [Cosa sono le "capabilities" e a cosa servono](#2-cosa-sono-le-capabilities-e-a-cosa-servono)
3. [La fase di negoziazione (handshake)](#3-la-fase-di-negoziazione-handshake)
4. [Capabilities del Client](#4-capabilities-del-client)
5. [Capabilities del Server](#5-capabilities-del-server)
6. [Le sotto-capabilities: `listChanged` e `subscribe`](#6-le-sotto-capabilities-listchanged-e-subscribe)
7. [Esempio concreto di scambio](#7-esempio-concreto-di-scambio)
8. [Domande che il prof potrebbe farti (con risposte)](#8-domande-che-il-prof-potrebbe-farti-con-risposte)

---

## 1. Cos'è MCP in due righe

**MCP (Model Context Protocol)** è un protocollo standard che permette a un'applicazione basata su un modello di linguaggio (l'**host/client**, es. Claude Desktop, un IDE) di collegarsi a dei **server** che forniscono contesto e funzionalità: file, database, strumenti (tool), prompt predefiniti, ecc.

L'idea è simile a quella di un "USB per i modelli AI": un unico protocollo standard, tanti server intercambiabili. La comunicazione avviene tramite messaggi **JSON-RPC 2.0**.

Attori principali:
- **Host / Client**: chi ospita il modello e apre le connessioni (uno o più).
- **Server**: chi espone risorse, tool e prompt verso il client.

---

## 2. Cosa sono le "capabilities" e a cosa servono

Le **capabilities** (capacità) sono la dichiarazione di **quali funzionalità opzionali del protocollo sono disponibili** durante quella sessione.

Il punto chiave da far capire al prof:

> Non tutti i client e non tutti i server supportano tutto. Invece di dare per scontato che una funzione esista, MCP fa dichiarare in anticipo a entrambe le parti cosa sanno fare. Così ognuno sa cosa può chiedere all'altro.

In pratica sono la risposta alla domanda: **"Cosa posso aspettarmi che tu supporti?"**

Vantaggi:
- **Compatibilità in avanti/indietro**: client e server di versioni diverse possono comunque parlarsi, usando solo ciò che hanno in comune.
- **Nessuna assunzione implicita**: se una capability non è dichiarata, l'altra parte sa che non deve usarla.
- **Estensibilità**: si possono aggiungere nuove funzioni (anche sperimentali) senza rompere chi non le conosce.

---

## 3. La fase di negoziazione (handshake)

Le capabilities si scambiano **all'inizio della sessione**, durante l'**inizializzazione** della connessione:

1. Il **client** invia un messaggio `initialize` in cui dichiara le **proprie** capabilities (cosa sa fare lui).
2. Il **server** risponde dichiarando le **proprie** capabilities.
3. Da quel momento la sessione userà solo l'**insieme delle funzioni supportate da entrambi**.

È una **negoziazione una tantum**: una volta stabilite, definiscono le "regole del gioco" per tutta la sessione.

---

## 4. Capabilities del Client

Sono le funzionalità che il **client** mette a disposizione del server (spesso perché richiedono l'accesso all'utente o al modello, che stanno dalla parte del client).

| Capability | Descrizione |
|---|---|
| **`roots`** | Capacità di fornire dei **root del filesystem**, cioè le cartelle/percorsi entro cui il server può lavorare. |
| **`sampling`** | Supporto alle **richieste di sampling dell'LLM**: il server può chiedere al client di far generare del testo al modello. |
| **`elicitation`** | Supporto alle richieste di **elicitation** del server: il server può chiedere ulteriori informazioni all'utente. |
| **`tasks`** | Supporto alle richieste **task-augmented** lato client (operazioni potenzialmente lunghe gestite come "task"). |
| **`experimental`** | Descrive il supporto a **funzionalità sperimentali** non standard. |

### Spiegazione discorsiva

- **`roots`** → Il client dice al server: "Ecco i confini del filesystem entro cui puoi muoverti". Sono i "punti di partenza" (radici) delle cartelle. Serve a delimitare dove il server può leggere/operare, per sicurezza e per contesto. *Esempio*: un client apre la cartella di un progetto come root, così il server "filesystem" sa che deve lavorare lì.

- **`sampling`** → È una delle idee più eleganti di MCP. Normalmente è il client che chiede al modello di generare testo. Con il sampling, **anche il server** può chiedere: "Fai generare questa risposta al tuo LLM". Il vantaggio è che il server può sfruttare l'intelligenza del modello **senza avere una propria chiave API né un proprio modello**. Il client mantiene il controllo (può mostrare la richiesta all'utente, approvarla, ecc.).

- **`elicitation`** → Permette al server di **chiedere informazioni aggiuntive all'utente** durante l'esecuzione. *Esempio*: un tool sta per fare un'operazione e ha bisogno di un parametro mancante o di una conferma → chiede tramite elicitation invece di fallire.

- **`tasks`** → Supporto alle operazioni gestite come **task**, cioè richieste che possono durare a lungo e che vengono seguite nel tempo (avviate, monitorate, completate) invece di essere una singola risposta immediata.

- **`experimental`** → Un contenitore per funzioni **non ancora standardizzate**. Serve a sperimentare estensioni senza toccare il protocollo ufficiale.

---

## 5. Capabilities del Server

Sono le funzionalità che il **server** offre al client. Sono le più importanti da capire perché descrivono **cosa un server MCP può effettivamente dare**.

| Capability | Descrizione |
|---|---|
| **`prompts`** | Offre **template di prompt** riutilizzabili. |
| **`resources`** | Fornisce **risorse leggibili** (dati, file, contenuti). |
| **`tools`** | Espone **tool richiamabili** (funzioni che il modello può invocare). |
| **`logging`** | Emette **messaggi di log strutturati**. |
| **`completions`** | Supporta l'**autocompletamento degli argomenti**. |
| **`tasks`** | Supporto alle richieste **task-augmented** lato server. |
| **`experimental`** | Descrive il supporto a **funzionalità sperimentali** non standard. |

### I tre "pilastri" (i più importanti)

MCP ha tre primitive fondamentali lato server. Vale la pena saperle distinguere bene, perché il prof potrebbe chiedere proprio la differenza:

- **`tools` (strumenti)** → Sono **azioni** che il modello può eseguire: funzioni richiamabili con dei parametri (es. "manda una email", "esegui una query", "calcola X"). Sono **model-controlled**: è il modello che decide di invocarli (di solito con supervisione dell'utente).

- **`resources` (risorse)** → Sono **dati leggibili** che il server mette a disposizione (es. il contenuto di un file, una tabella, una pagina). Sono **application-controlled**: tipicamente è l'applicazione/utente a decidere quali risorse includere nel contesto. Servono a *dare informazioni*, non a *fare azioni*.

- **`prompts` (prompt)** → Sono **template predefiniti** di istruzioni, spesso parametrizzati, che l'utente può richiamare (es. uno "slash command" tipo `/riassumi`). Sono **user-controlled**: è l'utente che li sceglie.

> Regola mnemonica: **tools = azioni**, **resources = dati**, **prompts = template**. Chi le controlla: tool → il modello, resource → l'applicazione, prompt → l'utente.

### Le altre capabilities server

- **`logging`** → Il server può inviare al client **messaggi di log strutturati** (con livelli tipo `info`, `warning`, `error`), utili per diagnostica e debug.

- **`completions`** → Supporto all'**autocompletamento degli argomenti**: mentre l'utente compila i parametri di un prompt o di una risorsa, il server può suggerire i valori possibili (come l'autocomplete di un editor).

- **`tasks`** → Come lato client, ma dal lato server: gestione di richieste lunghe come task tracciabili.

- **`experimental`** → Come sopra: estensioni non standard.

---

## 6. Le sotto-capabilities: `listChanged` e `subscribe`

Le capabilities non sono solo "sì/no": possono contenere **sotto-capacità** che descrivono funzioni più fini. Le due principali sono:

### `listChanged` — "la lista è cambiata"
- **Cosa fa**: indica il supporto alle **notifiche di cambiamento di una lista**. Quando l'elenco di prompt, risorse o tool cambia (uno viene aggiunto, rimosso, modificato), il server può **notificare** il client, così il client aggiorna la sua vista senza doverla richiedere di continuo.
- **Dove si applica**: **prompts, resources e tools** (tutti e tre gli elenchi).
- *Esempio*: un server aggiunge un nuovo tool a runtime → invia una notifica `listChanged` → il client ricarica la lista dei tool disponibili.

### `subscribe` — "avvisami su questo elemento specifico"
- **Cosa fa**: permette al client di **abbonarsi (sottoscrivere) ai cambiamenti di un singolo elemento**, per ricevere aggiornamenti quando *quello specifico contenuto* cambia.
- **Dove si applica**: **solo alle risorse (`resources`)**.
- *Esempio*: il client si abbona a un file di log. Ogni volta che il file cambia, riceve una notifica di aggiornamento per quella risorsa.

### Differenza chiave (importante per il prof)

| | `listChanged` | `subscribe` |
|---|---|---|
| **Cosa monitora** | L'**elenco** (quali elementi esistono) | Il **contenuto di un singolo elemento** |
| **Domanda a cui risponde** | "È cambiata la *lista* di ciò che offri?" | "È cambiato *questo specifico* contenuto?" |
| **Si applica a** | prompts, resources, tools | solo resources |

In sintesi: `listChanged` = "la lista degli oggetti è cambiata"; `subscribe` = "abbonami ai cambiamenti di *questo* oggetto".

---

## 7. Esempio concreto di scambio

Esempio semplificato di come un **server** dichiara le sue capabilities nel messaggio di inizializzazione:

```json
{
  "capabilities": {
    "prompts": {
      "listChanged": true
    },
    "resources": {
      "subscribe": true,
      "listChanged": true
    },
    "tools": {
      "listChanged": true
    },
    "logging": {},
    "completions": {}
  }
}
```

Come si legge:
- Il server offre **prompts**, e avvisa se la lista dei prompt cambia (`listChanged`).
- Offre **resources**, avvisa se la lista cambia **e** permette di abbonarsi ai singoli elementi (`subscribe`).
- Offre **tools**, avvisa se la lista cambia.
- Supporta **logging** e **completions** (senza sotto-opzioni: l'oggetto vuoto `{}` significa "capability presente, nessuna sotto-capacità particolare").

E un **client** che dichiara le sue:

```json
{
  "capabilities": {
    "roots": {
      "listChanged": true
    },
    "sampling": {},
    "elicitation": {}
  }
}
```

Qui il client dice: "posso fornire root del filesystem (e ti avviso se cambiano), supporto il sampling e l'elicitation". Il server ora **sa** che può chiedere al client di far generare testo al modello e di interrogare l'utente.

> Nota: la **presenza stessa** della chiave (`"sampling": {}`) indica che la capability è supportata. L'oggetto vuoto significa semplicemente "sì, senza sotto-opzioni specifiche".

---

## 8. Domande che il prof potrebbe farti (con risposte)

**D: Perché servono le capabilities? Non basta provare a chiamare una funzione?**
R: No: se un server chiamasse una funzione non supportata dal client (o viceversa) si avrebbe un errore o un comportamento indefinito. Le capabilities permettono di **sapere in anticipo** cosa è disponibile, garantendo compatibilità tra versioni diverse ed evitando assunzioni sbagliate.

**D: Quando avviene la negoziazione?**
R: All'**inizializzazione** della sessione (handshake), tramite lo scambio `initialize` / risposta. Vale per tutta la durata della sessione.

**D: Che differenza c'è tra tool, resource e prompt?**
R: **Tool = azione** che il modello può eseguire (model-controlled). **Resource = dato** leggibile fornito dal server (application-controlled). **Prompt = template** di istruzioni richiamabile dall'utente (user-controlled).

**D: Cos'è il sampling e perché è utile?**
R: È la capacità del **server di chiedere al client** di far generare del testo dall'LLM. È utile perché il server può usare l'intelligenza del modello **senza avere una propria API/chiave**, restando sotto il controllo del client/utente.

**D: Differenza tra `listChanged` e `subscribe`?**
R: `listChanged` notifica che è cambiato l'**elenco** di prompt/resource/tool. `subscribe` (solo per le resource) permette di abbonarsi ai cambiamenti del **contenuto di un singolo elemento**.

**D: A cosa serve `experimental`?**
R: A dichiarare il supporto a **funzionalità non standard/sperimentali**, così da poter estendere il protocollo senza romperne la compatibilità.

**D: Cosa sono i `roots`?**
R: I **confini del filesystem** che il client comunica al server: le cartelle/percorsi entro cui il server è autorizzato a operare. Servono per contesto e sicurezza.

---

### Riepilogo in una frase
Le **capabilities** sono la "carta d'identità delle funzioni" che client e server si scambiano all'inizio della sessione: dichiarano cosa ciascuno sa fare (roots, sampling, elicitation, tasks lato client; prompts, resources, tools, logging, completions, tasks lato server) ed eventuali dettagli fini (`listChanged` per gli elenchi, `subscribe` per i singoli contenuti delle risorse), così da comunicare in modo affidabile e compatibile.
