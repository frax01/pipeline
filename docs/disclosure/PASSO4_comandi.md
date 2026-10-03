# Passo 4 — i 29 repository con `SECURITY.md`

Ognuno dichiara una procedura propria: non sono automatizzabili in blocco.
Il testo da usare e' sempre quello gia' generato in `messaggi/`.

---

## A. Email dichiarata (12) — un comando ciascuno

Tenere Outlook aperto. Ogni riga e' un invio.

- [ ] `Agent-Hellboy/mcp-runtime` — 5 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/Agent-Hellboy__mcp-runtime.txt --a princekroshan01@gmail.com --invia --via outlook
  ```

- [ ] `langwatch/langwatch` — 4 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/langwatch__langwatch.txt --a security@langwatch.ai --invia --via outlook
  ```

- [ ] `neverinfamous/postgresql-mcp` — 2 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/neverinfamous__postgresql-mcp.txt --a admin@adamic.tech --invia --via outlook
  ```

- [ ] `Chieko-Seren/ARIES` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/Chieko-Seren__ARIES.txt --a chieko.seren@icloud.com --invia --via outlook
  ```

- [ ] `VeriTeknik/pluggedin-app` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/VeriTeknik__pluggedin-app.txt --a security@plugged.in --invia --via outlook
  ```

- [ ] `Wolfe-Jam/claude-faf-mcp` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/Wolfe-Jam__claude-faf-mcp.txt --a team@faf.one --invia --via outlook
  ```

- [ ] `director-run/director` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/director-run__director.txt --a security@director.run --invia --via outlook
  ```

- [ ] `enessari/metabase-ai-assistant` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/enessari__metabase-ai-assistant.txt --a security@onmartech.com --invia --via outlook
  ```

- [ ] `gawd-ai/sctl` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/gawd-ai__sctl.txt --a security@gawd.ai --invia --via outlook
  ```

- [ ] `karakeep-app/karakeep` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/karakeep-app__karakeep.txt --a security@karakeep.app --invia --via outlook
  ```

- [ ] `kenyaclaw/africa-payments-mcp` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/kenyaclaw__africa-payments-mcp.txt --a security@kenyaclaw.com --invia --via outlook
  ```

- [ ] `notsedano/f1-mcp-server` — 1 cred.

  ```bash
  python autorun/disclosure_uno.py --file docs/disclosure/messaggi/notsedano__f1-mcp-server.txt --a info@machinetomachine.ai --invia --via outlook
  ```

---

## B. Indirizzo che NON e' dell'owner (2) — da risolvere prima

Il `SECURITY.md` di questi due e' ereditato da un progetto a monte, e
l'indirizzo dichiarato e' quello di quel progetto, non del manutentore che
ha commesso la credenziale. Scrivere li' significa segnalare a un terzo un
problema che non puo' risolvere, e non raggiungere chi puo'.

- [ ] `cecil-the-coder/mcp-code-api` — 1 cred. — dichiara `security@cerebras.net`

      Cercare il contatto dell'owner; se non esiste, non mandare.

- [ ] `dolphina02/supersetAddAiChat` — 1 cred. — dichiara `security@superset.apache.org`

      Cercare il contatto dell'owner; se non esiste, non mandare.

---

## C. Link a un form o advisory esterno (5) — a mano nel browser

- [ ] `marc-shade/agentic-system-oss` — 3 cred.
      https://github.com/marc-shade/claude-code-security

- [ ] `marianfoo/local-llm-client-for-sap-consultants-librechat` — 2 cred.
      https://docs.github.com/en/code-security/getting-started-with-security

- [ ] `muphy/librechat` — 2 cred.
      https://docs.github.com/en/code-security/getting-started-with-security

- [ ] `egarcia74/warp-sql-server-mcp` — 1 cred.
      https://github.com/egarcia74/warp-sql-server-mcp/security

- [ ] `prettier/prettier` — 1 cred.
      https://tidelift.com/security

---

## D. Private vulnerability reporting di GitHub (3)

Sulla pagina del repository: scheda **Security** -> **Report a vulnerability**.
E' il canale migliore dei quattro, resta privato e traccia la conversazione.

- [ ] `timowhite88/Farnsworth` — 5 cred.
      https://github.com/timowhite88/Farnsworth/security/advisories/new

- [ ] `dev8372/graphitiMCP` — 1 cred.
      https://github.com/dev8372/graphitiMCP/security/advisories/new

- [ ] `ignaciohermosillacornejo/copilot-money-mcp` — 1 cred.
      https://github.com/ignaciohermosillacornejo/copilot-money-mcp/security/advisories/new

---

## E. Procedura non chiara (7) — leggere il file e decidere

Aprire il `SECURITY.md` e vedere cosa indica. Se non indica nulla di
utilizzabile, trattarli come irraggiungibili e annotarlo.

- [ ] `Garblesnarff/gemini-mcp-server` — 3 cred.
      https://github.com/Garblesnarff/gemini-mcp-server/blob/HEAD/SECURITY.md

- [ ] `MauricioDuarte100/ActiveDirectoryPentestingMCP` — 2 cred.
      https://github.com/MauricioDuarte100/ActiveDirectoryPentestingMCP/blob/HEAD/SECURITY.md

- [ ] `commercetools/commerce-mcp` — 2 cred.
      https://github.com/commercetools/commerce-mcp/blob/HEAD/SECURITY.md

- [ ] `commercetools/mcp-essentials` — 2 cred.
      https://github.com/commercetools/mcp-essentials/blob/HEAD/SECURITY.md

- [ ] `nagual69/MCP-Open-Discovery-with-AMQP` — 2 cred.
      https://github.com/nagual69/MCP-Open-Discovery-with-AMQP/blob/HEAD/SECURITY.md

- [ ] `ai-protocols/superstore-mcp` — 1 cred.
      https://github.com/ai-protocols/superstore-mcp/blob/HEAD/SECURITY.md

- [ ] `dbankscard/jamf-mcp-server` — 1 cred.
      https://github.com/dbankscard/jamf-mcp-server/blob/HEAD/SECURITY.md

