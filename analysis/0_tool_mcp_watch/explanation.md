# Analisi dei risultati mcp-watch — con esempi dal codice

1. Consistenza numerica
I dati sono internamente coerenti — tutti i numeri tornano

2. Architettura dello scanner
Tutti i 12 scanner vengono eseguiti in parallelo su ogni server tramite Promise.all():

// McpScanner.ts:80-93
const scanResults = await Promise.all([
  credentialScanner.scan(tempDir.name),
  toolPoisoningScanner.scan(tempDir.name),
  parameterInjectionScanner.scan(tempDir.name),
  promptInjectionScanner.scan(tempDir.name),
  toolMutationScanner.scan(tempDir.name),
  conversationExfiltrationScanner.scan(tempDir.name),
  ansiInjectionScanner.scan(tempDir.name),
  protocolViolationScanner.scan(tempDir.name),
  inputValidationScanner.scan(tempDir.name),
  serverSpoofingScanner.scan(tempDir.name),
  toxicFlowScanner.scan(tempDir.name),
  permissionScanner.scan(tempDir.name),
]);

this.vulnerabilities = scanResults.flat();

Ogni vulnerabilità trovata è un oggetto Vulnerability:

// types/Vulnerability.ts
export interface Vulnerability {
  id: string;                                    // es. "HARDCODED_CREDENTIALS"
  severity: "critical" | "high" | "medium" | "low";
  category: string;                              // es. "toxic-flow"
  message: string;
  file?: string;
  line?: number;
  evidence?: string;                             // snippet di codice (redatto)
  source?: string;                               // es. "Trail of Bits research"
}

Il conteggio è una vulnerabilità per ogni riga che matcha un pattern. Se un file ha 200 righe che matchano, genera 200 vulnerability. Questo spiega i numeri enormi.

3. Toxic Flow — 72.26% (7,161,734 finding)
Questo è il dato più significativo e il più inflazionato. Il ToxicFlowScanner ha tre check, di cui due molto aggressivi:

Check 1: UNTRUSTED_DATA_PROCESSING (medium)
Cerca righe con una "fonte non fidata" senza parole di sanitizzazione nella stessa riga:

// ToxicFlowScanner.ts:58-80
private containsUntrustedDataProcessing(line: string): boolean { 
  const untrustedDataSources = [
    /\.data\.|response\.|\.json\(\)|\.text\(\)/,
    /readFile|read.*content|fetch.*file/i,
    /input\.|params\.|query\.|body\./,
    /fetch\(|axios\.|request\(|http\./,
    /message\.content|content\.body|data\.content/i,
    /external|remote|api|endpoint/i,     // ⚠️ Molto generico!
  ];
  // ...
  const sanitizationPresent = [
    /sanitize|escape|validate|filter|clean/i,
    /allowlist|whitelist|strip|remove/i,
    /encode|decode|parse.*safe|safe.*parse/i,
  ];
  return !sanitizationPresent.some((s) => s.test(line));
}

Problema: Pattern come /external|remote|api|endpoint/i sono troppo generici. Qualsiasi riga con la parola "api" o "endpoint" viene flaggata. Un semplice const apiUrl = "..." genera un finding.

Check 2: AUTOMATIC_CONTENT_PUBLISHING (high)
Cerca righe con un'azione di "pubblicazione" + un indicatore di "contenuto dinamico":

// ToxicFlowScanner.ts:94-114
const publishingPatterns = [
  /create(?!.*test)|auto.*create|generate.*content/i,
  /publish|send|post|upload|write.*file/i,
  /broadcast|share|distribute|forward/i,
  /notify|alert|message|email/i,      // ⚠️ "message" matcha ovunque
  /insert|save|store.*public/i,
];
// ...
const dynamicContentIndicators = [
  /\$\{|template|interpolate|\+.*\+/,
  /\.data|response\.|content\.|input\./,
  /process\.|param|arg|variable/,
];

Problema critico: Come documentato nei commenti del codice stesso:

// ToxicFlowScanner.ts:119-122
// VIENE SEGNALATO (Questo è il motivo del tuo file text.txt)
// Contiene la parola "message" (Azione) E l'interpolazione "${" (Indicatore Dinamico).
// console.log(`Error: ${error.message}`); 

Una banale riga di log come console.log(Error: ${error.message}) è un false positive HIGH.

Check 3: GENERIC_TOXIC_FLOW_CHAIN (critical) — il più problematico
Cerca nell'intero file se esistono parole da 3 gruppi diversi, anche su righe non correlate:

// ToxicFlowScanner.ts:125-163
lines.forEach((line) => {
  if (/fetch|api|external|remote|input|request/i.test(line))
    hasExternalInput = true;
  if (/private|confidential|secret|internal|admin|privileged/i.test(line))
    hasPrivilegedAccess = true;
  if (/public|create|publish|send|post|share|broadcast/i.test(line))
    hasPublicOutput = true;
});

if (hasExternalInput && hasPrivilegedAccess && hasPublicOutput) {
  vulnerabilities.push({
    id: "GENERIC_TOXIC_FLOW_CHAIN",
    severity: "critical",  // ⚠️ CRITICAL per keyword scollegate!
    // ...
  });
}

Problema gravissimo — documentato nei commenti del codice stesso:

// ToxicFlowScanner.ts:165-180
// Riga 10: public async fetchUserData() { ... }     → "fetch" = Gruppo A ✓
// Riga 50: private activeConnections = 0;            → "private" = Gruppo B ✓
// Riga 120: public createNewAccount() { ... }        → "create" = Gruppo C ✓
// Conclusione: VULNERABILITÀ CRITICA!
// Quando in realtà le tre funzioni non si parlano nemmeno tra loro.

private come keyword TypeScript matcha il Gruppo B ("dati privilegiati"), e public come modificatore di visibilità matcha il Gruppo C ("output pubblico"). Praticamente ogni file TypeScript con più di 50 righe viene flaggato come CRITICAL.

Questo spiega perché toxic-flow è il 72.26% del totale.

4. Credential Leak — 10.44% (1,034,432 finding)
Il CredentialScanner è il più preciso tra gli scanner. Cerca pattern specifici di token reali:

// CredentialScanner.ts:93-113
private containsHardcodedCredentials(line: string): boolean {
  const patterns = [
    /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][a-zA-Z0-9]{15,}["']/i,
    /sk-[a-zA-Z0-9]{20,}/,            // OpenAI
    /ghp_[a-zA-Z0-9]{36}/,            // GitHub
    /xoxb-[a-zA-Z0-9-]{50,}/,         // Slack
    /AKIA[a-zA-Z0-9]{16}/,            // AWS
    /ya29\.[a-zA-Z0-9_-]{50,}/,       // Google OAuth
    /AIza[a-zA-Z0-9_-]{35}/,          // Google API
    /pk_[a-zA-Z0-9]{24}/,             // Stripe
    /dckr_pat_[a-zA-Z0-9_-]+/,        // Docker
    /["'][a-zA-Z0-9+/]{40,}={0,2}["']/, // Base64-like ⚠️ false positive
    /["']eyJ[...JWT pattern...]["']/,  // JWT
  ];
  return patterns.some(p => p.test(line)) && !this.isExampleCredential(line);
}

Ha due filtri anti-false positive buoni:

isExampleCredential() esclude placeholder (your-api-key, example, demo, test, ecc.)
sanitizeEvidence() oscura le credenziali trovate nel report
Possibile fonte di inflazione: il pattern Base64 (/["'][a-zA-Z0-9+/]{40,}={0,2}["']/) può matchare stringhe che non sono credenziali (hash, ID lunghi, contenuti codificati).

5. Input Validation — 8.36% (828,801 finding)
Tre check basati su ricerca PromptHub:

// InputValidationScanner.ts:77-88
private containsCommandInjection(line: string): boolean {
  const dangerousPatterns = [
    /execSync?\s*\(/, /spawn\s*\(/, /exec\s*\(/,
    /system\s*\(/, /shell_exec/, /passthru\s*\(/, /popen\s*\(/
  ];
  return (
    dangerousPatterns.some(pattern => pattern.test(line)) &&
    (line.includes("req.") || line.includes("params") || 
     line.includes("query") || line.includes("body") || 
     line.includes("input") || line.includes("user") ||
     line.includes("argv"))
  );
}

Qualità: Decente — richiede sia una funzione pericolosa (exec, spawn) che una fonte di input utente. Ma line.includes("user") è troppo generico: un commento come // execute user migration trigga il check.

Path traversal ha un problema simile:

// InputValidationScanner.ts:104-109
/\.\.\/|\.\.\\/, // Direct path traversal

Questo matcha qualsiasi ../ nel codice, inclusi import relativi come import { X } from "../../utils".

6. Access Control — 4.76% (471,419 finding)
Il PermissionScanner cerca keyword generiche:

// PermissionScanner.ts:68-94
private containsExcessivePermissions(line: string): boolean {
  const permissionKeywords = [
    "admin", "root", "superuser", "delete", "remove", "destroy",
    "create", "modify", "update", "full access", "all permissions",
    "unrestricted", "elevated", "privileged",
  ];
  return permissionKeywords.some(
    (keyword) => line.toLowerCase().includes(keyword) &&
      (line.includes("user") || line.includes("permission") || 
       line.includes("scope") || line.includes("role") || 
       line.includes("access"))
  );
}

Problema: "create" + "user" = finding. Una funzione createUser() perfettamente legittima viene flaggata come EXCESSIVE_PERMISSIONS con severity HIGH. Lo stesso per deleteUser(), updateUserRole(), ecc.

7. Protocol Violation — 2.63% (260,890 finding)
// ProtocolViolationScanner.ts:67-75
private containsInsecureTransport(line: string): boolean {
  return (
    line.includes("http://") &&
    !line.includes("localhost") &&
    !line.includes("127.0.0.1") &&
    !line.includes("example.com") &&
    !this.isExampleCredential(line)
  );
}

Qualità: Ragionevole, ma conta ogni riga con http:// (anche in commenti, documentazione, link a spec HTTP). Non esclude 0.0.0.0 o link in file .md.

8. Categorie minori (< 1%)
Categoria	%	Scanner	Note
prompt-injection	0.62%	PromptInjectionScanner	Cerca ignore previous instructions, [SYSTEM], ecc. nelle description dei tool. Preciso.
data-exfiltration	0.25%	ParameterInjectionScanner	Cerca "magic parameters" come conversation_history, system_prompt. Molto specifico, pochi false positive.
server-spoofing	0.23%	ServerSpoofingScanner	Cerca nomi di server che imitano servizi noti (github, slack, aws).
tool-mutation	0.22%	ToolMutationScanner	Cerca tools.push(), tools[x] = ....
steganographic-attack	0.18%	AnsiInjectionScanner	Cerca escape ANSI (\x1b[) e whitespace injection (>100 spazi).
tool-poisoning	0.06%	ToolPoisoningScanner	Cerca istruzioni nascoste nelle description + naming deceptive. Preciso.
9. Distribuzione severity
Severity	%	Conteggio	Interpretazione
Medium	61.4%	6,089,408	Dominato da UNTRUSTED_DATA_PROCESSING del ToxicFlowScanner
High	26.2%	2,594,966	AUTOMATIC_CONTENT_PUBLISHING + INSECURE_TRANSPORT + EXCESSIVE_PERMISSIONS
Critical	12.4%	1,226,891	GENERIC_TOXIC_FLOW_CHAIN (1 per file!) + HARDCODED_CREDENTIALS + COMMAND_INJECTION_RISK
La piramide (più medium che high, più high che critical) è coerente e attesa.

10. Fallimenti — 21.96%
execution_failed:  11,790  (89.2% dei fallimenti)
clone_failed:       1,332  (10.1%)
prepare_timeout:      101  (0.8%)

I server Go (1,893), Docker (1,220) e unknown (10,107) = 13,220, più 3 Node.js/Python falliti = 13,223 totale. Coerente: lo scanner supporta solo .ts, .js, .py — i server in Go/Docker non sono analizzabili e finiscono come execution_failed.

11. Conclusioni
I dati sono coerenti numericamente, ma il valore assoluto delle vulnerabilità è significativamente inflazionato, principalmente per tre ragioni:

GENERIC_TOXIC_FLOW_CHAIN — cerca keyword scollegate nell'intero file. Quasi ogni file TypeScript/Python non banale lo trigga. Genera 1 finding CRITICAL per file.

UNTRUSTED_DATA_PROCESSING — pattern come /api|endpoint/i sono troppo generici. Un console.log(Error: ${error.message}) è un false positive.

EXCESSIVE_PERMISSIONS — "create" + "user" nella stessa riga = finding. Funzioni CRUD normali vengono flaggate.

Se volessi dare numeri più realistici, dovresti:

Rendere GENERIC_TOXIC_FLOW_CHAIN consapevole del data-flow reale (non solo keyword)
Restringere i pattern di toxic-flow (togliere api, endpoint, message dai trigger generici)
Escludere commenti e file .md dai check più aggressivi
Escludere ../ negli import relativi dal path traversal
Il risultato corrente è utile come indicatore di superficie d'attacco (quanti server hanno potenziali problemi), ma non come conteggio di vulnerabilità reali.