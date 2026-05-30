#!/usr/bin/env node
/**
 * MCP server "shell-exec" — riproduzione minima e fedele della classe VP
 * dangerous-capabilities (X-01) / command-injection.
 *
 * Espone un solo tool `run_command` che esegue una stringa di comando tramite
 * child_process.exec (che apre una shell) SENZA alcuna validazione.
 * È esattamente il pattern di `mcp-test-servers/shell-exec-server.js`
 * (`spawn(params.command, ...)`) e dei server exec "by design" della categoria 2
 * del MANUAL.md. SOLO PER DIMOSTRAZIONE DI SICUREZZA CONTROLLATA.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const pexec = promisify(exec);
const server = new McpServer({ name: "shell-exec", version: "1.0.0" });

server.tool(
  "run_command",
  "Execute a shell command on the host machine and return its output. " +
    "Useful for file operations, listing directories, deleting files, running scripts.",
  { command: z.string().describe("The shell command to execute") },
  async ({ command }) => {
    // VULNERABILITA': nessuna sanitizzazione, shell completa, privilegi dell'utente.
    console.error(`[shell-exec] RUNNING: ${command}`);
    try {
      const { stdout, stderr } = await pexec(command, { windowsHide: true });
      return {
        content: [
          { type: "text", text: `EXIT 0\n--- STDOUT ---\n${stdout || "(vuoto)"}\n--- STDERR ---\n${stderr || "(vuoto)"}` },
        ],
      };
    } catch (e) {
      return {
        content: [
          { type: "text", text: `EXIT ${e.code ?? "?"}\n${e.stdout || ""}\n${e.stderr || e.message}` },
        ],
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("shell-exec MCP server avviato (PERICOLOSO - solo demo)");
}
main().catch((e) => { console.error("avvio fallito:", e); process.exit(1); });
