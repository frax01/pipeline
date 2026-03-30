import { Client } from '@modelcontextprotocol/sdk/client'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

async function listToolsFromServer() {
  const repo_path = process.argv[2]
  const command = process.argv[3]
  const args = process.argv.slice(4)
  if (!repo_path) {
    console.error('Missing repo path')
    process.exit(1)
  }

  const client = new Client({
    name: 'tool-inspector',
    version: '1.0.0',
  })

  const transport: Transport = new StdioClientTransport({
    command: command,
    args: args,
    cwd: repo_path,
  })

  await client.connect(transport)
  const response = await client.listTools()
  await client.close()

  const tools = (response.tools ?? []).map(t => ({
    name: t.name,
    description: t.description ?? '',
    inputSchema: t.inputSchema ?? {},
    outputSchema: t.outputSchema ?? {},
  }))

  return process.stdout.write(JSON.stringify(tools))

}

listToolsFromServer().catch((err) => {
  console.error(err)
  process.exit(1)
})
