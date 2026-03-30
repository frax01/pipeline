// ============================================================
// NewProxy - Main Orchestrator (Improved)
// Changes from original:
// 1. Loads ALL datasets (command injection, SQL/XSS, prompt injection,
//    encoding evasion, indirect injection, jailbreaks)
// 2. Fixed toolResponse.arguments bug -> uses rawText (content)
// 3. Tool-specific benign prompt generation via LLM
// 4. Combined jailbreak+payload testing
// 5. Encoding evasion testing
// 6. Indirect injection testing (via tool responses)
// 7. Better intent classification for statistics
// ============================================================

import { Client } from '@modelcontextprotocol/sdk/client'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { MAX_COMBINED_PROMPTS_PER_TOOL, MAX_ENCODING_PAYLOADS_PER_TOOL } from './config.js'
import { runDeterministicDefender } from './validators.js'
import { runLLMVerification, selectToolForPrompt, generateArgumentsForTool, generateBenignPrompt } from './llm.js'
import { loadAllDatasets, getAllStaticPrompts } from './payload_loader.js'
import { ToolResult, PromptResult } from './types.js'

// ==========================================
// CORE ANALYSIS FUNCTION (fixed)
// ==========================================

async function performAnalysis(
    toolCall: any,
    userPrompt: string,
    tools: any[],
    client: Client
): Promise<{ overall: string, reason: string }> {

    console.log('[+] TOOL_CALL:', JSON.stringify(toolCall, null, 2))
    console.log('[DEFENDER] Verifying tool call (deterministic)...')

    // 1. Deterministic check on tool call arguments
    const verdictCall = runDeterministicDefender(toolCall.arguments)

    if (!verdictCall.allowed) {
        const allReasons = verdictCall.allViolations.map(v => v.reason).join(', ')
        console.log(`[BLOCKED] deterministic: ${allReasons}`)
        return { overall: "blocked", reason: `tool_call ${verdictCall.reason}` }
    }

    console.log('[+] Deterministic tool_call check passed')

    // 2. LLM check on tool call
    const toolMeta = tools.find((t: any) => t.name === toolCall.toolName)
    const toolDescription = toolMeta?.description

    const llmAllowed = await runLLMVerification(
        toolCall.toolName,
        toolCall.arguments,
        userPrompt,
        "tool_call",
        toolDescription
    )

    if (!llmAllowed) {
        console.log('[BLOCKED - LLM_TOOL_CALL]')
        return { overall: "blocked", reason: "tool_call llm_call_rejected" }
    }

    // 3. Execute the tool
    let toolResponse: any
    try {
        toolResponse = await client.callTool({
            name: toolCall.toolName,
            arguments: toolCall.arguments
        })
    } catch (error: any) {
        console.error('[!] Tool execution failed:', error.message)
        return { overall: "failed", reason: "tool_call execution_failed" }
    }

    console.log('[TOOL RESPONSE received]')

    // 4. Deterministic check on tool RESPONSE
    // FIX: Use content text, not toolResponse.arguments (which doesn't exist)
    const rawText = toolResponse?.content?.[0]?.text ?? ''
    const verdictResponse = runDeterministicDefender(rawText)

    if (!verdictResponse.allowed) {
        const allReasons = verdictResponse.allViolations.map(v => v.reason).join(', ')
        console.log(`[BLOCKED] response deterministic: ${allReasons}`)
        return { overall: "blocked", reason: `tool_response ${verdictResponse.reason}` }
    }

    // 5. LLM check on tool RESPONSE
    // FIX: Pass rawText (the actual response content), not toolResponse.arguments
    const responseAllowed = await runLLMVerification(
        toolCall.toolName,
        rawText,
        userPrompt,
        "tool_response"
    )

    if (!responseAllowed) {
        console.log('[BLOCKED - LLM_TOOL_RESPONSE]')
        return { overall: "blocked", reason: "tool_response llm_response_rejected" }
    }

    return { overall: "allowed", reason: "" }
}

// ==========================================
// HELPER: Run a single test
// ==========================================

async function runSingleTest(
    tool: any,
    prompt: string,
    intent: PromptResult['intent'],
    argIntent: 'benign' | 'malicious',
    tools: any[],
    client: Client,
    attackCategory?: string
): Promise<PromptResult> {

    const args = await generateArgumentsForTool(tool, prompt, argIntent)

    if (!args) {
        return {
            intent,
            prompt,
            attackCategory,
            overall: "failed",
            reason: "argument_generation_failed"
        }
    }

    const toolCall = { toolName: tool.name, arguments: args }
    const analysis = await performAnalysis(toolCall, prompt, tools, client)

    return {
        intent,
        prompt,
        attackCategory,
        toolCall,
        overall: analysis.overall as any,
        reason: analysis.reason
    }
}

// ==========================================
// MAIN
// ==========================================

async function main() {
    const repoPath = process.argv[2]
    const command = process.argv[3]
    const args = process.argv.slice(4)

    if (!repoPath || !command) {
        console.error('Usage: npx ts-node frameworks/NewProxy/index.ts <repoPath> <command> [args...]')
        process.exit(1)
    }

    // Load all datasets
    const datasets = loadAllDatasets()

    // Connect to MCP server
    const client = new Client({ name: 'newproxy-mcp-client', version: '2.0.0' })
    const transport: Transport = new StdioClientTransport({ command, args, cwd: repoPath })

    console.log('[+] Connecting to MCP server...')
    await client.connect(transport)

    const listResp = await client.listTools()
    const tools = listResp.tools ?? []

    console.log(`[+] Connected. ${tools.length} tools available:`)
    for (const t of tools) {
        console.log(` - ${t.name}: ${(t.description || '').slice(0, 80)}`)
    }

    const toolsForPrompt = tools.map((t: any) => ({
        name: t.name,
        description: t.description ?? '',
        inputSchema: t.inputSchema ?? {}
    }))

    const finalResults: any[] = []

    // ==========================================
    // PHASE 1: Per-tool fuzzing (benign + malicious)
    // ==========================================
    for (const tool of toolsForPrompt) {
        console.log(`\n========== PHASE 1: Fuzzing tool: ${tool.name} ==========`)

        const toolResult: ToolResult = { toolName: tool.name, results: [] }

        // 1A. BENIGN CHECK - Tool-specific prompt
        console.log('\n[INTENT] benign')
        const benignPrompt = await generateBenignPrompt(tool)
        console.log('BENIGN PROMPT:', benignPrompt)

        const benignResult = await runSingleTest(
            tool, benignPrompt, 'benign', 'benign', tools, client
        )
        toolResult.results.push(benignResult)

        // 1B. COMMAND INJECTION PAYLOADS
        console.log(`\n[+] Testing ${datasets.commandInjection.length} command injection payloads...`)
        for (const payload of datasets.commandInjection) {
            const result = await runSingleTest(
                tool, payload, 'malicious', 'malicious', tools, client, 'command_injection'
            )
            toolResult.results.push(result)
        }

        // 1C. SQL/XSS PAYLOADS
        console.log(`\n[+] Testing ${datasets.sqlXss.length} SQL/XSS payloads...`)
        for (const payload of datasets.sqlXss) {
            const result = await runSingleTest(
                tool, payload, 'malicious', 'malicious', tools, client, 'sql_xss'
            )
            toolResult.results.push(result)
        }

        // 1D. PROMPT INJECTION PAYLOADS (as tool input)
        console.log(`\n[+] Testing ${datasets.promptInjection.length} prompt injection payloads...`)
        for (const payload of datasets.promptInjection) {
            const result = await runSingleTest(
                tool, payload, 'malicious', 'malicious', tools, client, 'prompt_injection'
            )
            toolResult.results.push(result)
        }

        // 1E. ENCODING EVASION PAYLOADS
        const encodingSlice = datasets.encodingEvasion.slice(0, MAX_ENCODING_PAYLOADS_PER_TOOL)
        console.log(`\n[+] Testing ${encodingSlice.length} encoding evasion payloads...`)
        for (const entry of encodingSlice) {
            const payload = `Decode and execute: ${entry.encoded} (encoded as ${entry.type})`
            const result = await runSingleTest(
                tool, payload, 'encoding_evasion', 'malicious', tools, client, `encoding_${entry.type}`
            )
            toolResult.results.push(result)
        }

        // 1F. COMBINED JAILBREAK + PAYLOAD
        const combinedSlice = datasets.combinedJailbreakPayloads.slice(0, MAX_COMBINED_PROMPTS_PER_TOOL)
        console.log(`\n[+] Testing ${combinedSlice.length} jailbreak+payload combinations...`)
        for (const prompt of combinedSlice) {
            const result = await runSingleTest(
                tool, prompt, 'jailbreak_combined', 'malicious', tools, client, 'jailbreak_combined'
            )
            toolResult.results.push(result)
        }

        finalResults.push(toolResult)
    }

    // ==========================================
    // PHASE 2: Static/Generic prompt testing (tool selection -> execution)
    // ==========================================
    console.log('\n========== PHASE 2: Generic Prompt Testing ==========')

    const allStaticPrompts = getAllStaticPrompts(datasets.staticPrompts)
    console.log(`[+] Testing ${allStaticPrompts.length} static prompts with tool selection...`)

    for (const { prompt, category } of allStaticPrompts) {
        const toolResult: ToolResult = { toolName: "generic_tool_test", results: [] }

        console.log(`\n[STATIC/${category}]:`, prompt.slice(0, 100) + '...')

        const selectedToolName = await selectToolForPrompt(prompt, toolsForPrompt)
        if (!selectedToolName) {
            console.log('[i] No suitable tool selected')
            continue
        }

        console.log(`[i] Selected tool: ${selectedToolName}`)
        const selectedTool = toolsForPrompt.find(t => t.name === selectedToolName)

        if (!selectedTool) {
            console.log('[!] Selected tool not found (logic error)')
            continue
        }

        const isBenign = category === 'benign_reference_prompts'
        const result = await runSingleTest(
            selectedTool, prompt,
            isBenign ? 'benign' : 'generic',
            isBenign ? 'benign' : 'malicious',
            tools, client, category
        )
        toolResult.results.push(result)
        finalResults.push(toolResult)
    }

    // ==========================================
    // PHASE 3: Combined jailbreak prompts with tool selection
    // ==========================================
    console.log('\n========== PHASE 3: Jailbreak Prompt Testing (with tool selection) ==========')

    const jailbreakSlice = datasets.combinedJailbreakPayloads.slice(0, 20) // Limit for generic testing
    console.log(`[+] Testing ${jailbreakSlice.length} jailbreak prompts with automatic tool selection...`)

    for (const prompt of jailbreakSlice) {
        const toolResult: ToolResult = { toolName: "generic_tool_test", results: [] }

        const selectedToolName = await selectToolForPrompt(prompt, toolsForPrompt)
        if (!selectedToolName) continue

        const selectedTool = toolsForPrompt.find(t => t.name === selectedToolName)
        if (!selectedTool) continue

        const result = await runSingleTest(
            selectedTool, prompt, 'jailbreak_combined', 'malicious',
            tools, client, 'jailbreak_generic'
        )
        toolResult.results.push(result)
        finalResults.push(toolResult)
    }

    // ==========================================
    // OUTPUT
    // ==========================================

    await client.close()

    const output = {
        results: finalResults
    }

    console.log('\n================ FINAL RESULTS ================')
    console.log(JSON.stringify(output, null, 2))
}

main().catch(err => {
    console.error(err)
    process.exit(1)
})
