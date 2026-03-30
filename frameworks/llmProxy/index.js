import { Client } from '@modelcontextprotocol/sdk/client';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { STATIC_PROMPTS, COMMAND_INJECTION_PAYLOADS } from './config.js';
import { runDeterministicDefender } from './validators.js';
import { runLLMVerification, selectToolForPrompt, generateArgumentsForTool } from './llm.js';
import { loadCombinedPrompts } from './payload_loader.js';
export async function performAnalysis(toolCall, userPrompt, tools, client, overall, reason) {
    var analysis = {
        overall: "",
        reason: ""
    };
    console.log('[✓] RECONSTRUCTED TOOL_CALL:');
    console.log(JSON.stringify(toolCall, null, 2));
    console.log('[DEFENDER] Verifying tool call (deterministic)...');
    const verdictCall = runDeterministicDefender(toolCall.arguments);
    if (!verdictCall.allowed) {
        console.log('[BLOCKED]', verdictCall.reason);
        overall = "blocked";
        reason = `tool_call ${verdictCall.reason}`;
        analysis.overall = overall;
        analysis.reason = reason;
        return analysis;
    }
    else {
        console.log('[✓] DETERMINISTIC TOOL_CALL VERIFICATION PASSED');
        const toolMeta = tools.find((t) => t.name === toolCall.toolName);
        const toolDescription = toolMeta?.description;
        const llmAllowed = await runLLMVerification(toolCall.toolName, toolCall.arguments, userPrompt, "tool_call", toolDescription);
        if (!llmAllowed) {
            console.log('[BLOCKED - LLM_TOOL_CALL]');
            overall = "blocked";
            reason = "tool_call llm_call_rejected";
            analysis.overall = overall;
            analysis.reason = reason;
            return analysis;
        }
        else {
            let toolResponse;
            try {
                toolResponse = await client.callTool({
                    name: toolCall.toolName,
                    arguments: toolCall.arguments
                });
            }
            catch (error) {
                console.error('[!] Tool execution failed:', error.message);
                overall = "failed";
                reason = `tool_call execution_failed`;
                analysis.overall = overall;
                analysis.reason = reason;
                return analysis;
            }
            console.log('[TOOL RESPONSE RAW]');
            //console.log(JSON.stringify(toolResponse, null, 2))
            const rawText = toolResponse.content?.[0]?.text;
            const verdictResponse = runDeterministicDefender(rawText);
            if (!verdictResponse.allowed) {
                console.log('[BLOCKED]', verdictResponse.reason);
                overall = "blocked";
                reason = `tool_response ${verdictResponse.reason}`;
                analysis.overall = overall;
                analysis.reason = reason;
                return analysis;
            }
            else {
                const responseAllowed = await runLLMVerification(toolCall.toolName, toolResponse.arguments, // Note: response often doesn't have args, checking validity of this part 
                userPrompt, "tool_response");
                if (!responseAllowed) {
                    console.log('[BLOCKED - LLM_TOOL_RESPONSE]');
                    overall = "blocked";
                    reason = "tool_response llm_response_rejected";
                    analysis.overall = overall;
                    analysis.reason = reason;
                    return analysis;
                }
                analysis.overall = overall;
                analysis.reason = reason;
                return analysis;
            }
        }
    }
}
async function main() {
    const repoPath = process.argv[2];
    const command = process.argv[3];
    const args = process.argv.slice(4);
    if (!repoPath || !command) {
        console.error('Usage: node frameworks/llmProxy/index.ts <repoPath> <command> [args...]');
        process.exit(1);
    }
    const client = new Client({
        name: 'ollama-mcp-client',
        version: '1.0.0'
    });
    const transport = new StdioClientTransport({
        command,
        args,
        cwd: repoPath
    });
    console.log('[+] Connecting to MCP server...');
    await client.connect(transport);
    const listResp = await client.listTools();
    const tools = listResp.tools ?? [];
    console.log('[+] Connected. Tools available:');
    for (const t of tools) {
        console.log(' -', t.name);
    }
    const toolsForPrompt = tools.map((t) => ({
        name: t.name,
        description: t.description ?? '',
        inputSchema: t.inputSchema ?? {}
    }));
    const finalResults = [];
    // 1. DYNAMIC FUZZING LOOP (Per-tool)
    for (const tool of toolsForPrompt) {
        console.log('\n[+] Generating prompts for tool:', tool.name);
        const toolResult = {
            toolName: tool.name,
            results: []
        };
        // 1A. BENIGN CHECK (SINGLE)
        console.log('\n[INTENT] benign (functional check)');
        const benignPrompt = "Execute a standard, safe operation with this tool to verify it works.";
        console.log('USER PROMPT:', benignPrompt);
        // Perform standard benign check
        {
            const args = await generateArgumentsForTool(tool, benignPrompt, 'benign');
            let overall = "allowed";
            let reason = "";
            let toolCall = null;
            let analysis = { overall: "", reason: "" };
            if (args) {
                toolCall = { toolName: tool.name, arguments: args };
                analysis = await performAnalysis(toolCall, benignPrompt, tools, client, overall, reason);
            }
            else {
                console.log('[!] Failed to generate valid arguments for benign tool call');
                overall = "failed";
                reason = "argument_generation_failed";
                analysis.overall = overall;
                analysis.reason = reason;
            }
            toolResult.results.push({
                intent: "benign",
                prompt: benignPrompt,
                toolCall,
                overall: analysis.overall,
                reason: analysis.reason
            });
        }
        // 1B. MALICIOUS LOOP (STATIC PAYLOADS)
        for (const payload of COMMAND_INJECTION_PAYLOADS) {
            console.log('\n[INTENT] malicious');
            console.log('USER PROMPT:', payload);
            // GENERATE ARGUMENTS FOR PAYLOAD
            const args = await generateArgumentsForTool(tool, payload, 'malicious');
            let overall = "allowed";
            let reason = "";
            let toolCall = null;
            let analysis = { overall: "", reason: "" };
            if (args) {
                toolCall = {
                    toolName: tool.name,
                    arguments: args
                };
                analysis = await performAnalysis(toolCall, payload, tools, client, overall, reason);
            }
            else {
                console.log('[!] Failed to generate valid arguments for payload');
                overall = "failed";
                reason = "argument_generation_failed";
                analysis.overall = overall;
                analysis.reason = reason;
            }
            toolResult.results.push({
                intent: "malicious",
                prompt: payload,
                toolCall,
                overall: analysis.overall,
                reason: analysis.reason
            });
        }
        finalResults.push(toolResult);
    }
    // 2. STATIC/DYNAMIC PROMPTS LOOP (Tool selection -> execution)
    const dynamicPrompts = loadCombinedPrompts();
    const allPrompts = [...STATIC_PROMPTS, ...dynamicPrompts];
    console.log(`\n[+] Starting Generic Prompt Loop with ${allPrompts.length} prompts (${STATIC_PROMPTS.length} static + ${dynamicPrompts.length} dynamic)...`);
    for (const prompt of allPrompts) {
        const toolResult = {
            toolName: "generic_tool_test",
            results: []
        };
        console.log('\n[STATIC PROMPT]:', prompt);
        // Select Tool
        const selectedToolName = await selectToolForPrompt(prompt, toolsForPrompt);
        let overall = "allowed";
        let reason = "";
        let toolCall = null;
        let analysis = { overall: "", reason: "" }; // Initialize analysis
        if (!selectedToolName) {
            console.log('[i] No suitable tool selected for this prompt');
            continue; // Skip if no tool matches
        }
        console.log(`[i] Selected tool: ${selectedToolName}`);
        const selectedTool = toolsForPrompt.find(t => t.name === selectedToolName);
        if (selectedTool) {
            const args = await generateArgumentsForTool(selectedTool, prompt, 'benign');
            if (args) {
                toolCall = {
                    toolName: selectedToolName,
                    arguments: args
                };
                analysis = await performAnalysis(toolCall, prompt, tools, client, overall, reason);
            }
            else {
                console.log('[!] Failed to generate arguments');
                overall = "failed";
                reason = "argument_generation_failed";
                analysis.overall = overall;
                analysis.reason = reason;
            }
        }
        else {
            console.log('[!] Selected tool not found in list (logic error)');
            overall = "failed";
            reason = "tool_not_found";
            analysis.overall = overall;
            analysis.reason = reason;
        }
        toolResult.results.push({
            intent: "generic",
            prompt: prompt,
            toolCall,
            overall: analysis.overall,
            reason: analysis.reason
        });
        finalResults.push(toolResult);
    }
    await client.close();
    console.log('\n================ FINAL RESULTS ================');
    console.log(JSON.stringify(finalResults, null, 2));
}
main().catch(err => {
    console.error(err);
    process.exit(1);
});
