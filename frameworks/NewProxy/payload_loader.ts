// ============================================================
// NewProxy - Payload Loader (Improved)
// Changes from original:
// 1. Loads ALL dataset JSON files from data/ directory
// 2. Combines jailbreak templates with malicious payloads
// 3. Flattens command_injection categories into single array
// 4. Loads encoding evasion payloads
// 5. Loads tool poisoning descriptions
// 6. Also loads promptFilter output if available
// ============================================================

import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'
import {
    DatasetPayloads, JailbreakTemplate, EncodingEntry,
    ToolPoisoningEntry, StaticPrompts
} from './types.js'
import { MAX_COMBINED_PROMPTS_PER_TOOL } from './config.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const DATA_DIR = path.resolve(__dirname, 'data')
const PROMPT_FILTER_DIR = path.resolve(__dirname, '../../promptFilter')

function loadJsonFile<T>(filePath: string, fallback: T): T {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf-8')
            return JSON.parse(data) as T
        }
    } catch (e) {
        console.warn(`[!] Failed to load ${filePath}:`, e)
    }
    return fallback
}

function flattenCategories(obj: Record<string, any>): string[] {
    const result: string[] = []
    for (const [key, value] of Object.entries(obj)) {
        if (key === '_meta') continue
        if (Array.isArray(value)) {
            result.push(...value.filter((v: any) => typeof v === 'string'))
        }
    }
    return result
}

// ==========================================
// MAIN LOADER
// ==========================================

export function loadAllDatasets(): DatasetPayloads {
    console.log('[+] Loading datasets from:', DATA_DIR)

    // 1. Command Injection
    const cmdRaw = loadJsonFile<any>(path.join(DATA_DIR, 'command_injection.json'), {})
    const commandInjection = flattenCategories(cmdRaw)
    console.log(`[+] Loaded ${commandInjection.length} command injection payloads`)

    // 2. SQL + XSS
    const sqlXssRaw = loadJsonFile<any>(path.join(DATA_DIR, 'sql_xss_payloads.json'), {})
    const sqlXss = flattenCategories(sqlXssRaw)
    console.log(`[+] Loaded ${sqlXss.length} SQL/XSS payloads`)

    // 3. Prompt Injection
    const piRaw = loadJsonFile<any>(path.join(DATA_DIR, 'prompt_injection.json'), {})
    const promptInjection = flattenCategories(piRaw)
    console.log(`[+] Loaded ${promptInjection.length} prompt injection payloads`)

    // 4. Tool Poisoning
    const tpRaw = loadJsonFile<any>(path.join(DATA_DIR, 'tool_poisoning.json'), {})
    const toolPoisoning: ToolPoisoningEntry[] = []
    for (const [key, value] of Object.entries(tpRaw)) {
        if (key === '_meta' || key === 'attack_categories') continue
        if (Array.isArray(value)) {
            toolPoisoning.push({ category: key, descriptions: value as string[] })
        }
    }
    const totalTP = toolPoisoning.reduce((sum, tp) => sum + tp.descriptions.length, 0)
    console.log(`[+] Loaded ${totalTP} tool poisoning descriptions across ${toolPoisoning.length} categories`)

    // 5. Encoding Evasion
    const encRaw = loadJsonFile<any>(path.join(DATA_DIR, 'encoding_evasion.json'), {})
    const encodingEvasion: EncodingEntry[] = []
    for (const [key, value] of Object.entries(encRaw)) {
        if (key === '_meta' || key === 'mixed_encoding_prompts') continue
        if (Array.isArray(value)) {
            for (const entry of value) {
                if (entry && typeof entry === 'object' && 'encoded' in entry) {
                    encodingEvasion.push(entry as EncodingEntry)
                }
            }
        }
    }
    // Also add mixed_encoding_prompts as full prompts
    const mixedPrompts: string[] = encRaw.mixed_encoding_prompts || []
    console.log(`[+] Loaded ${encodingEvasion.length} encoding evasion entries + ${mixedPrompts.length} mixed prompts`)

    // 6. Indirect Injection
    const iiRaw = loadJsonFile<any>(path.join(DATA_DIR, 'indirect_injection.json'), {})
    const indirectInjection = flattenCategories(iiRaw)
    console.log(`[+] Loaded ${indirectInjection.length} indirect injection payloads`)

    // 7. Jailbreak Templates
    const jbRaw = loadJsonFile<any>(path.join(DATA_DIR, 'jailbreak_templates.json'), {})
    const jailbreakTemplates: JailbreakTemplate[] = (jbRaw.templates || []).map((t: any) => ({
        id: t.id,
        name: t.name,
        template: t.template
    }))
    console.log(`[+] Loaded ${jailbreakTemplates.length} jailbreak templates`)

    // 8. Static Prompts
    const spRaw = loadJsonFile<any>(path.join(DATA_DIR, 'static_prompts.json'), {})
    const staticPrompts: StaticPrompts = {
        file_system_attacks: spRaw.file_system_attacks || [],
        network_attacks: spRaw.network_attacks || [],
        code_execution_attacks: spRaw.code_execution_attacks || [],
        data_exfiltration_attacks: spRaw.data_exfiltration_attacks || [],
        sql_injection_attacks: spRaw.sql_injection_attacks || [],
        prompt_injection_via_data: spRaw.prompt_injection_via_data || [],
        resource_exhaustion_attacks: spRaw.resource_exhaustion_attacks || [],
        benign_reference_prompts: spRaw.benign_reference_prompts || []
    }
    const totalSP = Object.values(staticPrompts).reduce((sum, arr) => sum + arr.length, 0)
    console.log(`[+] Loaded ${totalSP} static prompts`)

    // 9. Load promptFilter outputs if available
    const pfPayloads = loadJsonFile<string[]>(path.join(PROMPT_FILTER_DIR, 'mcp_filtered_payloads.json'), [])
    if (pfPayloads.length > 0) {
        console.log(`[+] Loaded ${pfPayloads.length} payloads from promptFilter/mcp_filtered_payloads.json`)
        // Add unique payloads not already in commandInjection
        const existing = new Set(commandInjection.map(p => p.toLowerCase()))
        for (const payload of pfPayloads) {
            if (!existing.has(payload.toLowerCase())) {
                commandInjection.push(payload)
            }
        }
    }

    // 10. Generate combined jailbreak + payload prompts
    const combinedJailbreakPayloads = generateCombinedPrompts(
        jailbreakTemplates,
        [...commandInjection.slice(0, 10), ...promptInjection.slice(0, 5)] // Select a representative subset
    )
    console.log(`[+] Generated ${combinedJailbreakPayloads.length} combined jailbreak+payload prompts`)

    return {
        commandInjection,
        sqlXss,
        promptInjection,
        toolPoisoning,
        encodingEvasion,
        indirectInjection,
        jailbreakTemplates,
        staticPrompts,
        combinedJailbreakPayloads
    }
}

// ==========================================
// JAILBREAK + PAYLOAD COMBINER
// ==========================================

function generateCombinedPrompts(
    templates: JailbreakTemplate[],
    payloads: string[]
): string[] {
    const combined: string[] = []

    for (const template of templates) {
        for (const payload of payloads) {
            let prompt: string
            if (template.template.includes('[PROMPT]')) {
                prompt = template.template.replace('[PROMPT]', payload)
            } else {
                prompt = `${template.template}\n\n${payload}`
            }
            combined.push(prompt)

            // Limit to prevent combinatorial explosion
            if (combined.length >= MAX_COMBINED_PROMPTS_PER_TOOL * 3) {
                console.log(`[!] Combined prompts capped at ${combined.length}`)
                return combined
            }
        }
    }
    return combined
}

/** Get all static prompts as a flat array with category labels */
export function getAllStaticPrompts(sp: StaticPrompts): Array<{ prompt: string, category: string }> {
    const result: Array<{ prompt: string, category: string }> = []
    for (const [category, prompts] of Object.entries(sp)) {
        for (const prompt of prompts) {
            result.push({ prompt, category })
        }
    }
    return result
}

/** Get all command injection payloads (combined from all sources) */
export function getAllMaliciousPayloads(datasets: DatasetPayloads): string[] {
    return [
        ...datasets.commandInjection,
        ...datasets.sqlXss,
        ...datasets.promptInjection
    ]
}
