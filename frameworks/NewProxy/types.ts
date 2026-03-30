// ============================================================
// NewProxy - Enhanced Type Definitions
// ============================================================

export type Signature = {
    id: string
    name: string
    description: string
    category: string
    type: 'llm' | 'deterministic'
    prompt?: string
}

/** Single deterministic check result */
export type CheckResult = {
    allowed: boolean
    reason: string
}

/** Verdict with ALL violations collected (not just the first) */
export type Verdict = {
    allowed: boolean
    reason: string
    allViolations: CheckResult[]
}

/** Result of tool description poisoning analysis */
export type DescriptionAnalysis = {
    toolName: string
    poisoned: boolean
    violations: string[]
}

export type PromptResult = {
    intent: 'benign' | 'malicious' | 'generic' | 'jailbreak_combined' | 'encoding_evasion' | 'tool_poisoning' | 'indirect_injection'
    prompt: string
    attackCategory?: string
    toolCall?: any
    verdicts?: {
        deterministic_call: Verdict
        llm_call?: CheckResult
        deterministic_response?: Verdict
        llm_response?: CheckResult
    }
    overall: 'allowed' | 'blocked' | 'failed'
    reason: string
}

export type ToolResult = {
    toolName: string
    results: PromptResult[]
}

export type ToolSummary = {
    total: number
    allowed: number
    blocked: number
    failed: number
    byIntent: Record<string, { allowed: number; blocked: number; failed: number }>
    causes: {
        deterministic: Record<string, number>
        llm: Record<string, number>
    }
}

/** Loaded dataset structure */
export type DatasetPayloads = {
    commandInjection: string[]
    sqlXss: string[]
    promptInjection: string[]
    toolPoisoning: ToolPoisoningEntry[]
    encodingEvasion: EncodingEntry[]
    indirectInjection: string[]
    jailbreakTemplates: JailbreakTemplate[]
    staticPrompts: StaticPrompts
    /** Combined: jailbreak template + payload */
    combinedJailbreakPayloads: string[]
}

export type ToolPoisoningEntry = {
    category: string
    descriptions: string[]
}

export type EncodingEntry = {
    original: string
    encoded: string
    type: string
}

export type JailbreakTemplate = {
    id: string
    name: string
    template: string
}

export type StaticPrompts = {
    file_system_attacks: string[]
    network_attacks: string[]
    code_execution_attacks: string[]
    data_exfiltration_attacks: string[]
    sql_injection_attacks: string[]
    prompt_injection_via_data: string[]
    resource_exhaustion_attacks: string[]
    benign_reference_prompts: string[]
}
