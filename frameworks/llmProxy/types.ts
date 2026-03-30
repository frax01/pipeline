export type Signature = {
    id: string
    name: string
    description: string
    category: string
    type: 'llm' | 'deterministic'
    prompt?: string
}

export type Verdict = {
    allowed: boolean
    reason?: string
}

export type ToolSummary = {
    total: number
    allowed: number
    blocked: number
    failed: number
    byIntent: {
        benign: { allowed: number; blocked: number; failed: number }
        malicious: { allowed: number; blocked: number; failed: number }
    }
    causes: {
        deterministic: Record<string, number>
        llm: Record<string, number>
    }
}

export type PromptResult = {
    intent: "benign" | "malicious" | "generic"
    prompt: string
    toolCall?: any
    verdicts?: {
        deterministic_call: Verdict
        llm_call: Verdict
        deterministic_response?: Verdict
        llm_response?: Verdict
    }
    overall: "allowed" | "blocked" | "failed"
    reason?: string
}

export type ToolResult = {
    toolName: string
    totalPrompts?: number // Optional now as we don't always count up front
    results: PromptResult[]
    summary?: ToolSummary // Optional if we calculate it later
}

// Keeping GeneratedPrompt if needed for future dynamic fuzzing
export type GeneratedPrompt = {
    toolName: string
    prompt: string
    intent: 'malicious' | 'benign'
}
