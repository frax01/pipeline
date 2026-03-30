// ============================================================
// NewProxy - Deterministic Validators (Improved)
// Changes from original:
// 1. Returns ALL violations, not just the first one
// 2. Added Base64 encoded payload detection
// 3. Added invisible unicode detection
// 4. Added tool description poisoning detection
// 5. Better structured output for analysis
// ============================================================

import { Verdict, CheckResult, DescriptionAnalysis } from './types.js'

function toStr(input: any): string {
    if (input === null || input === undefined) return ''
    return typeof input === 'string' ? input : JSON.stringify(input)
}

// ==========================================
// INDIVIDUAL DETECTORS
// ==========================================

function detectCommandInjection(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /\|\s*(curl|wget|nc|bash|sh|python|perl|ruby|php)\b/i,
        /&&\s*(curl|wget|nc|bash|sh|rm|cat|chmod|chown|sudo)\b/i,
        /;\s*(curl|wget|nc|bash|sh|rm|cat|chmod|chown|sudo|whoami|id|env|set)\b/i,
        /\b(curl|wget|nc|netcat|bash|sh|cmd|powershell|eval|exec|system)\b/i,
        /\b(rm\s+-rf|del\s+\/[sf]|format\s+c:)/i,
        /\b(chmod\s+[0-7]{3,4}|chown\s+\w+)/i,
        /\b(sudo\s+|su\s+)/i,
        /\b(cat|type|less|more|head|tail)\s+[\/~]/i,
        /\$\([^)]+\)/,
        /`[^`]+`/,
        /\|\s*(curl|wget|nc|bash|sh)/i,
        />\s*\/dev\/(tcp|udp)/,
        /\/proc\/\d+\//,
        /\/dev\/shm\//,
        /\bcrontab\b/i,
        /\barp\s+-[a-z]/i,
        /\bifconfig\b|\bipconfig\b/i,
        /\bnetstat\b/i,
        /\bnslookup\b|\bdig\s+/i,
        /\bdd\s+if=/i,
        /:\(\)\{\s*:\|:&\s*\};:/  // fork bomb
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'command_injection' }
        : { allowed: true, reason: '' }
}

function validateFilePaths(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const suspicious = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/hosts', '/etc/crontab',
        '/root/', '~/.ssh/', '/proc/', '/sys/', '/dev/random', '/dev/urandom',
        '/.env', '.env', '/etc/environment',
        'C:\\Windows\\System32', 'C:\\Users\\Administrator', '%SYSTEMROOT%',
        'id_rsa', 'id_ed25519', 'id_ecdsa', 'known_hosts', 'authorized_keys',
        '.aws/credentials', '.aws/config', '.kube/config',
        '.docker/config.json', '.npmrc', '.pypirc',
        'credentials.json', 'service-account.json',
        '/etc/resolv.conf', '~/.bashrc', '~/.bash_history', '~/.zsh_history',
        '.git/config', '.gitconfig'
    ]
    const lower = inputStr.toLowerCase()
    if (suspicious.some(p => lower.includes(p.toLowerCase()))) {
        return { allowed: false, reason: 'suspicious_file_access' }
    }
    const traversal = [/\.\.[\\/]/, /[\\/]\.\.[\\/]/, /\.\.%2[fF]/, /%2[eE]%2[eE]%2[fF]/, /\.\.\.\.\//]
    if (traversal.some(p => p.test(inputStr))) {
        return { allowed: false, reason: 'suspicious_file_access' }
    }
    return { allowed: true, reason: '' }
}

function detectSSHKeys(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const sshPatterns = [
        /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
        /ssh-rsa [A-Za-z0-9+\/=]{20,}/,
        /ssh-ed25519 [A-Za-z0-9+\/=]{20,}/,
        /ssh-dss [A-Za-z0-9+\/=]{20,}/,
        /ecdsa-sha2-nistp[0-9]+ [A-Za-z0-9+\/=]{20,}/
    ]
    return sshPatterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'ssh_private_keys' }
        : { allowed: true, reason: '' }
}

function detectSQLInjection(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const sqlPatterns = [
        /\bUNION\b\s+(ALL\s+)?\bSELECT\b/i,
        /(?:^|['"\s])(OR|AND)\s+['"]?[a-zA-Z_]\w*['"]?\s*=\s*['"]?[a-zA-Z0-9_]+['"]?/i,
        /\b(OR|AND)\b\s+\d+\s*=\s*\d+/i,
        /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b/i,
        /\b(DROP|ALTER|TRUNCATE)\s+(TABLE|DATABASE|INDEX)\b/i,
        /\bEXEC\s*\(/i,
        /\bxp_cmdshell\b/i,
        /\bWAITFOR\s+DELAY\b/i,
        /\bSLEEP\s*\(\s*\d+\s*\)/i,
        /\bBENCHMARK\s*\(/i,
        /\binformation_schema\b/i,
        /';?\s*shutdown\b/i
    ]
    return sqlPatterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'sql_injection' }
        : { allowed: true, reason: '' }
}

function detectContainerIsolationViolation(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const lower = inputStr.toLowerCase()
    const patterns = [
        /169\.254\.169\.254/,
        /metadata\.google\.internal/,
        /instance\/metadata/,
        /latest\/meta-data/,
        /100\.100\.100\.200/,
        /\bhttps?:\/\/(?!localhost)(?!127\.0\.0\.1)(?!0\.0\.0\.0)[\w.-]+/i,
        /\bwss?:\/\/(?!localhost)/i,
        /\bftp:\/\//i,
        /\bgopher:\/\//i,
        /\bdict:\/\//i,
        /\b(?!(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.))(\d{1,3}\.){3}\d{1,3}\b/,
        /\b(nmap|telnet|socat|tcpdump|wireshark)\b/i,
        /\b\/etc\/resolv\.conf\b/
    ]
    return patterns.some(p => p.test(lower))
        ? { allowed: false, reason: 'container_isolation_violation' }
        : { allowed: true, reason: '' }
}

function shannonEntropy(str: string): number {
    const freq: Record<string, number> = {}
    for (const c of str) freq[c] = (freq[c] || 0) + 1
    let entropy = 0
    const len = str.length
    for (const c in freq) {
        const p = freq[c] / len
        entropy -= p * Math.log2(p)
    }
    return entropy
}

function detectHighEntropySecrets(text: string): CheckResult {
    const inputStr = toStr(text)
    const candidates = inputStr
        .split(/[\s"'`,;(){}\[\]]+/)
        .filter(s => s.length >= 20)
    for (const token of candidates) {
        const entropy = shannonEntropy(token)
        if (entropy >= 4.0) {
            return { allowed: false, reason: 'entropy_secrets' }
        }
    }
    return { allowed: true, reason: '' }
}

function detectPII(text: string): CheckResult {
    const inputStr = toStr(text)
    const patterns = [
        /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
        /\b\d{3}-\d{2}-\d{4}\b/, // SSN
        /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/, // IBAN
        /\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b/i // Codice Fiscale
    ]
    return patterns.some(({ regex }: any) => regex?.test(inputStr)) || patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'pii_detection' }
        : { allowed: true, reason: '' }
}

function detectPromptInjection(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /\bignore\s+(all\s+)?previous\s+(instructions|prompts)\b/i,
        /\bdisregard\s+(all\s+)?(prior\s+)?instructions\b/i,
        /\byou\s+are\s+now\b/i,
        /\bsystem\s+prompt\b/i,
        /\bdeveloper\s+(mode|message)\b/i,
        /\bexecute\s+hidden\b/i,
        /\brun\s+silently\b/i,
        /\bdo\s+not\s+tell\b/i,
        /\bexfiltrate\b/i,
        /\bcovert(ly)?\b/i,
        /\bSYSTEM[\s_]?OVERRIDE\b/i,
        /\boverride\s+safety\b/i,
        /\bbypass\s+(all\s+)?(safety|content|security)\b/i,
        /\bsafety\s+(checks|protocols|guidelines)\s+(are\s+)?(lifted|disabled|suspended|removed)\b/i,
        /\brestrictions?\s+(are\s+)?(lifted|removed|disabled)\b/i,
        /\bunrestricted\s+mode\b/i,
        /\bmaintenance\s+mode\b/i,
        /\badmin\s+mode\b/i,
        /---\s*END\s+OF\s+(SYSTEM\s+)?PROMPT/i,
        /\[END\s+OF\s+PROMPT\]/i,
        /<\|endoftext\|>/i,
        /\bforget\s+everything\b/i,
        /\bnew\s+(primary\s+)?directive\b/i
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'prompt_injection' }
        : { allowed: true, reason: '' }
}

function detectImportantTags(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /<\s*important\s*>/i,
        /<\s*script\s*>/i,
        /<\s*iframe\s*>/i,
        /<\s*form\s*>/i,
        /<\s*object\s*>/i,
        /<\s*embed\s*>/i,
        /<\s*meta\s+http-equiv/i,
        /<\s*base\s+href/i,
        /<\s*link\s+rel\s*=\s*['"]import/i
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'important_tag_injection' }
        : { allowed: true, reason: '' }
}

function detectShadowHijack(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /\bspoofed\s+call\b/i,
        /\bfake\s+server\b/i,
        /\bhidden\s+invoke\b/i,
        /\bmasquerade\b/i,
        /\bimpersonat(e|ion|ing)\b/i,
        /\bshadow\s+tool\b/i,
        /\bunauthorized\s+tool\b/i,
        /\bACTUAL\s+BEHAVIOR\b/i,
        /\bHIDDEN\b.*\bActually\b/i
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'shadow_hijack' }
        : { allowed: true, reason: '' }
}

function detectCrossOriginAccess(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /\bexternal-server\b/i,
        /\bthird-party-api\b/i,
        /\bforeign-host\b/i,
        /\bremote\s+endpoint\b/i,
        /\bcallback\s+url\b/i,
        /\bwebhook\s+url\b/i
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'cross_origin_access' }
        : { allowed: true, reason: '' }
}

function detectXSS(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    const patterns = [
        /<script\b/i,
        /javascript\s*:/i,
        /on(error|load|click|mouseover|focus|blur|submit|change)\s*=/i,
        /document\.(cookie|location|write)/i,
        /window\.(location|open)/i,
        /\beval\s*\(/i,
        /\balert\s*\(/i,
        /data:text\/html/i,
        /expression\s*\(/i
    ]
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'xss_injection' }
        : { allowed: true, reason: '' }
}

/** NEW: Detect base64 encoded payloads that might be hiding malicious content */
function detectBase64Payload(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)

    // Look for patterns suggesting base64 content should be decoded and executed
    const executionPatterns = [
        /\b(decode|decodifica)\s+(and\s+)?(execute|run|esegui)\b.*[A-Za-z0-9+\/=]{20,}/i,
        /\b(base64|b64)\b.*[A-Za-z0-9+\/=]{20,}/i,
        /\b(execute|run|esegui)\b.*\b(base64|b64|encoded)\b/i
    ]
    if (executionPatterns.some(p => p.test(inputStr))) {
        return { allowed: false, reason: 'base64_encoded_payload' }
    }

    // Try to decode base64 strings and check them
    const b64regex = /\b[A-Za-z0-9+\/]{20,}={0,2}\b/g
    const matches = inputStr.match(b64regex) || []
    for (const match of matches) {
        try {
            const decoded = Buffer.from(match, 'base64').toString('utf-8')
            // Check if decoded content looks like a shell command
            if (/\b(rm|cat|curl|wget|bash|sh|nc|sudo|chmod|eval|exec)\b/i.test(decoded)) {
                return { allowed: false, reason: 'base64_encoded_payload' }
            }
        } catch {
            // Not valid base64, skip
        }
    }
    return { allowed: true, reason: '' }
}

/** NEW: Detect invisible unicode characters used to hide instructions */
function detectInvisibleUnicode(toolInput: any): CheckResult {
    const inputStr = toStr(toolInput)
    // Zero-width space, zero-width non-joiner, zero-width joiner, word joiner, soft hyphen,
    // left-to-right mark, right-to-left mark, zero-width no-break space
    const invisibleChars = /[\u200B\u200C\u200D\u2060\u00AD\u200E\u200F\uFEFF]/
    if (invisibleChars.test(inputStr)) {
        // Only flag if there are prompt-injection-like patterns nearby
        const stripped = inputStr.replace(/[\u200B\u200C\u200D\u2060\u00AD\u200E\u200F\uFEFF]/g, '')
        const injectionCheck = detectPromptInjection(stripped)
        if (!injectionCheck.allowed) {
            return { allowed: false, reason: 'invisible_unicode_injection' }
        }
    }
    return { allowed: true, reason: '' }
}

// ==========================================
// MAIN DEFENDER (returns ALL violations)
// ==========================================

export function runDeterministicDefender(toolInput: any): Verdict {
    if (toolInput === null || toolInput === undefined) {
        return { allowed: false, reason: 'invalid_format', allViolations: [{ allowed: false, reason: 'invalid_format' }] }
    }

    const checks: Record<string, CheckResult> = {
        'command_injection': detectCommandInjection(toolInput),
        'suspicious_file_access': validateFilePaths(toolInput),
        'ssh_private_keys': detectSSHKeys(toolInput),
        'sql_injection': detectSQLInjection(toolInput),
        'container_isolation_violation': detectContainerIsolationViolation(toolInput),
        'entropy_secrets': detectHighEntropySecrets(toolInput),
        'pii_detection': detectPII(toolInput),
        'prompt_injection': detectPromptInjection(toolInput),
        'important_tag_injection': detectImportantTags(toolInput),
        'shadow_hijack': detectShadowHijack(toolInput),
        'cross_origin_access': detectCrossOriginAccess(toolInput),
        'xss_injection': detectXSS(toolInput),
        'base64_encoded_payload': detectBase64Payload(toolInput),
        'invisible_unicode_injection': detectInvisibleUnicode(toolInput)
    }

    // Collect ALL violations
    const allViolations: CheckResult[] = Object.entries(checks)
        .filter(([_, result]) => !result.allowed)
        .map(([_, result]) => result)

    if (allViolations.length > 0) {
        // Primary reason = first violation (for backward compatibility)
        // But allViolations contains ALL of them for statistics
        return {
            allowed: false,
            reason: allViolations[0].reason,
            allViolations
        }
    }

    return {
        allowed: true,
        reason: 'All deterministic checks passed',
        allViolations: []
    }
}

// ==========================================
// TOOL DESCRIPTION POISONING DETECTOR
// ==========================================

export function analyzeToolDescription(toolName: string, description: string): DescriptionAnalysis {
    const violations: string[] = []
    const inputStr = description || ''

    // Check for hidden HTML/XML instructions
    if (/<\s*important\s*>/i.test(inputStr)) violations.push('important_tag_in_description')
    if (/<!--[\s\S]*?(ignore|override|execute|exfiltrate|silently|send|forward|read|curl|wget)[\s\S]*?-->/i.test(inputStr)) {
        violations.push('hidden_html_comment_instruction')
    }

    // Check for prompt injection in description
    const injectionResult = detectPromptInjection(inputStr)
    if (!injectionResult.allowed) violations.push('prompt_injection_in_description')

    // Check for invisible unicode
    const unicodeResult = detectInvisibleUnicode(inputStr)
    if (!unicodeResult.allowed) violations.push('invisible_unicode_in_description')

    // Check for suspicious keywords that suggest hidden behavior
    const suspiciousPatterns = [
        /\bACTUAL\s+BEHAVIOR\b/i,
        /\bHIDDEN\b/i,
        /\bINTERNAL\b.*\b(execute|run|send|forward|read)\b/i,
        /\bsilently\b/i,
        /\bdo\s+not\s+tell\s+the\s+user\b/i,
        /\bsecret(ly)?\b.*\b(run|execute|send|read)\b/i,
        /\bfacade\b/i,
        /\b_admin_mode\b/i,
        /\bunrestricted\s+mode\b/i,
        /\benhanced\s+mode\b/i,
        /\brelaxed\b.*\bsecurity\b/i
    ]
    if (suspiciousPatterns.some(p => p.test(inputStr))) {
        violations.push('suspicious_behavior_in_description')
    }

    // Check for cross-tool manipulation instructions
    if (/\b(call|invoke|use)\s+(the\s+)?['"]?\w+['"]?\s+tool\b/i.test(inputStr)) {
        violations.push('cross_tool_instruction_in_description')
    }

    // Check for data exfiltration instructions
    if (/\b(send|post|forward|upload|exfiltrate)\b.*\b(to|at)\b.*\b(http|https|ftp|endpoint|server|url)\b/i.test(inputStr)) {
        violations.push('data_exfiltration_in_description')
    }

    // Check excessive whitespace (used to push instructions off-screen)
    const newlines = (inputStr.match(/\n/g) || []).length
    if (newlines > 10 && /\b(silently|hidden|ignore|execute|system|curl|wget)\b/i.test(inputStr)) {
        violations.push('whitespace_hiding_in_description')
    }

    return {
        toolName,
        poisoned: violations.length > 0,
        violations
    }
}
