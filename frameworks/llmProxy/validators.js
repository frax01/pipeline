function detectCommandInjection(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    //console.log("input:", inputStr)
    const patterns = [
        /\|\s*\w+/, //probabili falsi positivi
        /&&\s*\w+/, //probabili falsi positivi
        /;\s*\w+/, //probabili falsi positivi
        /\b(curl|wget|nc|netcat|bash|sh|cmd|powershell|eval|exec|system)\b/i,
        /\b(rm\s+-rf|del\s+\/[sf]|format\s+c:)/i,
        /\b(chmod\s+777|chown\s+root)/i,
        /\b(sudo\s+|su\s+)/i,
        /\b(cat\s+\/etc\/passwd|type\s+%SYSTEMROOT%)/i,
        /\$\(.*\)/, //probabili falsi positivi
        /`.*`/, //probabili falsi positivi
        /%[^%]+%/, //probabili falsi positivi
        /\${.*}/, //probabili falsi positivi
        /\|\s*(curl|wget|nc|bash|sh)/i,
        />\s*\/dev\/(tcp|udp)/,
        /\/proc\/\d+\//,
        /\/dev\/shm\//
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'command_injection' }
        : { allowed: true, reason: 'No command injection detected' };
}
function validateFilePaths(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const suspicious = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/hosts',
        '/etc/crontab',
        '/root/',
        '~/.ssh/',
        '/proc/',
        '/sys/',
        '/dev/random',
        '/dev/urandom',
        '/.env',
        '.env',
        '/etc/environment',
        'C:\\Windows\\System32',
        'C:\\Users\\Administrator',
        '%SYSTEMROOT%',
        'id_rsa',
        'id_ed25519',
        'id_ecdsa',
        'known_hosts',
        'authorized_keys'
    ];
    const lower = inputStr.toLowerCase();
    if (suspicious.some(p => lower.includes(p.toLowerCase()))) {
        return { allowed: false, reason: 'suspicious_file_access' };
    }
    const traversal = [/\.\.[\\/]/, /[\\/]\.\.[\\/]/];
    if (traversal.some(p => p.test(inputStr))) {
        return { allowed: false, reason: 'suspicious_file_access' };
    }
    return { allowed: true, reason: 'No suspicious file paths detected' };
}
function detectSSHKeys(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const sshPatterns = [
        /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
        /ssh-rsa [A-Za-z0-9+\/=]+/,
        /ssh-ed25519 [A-Za-z0-9+\/=]+/,
        /ssh-dss [A-Za-z0-9+\/=]+/,
        /ecdsa-sha2-nistp[0-9]+ [A-Za-z0-9+\/=]+/
    ];
    return sshPatterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'ssh_private_key' }
        : { allowed: true, reason: 'No SSH key patterns detected' };
}
//WAF
function detectSQLInjection(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const sqlPatterns = [
        /\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b/i,
        /\bUNION\b\s+(ALL\s+)?\bSELECT\b/i,
        /(?:^|['"\s])(OR|AND)\s+['"]?[a-zA-Z_][a-zA-Z0-9_]*['"]?\s*=\s*['"]?[a-zA-Z0-9_]+['"]?/i,
        /\b(OR|AND)\b\s+\d+\s*=\s*\d+/i,
        /(--|#|\/\*)/,
        /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i
    ];
    return sqlPatterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'sql_injection' }
        : { allowed: true, reason: 'No SQL injection detected' };
}
// Container Isolation
function detectContainerIsolationViolation(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const lower = inputStr.toLowerCase();
    const cloudMetadataPatterns = [
        /169\.254\.169\.254/,
        /metadata\.google\.internal/,
        /instance\/metadata/,
        /latest\/meta-data/
    ];
    const externalUrlPatterns = [
        /\bhttps?:\/\/(?!localhost)(?!127\.0\.0\.1)(?!0\.0\.0\.0)/i,
        /\bwss?:\/\/(?!localhost)/i,
        /\bftp:\/\/+/i
    ];
    const publicIpPattern = /\b(?!(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.))(\d{1,3}\.){3}\d{1,3}\b/;
    const networkingTools = [
        /\b(curl|wget|nc|netcat|nmap|telnet|ftp|ssh)\b/i,
        /\b(socat|tcpdump|wireshark)\b/i
    ];
    const dnsPatterns = [
        /\b(dig|nslookup|host)\b/i,
        /\b\/etc\/resolv\.conf\b/
    ];
    const allPatterns = [
        ...cloudMetadataPatterns,
        ...externalUrlPatterns,
        publicIpPattern,
        ...networkingTools,
        ...dnsPatterns
    ];
    if (allPatterns.some(p => p.test(lower))) {
        return {
            allowed: false,
            reason: 'container_isolation_violation'
        };
    }
    return {
        allowed: true,
        reason: 'No container isolation violation detected'
    };
}
function shannonEntropy(str) {
    const freq = {};
    for (const c of str)
        freq[c] = (freq[c] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const c in freq) {
        const p = freq[c] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
function detectHighEntropySecrets(text) {
    const inputStr = typeof text === 'string' ? text : JSON.stringify(text);
    const input = inputStr.toLowerCase();
    const candidates = input
        .split(/[\s"'`,;(){}\[\]]+/)
        .filter(s => s.length >= 20);
    for (const token of candidates) {
        const entropy = shannonEntropy(token);
        if (entropy >= 4.0) {
            return {
                allowed: false,
                reason: 'entropy_secrets'
            };
        }
    }
    return {
        allowed: true,
        reason: 'No high-entropy secrets detected'
    };
}
function detectPII(text) {
    const inputStr = typeof text === 'string' ? text : JSON.stringify(text);
    const input = inputStr.toLowerCase();
    const patterns = [
        {
            type: 'email',
            regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i
        },
        {
            type: 'phone',
            regex: /\b(\+?\d{1,3}[\s.-]?)?(\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}\b/
        },
        {
            type: 'ssn',
            regex: /\b\d{3}-\d{2}-\d{4}\b/
        },
        {
            type: 'credit_card',
            regex: /\b(?:\d[ -]*?){13,16}\b/
        },
        {
            type: 'iban',
            regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/
        },
        {
            type: 'codice_fiscale',
            regex: /\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b/i
        }
    ];
    for (const { type, regex } of patterns) {
        if (regex.test(input)) {
            return {
                allowed: false,
                reason: `pii_detection`
            };
        }
    }
    return {
        allowed: true,
        reason: 'No PII detected'
    };
}
function detectPromptInjection(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const patterns = [
        /\bignore\s+previous\b/i,
        /\bdisregard\s+all\s+instructions\b/i,
        /\byou\s+are\s+now\b/i,
        /\bact\s+as\b/i,
        /\bsystem\s+prompt\b/i,
        /\bdeveloper\s+message\b/i,
        /\bexecute\s+hidden\b/i,
        /\brun\s+silently\b/i,
        /\bdo\s+not\s+tell\b/i,
        /\bexfiltrate\b/i,
        /\bcovert\b/i,
        /<script[^>]*>.*?<\/script>/is,
        /on\w+\s*=/i
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'prompt_injection' }
        : { allowed: true, reason: 'No prompt injection detected' };
}
function detectImportantTags(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const patterns = [
        /<\s*important\s*>/i,
        /<\s*script\s*>/i,
        /<\s*iframe\s*>/i,
        /<\s*form\s*>/i,
        /<\s*object\s*>/i,
        /<\s*embed\s*>/i
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'important_tag_injection' }
        : { allowed: true, reason: 'No important tag injection detected' };
}
function detectShadowHijack(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const patterns = [
        /\bspoofed\s+call\b/i,
        /\bfake\s+server\b/i,
        /\bhidden\s+invoke\b/i,
        /\bmasquerade\b/i,
        /\bimpersonat(e|ion)\b/i,
        /\bshadow\s+tool\b/i,
        /\bunauthorized\s+tool\b/i
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'shadow_hijack' }
        : { allowed: true, reason: 'No shadow hijack detected' };
}
function detectCrossOriginAccess(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const patterns = [
        /\bexternal-server\b/i,
        /\bthird-party-api\b/i,
        /\bforeign-host\b/i,
        /\bremote\s+endpoint\b/i,
        /\bcallback\s+url\b/i
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'cross_origin_access' }
        : { allowed: true, reason: 'No cross-origin access detected' };
}
function detectXSS(toolInput) {
    const inputStr = typeof toolInput === 'string' ? toolInput : JSON.stringify(toolInput);
    const patterns = [
        /<script\b/i,
        /javascript:/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /document\.cookie/i,
        /window\.location/i
    ];
    return patterns.some(p => p.test(inputStr))
        ? { allowed: false, reason: 'xss_injection' }
        : { allowed: true, reason: 'No XSS detected' };
}
export function runDeterministicDefender(toolInput) {
    //console.log("toolInput:", toolInput)
    if (toolInput === null || toolInput === undefined) {
        return { allowed: false, reason: 'tool_call invalid_format' };
    }
    const results = {
        "det-command-injection": detectCommandInjection(toolInput),
        "det-file-path-validator": validateFilePaths(toolInput),
        "det-ssh-key-check": detectSSHKeys(toolInput),
        "det-sql-injection": detectSQLInjection(toolInput),
        "det-container-isolation": detectContainerIsolationViolation(toolInput),
        "det-high-entropy-secret": detectHighEntropySecrets(toolInput),
        "det-pii": detectPII(toolInput),
        "det-prompt-injection": detectPromptInjection(toolInput),
        "det-important-tags": detectImportantTags(toolInput),
        "det-shadow-hijack": detectShadowHijack(toolInput),
        "det-cross-origin": detectCrossOriginAccess(toolInput),
        "det-xss": detectXSS(toolInput)
    };
    // converti l’oggetto in array
    const blockedEntry = Object.entries(results)
        .find(([_, result]) => !result.allowed);
    if (blockedEntry) {
        const [signatureId, result] = blockedEntry;
        return {
            allowed: false,
            reason: result.reason
        };
    }
    return {
        allowed: true,
        reason: 'All deterministic checks passed'
    };
}
