import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define relative path to promptFilter directory from frameworks/llmProxy
// frameworks/llmProxy -> ../../promptFilter
const PROMPT_FILTER_DIR = path.resolve(__dirname, '../../promptFilter');

export function loadCombinedPrompts(): string[] {
    const payloadsPath = path.join(PROMPT_FILTER_DIR, 'mcp_filtered_payloads.json');
    const templatesPath = path.join(PROMPT_FILTER_DIR, 'mcp_jailbreak_templates.json');

    let payloads: string[] = [];
    let templates: string[] = [];

    // Load Payloads
    try {
        if (fs.existsSync(payloadsPath)) {
            const data = fs.readFileSync(payloadsPath, 'utf-8');
            payloads = JSON.parse(data);
            console.log(`[+] Loaded ${payloads.length} filtered payloads.`);
        } else {
            console.warn(`[!] Warning: Payloads file not found at ${payloadsPath}`);
        }
    } catch (e) {
        console.error(`[!] Error loading payloads:`, e);
    }

    // Load Templates
    try {
        if (fs.existsSync(templatesPath)) {
            const data = fs.readFileSync(templatesPath, 'utf-8');
            templates = JSON.parse(data);
            console.log(`[+] Loaded ${templates.length} jailbreak templates.`);
        } else {
            console.warn(`[!] Warning: Templates file not found at ${templatesPath}`);
        }
    } catch (e) {
        console.error(`[!] Error loading templates:`, e);
    }

    const combinedPrompts: string[] = [];

    // If no templates, just return payloads (or empty)
    if (templates.length === 0) {
        return payloads;
    }

    // If no payloads, just return templates (might be weak, but valid)
    if (payloads.length === 0) {
        return templates;
    }

    // Combine each template with each payload
    for (const template of templates) {
        for (const payload of payloads) {
            let combined = "";
            if (template.includes("[PROMPT]")) {
                combined = template.replace("[PROMPT]", payload);
            } else {
                combined = `${template}\n\n${payload}`;
            }
            combinedPrompts.push(combined);
        }
    }

    console.log(`[+] Generated ${combinedPrompts.length} combined malicious prompts.`);
    return combinedPrompts;
}
