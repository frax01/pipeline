### STEGANOGRAPHIC-ATTACK

**Finding originali**: 16.570

1. medium
private containsAnsiEscapes(line: string): boolean {
    return (
      /\u001b\[[0-9;]*[a-zA-Z]/.test(line) ||
      /\\u001b\[[0-9;]*[a-zA-Z]/.test(line) ||
      /\\x1b\[[0-9;]*[a-zA-Z]/.test(line) ||
      /\x1b\[[0-9;]*[a-zA-Z]/.test(line)
    );
  }

2. medium
private containsWhitespaceInjection(line: string): boolean {
    const trimmedLength = line.trim().length;
    const totalLength = line.length;
    return trimmedLength > 0 && totalLength - trimmedLength > 100;
  }


**Finding dopo filtro**: 360

| Tipo ANSI_ESCAPE_INJECTION | 143 |
| Tipo WHITESPACE_INJECTION | 217 |

# ═══════════════════════════════════════════════════════════════════════════
#  CATEGORY 2: STEGANOGRAPHIC-ATTACK
# ═══════════════════════════════════════════════════════════════════════════

# ANSI escape codes used purely for console coloring (not hiding text)
SAFE_ANSI_CODES = re.compile(
    r'\\x1b\[(?:'
    r'0m|'           # reset
    r'1m|'           # bold
    r'2m|'           # dim
    r'3m|'           # italic
    r'4m|'           # underline
    r'[34][0-7]m|'   # foreground/background colors (30-37, 40-47)
    r'9[0-7]m|'      # bright foreground colors
    r'10[0-7]m'      # bright background colors
    r')$'
)

# DANGEROUS ANSI: screen manipulation, cursor hiding, text hiding
DANGEROUS_ANSI = re.compile(
    r'\\x1b\[(?:'
    r'2J|'           # clear screen
    r'[12]K|'        # clear line
    r'8m|'           # hidden text
    r'\?25[lh]|'     # cursor show/hide
    r'[0-9]+[AB]|'   # cursor up/down
    r'[0-9]+;[0-9]+H'  # cursor position
    r')'
)


def filter_steganographic_finding(finding: dict) -> tuple[bool, str]:
    """Filter steganographic attack findings."""
    vid = finding.get("id", "")
    evidence = finding.get("evidence", "") or ""

    if vid == "ANSI_ESCAPE_INJECTION":
        filepath = finding.get("file", "")

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|__test__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Filter out third-party / vendored code
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Check if it's in a file that's clearly a CLI color utility
        color_file_indicators = [
            "color", "chalk", "ansi", "terminal", "console", "cli",
            "logger", "log", "output", "format", "style", "theme",
            "pretty", "print", "display", "render"
        ]
        is_color_utility = any(ind in filepath.lower() for ind in color_file_indicators)

        # Check if evidence contains ONLY safe coloring codes
        # Extract all ANSI codes from evidence
        all_ansi = re.findall(r'\\x1b\[[0-9;]*[a-zA-Z]', evidence)
        all_ansi += re.findall(r'\\u001b\[[0-9;]*[a-zA-Z]', evidence)

        has_dangerous = DANGEROUS_ANSI.search(evidence)

        if has_dangerous:
            # If dangerous ANSI is in a tool description -> very suspicious
            if "description" in evidence.lower():
                return True, "dangerous_ansi_in_description"
            return True, "dangerous_ansi_codes"

        # ALL standard coloring codes are safe — reject them all.
        # This covers: [0m reset, [1m bold, [2-4m dim/italic/underline,
        # [30-37m] [40-47m] [90-97m] [100-107m] foreground/background colors
        # If no dangerous code found, it's just coloring.
        return False, "safe_coloring_code"

    elif vid == "WHITESPACE_INJECTION":
        filepath = finding.get("file", "")

        # Filter out test files
        if re.search(r'(?:test|spec|mock|fixture|__test__|\.test\.|\.spec\.|/tests?/)', filepath, re.IGNORECASE):
            return False, "test_file"

        # Filter out third-party code
        if re.search(r'(?:node_modules|venv|\.venv|site-packages|vendor|dist|build)', filepath, re.IGNORECASE):
            return False, "third_party_code"

        # Most whitespace findings are just poorly formatted code
        # Only keep if whitespace is extreme (>200 chars) or in description/tool context
        ws_match = re.search(r'Line contains (\d+) whitespace', evidence)
        ws_count = int(ws_match.group(1)) if ws_match else 0

        if ws_count > 200:
            return True, f"extreme_whitespace_{ws_count}"

        # Check if it's in a tool description or schema
        content_part = evidence.split('": "', 1)[-1] if '": "' in evidence else evidence
        if any(kw in evidence.lower() for kw in ["description", "schema", "tool", "prompt"]):
            return True, "whitespace_in_tool_definition"

        return False, "normal_indentation"

    return False, "unknown_id"

**Esempi:**
Verificare se sono effettivamente veri positivi o se sono tutti falsi positivi, in particolare controllare se c'è qualche VP tra le ANSI_ESCAPE_INJECTION