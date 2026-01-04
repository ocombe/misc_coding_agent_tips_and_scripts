# Destructive Git Command Protection for Claude Code

## Overview

This documentation describes a safety system that prevents AI agents from executing dangerous Git and filesystem commands. The setup includes a Python guard script and Claude Code hook configuration with **two-tier protection**:

- **DANGEROUS** patterns are **blocked completely** (catastrophic operations)
- **RISKY** patterns **prompt the user** for confirmation (dangerous but sometimes needed)

## Key Components

**The Problem**: AI agents can execute `git checkout --`, `git reset --hard`, or `rm -rf` on files, permanently erasing uncommitted changes. While instructions may forbid this, mechanical enforcement is needed.

**The Solution**: A PreToolUse hook that intercepts Bash commands before execution:
- Blocks catastrophic operations with explanatory feedback
- Prompts user confirmation for risky operations

## Two-Tier Protection

### DANGEROUS (Blocked Completely)

| Pattern | Reason |
|---------|--------|
| `rm -rf /` or `rm -rf ~` | Catastrophic filesystem destruction |
| `git push --force main/master` | Destroys shared remote history |
| `git stash clear` | Permanently deletes ALL stashes |
| `git restore <path>` | Discards uncommitted changes |
| `git restore --worktree` | Discards uncommitted changes |
| `git reset --hard` | Destroys uncommitted changes |
| `git reset --merge` | Can lose uncommitted changes |
| `git clean -f` | Removes untracked files permanently |

### RISKY (Prompts User)

| Pattern | Reason |
|---------|--------|
| `git checkout -- <path>` | Discards uncommitted changes |
| `git checkout <path>` (old-style) | Discards uncommitted changes |
| `git push --force` (non-main) | Can destroy remote history |
| `git push -f` | Can destroy remote history |
| `git branch -D` | Force-deletes without merge check |
| `rm -rf <dir>` | Recursive forced delete |
| `rm <file>` | Deletes source files |
| `git stash drop` | Deletes single stash |
| `> file.rs` | Truncates file to zero bytes |
| `: > file` | Truncates file to zero bytes |
| `truncate <file>` | Truncates file |
| `mv -f <src> <dest>` | Overwrites without backup |

### Safe Allowlist (Always Allowed)

- `git checkout -b` (creates branches)
- `git checkout --orphan` (orphan branches)
- `git restore --staged` (unstaging only)
- `git clean -n` / `git clean --dry-run` (dry-run preview)
- `rm -rf` targeting `/tmp/`, `/var/tmp/`, or `$TMPDIR`

## Installation

### Automated Setup Script

```bash
#!/usr/bin/env bash
# install-claude-git-guard.sh
# Installs two-tier protection hooks for Claude Code

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Determine location
if [[ "${1:-}" == "--global" ]]; then
    INSTALL_DIR="$HOME/.claude"
    HOOK_PATH="\$HOME/.claude/hooks/git_safety_guard.py"
    INSTALL_TYPE="global"
    echo -e "${BLUE}Installing globally to ~/.claude/${NC}"
else
    INSTALL_DIR=".claude"
    HOOK_PATH="\$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py"
    INSTALL_TYPE="project"
    echo -e "${BLUE}Installing to current project (.claude/)${NC}"
fi

mkdir -p "$INSTALL_DIR/hooks"

# Create the guard script
cat > "$INSTALL_DIR/hooks/git_safety_guard.py" << 'GUARD_SCRIPT'
#!/usr/bin/env python3
"""
Git/filesystem safety guard for Claude Code.

Protects against destructive commands that can lose uncommitted work or delete files.
This hook runs before Bash commands execute.

Permission decisions:
  - "deny"  = Block completely (truly dangerous, catastrophic)
  - "ask"   = Prompt user for confirmation (risky but sometimes needed)
  - (no output) = Allow
"""
import json
import re
import sys

# DANGEROUS: Block completely - catastrophic or affects shared resources
DANGEROUS_PATTERNS = [
    # Catastrophic filesystem operations
    (
        r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+[/~]\s*$",
        "rm -rf on root or home is catastrophic."
    ),
    (
        r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+~/\s*$",
        "rm -rf on home directory is catastrophic."
    ),
    # Force push to main/master - affects shared history
    (
        r"git\s+push\s+.*--force(?!-with-lease).*\s+(main|master)\b",
        "Force push to main/master destroys shared history."
    ),
    (
        r"git\s+push\s+-f\b.*\s+(main|master)\b",
        "Force push to main/master destroys shared history."
    ),
    # Clear all stashes - no recovery
    (
        r"git\s+stash\s+clear",
        "git stash clear permanently deletes ALL stashed changes."
    ),
    # Git restore - discards uncommitted changes
    (
        r"git\s+restore\s+(?!--staged\b)[^\s]*\s*$",
        "git restore discards uncommitted changes."
    ),
    (
        r"git\s+restore\s+--worktree",
        "git restore --worktree discards uncommitted changes."
    ),
    # Git reset variants - destroys uncommitted changes
    (
        r"git\s+reset\s+--hard",
        "git reset --hard destroys uncommitted changes."
    ),
    (
        r"git\s+reset\s+--merge",
        "git reset --merge can lose uncommitted changes."
    ),
    # Git clean - removes untracked files
    (
        r"git\s+clean\s+-[a-z]*f",
        "git clean -f removes untracked files permanently."
    ),
]

# RISKY: Prompt user - dangerous but sometimes needed
RISKY_PATTERNS = [
    # Git checkout variants that discard changes
    (
        r"git\s+checkout\s+--\s+",
        "This discards uncommitted changes. Continue?"
    ),
    (
        r"git\s+checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
        "This overwrites working tree files. Continue?"
    ),
    # git checkout <path> without -- (old-style syntax)
    (
        r"git\s+checkout\s+(?!-)[^\s]*[/][^\s]*\.[a-zA-Z]+\s*(?:2>|$|&&|\|\|)",
        "This discards uncommitted changes. Continue?"
    ),
    (
        r"git\s+checkout\s+(?!-)[^\s]+\.(rs|ts|js|vue|py|lua|json|toml|md|txt|yaml|yml|sh|css|html)\s*(?:2>|$|&&|\|\|)",
        "This discards uncommitted changes. Continue?"
    ),
    # Force push (not to main/master - those are blocked above)
    (
        r"git\s+push\s+.*--force(?!-with-lease)",
        "Force push can destroy remote history. Continue?"
    ),
    (
        r"git\s+push\s+-f\b",
        "Force push can destroy remote history. Continue?"
    ),
    # Branch force delete
    (
        r"git\s+branch\s+-D\b",
        "git branch -D force-deletes without merge check. Continue?"
    ),
    # rm -rf (general, not root/home - those are blocked above)
    (
        r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r",
        "rm -rf is destructive. Continue?"
    ),
    # Git stash drop (single stash)
    (
        r"git\s+stash\s+drop",
        "git stash drop permanently deletes stashed changes. Continue?"
    ),
    # Plain rm on source files
    (
        r"rm\s+(?!-)[^\s]*\.(rs|ts|js|vue|py|lua|json|toml|md|txt|yaml|yml|sh|css|html)\b",
        "This deletes a source file. Continue?"
    ),
    (
        r"rm\s+(?!-)[^\s]*[/][^\s]*\.[a-zA-Z]+\s*(?:2>|$|&&|\|\||;)",
        "This deletes a file. Continue?"
    ),
    # File truncation (silent and destructive)
    (
        r"(?:^|&&|\|\||;)\s*>\s*[^\s]+\.(rs|ts|js|vue|py|lua|json|toml|md|txt|yaml|yml|sh|css|html)\b",
        "This truncates a file to zero bytes. Continue?"
    ),
    (
        r":\s*>\s*[^\s]+\.[a-zA-Z]+",
        "This truncates a file to zero bytes. Continue?"
    ),
    (
        r"truncate\s+(-s\s*0\s+)?[^\s]+\.[a-zA-Z]+",
        "This truncates a file. Continue?"
    ),
    # Overwrite without backup (mv -f)
    (
        r"mv\s+-[a-z]*f[a-z]*\s+[^\s]+\s+[^\s]+\.(rs|ts|js|vue|py|lua|json|toml|md|txt|yaml|yml|sh|css|html)\b",
        "This overwrites a file without backup. Continue?"
    ),
]

# Patterns that are safe even if they match above (allowlist)
SAFE_PATTERNS = [
    r"git\s+checkout\s+-b\s+",           # Creating new branch
    r"git\s+checkout\s+--orphan\s+",     # Creating orphan branch
    r"git\s+restore\s+--staged\s+",      # Unstaging (safe)
    r"git\s+clean\s+-n",                 # Dry run
    r"git\s+clean\s+--dry-run",          # Dry run
    # Allow rm -rf on temp directories
    r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/tmp/",
    r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/var/tmp/",
    r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+\$TMPDIR/",
    r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+\$\{TMPDIR",
    r'rm\s+-[a-z]*r[a-z]*f[a-z]*\s+"\$TMPDIR/',
    r'rm\s+-[a-z]*r[a-z]*f[a-z]*\s+"\$\{TMPDIR',
]


def make_response(decision: str, reason: str, command: str) -> dict:
    """Create the hook response JSON."""
    if decision == "deny":
        message = f"🚫 BLOCKED: {reason}\n\nRun this command manually if truly needed."
    else:  # ask
        message = f"⚠️  {reason}"

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": message
        }
    }


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    # Only check Bash commands
    if tool_name != "Bash" or not command:
        sys.exit(0)

    # Check safe patterns first (allowlist)
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            sys.exit(0)

    # Check dangerous patterns (block completely)
    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            print(json.dumps(make_response("deny", reason, command)))
            sys.exit(0)

    # Check risky patterns (prompt user)
    for pattern, reason in RISKY_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            print(json.dumps(make_response("ask", reason, command)))
            sys.exit(0)

    # Allow all other commands
    sys.exit(0)


if __name__ == "__main__":
    main()
GUARD_SCRIPT

chmod +x "$INSTALL_DIR/hooks/git_safety_guard.py"
echo -e "${GREEN}✓${NC} Created guard script"

# Handle settings.json creation/merging
SETTINGS_FILE="$INSTALL_DIR/settings.json"

# Determine the correct hook path for the JSON
if [[ "$INSTALL_TYPE" == "global" ]]; then
    JSON_HOOK_PATH="\$HOME/.claude/hooks/git_safety_guard.py"
else
    JSON_HOOK_PATH="\$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py"
fi

if [[ -f "$SETTINGS_FILE" ]]; then
    # Merge into existing config using Python
    python3 << MERGE_SCRIPT
import json

with open("$SETTINGS_FILE", "r") as f:
    settings = json.load(f)

if "hooks" not in settings:
    settings["hooks"] = {}

settings["hooks"]["PreToolUse"] = [
    {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "$JSON_HOOK_PATH"
            }
        ]
    }
]

with open("$SETTINGS_FILE", "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
MERGE_SCRIPT
    echo -e "${GREEN}✓${NC} Updated existing settings.json"
else
    # Create new settings.json
    cat > "$SETTINGS_FILE" << SETTINGS_JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$JSON_HOOK_PATH"
          }
        ]
      }
    ]
  }
}
SETTINGS_JSON
    echo -e "${GREEN}✓${NC} Created settings.json"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${RED}🚫 BLOCKED (dangerous):${NC}"
echo "   • git restore <files>"
echo "   • git reset --hard / --merge"
echo "   • git clean -f"
echo "   • git push --force main/master"
echo "   • git stash clear"
echo "   • rm -rf / or ~"
echo ""
echo -e "${YELLOW}⚠️  PROMPTS (risky):${NC}"
echo "   • git checkout <files>"
echo "   • git push --force (non-main branches)"
echo "   • git branch -D"
echo "   • rm -rf <dir>, rm <file>"
echo "   • git stash drop"
echo "   • File truncation (> file)"
echo "   • mv -f overwrite"
echo ""
echo -e "${YELLOW}Restart Claude Code for the hook to take effect.${NC}"
echo ""

# Test the hook
echo "Testing hook..."
TEST_RESULT=$(echo '{"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}}' | \
    python3 "$INSTALL_DIR/hooks/git_safety_guard.py" 2>/dev/null || true)

if echo "$TEST_RESULT" | grep -q "permissionDecision.*deny" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Hook test passed (dangerous command blocked)"
else
    echo -e "${RED}✗${NC} Hook test failed"
    exit 1
fi

TEST_RESULT2=$(echo '{"tool_name": "Bash", "tool_input": {"command": "git checkout -- file.txt"}}' | \
    python3 "$INSTALL_DIR/hooks/git_safety_guard.py" 2>/dev/null || true)

if echo "$TEST_RESULT2" | grep -q "permissionDecision.*ask" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Hook test passed (risky command prompts)"
else
    echo -e "${RED}✗${NC} Hook test failed"
    exit 1
fi
```

### Manual Installation

1. Create the hooks directory:
   ```bash
   mkdir -p .claude/hooks
   ```

2. Copy the Python guard script to `.claude/hooks/git_safety_guard.py`

3. Make it executable:
   ```bash
   chmod +x .claude/hooks/git_safety_guard.py
   ```

4. Create or update `.claude/settings.json`:
   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [
             {
               "type": "command",
               "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py"
             }
           ]
         }
       ]
     }
   }
   ```

5. Restart Claude Code

## Configuration

### Project-Level (Recommended)

Place files in your project's `.claude/` directory. The hook applies only to that project.

### Global Installation

Use `--global` flag or place files in `~/.claude/`. The hook applies to all projects.

```bash
./install-claude-git-guard.sh --global
```

## How It Works

The Python script receives JSON via stdin containing the command about to execute:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "git checkout -- file.txt"
  }
}
```

The guard then:
1. Checks against **safe patterns** first (allowlist)
2. Checks against **dangerous patterns** → returns `"permissionDecision": "deny"`
3. Checks against **risky patterns** → returns `"permissionDecision": "ask"`
4. If no match, exits silently (allows command)

### Permission Decisions

| Decision | Behavior | User Experience |
|----------|----------|-----------------|
| `deny` | Blocked completely | Shows 🚫 BLOCKED message, command not run |
| `ask` | Prompts user | Shows ⚠️ warning, user chooses Yes/No |
| (none) | Allowed | Command runs normally |

## Testing

```bash
# Should be BLOCKED (deny)
echo '{"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}}' | \
    python3 .claude/hooks/git_safety_guard.py

# Should PROMPT (ask)
echo '{"tool_name": "Bash", "tool_input": {"command": "git checkout -- file.txt"}}' | \
    python3 .claude/hooks/git_safety_guard.py

# Should be ALLOWED (no output)
echo '{"tool_name": "Bash", "tool_input": {"command": "git status"}}' | \
    python3 .claude/hooks/git_safety_guard.py

# rm -rf on temp should be ALLOWED
echo '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/test-dir"}}' | \
    python3 .claude/hooks/git_safety_guard.py
```

## Customization

### Adding New Patterns

Edit the Python script to add patterns to the appropriate list:

```python
# Block completely
DANGEROUS_PATTERNS = [
    (r"your-regex-here", "Explanation shown when blocked."),
    ...
]

# Prompt user
RISKY_PATTERNS = [
    (r"your-regex-here", "Question shown to user. Continue?"),
    ...
]

# Always allow (checked first)
SAFE_PATTERNS = [
    r"safe-pattern-regex",
    ...
]
```

### Adjusting File Extensions

The default patterns protect common source files:
- `rs`, `ts`, `js`, `vue`, `py`, `lua`, `json`, `toml`, `md`, `txt`, `yaml`, `yml`, `sh`, `css`, `html`

Add more extensions to the regex patterns as needed.

## Important Notes

**Restart Required**: Claude Code snapshots hook configuration at startup. Changes require application restart.

**Works with Bypass Mode**: The `ask` permission decision prompts the user even when running in bypass permissions mode.

**Not Foolproof**: Pattern matching via regex can be bypassed with obfuscation. This is a safety net for honest mistakes, not a security boundary.

**Chained Commands**: The hook catches patterns in chained commands like `touch file && rm file`.

**Commit Messages**: Be aware that patterns can match text inside commit messages (e.g., mentioning "rm -rf" in a commit message may trigger a prompt).

## Troubleshooting

### Hook not working

1. Verify the script is executable: `chmod +x .claude/hooks/git_safety_guard.py`
2. Check settings.json syntax is valid JSON
3. Restart Claude Code completely
4. Test the hook manually with the echo commands above

### False positives

If legitimate commands are being blocked/prompted, add them to `SAFE_PATTERNS` in the Python script.

### Hook timeout

The default hook timeout is 60 seconds. The guard script runs in milliseconds, so timeouts indicate a different issue (check script syntax).
