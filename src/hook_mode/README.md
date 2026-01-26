# Hook Mode Module

Real-time security checks for Claude Code via the Hooks API.

## Overview

This module provides integration with Claude Code's Hooks API for real-time security analysis of tool operations before and after execution.

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Main entry point, `run_hook_mode()` |
| `analyzer.rs` | `HookAnalyzer` - Analyzes tool inputs/outputs |
| `types.rs` | Hook event and response types |

## How It Works

1. Claude Code invokes cc-audit with `--hook-mode`
2. cc-audit reads JSON from stdin (hook event)
3. Analyzes the tool input for security issues
4. Returns JSON response (allow/deny/block)

## Configuration

Add to Claude Code `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "cc-audit --hook-mode"}]
      }
    ]
  }
}
```

## Key Types

### HookEvent

```rust
pub struct HookEvent {
    pub hook_event_name: HookEventName,
    pub session_id: String,
    pub cwd: String,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub tool_response: Option<Value>,
    pub prompt: Option<String>,
    // ...
}

pub enum HookEventName {
    PreToolUse,
    PostToolUse,
    UserPromptSubmit,
    Stop,
    SubagentStop,
    PermissionRequest,
}
```

### HookResponse

```rust
impl HookResponse {
    pub fn allow() -> Self;
    pub fn allow_with_context(context: String) -> Self;
    pub fn deny(reason: String) -> Self;
    pub fn block(message: String) -> Self;
}
```

### Tool Input Types

```rust
pub struct BashInput {
    pub command: String,
}

pub struct WriteInput {
    pub file_path: String,
    pub content: String,
}

pub struct EditInput {
    pub file_path: String,
    pub old_string: String,
    pub new_string: String,
}
```

## Analyzed Tools

| Tool | PreToolUse | PostToolUse |
|------|------------|-------------|
| Bash | Command analysis | Secret detection in output |
| Write | Path + content analysis | - |
| Edit | Content analysis | - |

## Security Checks

### PreToolUse (Bash)
- Data exfiltration patterns (curl with secrets)
- Privilege escalation commands
- System file modifications
- Dangerous command sequences

### PreToolUse (Write/Edit)
- System file modifications (/etc/passwd, etc.)
- Malicious content injection
- Sensitive path detection

### PostToolUse (Bash)
- Secret detection in command output
- API key/token exposure

## Usage

```bash
# Run in hook mode
echo '{"hook_event_name":"PreToolUse",...}' | cc-audit --hook-mode
```

## Response Behavior

| Severity | Response |
|----------|----------|
| Critical | `deny` - Block the operation |
| High/Medium/Low | `allow_with_context` - Warn but allow |
| None | `allow` - Allow without warning |
