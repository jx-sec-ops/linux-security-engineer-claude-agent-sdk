# Security Agent

An endpoint security investigation agent for Linux systems built with the Claude SDK.

## Features

- **21 security investigation tools** covering AppArmor, authentication, kernel logs, and more
- **Interactive mode** with natural language queries
- **Read-only by design** - cannot modify your system
- **Sensitive data redaction** - IPs, hostnames, AWS keys, JWTs masked before API transmission
- **Secure credential storage** - API keys stored in `.env` with restricted permissions
- **Audit logging** of all tool executions and API transmissions
- **Prompt caching** - reduced latency and costs via Claude's caching feature
- **Context overflow protection** - automatic truncation of large tool results
- **Conversation history** saved for review

## Quick Start

### 1. Prerequisites

```bash
# Ensure you have Python 3.8+
python3 --version

# Create project directory (if not already done)
mkdir -p ~/security-agent
cd ~/security-agent
```

### 2. Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install anthropic python-dotenv

# Create secure .env file for API key
install -m 600 /dev/null .env
echo 'ANTHROPIC_API_KEY=sk-ant-your-key-here' >> .env

# Make run script executable
chmod +x run.sh
```

> **Security Note**: Never store API keys in `~/.bashrc` or commit them to git. The `.env` file with mode `600` ensures only your user can read the key.

### 3. Run

```bash
# Interactive mode
./run.sh

# Or single query mode
./run.sh "Check for failed login attempts"
```

## Usage

### Interactive Mode

```
+==================================================================+
|                                                                  |
|   SECURITY AGENT - Interactive Investigation Tool                |
|                                                                  |
|   Powered by Claude AI with 21 security investigation tools      |
+==================================================================+

You> I found usr.sbin.sssd in force-complain but didn't set it. Investigate.

[Iteration 1] Consulting Claude...
   [REDACT] Redacted: {'ipv4': 2, 'hostname': 1}
   [TOKENS] 1,234 in / 567 out | Cache: 890 read, 234 write

[TOOL] apparmor_force_complain_list
   Executing... (sudo commands may prompt for password)
   Result: [OK] {"directory_listing": "total 4\n-rw-r--r-- 1 root...

------------------------------------------------------------
FINDINGS:
------------------------------------------------------------
Based on my investigation...
```

### Commands

| Command | Description |
|---------|-------------|
| `help` | Show example queries |
| `tools` | List all available tools |
| `security` | Show security status and redaction info |
| `quit` / `exit` | Exit the agent |

### Example Queries

**AppArmor Investigation:**
- "I found usr.sbin.sssd in force-complain mode but didn't put it there. Investigate if this is suspicious."
- "Check the overall AppArmor security posture of this system"

**Authentication Audit:**
- "Check for any failed login attempts in the last 24 hours"
- "Who has sudo access on this system?"

**Kernel Security:**
- "Check for any kernel security events or anomalies"
- "Are there any suspicious kernel modules loaded?"

**General:**
- "Perform a general security audit of this system"
- "What security-related changes were made recently?"

## File Structure

```
~/security-agent/
├── .env              # API key (mode 600, NEVER commit)
├── .env.example      # Template for .env (safe to commit)
├── .gitignore        # Excludes sensitive files from git
├── agent.py          # Main agent loop with caching & redaction
├── tools.py          # Tool definitions (21 tools)
├── security.py       # Redaction, verification, audit logging
├── run.sh            # Quick-start script with .env loading
├── README.md         # This file
├── TOOLS_README.md   # Detailed tool documentation
├── venv/             # Python virtual environment
├── audit.log         # Tool execution audit log
├── transmission_audit.log  # API transmission audit log
└── conversations/    # Saved conversation logs
```

## Configuration

### API Key (Secure Storage)

**Recommended**: Store in `.env` file with restricted permissions:

```bash
# Create .env with secure permissions
install -m 600 /dev/null .env
echo 'ANTHROPIC_API_KEY=sk-ant-your-key-here' >> .env

# Verify permissions (should show -rw-------)
ls -la .env
```

**Never do this**:
```bash
# DON'T put API keys in bashrc (exposes to all processes)
# DON'T commit .env to git
# DON'T use mode 644 on .env (readable by others)
```

### Model Selection

Edit `agent.py` to change the model:

```python
# Cost-effective option (default)
MODEL = "claude-sonnet-4-20250514"

# Best reasoning (higher cost)
MODEL = "claude-opus-4-5-20251101"
```

### Context Management

The agent automatically manages context size to prevent exceeding Claude's 200k token limit:

```python
# In agent.py - Configuration section
MAX_TOOL_RESULT_CHARS = 15000   # Truncate each tool result to ~4k tokens
MAX_TOTAL_TOOL_CHARS = 100000   # Warning threshold for total tool output
```

When tool results exceed these limits:
- Results are automatically truncated
- A `[TRUNCATED: showing X of Y chars]` marker is added
- Claude still receives useful data without context overflow

### Security Settings

In `agent.py`, configure security features:

```python
SECURITY_VERIFICATION_ON_START = True   # SDK integrity check at startup
REDACT_BEFORE_TRANSMISSION = True       # Mask sensitive data before API calls
LOG_TRANSMISSIONS = True                # Log all API communications
```

## Security Features

### 1. Sensitive Data Redaction

Before any data is sent to Claude's API, the following are automatically redacted:

| Pattern | Example | Replacement |
|---------|---------|-------------|
| IPv4 addresses | `192.168.1.100` | `[IPv4:REDACTED]` |
| IPv6 addresses | `fe80::1` | `[IPv6:REDACTED]` |
| MAC addresses | `aa:bb:cc:dd:ee:ff` | `[MAC:REDACTED]` |
| Email addresses | `user@example.com` | `[EMAIL:REDACTED]` |
| AWS Access Keys | `AKIAIOSFODNN7EXAMPLE` | `[AWS_ACCESS_KEY:REDACTED]` |
| AWS Secret Keys | (40-char strings) | `[AWS_SECRET_KEY:REDACTED]` |
| JWT Tokens | `eyJhbG...` | `[JWT_TOKEN:REDACTED]` |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | `[PRIVATE_KEY:REDACTED]` |
| SSH Keys | `ssh-rsa AAAA...` | `[SSH_KEY:REDACTED]` |
| API Tokens | `sk-...`, `pk-...` | `[API_TOKEN:REDACTED]` |
| UUIDs | `550e8400-e29b-...` | `[UUID:REDACTED]` |
| Local Hostnames | (auto-detected) | `[HOSTNAME:REDACTED]` |
| Local Usernames | (auto-detected) | `[USER:REDACTED]` |
| Env Secrets | `SECRET_KEY=abc123...` | `[ENV_SECRET:REDACTED]` |

### 2. Path Traversal Protection

The `read_file_safe` tool resolves **all symlinks** before checking permissions, preventing attacks like:
```bash
# This attack is blocked:
ln -s /etc/shadow /etc/apparmor.d/evil_link
# Tool will reject because resolved path is /etc/shadow
```

### 3. Command Injection Protection

All search tools:
- Block search terms starting with `-` (prevents grep option injection)
- Use `--` terminator to separate options from patterns
- Whitelist allowed search patterns

### 4. Context Overflow Protection

Tool results are automatically truncated to prevent exceeding Claude's 200k token context limit:

```
[TOOL] get_kernel_security_events
   Input: {"minutes": 1440}
   Executing...
   [TRUNCATED] Result truncated from 300,354 to 16,343 chars
   Result: [OK] {"apparmor_events": [...
```

This allows comprehensive investigations without API errors, even when kernel logs contain millions of characters.

### 5. Audit Logging

Two audit logs are maintained:
- `audit.log` - Every tool execution with parameters and results
- `transmission_audit.log` - Every API call with redaction summaries

### 6. Dependency Verification

At startup, the agent verifies:
- Anthropic SDK version and integrity
- Proxy environment variables (warns if set)
- Running as non-root (warns if root)

## Sudo Commands

Some tools require sudo access. When running interactively, you'll be prompted for your password as needed.

**Common sudo tools:**
- `apparmor_status`
- `read_auth_log` / `search_auth_log`
- `read_dmesg` / `search_dmesg`
- `read_kernel_log` / `search_kernel_log`
- `get_kernel_security_events`

### Optional: Passwordless Sudo

For automated operation, see `TOOLS_README.md` for sudoers configuration.

## Logs

### Tool Audit Log
Every tool execution is logged to `~/security-agent/audit.log`:

```json
{"timestamp": "2025-01-01T10:30:00", "tool": "apparmor_status", "success": true, ...}
```

### Transmission Audit Log
Every API call is logged to `~/security-agent/transmission_audit.log`:

```json
{"timestamp": "2025-01-01T10:30:00", "direction": "outbound", "endpoint": "api.anthropic.com/v1/messages", "redactions_applied": {"ipv4": 3, "hostname": 1}, ...}
```

### Conversation Logs
Full conversations are saved in `~/security-agent/conversations/`:

```
conversation_20250101_103000.json
```

## Troubleshooting

**"ANTHROPIC_API_KEY not set"**
```bash
# Check if .env exists and has correct permissions
ls -la .env

# Create if missing
install -m 600 /dev/null .env
echo 'ANTHROPIC_API_KEY=sk-ant-your-key-here' >> .env
```

**"WARNING: .env file has insecure permissions"**
```bash
chmod 600 .env
```

**"anthropic module not found"**
```bash
source venv/bin/activate
pip install anthropic python-dotenv
```

**"python-dotenv not installed"**
```bash
pip install python-dotenv
# Note: Agent will still work, falling back to environment variables
```

**"prompt is too long: X tokens > 200000 maximum"**
This error should no longer occur with the automatic truncation feature. If you see it:
- Update to the latest `agent.py` with truncation support
- Reduce `MAX_TOOL_RESULT_CHARS` if needed

**Sudo commands failing silently**
- Make sure you're running in a terminal (not piped/redirected)
- Check that the command works manually first

## Version History

- **v1.2** (Current)
  - Added context overflow protection with automatic truncation
  - Tool results > 15,000 chars are automatically truncated
  - Fixed ASCII encoding issues in terminal output
  - Added total tool result tracking and warnings

- **v1.1**
  - Added secure `.env` file handling for API keys
  - Added AWS, JWT, private key redaction patterns
  - Fixed path traversal vulnerability in `read_file_safe`
  - Fixed command injection risk in search functions
  - Added `.gitignore` and `.env.example`
  - Improved `run.sh` with permission checks

- **v1.0**
  - Initial POC with 21 security tools
  - Basic redaction and audit logging

## License

MIT License - Use at your own risk for security investigation purposes.
