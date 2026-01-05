# Security Agent - Tool Definitions

## Overview

This module defines **21 read-only investigation tools** for security analysis across four domains:
- **AppArmor & Config** — Profile management, file permissions, and configuration auditing
- **Authentication** — Login events, user enumeration, and privilege analysis
- **Packages & Services** — Service status, package verification, and installation history
- **Kernel & Modules** — Kernel logs, security events, and module analysis

---

## Safety Features

### 1. Read-Only by Design
All tools perform **read operations only**. No tool can:
- Modify files
- Change configurations
- Install/remove packages
- Start/stop services
- Load/unload kernel modules

### 2. Command Whitelisting
Tools don't accept arbitrary shell commands. Each tool runs a **predefined command set**.

### 3. Input Validation
User-supplied parameters are validated:
- Service/package names: alphanumeric + hyphens/underscores only
- File paths: must be in allowed directories (symlinks fully resolved)
- Search patterns: must be from predefined safe list
- Search terms: cannot start with `-` (prevents option injection)
- Module names: alphanumeric + hyphens/underscores only
- Length limits enforced on all string inputs

### 4. Path Restrictions & Symlink Protection
`read_file_safe` only allows these paths:
- `/etc/apparmor.d/`
- `/etc/pam.d/`
- `/etc/sssd/`
- `/etc/security/`
- `/etc/login.defs`
- `/etc/passwd`
- `/etc/group`
- `/etc/shells`

**Security measures:**
- Uses `os.path.realpath()` to resolve **all** symlinks before validation
- Blocks access if resolved path is outside allowed directories
- Blocks files containing: `shadow`, `gshadow`, `.secret`, `password`, `private`
- Verifies target is a regular file (not device, socket, etc.)

**Example attack prevention:**
```bash
# Attacker creates symlink inside allowed directory pointing to sensitive file
ln -s /etc/shadow /etc/apparmor.d/evil_link

# Tool resolves symlink and correctly rejects:
# "Path not in allowed list. Resolved path: /etc/shadow"
```

### 5. Command Injection Protection
All search functions use multiple layers of protection:

1. **Dash-prefix blocking**: Search terms starting with `-` are rejected
2. **Option terminator**: All grep commands use `--` to separate options from patterns
3. **Pattern whitelisting**: Only predefined safe patterns allowed for log searches
4. **Length limits**: Search terms capped at 100 characters

**Example protection:**
```bash
# Attacker tries to inject grep options
search_apt_history("--help")
# → "Search term cannot start with a dash (security restriction)"

# Even if validation missed something, -- prevents interpretation as option
grep -i -- "pattern" /var/log/file
```

### 6. Audit Logging
Every tool execution is logged to `~/security-agent/audit.log` with:
- Timestamp
- Tool name
- Parameters
- Success/failure
- Result preview (first 200 chars)

### 7. Execution Timeout
All commands have a 30-second timeout (120 seconds for sudo commands to allow password entry).

---

## Tool Reference

### AppArmor & Config Tools

| Tool | Purpose | Requires sudo |
|------|---------|---------------|
| `apparmor_status` | Full AppArmor profile status (JSON) | Yes |
| `apparmor_force_complain_list` | List force-complain directory with file details | No |
| `read_file_safe` | Read allowed config files (symlink-safe) | No |
| `file_stat` | Get file ownership/permissions/timestamps | No |
| `find_recent_file_changes` | Find recently modified files | No |

### Authentication Tools

| Tool | Purpose | Requires sudo |
|------|---------|---------------|
| `read_auth_log` | Read recent auth.log entries | Yes |
| `search_auth_log` | Search auth.log for patterns | Yes |
| `list_users` | List regular users + root | No |
| `check_sudoers` | Check sudo group membership | No |
| `check_sssd_config` | SSSD service and config status | No |

### Packages & Services Tools

| Tool | Purpose | Requires sudo |
|------|---------|---------------|
| `check_service_status` | Systemd service status | No |
| `check_package_installed` | Check if package is installed (dpkg) | No |
| `search_apt_history` | Search apt history logs | No |

### Kernel & Modules Tools

| Tool | Purpose | Requires sudo |
|------|---------|---------------|
| `read_dmesg` | Read kernel ring buffer with optional level filter | Yes |
| `search_dmesg` | Search dmesg for security patterns | Yes |
| `read_kernel_log` | Read /var/log/kern.log (persistent) | Yes |
| `search_kernel_log` | Search kern.log for patterns | Yes |
| `get_kernel_security_events` | Categorized security events (AppArmor, audit, segfaults, OOM, modules) | Yes |
| `get_loaded_kernel_modules` | List all loaded modules (lsmod) | No |
| `get_module_info` | Detailed info about a specific module | No |
| `check_kernel_taint` | Check kernel taint status and decode flags | No |

---

## Data Redaction (security.py)

Before tool outputs are sent to Claude's API, sensitive data is automatically redacted:

### Redaction Patterns

| Pattern | Matches | Replacement |
|---------|---------|-------------|
| `ipv4` | `192.168.1.100` | `[IPv4:REDACTED]` |
| `ipv6` | `fe80::1` | `[IPv6:REDACTED]` |
| `mac` | `aa:bb:cc:dd:ee:ff` | `[MAC:REDACTED]` |
| `email` | `user@example.com` | `[EMAIL:REDACTED]` |
| `ssh_key` | `ssh-rsa AAAA...` | `[SSH_KEY:REDACTED]` |
| `api_token` | `sk-...`, `pk-...`, `api_key_...` | `[API_TOKEN:REDACTED]` |
| `uuid` | `550e8400-e29b-41d4-...` | `[UUID:REDACTED]` |
| `aws_access_key` | `AKIAIOSFODNN7EXAMPLE` | `[AWS_ACCESS_KEY:REDACTED]` |
| `aws_secret_key` | 40-char base64 strings after `=` | `[AWS_SECRET_KEY:REDACTED]` |
| `jwt_token` | `eyJhbGciOiJ...` | `[JWT_TOKEN:REDACTED]` |
| `private_key` | `-----BEGIN RSA PRIVATE KEY-----` | `[PRIVATE_KEY:REDACTED]` |
| `env_secret` | `SECRET_KEY=abc123...` | `[ENV_SECRET:REDACTED]` |

### Dynamic Redaction
Additionally, the following are auto-detected and redacted:
- Local hostname (all variations)
- Local usernames (UID >= 1000 and root)

### Exceptions
Some values are NOT redacted:
- Localhost IPs: `127.0.0.1`, `0.0.0.0`, `255.255.255.255`, `::1`

---

## Usage

### Test the tools directly:
```bash
cd ~/security-agent
source venv/bin/activate
python tools.py
```

### Import in your agent:
```python
from tools import TOOL_DEFINITIONS, execute_tool

# Get tool schemas for Claude API
tools = TOOL_DEFINITIONS

# Execute a tool
result = execute_tool("apparmor_status", {})

# Execute kernel security scan
result = execute_tool("get_kernel_security_events", {"minutes": 120})
```

### Test security features:
```python
# Test symlink protection
from tools import read_file_safe
result = read_file_safe("/etc/apparmor.d/some_symlink")
# Will reject if symlink points outside allowed paths

# Test command injection protection
from tools import search_apt_history
result = search_apt_history("--help")
# Returns: {"success": False, "output": "Search term cannot start with a dash..."}

# Test redaction
from security import redact_sensitive_data
text = "User logged in from 192.168.1.100 with key AKIAIOSFODNN7EXAMPLE"
redacted, summary = redact_sensitive_data(text)
# redacted: "User logged in from [IPv4:REDACTED] with key [AWS_ACCESS_KEY:REDACTED]"
# summary: {"ipv4": 1, "aws_access_key": 1}
```

---

## Sudo Configuration

Some tools require sudo. For smoother operation, you can allow passwordless sudo for specific commands by adding to `/etc/sudoers.d/security-agent`:

```
# /etc/sudoers.d/security-agent
# Allow security agent to run specific read-only commands without password

your_username ALL=(ALL) NOPASSWD: /usr/sbin/aa-status --json
your_username ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/auth.log
your_username ALL=(ALL) NOPASSWD: /usr/bin/grep -i * /var/log/auth.log
your_username ALL=(ALL) NOPASSWD: /usr/bin/dmesg *
your_username ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/kern.log
your_username ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/syslog
your_username ALL=(ALL) NOPASSWD: /usr/bin/grep -i * /var/log/kern.log
```

**Note**: This is optional. Without it, sudo commands will prompt for password (which won't work in automated agent mode).

---

## Search Patterns Reference

### auth.log Patterns (`search_auth_log`)
| Pattern | Use Case |
|---------|----------|
| `failed` | Failed login attempts |
| `failure` | Authentication failures |
| `invalid` | Invalid user attempts |
| `sudo` | Sudo command usage |
| `ssh` | SSH connections |
| `login` | Login events |
| `authentication` | Auth subsystem events |
| `session` | Session open/close |
| `pam` | PAM module events |
| `accepted` | Successful authentications |
| `root` | Root user activity |

### Kernel Log Patterns (`search_dmesg`, `search_kernel_log`)
| Pattern | Indicates |
|---------|-----------|
| `apparmor` | AppArmor policy enforcement/denials |
| `selinux` | SELinux events |
| `audit` | Audit subsystem events |
| `segfault` | Segmentation faults (crashes, potential exploits) |
| `oom` | Out-of-memory kills |
| `killed` | Process terminations |
| `error` | General errors |
| `fail` | Failure events |
| `denied` | Access denials |
| `blocked` | Blocked operations |
| `violation` | Policy violations |
| `warning` | Warning messages |
| `usb` | USB device events |
| `firmware` | Firmware loading |
| `module` | Kernel module events |
| `loaded` | Module/driver loading |
| `unloaded` | Module unloading |
| `tainted` | Kernel taint events |
| `panic` | Kernel panics |
| `oops` | Kernel oops |
| `bug` | Kernel bugs |
| `call trace` | Stack traces |
| `rip` | Instruction pointer (crash location) |
| `crash` | Crash events |

---

## API Transmission Logging

All API calls are logged to `~/security-agent/transmission_audit.log`:

```json
{
  "timestamp": "2025-01-01T10:30:00",
  "direction": "outbound",
  "endpoint": "api.anthropic.com/v1/messages (claude-sonnet-4-20250514)",
  "data_summary": {
    "message_count": 3,
    "roles": {"user": 2, "assistant": 1},
    "tool_results_count": 2,
    "total_chars": 15234
  },
  "redactions_applied": {
    "ipv4": 5,
    "hostname": 2,
    "username": 1
  }
}
```

---

## Version History

### v1.2 (Current)
- **Documentation update:**
  - Reorganized Tool Reference into 4 domain categories matching agent.py
  - Updated Overview section with clearer domain descriptions

### v1.1
- **Security fixes:**
  - `read_file_safe`: Now uses `os.path.realpath()` to resolve all symlinks
  - `search_apt_history`: Blocks dash-prefixed terms, adds `--` to grep
  - `search_auth_log`: Added `--` option terminator
  - `search_kernel_log`: Added `--` option terminator
- **New redaction patterns:**
  - AWS Access Key IDs (`AKIA...`)
  - AWS Secret Access Keys
  - JWT tokens (`eyJ...`)
  - Private key blocks (`-----BEGIN...PRIVATE KEY-----`)
  - Environment variable secrets (`SECRET_KEY=...`)
- **Improved input validation:**
  - Length limits on search terms (100 chars)
  - Better error messages

### v1.0
- Initial release with 21 security tools
- Basic IPv4, IPv6, MAC, email, SSH key, UUID redaction
