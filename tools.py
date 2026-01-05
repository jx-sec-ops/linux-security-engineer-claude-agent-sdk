"""
Security Agent Tool Definitions
================================
Read-only investigation tools for AppArmor, authentication, and system security.

These tools are designed to be SAFE by default:
- Read-only operations only
- No system modifications
- Whitelisted commands only
- All executions are logged
"""

import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# AUDIT LOGGING
# ============================================================================

AUDIT_LOG_PATH = Path.home() / "security-agent" / "audit.log"

def log_tool_execution(tool_name: str, parameters: dict, result: str, success: bool):
    """Log every tool execution for audit trail."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "parameters": parameters,
        "success": success,
        "result_length": len(result),
        # Don't log full result to avoid sensitive data in logs
        # but log first 200 chars for debugging
        "result_preview": result[:200] if success else result
    }
    
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def run_command(command: list[str], tool_name: str) -> dict:
    """Safely execute a whitelisted command and return structured result."""
    try:
        # Check if command uses sudo - if so, we need special handling
        # to allow password prompts to reach the user's terminal
        uses_sudo = command[0] == "sudo"
        
        if uses_sudo and sys.stdin.isatty():
            # Interactive mode: let sudo use the terminal for password prompt
            # We capture stdout but let stderr go to terminal (for the prompt)
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,  # Password prompt goes to terminal
                stdin=sys.stdin,     # User can type password
                text=True,
                timeout=120  # 2 min timeout (includes password entry time)
            )
            output = result.stdout
            success = result.returncode == 0
            
            # If failed, we need to get error info somehow
            if not success and not output:
                output = f"Command failed with return code {result.returncode}"
        else:
            # Non-interactive or non-sudo: capture everything
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout if result.returncode == 0 else result.stderr
            success = result.returncode == 0
        
        log_tool_execution(tool_name, {"command": command}, output, success)
        
        return {
            "success": success,
            "output": output,
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        error_msg = "Command timed out"
        log_tool_execution(tool_name, {"command": command}, error_msg, False)
        return {"success": False, "output": error_msg, "return_code": -1}
    except Exception as e:
        error_msg = f"Execution error: {str(e)}"
        log_tool_execution(tool_name, {"command": command}, error_msg, False)
        return {"success": False, "output": error_msg, "return_code": -1}


# ============================================================================
# TOOL IMPLEMENTATIONS
# ============================================================================

def apparmor_status() -> dict:
    """Get comprehensive AppArmor status including all profiles and their modes."""
    return run_command(["sudo", "aa-status", "--json"], "apparmor_status")


def apparmor_force_complain_list() -> dict:
    """List contents of force-complain directory to identify profiles in permissive mode."""
    path = "/etc/apparmor.d/force-complain"
    try:
        if os.path.exists(path):
            result = subprocess.run(
                ["ls", "-la", path],
                capture_output=True,
                text=True,
                timeout=10
            )
            # Also get stat info for each file
            files = os.listdir(path) if os.path.isdir(path) else []
            file_details = []
            for f in files:
                filepath = os.path.join(path, f)
                stat_result = subprocess.run(
                    ["stat", filepath],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                file_details.append({
                    "name": f,
                    "stat": stat_result.stdout
                })
            
            output = {
                "directory_listing": result.stdout,
                "file_details": file_details
            }
            log_tool_execution("apparmor_force_complain_list", {}, json.dumps(output), True)
            return {"success": True, "output": output}
        else:
            msg = f"Directory {path} does not exist"
            log_tool_execution("apparmor_force_complain_list", {}, msg, True)
            return {"success": True, "output": msg}
    except Exception as e:
        error_msg = str(e)
        log_tool_execution("apparmor_force_complain_list", {}, error_msg, False)
        return {"success": False, "output": error_msg}


def check_service_status(service_name: str) -> dict:
    """Check systemd service status. Only allows alphanumeric service names."""
    # Input validation - prevent injection
    if not service_name.replace("-", "").replace("_", "").isalnum():
        return {"success": False, "output": "Invalid service name format"}
    
    return run_command(["systemctl", "status", service_name], f"check_service_status:{service_name}")


def check_package_installed(package_name: str) -> dict:
    """Check if a package is installed and get its version."""
    # Input validation
    if not package_name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return {"success": False, "output": "Invalid package name format"}
    
    return run_command(["dpkg", "-l", package_name], f"check_package_installed:{package_name}")


def search_apt_history(search_term: str) -> dict:
    """Search APT history logs for package installation/removal events."""
    # Input validation - comprehensive security checks
    
    # Check for empty input
    if not search_term or not search_term.strip():
        return {"success": False, "output": "Search term cannot be empty"}
    
    search_term = search_term.strip()
    
    # Block dash-prefixed terms to prevent grep option injection
    # e.g., "--help", "-r", "-e" could alter grep behavior
    if search_term.startswith("-"):
        return {"success": False, "output": "Search term cannot start with a dash (security restriction)"}
    
    # Length limit to prevent abuse
    if len(search_term) > 100:
        return {"success": False, "output": "Search term too long (max 100 characters)"}
    
    # Character whitelist - only allow safe characters
    if not search_term.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return {"success": False, "output": "Invalid search term format. Only alphanumeric characters, hyphens, underscores, and dots allowed."}
    
    results = []
    
    # Check current log
    # Use "--" to explicitly end grep options, preventing any option injection
    current_log = run_command(
        ["grep", "-i", "--", search_term, "/var/log/apt/history.log"],
        f"search_apt_history:{search_term}"
    )
    results.append({"file": "history.log", "matches": current_log["output"]})
    
    # Check rotated logs
    for i in range(1, 4):  # Check up to 3 rotated logs
        log_path = f"/var/log/apt/history.log.{i}.gz"
        if os.path.exists(log_path):
            rotated = run_command(
                ["zgrep", "-i", "--", search_term, log_path],
                f"search_apt_history:{search_term}:rotated:{i}"
            )
            results.append({"file": f"history.log.{i}.gz", "matches": rotated["output"]})
    
    return {"success": True, "output": results}


def read_auth_log(lines: int = 100) -> dict:
    """Read recent authentication log entries. Defaults to last 100 lines."""
    # Clamp lines to reasonable range
    lines = max(10, min(lines, 1000))
    return run_command(
        ["sudo", "tail", "-n", str(lines), "/var/log/auth.log"],
        f"read_auth_log:{lines}"
    )


def search_auth_log(pattern: str, lines: int = 500) -> dict:
    """Search auth.log for specific patterns (failed logins, sudo, ssh, etc)."""
    # Whitelist of safe patterns
    safe_patterns = [
        "failed", "failure", "invalid", "sudo", "ssh", "login", 
        "authentication", "session", "pam", "accepted", "root"
    ]
    
    pattern_lower = pattern.lower()
    if pattern_lower not in safe_patterns:
        return {
            "success": False, 
            "output": f"Pattern must be one of: {', '.join(safe_patterns)}"
        }
    
    lines = max(10, min(lines, 2000))
    # Use "--" to explicitly end grep options for defense in depth
    return run_command(
        ["sudo", "grep", "-i", "--", pattern, "/var/log/auth.log"],
        f"search_auth_log:{pattern}"
    )


def list_users() -> dict:
    """List system users with UID >= 1000 (regular users) plus root."""
    return run_command(
        ["awk", "-F:", "$3 >= 1000 || $3 == 0 {print $1, $3, $6, $7}", "/etc/passwd"],
        "list_users"
    )


def check_sudoers() -> dict:
    """List sudoers configuration (non-sensitive parts)."""
    results = {}
    
    # Check /etc/sudoers.d/ directory contents
    sudoers_d = "/etc/sudoers.d"
    if os.path.exists(sudoers_d):
        try:
            files = os.listdir(sudoers_d)
            results["sudoers_d_files"] = files
        except PermissionError:
            results["sudoers_d_files"] = "Permission denied"
    
    # Check groups with sudo access
    groups_result = run_command(["getent", "group", "sudo"], "check_sudoers:sudo_group")
    results["sudo_group_members"] = groups_result["output"]
    
    admin_result = run_command(["getent", "group", "admin"], "check_sudoers:admin_group")
    results["admin_group_members"] = admin_result["output"]
    
    log_tool_execution("check_sudoers", {}, json.dumps(results), True)
    return {"success": True, "output": results}


def read_file_safe(filepath: str) -> dict:
    """
    Read a file from a whitelist of safe security-related paths.
    Prevents arbitrary file reading.
    
    Security measures:
    - Resolves ALL symlinks to prevent path traversal attacks
    - Blocks symlinks that resolve outside allowed directories
    - Blocks sensitive filenames even in allowed directories
    """
    # Whitelist of readable paths
    allowed_paths = [
        "/etc/apparmor.d/",
        "/etc/pam.d/",
        "/etc/sssd/",
        "/etc/security/",
        "/etc/login.defs",
        "/etc/passwd",
        "/etc/group",
        "/etc/shells",
    ]
    
    # Get the absolute path (without resolving symlinks) for logging
    original_path = os.path.abspath(filepath)
    
    # Resolve ALL symlinks to get the true filesystem path
    # This prevents symlink-based path traversal attacks
    try:
        resolved_path = os.path.realpath(filepath)
    except (OSError, ValueError) as e:
        return {"success": False, "output": f"Cannot resolve path: {e}"}
    
    # Security check: detect if symlinks were used to escape allowed directories
    if original_path != resolved_path:
        # Path contained symlinks - verify the resolved path is still allowed
        log_tool_execution(
            "read_file_safe", 
            {"filepath": original_path, "resolved": resolved_path}, 
            "Symlink detected - verifying resolved path", 
            True
        )
    
    # Check if the RESOLVED path is in allowed locations
    allowed = any(resolved_path.startswith(p) or resolved_path == p.rstrip('/') for p in allowed_paths)
    
    # Block sensitive files even in allowed directories
    blocked_files = ["shadow", "gshadow", ".secret", "password", "private"]
    has_blocked = any(b in resolved_path.lower() for b in blocked_files)
    
    if not allowed:
        return {
            "success": False, 
            "output": f"Path not in allowed list. Resolved path: {resolved_path}. Allowed prefixes: {allowed_paths}"
        }
    
    if has_blocked:
        return {
            "success": False,
            "output": f"Path contains blocked sensitive filename. Blocked patterns: {blocked_files}"
        }
    
    # Additional check: ensure the file exists and is a regular file (not a device, socket, etc.)
    if not os.path.exists(resolved_path):
        return {"success": False, "output": "File does not exist"}
    
    if not os.path.isfile(resolved_path):
        return {"success": False, "output": "Path is not a regular file"}
    
    try:
        with open(resolved_path, "r") as f:
            content = f.read()
        log_tool_execution("read_file_safe", {"filepath": original_path, "resolved": resolved_path}, f"Read {len(content)} bytes", True)
        return {"success": True, "output": content}
    except Exception as e:
        error_msg = str(e)
        log_tool_execution("read_file_safe", {"filepath": original_path}, error_msg, False)
        return {"success": False, "output": error_msg}


def file_stat(filepath: str) -> dict:
    """Get detailed file information including ownership, permissions, timestamps."""
    # Basic path validation
    filepath = os.path.abspath(filepath)
    if not os.path.exists(filepath):
        return {"success": False, "output": "Path does not exist"}
    
    return run_command(["stat", filepath], f"file_stat:{filepath}")


def find_recent_file_changes(directory: str, minutes: int = 60) -> dict:
    """Find files modified in the last N minutes within a directory."""
    # Whitelist directories that can be searched
    allowed_dirs = [
        "/etc/apparmor.d",
        "/etc/pam.d", 
        "/etc/sssd",
        "/etc/security",
        "/var/log"
    ]
    
    directory = os.path.abspath(directory)
    if not any(directory.startswith(d) for d in allowed_dirs):
        return {
            "success": False,
            "output": f"Directory not allowed. Allowed: {allowed_dirs}"
        }
    
    minutes = max(1, min(minutes, 10080))  # Cap at 1 week
    
    return run_command(
        ["find", directory, "-type", "f", "-mmin", f"-{minutes}", "-ls"],
        f"find_recent_file_changes:{directory}:{minutes}"
    )


def check_sssd_config() -> dict:
    """Check SSSD configuration and status."""
    results = {}
    
    # Service status
    status = run_command(["systemctl", "status", "sssd"], "check_sssd_config:status")
    results["service_status"] = status["output"]
    
    # Check if config exists
    config_path = "/etc/sssd/sssd.conf"
    if os.path.exists(config_path):
        results["config_exists"] = True
        stat = run_command(["stat", config_path], "check_sssd_config:stat")
        results["config_stat"] = stat["output"]
    else:
        results["config_exists"] = False
    
    # Check sssd.conf.d directory
    conf_d = "/etc/sssd/conf.d"
    if os.path.exists(conf_d):
        try:
            results["conf_d_contents"] = os.listdir(conf_d)
        except PermissionError:
            results["conf_d_contents"] = "Permission denied"
    
    log_tool_execution("check_sssd_config", {}, json.dumps(results), True)
    return {"success": True, "output": results}


# ============================================================================
# KERNEL LOG TOOLS
# ============================================================================

def read_dmesg(lines: int = 100, level: str = None) -> dict:
    """
    Read kernel ring buffer (dmesg) messages.
    Optionally filter by log level.
    """
    lines = max(10, min(lines, 2000))
    
    # Build command
    cmd = ["sudo", "dmesg", "--time-format=iso", "-T"]
    
    # Filter by level if specified
    valid_levels = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"]
    if level and level.lower() in valid_levels:
        cmd.extend(["--level", level.lower()])
    
    # Get output and tail it
    result = run_command(cmd, f"read_dmesg:{lines}:{level}")
    
    if result["success"]:
        # Tail the output to requested lines
        output_lines = result["output"].strip().split("\n")
        result["output"] = "\n".join(output_lines[-lines:])
    
    return result


def search_dmesg(pattern: str) -> dict:
    """
    Search kernel ring buffer for specific patterns.
    Uses predefined safe patterns for security investigation.
    """
    # Whitelist of safe kernel log patterns
    safe_patterns = [
        "apparmor", "selinux", "audit", "segfault", "oom", "killed",
        "error", "fail", "denied", "blocked", "violation", "warning",
        "usb", "firmware", "module", "loaded", "unloaded", "tainted",
        "panic", "oops", "bug", "call trace", "rip", "crash"
    ]
    
    pattern_lower = pattern.lower()
    if pattern_lower not in safe_patterns:
        return {
            "success": False,
            "output": f"Pattern must be one of: {', '.join(safe_patterns)}"
        }
    
    # Get dmesg and grep
    dmesg_result = run_command(
        ["sudo", "dmesg", "--time-format=iso", "-T"],
        f"search_dmesg:{pattern}"
    )
    
    if not dmesg_result["success"]:
        return dmesg_result
    
    # Filter lines containing pattern (case-insensitive)
    lines = dmesg_result["output"].split("\n")
    matches = [l for l in lines if pattern_lower in l.lower()]
    
    return {
        "success": True,
        "output": "\n".join(matches[-500:]),  # Last 500 matches
        "match_count": len(matches)
    }


def read_kernel_log(lines: int = 100) -> dict:
    """
    Read /var/log/kern.log for persistent kernel messages.
    Unlike dmesg, this survives reboots.
    """
    lines = max(10, min(lines, 2000))
    
    log_path = "/var/log/kern.log"
    if not os.path.exists(log_path):
        # Try syslog as fallback (some systems don't have separate kern.log)
        log_path = "/var/log/syslog"
    
    return run_command(
        ["sudo", "tail", "-n", str(lines), log_path],
        f"read_kernel_log:{lines}"
    )


def search_kernel_log(pattern: str, lines: int = 500) -> dict:
    """
    Search kern.log for specific patterns.
    """
    safe_patterns = [
        "apparmor", "selinux", "audit", "segfault", "oom", "killed",
        "error", "fail", "denied", "blocked", "violation", "warning",
        "usb", "firmware", "module", "loaded", "unloaded", "tainted",
        "panic", "oops", "bug", "kernel", "crash"
    ]
    
    pattern_lower = pattern.lower()
    if pattern_lower not in safe_patterns:
        return {
            "success": False,
            "output": f"Pattern must be one of: {', '.join(safe_patterns)}"
        }
    
    lines = max(10, min(lines, 2000))
    
    log_path = "/var/log/kern.log"
    if not os.path.exists(log_path):
        log_path = "/var/log/syslog"
    
    # Use "--" to explicitly end grep options for defense in depth
    return run_command(
        ["sudo", "grep", "-i", "--", pattern, log_path],
        f"search_kernel_log:{pattern}"
    )


def get_kernel_security_events(minutes: int = 60) -> dict:
    """
    Get security-relevant kernel events from the last N minutes.
    Focuses on: AppArmor, audit, segfaults, OOM kills, and module loading.
    """
    minutes = max(1, min(minutes, 1440))  # Cap at 24 hours
    
    results = {
        "apparmor_events": [],
        "audit_events": [],
        "segfaults": [],
        "oom_events": [],
        "module_events": [],
        "other_security": []
    }
    
    # Get recent dmesg with timestamps
    dmesg_result = run_command(
        ["sudo", "dmesg", "--time-format=iso", "-T", "--since", f"-{minutes}min"],
        f"get_kernel_security_events:{minutes}"
    )
    
    if not dmesg_result["success"]:
        # Fallback: get all dmesg and filter manually (older kernels)
        dmesg_result = run_command(
            ["sudo", "dmesg", "-T"],
            f"get_kernel_security_events:{minutes}:fallback"
        )
    
    if dmesg_result["success"]:
        for line in dmesg_result["output"].split("\n"):
            line_lower = line.lower()
            
            if "apparmor" in line_lower:
                results["apparmor_events"].append(line)
            elif "audit" in line_lower:
                results["audit_events"].append(line)
            elif "segfault" in line_lower:
                results["segfaults"].append(line)
            elif "oom" in line_lower or "killed process" in line_lower:
                results["oom_events"].append(line)
            elif "module" in line_lower and ("loaded" in line_lower or "unloaded" in line_lower):
                results["module_events"].append(line)
            elif any(term in line_lower for term in ["denied", "blocked", "violation", "tainted"]):
                results["other_security"].append(line)
    
    # Add summary counts
    results["summary"] = {
        "apparmor_count": len(results["apparmor_events"]),
        "audit_count": len(results["audit_events"]),
        "segfault_count": len(results["segfaults"]),
        "oom_count": len(results["oom_events"]),
        "module_count": len(results["module_events"]),
        "other_security_count": len(results["other_security"])
    }
    
    log_tool_execution("get_kernel_security_events", {"minutes": minutes}, json.dumps(results["summary"]), True)
    return {"success": True, "output": results}


def get_loaded_kernel_modules() -> dict:
    """
    List all currently loaded kernel modules.
    Useful for detecting unauthorized or suspicious modules.
    """
    return run_command(["lsmod"], "get_loaded_kernel_modules")


def get_module_info(module_name: str) -> dict:
    """
    Get detailed information about a specific kernel module.
    """
    # Input validation
    if not module_name.replace("-", "").replace("_", "").isalnum():
        return {"success": False, "output": "Invalid module name format"}
    
    results = {}
    
    # Get modinfo
    modinfo = run_command(["modinfo", module_name], f"get_module_info:{module_name}")
    results["modinfo"] = modinfo["output"]
    
    # Check if module is currently loaded
    lsmod = run_command(["lsmod"], f"get_module_info:{module_name}:lsmod")
    if lsmod["success"]:
        loaded = module_name in lsmod["output"] or module_name.replace("-", "_") in lsmod["output"]
        results["currently_loaded"] = loaded
    
    log_tool_execution("get_module_info", {"module_name": module_name}, json.dumps(results), True)
    return {"success": True, "output": results}


def check_kernel_taint() -> dict:
    """
    Check if the kernel is tainted and why.
    Tainted kernels may have loaded proprietary modules, had errors, etc.
    """
    results = {}
    
    # Read taint flags
    try:
        with open("/proc/sys/kernel/tainted", "r") as f:
            taint_value = int(f.read().strip())
            results["taint_value"] = taint_value
            results["is_tainted"] = taint_value != 0
            
            # Decode taint flags
            taint_flags = []
            flag_meanings = {
                0: "Proprietary module loaded (P)",
                1: "Module force loaded (F)",
                2: "Kernel running on out-of-spec system (S)",
                3: "Module force unloaded (R)",
                4: "Processor reported MCE (M)",
                5: "Bad page referenced (B)",
                6: "User requested taint (U)",
                7: "ACPI table overridden (A)",
                8: "Kernel issued warning (W)",
                9: "Staging driver loaded (C)",
                10: "Working around firmware bug (I)",
                11: "Externally-built module loaded (O)",
                12: "Unsigned module loaded (E)",
                13: "Soft lockup occurred (L)",
                14: "Kernel live patched (K)",
                15: "Auxiliary taint (X)",
                16: "Randstruct plugin randomized layout (T)"
            }
            
            for bit, meaning in flag_meanings.items():
                if taint_value & (1 << bit):
                    taint_flags.append(meaning)
            
            results["taint_reasons"] = taint_flags
            
    except Exception as e:
        results["error"] = str(e)
    
    log_tool_execution("check_kernel_taint", {}, json.dumps(results), True)
    return {"success": True, "output": results}


# ============================================================================
# TOOL DEFINITIONS FOR CLAUDE API
# ============================================================================

TOOL_DEFINITIONS = [
    {
        "name": "apparmor_status",
        "description": "Get comprehensive AppArmor status including all profiles, their enforcement modes (enforce/complain/unconfined), and any errors. Use this to understand the overall AppArmor security posture.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "apparmor_force_complain_list",
        "description": "List contents of /etc/apparmor.d/force-complain directory with detailed file information including creation timestamps and ownership. Profiles listed here are forced into complain (permissive) mode even after updates.",
        "input_schema": {
            "type": "object", 
            "properties": {},
            "required": []
        }
    },
    {
        "name": "check_service_status",
        "description": "Check the systemd status of a specific service (e.g., sssd, sshd, apparmor). Shows if it's running, enabled, and recent log entries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Name of the systemd service (e.g., 'sssd', 'sshd', 'apparmor')"
                }
            },
            "required": ["service_name"]
        }
    },
    {
        "name": "check_package_installed",
        "description": "Check if a specific package is installed via dpkg and get its version information.",
        "input_schema": {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Name of the package to check (e.g., 'sssd', 'apparmor')"
                }
            },
            "required": ["package_name"]
        }
    },
    {
        "name": "search_apt_history",
        "description": "Search APT package manager history logs for installation, removal, or upgrade events related to a specific term. Searches both current and rotated log files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "search_term": {
                    "type": "string",
                    "description": "Term to search for in apt history (e.g., 'sssd', 'apparmor', 'auth')"
                }
            },
            "required": ["search_term"]
        }
    },
    {
        "name": "read_auth_log",
        "description": "Read recent entries from /var/log/auth.log which contains authentication events, sudo usage, SSH logins, and PAM activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Number of recent lines to read (default: 100, max: 1000)"
                }
            },
            "required": []
        }
    },
    {
        "name": "search_auth_log",
        "description": "Search auth.log for specific security-relevant patterns. Allowed patterns: failed, failure, invalid, sudo, ssh, login, authentication, session, pam, accepted, root.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for (must be from allowed list: failed, failure, invalid, sudo, ssh, login, authentication, session, pam, accepted, root)"
                },
                "lines": {
                    "type": "integer",
                    "description": "Maximum lines to return (default: 500, max: 2000)"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_users",
        "description": "List system users with UID >= 1000 (regular users) plus root, showing username, UID, home directory, and shell.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "check_sudoers",
        "description": "Check sudo configuration including files in /etc/sudoers.d/ and members of sudo/admin groups. Does not read sensitive sudoers content directly.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "read_file_safe",
        "description": "Read contents of security-related configuration files from allowed paths: /etc/apparmor.d/, /etc/pam.d/, /etc/sssd/, /etc/security/, /etc/login.defs, /etc/passwd, /etc/group, /etc/shells. Blocks sensitive files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Full path to the file to read"
                }
            },
            "required": ["filepath"]
        }
    },
    {
        "name": "file_stat",
        "description": "Get detailed file/directory information including ownership, permissions, access/modify/change timestamps. Useful for determining when a file was created or modified.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Full path to the file or directory"
                }
            },
            "required": ["filepath"]
        }
    },
    {
        "name": "find_recent_file_changes",
        "description": "Find files modified within the last N minutes in security-related directories: /etc/apparmor.d, /etc/pam.d, /etc/sssd, /etc/security, /var/log.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Directory to search (must be in allowed list)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Find files modified in the last N minutes (default: 60, max: 10080)"
                }
            },
            "required": ["directory"]
        }
    },
    {
        "name": "check_sssd_config",
        "description": "Comprehensive SSSD (System Security Services Daemon) check including service status, configuration file existence and permissions, and conf.d directory contents.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "read_dmesg",
        "description": "Read kernel ring buffer (dmesg) messages with timestamps. Can filter by log level: emerg, alert, crit, err, warn, notice, info, debug.",
        "input_schema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Number of recent lines to return (default: 100, max: 2000)"
                },
                "level": {
                    "type": "string",
                    "description": "Filter by log level: emerg, alert, crit, err, warn, notice, info, debug"
                }
            },
            "required": []
        }
    },
    {
        "name": "search_dmesg",
        "description": "Search kernel ring buffer for specific security-relevant patterns. Allowed patterns: apparmor, selinux, audit, segfault, oom, killed, error, fail, denied, blocked, violation, warning, usb, firmware, module, loaded, unloaded, tainted, panic, oops, bug, call trace, rip, crash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for (must be from allowed list)"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "read_kernel_log",
        "description": "Read /var/log/kern.log for persistent kernel messages that survive reboots. Falls back to /var/log/syslog if kern.log doesn't exist.",
        "input_schema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Number of recent lines to return (default: 100, max: 2000)"
                }
            },
            "required": []
        }
    },
    {
        "name": "search_kernel_log",
        "description": "Search kern.log for specific patterns. Allowed patterns: apparmor, selinux, audit, segfault, oom, killed, error, fail, denied, blocked, violation, warning, usb, firmware, module, loaded, unloaded, tainted, panic, oops, bug, kernel, crash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for (must be from allowed list)"
                },
                "lines": {
                    "type": "integer",
                    "description": "Maximum lines to return (default: 500, max: 2000)"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "get_kernel_security_events",
        "description": "Get categorized security-relevant kernel events from the last N minutes. Returns AppArmor events, audit events, segfaults, OOM kills, module loading events, and other security-related messages with summary counts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "minutes": {
                    "type": "integer",
                    "description": "Look back N minutes (default: 60, max: 1440/24 hours)"
                }
            },
            "required": []
        }
    },
    {
        "name": "get_loaded_kernel_modules",
        "description": "List all currently loaded kernel modules using lsmod. Useful for detecting unauthorized or suspicious modules.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_module_info",
        "description": "Get detailed information about a specific kernel module including filename, version, author, description, dependencies, and whether it's currently loaded.",
        "input_schema": {
            "type": "object",
            "properties": {
                "module_name": {
                    "type": "string",
                    "description": "Name of the kernel module (e.g., 'nvidia', 'bluetooth', 'usbhid')"
                }
            },
            "required": ["module_name"]
        }
    },
    {
        "name": "check_kernel_taint",
        "description": "Check if the kernel is tainted and decode the reasons. Taint flags indicate proprietary modules, force-loaded modules, kernel warnings, unsigned modules, etc.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        },
        "cache_control": {"type": "ephemeral"}
    }
]


# ============================================================================
# TOOL DISPATCHER
# ============================================================================

def execute_tool(tool_name: str, tool_input: dict) -> str:
    """
    Execute a tool by name with given input.
    Returns the result as a string for Claude to process.
    """
    tool_map = {
        "apparmor_status": lambda _: apparmor_status(),
        "apparmor_force_complain_list": lambda _: apparmor_force_complain_list(),
        "check_service_status": lambda i: check_service_status(i.get("service_name", "")),
        "check_package_installed": lambda i: check_package_installed(i.get("package_name", "")),
        "search_apt_history": lambda i: search_apt_history(i.get("search_term", "")),
        "read_auth_log": lambda i: read_auth_log(i.get("lines", 100)),
        "search_auth_log": lambda i: search_auth_log(i.get("pattern", ""), i.get("lines", 500)),
        "list_users": lambda _: list_users(),
        "check_sudoers": lambda _: check_sudoers(),
        "read_file_safe": lambda i: read_file_safe(i.get("filepath", "")),
        "file_stat": lambda i: file_stat(i.get("filepath", "")),
        "find_recent_file_changes": lambda i: find_recent_file_changes(
            i.get("directory", ""), i.get("minutes", 60)
        ),
        "check_sssd_config": lambda _: check_sssd_config(),
        # Kernel tools
        "read_dmesg": lambda i: read_dmesg(i.get("lines", 100), i.get("level")),
        "search_dmesg": lambda i: search_dmesg(i.get("pattern", "")),
        "read_kernel_log": lambda i: read_kernel_log(i.get("lines", 100)),
        "search_kernel_log": lambda i: search_kernel_log(i.get("pattern", ""), i.get("lines", 500)),
        "get_kernel_security_events": lambda i: get_kernel_security_events(i.get("minutes", 60)),
        "get_loaded_kernel_modules": lambda _: get_loaded_kernel_modules(),
        "get_module_info": lambda i: get_module_info(i.get("module_name", "")),
        "check_kernel_taint": lambda _: check_kernel_taint(),
    }
    
    if tool_name not in tool_map:
        return json.dumps({"success": False, "output": f"Unknown tool: {tool_name}"})
    
    result = tool_map[tool_name](tool_input)
    return json.dumps(result, indent=2, default=str)


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("Security Agent Tools - Quick Test")
    print("=" * 50)
    
    # Test a simple tool
    print("\nTesting list_users:")
    result = execute_tool("list_users", {})
    print(result[:500] + "..." if len(result) > 500 else result)
    
    print("\n" + "=" * 50)
    print(f"Total tools available: {len(TOOL_DEFINITIONS)}")
    print("Tools:", [t["name"] for t in TOOL_DEFINITIONS])
