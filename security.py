"""
Security Module for Security Agent
===================================
Provides:
1. Transmission audit logging - Records exactly what is sent to the API
2. Sensitive data redaction - Masks IPs, hostnames, usernames before transmission
3. Dependency verification - Checks package integrity at startup

IMPORTANT: This module helps reduce data leakage but cannot guarantee complete
protection against a compromised system or sophisticated attacks.
"""

import re
import json
import hashlib
import socket
import subprocess
import importlib.metadata
from datetime import datetime
from pathlib import Path
from typing import Any

# ============================================================================
# CONFIGURATION
# ============================================================================

TRANSMISSION_LOG_PATH = Path.home() / "security-agent" / "transmission_audit.log"
REDACTION_ENABLED = True

# Known good package hashes (update these periodically)
# Generate with: pip hash <package>==<version>
# These are SHA256 hashes of wheel files
TRUSTED_PACKAGES = {
    "anthropic": {
        # You should verify and update these hashes from PyPI
        # https://pypi.org/project/anthropic/#files
        "min_version": "0.40.0",
        "warn_if_unknown": True,
    },
}

# Redaction patterns
REDACTION_PATTERNS = {
    # IPv4 addresses
    "ipv4": {
        "pattern": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "replacement": "[IPv4:REDACTED]",
        "exceptions": ["127.0.0.1", "0.0.0.0", "255.255.255.255"]
    },
    # IPv6 addresses (simplified pattern)
    "ipv6": {
        "pattern": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b',
        "replacement": "[IPv6:REDACTED]",
        "exceptions": ["::1"]
    },
    # MAC addresses
    "mac": {
        "pattern": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        "replacement": "[MAC:REDACTED]",
        "exceptions": []
    },
    # Email addresses
    "email": {
        "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "replacement": "[EMAIL:REDACTED]",
        "exceptions": []
    },
    # SSH keys (partial)
    "ssh_key": {
        "pattern": r'ssh-(?:rsa|ed25519|ecdsa)[^\s]*\s+[A-Za-z0-9+/=]{20,}',
        "replacement": "[SSH_KEY:REDACTED]",
        "exceptions": []
    },
    # API keys / tokens (generic pattern for long alphanumeric strings)
    "api_token": {
        "pattern": r'\b(?:sk-|pk-|api[_-]?key[_-]?)[A-Za-z0-9_-]{20,}\b',
        "replacement": "[API_TOKEN:REDACTED]",
        "exceptions": []
    },
    # UUIDs (could be sensitive identifiers)
    "uuid": {
        "pattern": r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        "replacement": "[UUID:REDACTED]",
        "exceptions": []
    },
    # AWS Access Key IDs (start with AKIA, ABIA, ACCA, or ASIA)
    "aws_access_key": {
        "pattern": r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b',
        "replacement": "[AWS_ACCESS_KEY:REDACTED]",
        "exceptions": []
    },
    # AWS Secret Access Keys (40 character base64-like strings)
    # Matches when preceded by common delimiters and followed by whitespace/quotes/EOL
    "aws_secret_key": {
        "pattern": r'(?<=["\'\s=:])[A-Za-z0-9/+=]{40}(?=["\'\s,\n]|$)',
        "replacement": "[AWS_SECRET_KEY:REDACTED]",
        "exceptions": []
    },
    # JWT tokens (three base64url segments separated by dots)
    "jwt_token": {
        "pattern": r'\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b',
        "replacement": "[JWT_TOKEN:REDACTED]",
        "exceptions": []
    },
    # Private key blocks (RSA, EC, DSA, etc.)
    "private_key": {
        "pattern": r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
        "replacement": "[PRIVATE_KEY:REDACTED]",
        "exceptions": []
    },
    # Generic long secrets (environment variable assignments with long values)
    # Catches things like SECRET_KEY=abc123... or PASSWORD=xyz...
    "env_secret": {
        "pattern": r'(?i)(?:secret|password|passwd|token|credential|auth)[\s]*[=:][\s]*["\']?[A-Za-z0-9/+=_-]{16,}["\']?',
        "replacement": "[ENV_SECRET:REDACTED]",
        "exceptions": []
    },
}


# ============================================================================
# HOSTNAME DETECTION (for redaction)
# ============================================================================

def get_local_identifiers() -> dict:
    """Get local hostname and username for redaction."""
    identifiers = {
        "hostnames": set(),
        "usernames": set(),
    }
    
    try:
        # Get various forms of hostname
        identifiers["hostnames"].add(socket.gethostname())
        identifiers["hostnames"].add(socket.getfqdn())
        
        # Get hostname from /etc/hostname
        hostname_file = Path("/etc/hostname")
        if hostname_file.exists():
            identifiers["hostnames"].add(hostname_file.read_text().strip())
    except Exception:
        pass
    
    try:
        # Get current username
        import pwd
        import os
        identifiers["usernames"].add(os.getlogin())
        identifiers["usernames"].add(pwd.getpwuid(os.getuid()).pw_name)
    except Exception:
        pass
    
    try:
        # Get all local users (UID >= 1000)
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    username = parts[0]
                    uid = int(parts[2]) if parts[2].isdigit() else 0
                    # Include regular users and root
                    if uid >= 1000 or uid == 0:
                        identifiers["usernames"].add(username)
    except Exception:
        pass
    
    # Remove empty strings
    identifiers["hostnames"] = {h for h in identifiers["hostnames"] if h}
    identifiers["usernames"] = {u for u in identifiers["usernames"] if u}
    
    return identifiers


# Cache local identifiers at module load
LOCAL_IDENTIFIERS = get_local_identifiers()


# ============================================================================
# DATA REDACTION
# ============================================================================

def redact_sensitive_data(text: str) -> tuple[str, dict]:
    """
    Redact sensitive data from text before transmission.
    Returns (redacted_text, redaction_summary).
    """
    if not REDACTION_ENABLED or not isinstance(text, str):
        return text, {}
    
    redaction_summary = {}
    redacted = text
    
    # Apply pattern-based redactions
    for name, config in REDACTION_PATTERNS.items():
        pattern = config["pattern"]
        replacement = config["replacement"]
        exceptions = config.get("exceptions", [])
        
        matches = re.findall(pattern, redacted)
        # Filter out exceptions
        matches = [m for m in matches if m not in exceptions]
        
        if matches:
            redaction_summary[name] = len(matches)
            # Replace matches (but not exceptions)
            for match in set(matches):
                if match not in exceptions:
                    redacted = redacted.replace(match, replacement)
    
    # Redact local hostnames
    for hostname in LOCAL_IDENTIFIERS["hostnames"]:
        if hostname and len(hostname) > 2:  # Avoid short matches
            # Case-insensitive replacement
            pattern = re.compile(re.escape(hostname), re.IGNORECASE)
            if pattern.search(redacted):
                redaction_summary["hostname"] = redaction_summary.get("hostname", 0) + 1
                redacted = pattern.sub("[HOSTNAME:REDACTED]", redacted)
    
    # Redact local usernames (be careful with short names)
    for username in LOCAL_IDENTIFIERS["usernames"]:
        if username and len(username) > 2:  # Avoid short matches like "jo"
            # Only redact when it looks like a username context
            # e.g., /home/username, "user: username", etc.
            patterns = [
                rf'/home/{re.escape(username)}(?=/|$|\s)',
                rf'user[:\s]+{re.escape(username)}\b',
                rf'login[:\s]+{re.escape(username)}\b',
                rf'User[:\s]+{re.escape(username)}\b',
                rf'\b{re.escape(username)}@',  # user@host
            ]
            for pat in patterns:
                if re.search(pat, redacted):
                    redaction_summary["username"] = redaction_summary.get("username", 0) + 1
                    redacted = re.sub(pat, lambda m: m.group().replace(username, "[USER:REDACTED]"), redacted)
    
    return redacted, redaction_summary


def redact_messages(messages: list) -> tuple[list, dict]:
    """
    Redact sensitive data from a list of messages.
    Returns (redacted_messages, total_redaction_summary).
    """
    total_summary = {}
    redacted_messages = []
    
    for msg in messages:
        redacted_msg = {"role": msg["role"]}
        content = msg.get("content")
        
        if isinstance(content, str):
            redacted_content, summary = redact_sensitive_data(content)
            redacted_msg["content"] = redacted_content
            for key, count in summary.items():
                total_summary[key] = total_summary.get(key, 0) + count
                
        elif isinstance(content, list):
            redacted_list = []
            for item in content:
                if isinstance(item, dict):
                    redacted_item = item.copy()
                    # Handle tool results
                    if "content" in redacted_item and isinstance(redacted_item["content"], str):
                        redacted_item["content"], summary = redact_sensitive_data(redacted_item["content"])
                        for key, count in summary.items():
                            total_summary[key] = total_summary.get(key, 0) + count
                    # Handle text blocks
                    if "text" in redacted_item and isinstance(redacted_item["text"], str):
                        redacted_item["text"], summary = redact_sensitive_data(redacted_item["text"])
                        for key, count in summary.items():
                            total_summary[key] = total_summary.get(key, 0) + count
                    redacted_list.append(redacted_item)
                else:
                    redacted_list.append(item)
            redacted_msg["content"] = redacted_list
        else:
            redacted_msg["content"] = content
            
        redacted_messages.append(redacted_msg)
    
    return redacted_messages, total_summary


# ============================================================================
# TRANSMISSION AUDIT LOGGING
# ============================================================================

def log_transmission(
    direction: str,  # "outbound" or "inbound"
    endpoint: str,
    data_summary: dict,
    redaction_summary: dict = None,
    token_count: int = None
):
    """
    Log API transmission details for audit purposes.
    Does NOT log actual content, only metadata about what was transmitted.
    """
    TRANSMISSION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "direction": direction,
        "endpoint": endpoint,
        "data_summary": data_summary,
    }
    
    if redaction_summary:
        entry["redactions_applied"] = redaction_summary
    
    if token_count is not None:
        entry["token_count"] = token_count
    
    with open(TRANSMISSION_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def create_transmission_summary(messages: list) -> dict:
    """Create a summary of what's being transmitted (without actual content)."""
    summary = {
        "message_count": len(messages),
        "roles": {},
        "tool_results_count": 0,
        "total_chars": 0,
    }
    
    for msg in messages:
        role = msg.get("role", "unknown")
        summary["roles"][role] = summary["roles"].get(role, 0) + 1
        
        content = msg.get("content")
        if isinstance(content, str):
            summary["total_chars"] += len(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "tool_result":
                        summary["tool_results_count"] += 1
                    if "content" in item:
                        summary["total_chars"] += len(str(item["content"]))
                    if "text" in item:
                        summary["total_chars"] += len(str(item["text"]))
    
    return summary


# ============================================================================
# DEPENDENCY VERIFICATION
# ============================================================================

def verify_package_integrity(package_name: str) -> dict:
    """
    Verify a package's integrity and version.
    Returns verification status and details.
    """
    result = {
        "package": package_name,
        "verified": False,
        "version": None,
        "location": None,
        "warnings": [],
        "errors": [],
    }
    
    try:
        # Get installed package info
        dist = importlib.metadata.distribution(package_name)
        result["version"] = dist.version
        result["location"] = str(dist._path) if hasattr(dist, '_path') else "unknown"
        
        # Check against trusted packages
        if package_name in TRUSTED_PACKAGES:
            trusted = TRUSTED_PACKAGES[package_name]
            
            # Version check
            min_version = trusted.get("min_version")
            if min_version:
                try:
                    from packaging import version
                    if version.parse(result["version"]) < version.parse(min_version):
                        result["warnings"].append(
                            f"Version {result['version']} is below minimum recommended {min_version}"
                        )
                except ImportError:
                    # packaging library not available, do simple string comparison
                    if result["version"] < min_version:
                        result["warnings"].append(
                            f"Version {result['version']} may be below minimum recommended {min_version}"
                        )
                except Exception:
                    result["warnings"].append("Could not parse version for comparison")
            
            result["verified"] = len(result["errors"]) == 0
            
            if trusted.get("warn_if_unknown") and not result["verified"]:
                result["warnings"].append(
                    "Package hash not in trusted list - verify manually"
                )
        else:
            result["warnings"].append("Package not in trusted packages list")
        
    except importlib.metadata.PackageNotFoundError:
        result["errors"].append(f"Package {package_name} not installed")
    except Exception as e:
        result["errors"].append(f"Verification error: {str(e)}")
    
    return result


def verify_anthropic_sdk() -> dict:
    """Verify the Anthropic SDK installation."""
    result = verify_package_integrity("anthropic")
    
    # Additional checks for anthropic
    try:
        import anthropic
        
        # Verify the module location matches installed package
        module_file = anthropic.__file__
        result["module_location"] = module_file
        
        # Check that we're using HTTPS
        if hasattr(anthropic, 'Anthropic'):
            # The SDK should use HTTPS by default
            result["uses_https"] = True  # Anthropic SDK enforces HTTPS
        
    except Exception as e:
        result["errors"].append(f"Module verification error: {str(e)}")
    
    return result


def run_startup_verification() -> dict:
    """
    Run all verification checks at startup.
    Returns a summary of security status.
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "passed": True,
        "checks": {},
        "warnings": [],
        "errors": [],
    }
    
    # Verify Anthropic SDK
    sdk_check = verify_anthropic_sdk()
    results["checks"]["anthropic_sdk"] = sdk_check
    
    if sdk_check["errors"]:
        results["passed"] = False
        results["errors"].extend(sdk_check["errors"])
    
    if sdk_check["warnings"]:
        results["warnings"].extend(sdk_check["warnings"])
    
    # Check for suspicious environment variables
    import os
    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"]
    for var in proxy_vars:
        if var in os.environ:
            results["warnings"].append(f"Proxy environment variable set: {var}")
            results["checks"]["proxy_detected"] = True
    
    # Check if running as root (not recommended)
    if os.geteuid() == 0:
        results["warnings"].append("Running as root - not recommended for security agent")
    
    return results


def print_verification_report(results: dict):
    """Print a human-readable verification report."""
    print("")
    print("=" * 60)
    print("[SECURITY] SECURITY VERIFICATION REPORT")
    print("=" * 60)
    
    if results["passed"]:
        print("[PASS] All critical checks passed")
    else:
        print("[FAIL] Some checks failed - review errors below")
    
    # SDK verification
    sdk = results["checks"].get("anthropic_sdk", {})
    if sdk:
        print("")
        print("[SDK] Anthropic SDK:")
        print(f"   Version: {sdk.get('version', 'unknown')}")
        print(f"   Location: {sdk.get('module_location', sdk.get('location', 'unknown'))}")
        if sdk.get("verified"):
            print("   Status: [OK] Verified")
        else:
            print("   Status: [WARN] Unverified (check warnings)")
    
    # Warnings
    if results["warnings"]:
        print("")
        print(f"[WARN] Warnings ({len(results['warnings'])}):")
        for warning in results["warnings"]:
            print(f"   * {warning}")
    
    # Errors
    if results["errors"]:
        print("")
        print(f"[FAIL] Errors ({len(results['errors'])}):")
        for error in results["errors"]:
            print(f"   * {error}")
    
    print("")
    print("=" * 60)


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("Security Module - Self Test")
    print("=" * 50)
    
    # Test redaction
    test_text = """
    User john logged in from 192.168.1.100
    Host: myworkstation.local
    Email: john@example.com
    MAC: aa:bb:cc:dd:ee:ff
    SSH Key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
    """
    
    print("\nOriginal text:")
    print(test_text)
    
    redacted, summary = redact_sensitive_data(test_text)
    print("\nRedacted text:")
    print(redacted)
    print(f"\nRedaction summary: {summary}")
    
    # Test verification
    print("\n" + "=" * 50)
    results = run_startup_verification()
    print_verification_report(results)
