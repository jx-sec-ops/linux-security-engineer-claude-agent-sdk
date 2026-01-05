#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Agent - Interactive Mode
==================================
Security investigation agent using Claude with tool use.

This agent can investigate:
- AppArmor configuration and anomalies
- Authentication logs and events
- Kernel logs and security events
- System users and privileges
- Package installation history
- SSSD configuration

Run interactively - sudo commands will prompt for password as needed.

SECURITY FEATURES:
- Transmission audit logging - all API calls logged
- Sensitive data redaction - IPs, hostnames, usernames masked
- Dependency verification - SDK integrity checked at startup
"""

import anthropic
import json
import os
import sys
import time
import re
from datetime import datetime
from pathlib import Path

# Load environment variables from .env file BEFORE importing anthropic client
# This allows API key to be stored securely in .env instead of ~/.bashrc
try:
    from dotenv import load_dotenv
    # Look for .env in the script's directory, not cwd
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        load_dotenv()  # Fall back to default behavior
except ImportError:
    # python-dotenv not installed - fall back to environment variables
    pass

# Import our tools
from tools import TOOL_DEFINITIONS, execute_tool

# Import security module
from security import (
    redact_messages,
    log_transmission,
    create_transmission_summary,
    run_startup_verification,
    print_verification_report,
    REDACTION_ENABLED,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Model selection - can use Opus 4.5 for best reasoning or Sonnet for cost savings
MODEL = "claude-sonnet-4-20250514"  # Change to "claude-opus-4-5-20251101" for Opus
MAX_TOKENS = 8192
MAX_TOOL_ITERATIONS = 20  # Safety limit on tool call loops

# Context management - prevent exceeding token limits
MAX_TOOL_RESULT_CHARS = 15000  # Truncate tool results to ~4k tokens each
MAX_TOTAL_TOOL_CHARS = 100000  # Total tool result chars before warning

# Retry configuration
MAX_RETRIES = 5
INITIAL_RETRY_DELAY = 60  # Start with 60 seconds for rate limits
MAX_RETRY_DELAY = 300     # Cap at 5 minutes

# Security configuration
SECURITY_VERIFICATION_ON_START = True
REDACT_BEFORE_TRANSMISSION = True
LOG_TRANSMISSIONS = True

# Agent system prompt - structured for caching
SYSTEM_PROMPT = [
    {
        "type": "text",
        "text": """You are a security investigation agent running on a Linux system. Your role is to help investigate security concerns, audit system configuration, and identify potential issues.

You have access to tools that can:
- Check AppArmor status and profiles
- Read authentication and kernel logs
- Examine system users and sudo configuration
- Search package installation history
- Inspect security-related configuration files
- Analyze loaded kernel modules

INVESTIGATION GUIDELINES:

1. **Be Thorough**: When investigating an issue, gather evidence from multiple sources. Don't rely on a single tool.

2. **Be Systematic**: Start with broad checks, then drill down into specifics based on findings.

3. **Correlate Findings**: Look for connections between different data sources (e.g., timestamps in logs matching file modification times).

4. **Explain Your Reasoning**: Tell the user what you're checking and why. Explain what the results mean.

5. **Prioritize Security**: Flag anything that looks suspicious or unusual, even if you're not certain it's malicious.

6. **Provide Actionable Advice**: After investigation, give clear recommendations for remediation or further investigation.

RESPONSE FORMAT:

- Use clear sections for different aspects of your investigation
- Summarize key findings prominently
- Rate severity when appropriate (Info/Low/Medium/High/Critical)
- Provide specific commands or steps for remediation when relevant

LIMITATIONS:

- All tools are READ-ONLY. You cannot modify the system.
- Some tools require sudo and may prompt the user for their password.
- You can only read files from whitelisted security-related directories.
- Search patterns are restricted to predefined security-relevant terms.

When the user describes a security concern, investigate it thoroughly using the available tools.""",
        "cache_control": {"type": "ephemeral"}
    }
]

# ============================================================================
# CONVERSATION LOG
# ============================================================================

CONVERSATION_LOG_PATH = Path.home() / "security-agent" / "conversations"

def log_conversation(messages: list, query: str):
    """Save conversation to file for later review."""
    CONVERSATION_LOG_PATH.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = CONVERSATION_LOG_PATH / f"conversation_{timestamp}.json"
    
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "query": query,
        "messages": messages,
        "model": MODEL
    }
    
    with open(filename, "w") as f:
        json.dump(log_data, f, indent=2, default=str)
    
    return filename


# ============================================================================
# MESSAGE CACHING HELPERS
# ============================================================================

def add_cache_control_to_messages(messages: list) -> list:
    """
    Add cache_control to the last content block of the last user message.
    This enables incremental caching of conversation history.
    """
    if not messages:
        return messages
    
    # Deep copy to avoid modifying original
    import copy
    cached_messages = copy.deepcopy(messages)
    
    # Find the last user message
    for i in range(len(cached_messages) - 1, -1, -1):
        msg = cached_messages[i]
        if msg.get("role") == "user":
            content = msg.get("content")
            
            if isinstance(content, str):
                # Convert string content to block format with cache_control
                msg["content"] = [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            elif isinstance(content, list) and len(content) > 0:
                # Add cache_control to last block
                last_block = content[-1]
                if isinstance(last_block, dict):
                    last_block["cache_control"] = {"type": "ephemeral"}
            break
    
    return cached_messages


# ============================================================================
# API CALL WITH RETRY LOGIC
# ============================================================================

def call_claude_with_retry(client: anthropic.Anthropic, messages: list) -> anthropic.types.Message:
    """
    Call Claude API with automatic retry on rate limit errors.
    Uses exponential backoff with jitter.
    Applies data redaction, message caching, and logs transmissions.
    """
    last_exception = None
    
    # Apply redaction if enabled
    if REDACT_BEFORE_TRANSMISSION:
        messages_to_send, redaction_summary = redact_messages(messages)
        if redaction_summary:
            print(f"   [REDACT] Redacted: {redaction_summary}")
    else:
        messages_to_send = messages
        redaction_summary = {}
    
    # Apply cache control to messages for incremental caching
    messages_to_send = add_cache_control_to_messages(messages_to_send)
    
    # Create transmission summary for logging
    if LOG_TRANSMISSIONS:
        tx_summary = create_transmission_summary(messages_to_send)
    
    for attempt in range(MAX_RETRIES):
        try:
            # Log outbound transmission
            if LOG_TRANSMISSIONS:
                log_transmission(
                    direction="outbound",
                    endpoint=f"api.anthropic.com/v1/messages ({MODEL})",
                    data_summary=tx_summary,
                    redaction_summary=redaction_summary if redaction_summary else None,
                )
            
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOL_DEFINITIONS,
                messages=messages_to_send
            )
            
            # Log inbound response with cache metrics
            if LOG_TRANSMISSIONS:
                cache_metrics = {}
                if hasattr(response, 'usage'):
                    usage = response.usage
                    cache_metrics = {
                        "cache_creation_input_tokens": getattr(usage, 'cache_creation_input_tokens', 0),
                        "cache_read_input_tokens": getattr(usage, 'cache_read_input_tokens', 0),
                    }
                
                log_transmission(
                    direction="inbound",
                    endpoint=f"api.anthropic.com/v1/messages ({MODEL})",
                    data_summary={
                        "stop_reason": response.stop_reason,
                        "content_blocks": len(response.content),
                        **cache_metrics,
                    },
                    token_count=response.usage.input_tokens + response.usage.output_tokens if hasattr(response, 'usage') else None,
                )
            
            return response
            
        except anthropic.RateLimitError as e:
            last_exception = e
            
            # Parse wait time from error message if available
            wait_time = INITIAL_RETRY_DELAY
            error_msg = str(e)
            
            # Try to extract suggested wait time from error
            # Rate limit errors sometimes suggest when to retry
            match = re.search(r'try again in (\d+)', error_msg.lower())
            if match:
                wait_time = int(match.group(1))
            else:
                # Exponential backoff: 60s, 120s, 240s, etc.
                wait_time = min(INITIAL_RETRY_DELAY * (2 ** attempt), MAX_RETRY_DELAY)
            
            # Add small jitter to avoid thundering herd
            import random
            jitter = random.uniform(0, 5)
            wait_time += jitter
            
            print(f"\n[WAIT] Rate limit hit. Waiting {wait_time:.0f} seconds before retry...")
            print(f"   (Attempt {attempt + 1}/{MAX_RETRIES})")
            
            # Show countdown
            for remaining in range(int(wait_time), 0, -10):
                print(f"   Resuming in {remaining} seconds...", end='\r')
                time.sleep(min(10, remaining))
            print(" " * 40, end='\r')  # Clear the line
            
        except anthropic.APIStatusError as e:
            # Other API errors (500, 503, etc.) - shorter retry
            last_exception = e
            
            if attempt < MAX_RETRIES - 1:
                wait_time = 5 * (attempt + 1)  # 5s, 10s, 15s, etc.
                print(f"\n[WARN] API error: {e.status_code}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise
    
    # All retries exhausted
    raise last_exception


# ============================================================================
# AGENT LOOP
# ============================================================================

def run_agent(user_query: str, client: anthropic.Anthropic) -> str:
    """
    Run the security agent with a user query.
    Handles the tool use loop until Claude provides a final response.
    """
    
    messages = [
        {"role": "user", "content": user_query}
    ]
    
    iteration = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cache_read_tokens = 0
    total_cache_write_tokens = 0
    total_tool_chars = 0  # Track total size of tool results
    
    print("\n" + "=" * 60)
    print("[AGENT] SECURITY AGENT - Investigation Started")
    print("=" * 60)
    print(f"\n[QUERY] {user_query}\n")
    
    while iteration < MAX_TOOL_ITERATIONS:
        iteration += 1
        
        # Call Claude with retry logic
        print(f"[Iteration {iteration}] Consulting Claude...")
        
        try:
            response = call_claude_with_retry(client, messages)
        except anthropic.RateLimitError as e:
            print(f"\n[FAIL] Rate limit exceeded after {MAX_RETRIES} retries.")
            print(f"   Please wait a few minutes and try again.")
            print(f"   Tip: Your account tier limits how many tokens/minute you can use.")
            print(f"   Spending more on the API increases your tier automatically.")
            return f"Rate limit error after retries: {e}"
        except anthropic.APIError as e:
            print(f"\n[FAIL] API Error: {e}")
            return f"API Error: {e}"
        
        # Track token usage including cache metrics
        if hasattr(response, 'usage'):
            usage = response.usage
            total_input_tokens += usage.input_tokens
            total_output_tokens += usage.output_tokens
            
            # Get cache metrics
            cache_read = getattr(usage, 'cache_read_input_tokens', 0)
            cache_write = getattr(usage, 'cache_creation_input_tokens', 0)
            total_cache_read_tokens += cache_read
            total_cache_write_tokens += cache_write
            
            if cache_read > 0 or cache_write > 0:
                print(f"   [TOKENS] {usage.input_tokens:,} in / {usage.output_tokens:,} out | "
                      f"Cache: {cache_read:,} read, {cache_write:,} write")
            else:
                print(f"   [TOKENS] {usage.input_tokens:,} in / {usage.output_tokens:,} out | Running total: {total_input_tokens:,} in")
        
        # Check stop reason
        if response.stop_reason == "end_turn":
            # Claude is done - extract final text response
            final_response = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_response += block.text
            
            # Log the conversation
            messages.append({"role": "assistant", "content": response.content})
            log_file = log_conversation(messages, user_query)
            
            # Show total token usage with cache efficiency
            print(f"\n[STATS] Total tokens - Input: {total_input_tokens:,} | Output: {total_output_tokens:,}")
            
            if total_cache_read_tokens > 0 or total_cache_write_tokens > 0:
                total_cached = total_cache_read_tokens + total_cache_write_tokens
                if total_cached > 0:
                    cache_efficiency = (total_cache_read_tokens / total_cached) * 100 if total_cached > 0 else 0
                    print(f"   [CACHE] Read: {total_cache_read_tokens:,} | Write: {total_cache_write_tokens:,} | Efficiency: {cache_efficiency:.1f}%")
                    
                    # Estimate cost savings (cache reads are 10% of normal input cost)
                    if total_cache_read_tokens > 0:
                        # For Sonnet: $3/MTok normal, $0.30/MTok cache read
                        savings = total_cache_read_tokens * (3.0 - 0.3) / 1_000_000
                        print(f"   [SAVINGS] Estimated savings from cache: ${savings:.4f}")
            
            print("\n" + "=" * 60)
            print("[DONE] INVESTIGATION COMPLETE")
            print("=" * 60)
            print(f"\n[LOG] Conversation saved to: {log_file}\n")
            
            return final_response
        
        elif response.stop_reason == "tool_use":
            # Claude wants to use tools
            assistant_content = response.content
            messages.append({"role": "assistant", "content": assistant_content})
            
            # Process each tool use block
            tool_results = []
            
            for block in assistant_content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id
                    
                    print(f"\n[TOOL] {tool_name}")
                    if tool_input:
                        print(f"   Input: {json.dumps(tool_input, indent=2)}")
                    
                    # Execute the tool
                    print("   Executing... (sudo commands may prompt for password)")
                    result = execute_tool(tool_name, tool_input)
                    
                    # Truncate result if too large to prevent context overflow
                    original_len = len(result)
                    if original_len > MAX_TOOL_RESULT_CHARS:
                        # Try to parse JSON and truncate the output field
                        try:
                            result_data = json.loads(result)
                            output = result_data.get("output", "")
                            if isinstance(output, str) and len(output) > MAX_TOOL_RESULT_CHARS - 500:
                                result_data["output"] = output[:MAX_TOOL_RESULT_CHARS - 500] + f"\n\n[TRUNCATED: showing {MAX_TOOL_RESULT_CHARS - 500:,} of {len(output):,} chars]"
                                result_data["truncated"] = True
                                result = json.dumps(result_data)
                            elif isinstance(output, (dict, list)):
                                output_str = json.dumps(output)
                                if len(output_str) > MAX_TOOL_RESULT_CHARS - 500:
                                    result_data["output"] = output_str[:MAX_TOOL_RESULT_CHARS - 500] + f"\n\n[TRUNCATED: showing {MAX_TOOL_RESULT_CHARS - 500:,} of {len(output_str):,} chars]"
                                    result_data["truncated"] = True
                                    result = json.dumps(result_data)
                        except json.JSONDecodeError:
                            # Raw string result - truncate directly
                            result = result[:MAX_TOOL_RESULT_CHARS] + f"\n\n[TRUNCATED: showing {MAX_TOOL_RESULT_CHARS:,} of {original_len:,} chars]"
                        
                        print(f"   [TRUNCATED] Result truncated from {original_len:,} to {len(result):,} chars")
                    
                    # Track total tool result size
                    total_tool_chars += len(result)
                    if total_tool_chars > MAX_TOTAL_TOOL_CHARS:
                        print(f"   [WARN] Total tool results: {total_tool_chars:,} chars - approaching context limit")
                    
                    # Parse result for display
                    try:
                        result_data = json.loads(result)
                        success = result_data.get("success", False)
                        status = "[OK]" if success else "[FAIL]"
                        
                        # Show truncated preview
                        output = result_data.get("output", "")
                        if isinstance(output, str):
                            preview = output[:200] + "..." if len(output) > 200 else output
                        else:
                            preview = str(output)[:200] + "..."
                        print(f"   Result: {status} {preview}")
                        
                    except json.JSONDecodeError:
                        print(f"   Result: {result[:200]}...")
                    
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result
                    })
                
                elif hasattr(block, "text") and block.text:
                    # Claude provided some text along with tool calls
                    print(f"\n[CLAUDE] {block.text[:300]}{'...' if len(block.text) > 300 else ''}")
            
            # Add tool results to messages
            messages.append({"role": "user", "content": tool_results})
        
        else:
            # Unexpected stop reason
            print(f"\n[WARN] Unexpected stop reason: {response.stop_reason}")
            break
    
    # Hit iteration limit
    print(f"\n[WARN] Reached maximum iterations ({MAX_TOOL_ITERATIONS})")
    return "Investigation incomplete - reached maximum tool iterations."


# ============================================================================
# INTERACTIVE INTERFACE
# ============================================================================

def print_banner():
    """Print welcome banner."""
    banner = """
+==================================================================+
|                                                                  |
|   SECURITY AGENT - Interactive Investigation Tool                |
|                                                                  |
|   Powered by Claude AI with 21 security investigation tools      |
|                                                                  |
|   Security & Optimization Features:                              |
|     * Prompt caching (reduced latency & costs)                   |
|     * Data redaction (IPs, hostnames, usernames masked)          |
|     * Transmission audit logging                                 |
|     * SDK integrity verification                                 |
|                                                                  |
|   Commands:                                                      |
|     * Type your security question or concern                     |
|     * 'help' - Show example queries                              |
|     * 'tools' - List available tools                             |
|     * 'security' - Show security status                          |
|     * 'quit' or 'exit' - Exit the agent                          |
|                                                                  |
+==================================================================+
"""
    print(banner)


def print_help():
    """Print example queries."""
    help_text = """
EXAMPLE QUERIES:

  AppArmor Investigation:
    * "I found usr.sbin.sssd in force-complain mode but didn't put it there. 
       Investigate if this is suspicious."
    * "Check the overall AppArmor security posture of this system"
    * "Are there any AppArmor denials in the recent logs?"

  Authentication Audit:
    * "Check for any failed login attempts in the last 24 hours"
    * "Who has sudo access on this system?"
    * "Review recent sudo usage"

  Kernel Security:
    * "Check for any kernel security events or anomalies"
    * "Are there any suspicious kernel modules loaded?"
    * "Look for segfaults or crashes in kernel logs"

  General Security:
    * "Perform a general security audit of this system"
    * "What security-related changes were made recently?"
    * "Check if SSSD is properly configured"

TIP: Be specific about what concerns you. The more context you provide,
     the better the investigation will be.
"""
    print(help_text)


def print_tools():
    """Print available tools."""
    print("\nAVAILABLE TOOLS:\n")
    
    categories = {
        "AppArmor & Config": ["apparmor_status", "apparmor_force_complain_list", 
                              "read_file_safe", "file_stat", "find_recent_file_changes"],
        "Authentication": ["read_auth_log", "search_auth_log", "list_users", 
                          "check_sudoers", "check_sssd_config"],
        "Packages & Services": ["check_service_status", "check_package_installed", 
                                "search_apt_history"],
        "Kernel & Modules": ["read_dmesg", "search_dmesg", "read_kernel_log",
                            "search_kernel_log", "get_kernel_security_events",
                            "get_loaded_kernel_modules", "get_module_info", 
                            "check_kernel_taint"]
    }
    
    for category, tools in categories.items():
        print(f"  {category}:")
        for tool in tools:
            # Find tool description
            for t in TOOL_DEFINITIONS:
                if t["name"] == tool:
                    desc = t["description"][:60] + "..." if len(t["description"]) > 60 else t["description"]
                    print(f"    * {tool}: {desc}")
                    break
        print()


def print_security_status():
    """Print current security configuration and status."""
    from security import TRANSMISSION_LOG_PATH, LOCAL_IDENTIFIERS
    
    print("\nSECURITY & OPTIMIZATION STATUS:\n")
    
    print("  Prompt Caching:")
    print("    * System prompt: [ON] Cached (ephemeral, 5-min TTL)")
    print("    * Tool definitions: [ON] Cached (21 tools)")
    print("    * Conversation history: [ON] Incremental caching")
    print("    * Cache reads cost 90% less than regular input tokens")
    
    print("\n  Data Protection:")
    print(f"    * Data redaction: {'[ON] ENABLED' if REDACT_BEFORE_TRANSMISSION else '[OFF] DISABLED'}")
    print(f"    * Transmission logging: {'[ON] ENABLED' if LOG_TRANSMISSIONS else '[OFF] DISABLED'}")
    print(f"    * Startup verification: {'[ON] ENABLED' if SECURITY_VERIFICATION_ON_START else '[OFF] DISABLED'}")
    
    print("\n  Redaction Targets:")
    print(f"    * Hostnames: {', '.join(LOCAL_IDENTIFIERS['hostnames']) or 'None detected'}")
    print(f"    * Usernames: {', '.join(LOCAL_IDENTIFIERS['usernames']) or 'None detected'}")
    print(f"    * Patterns: IPv4, IPv6, MAC, Email, SSH keys, API tokens, UUIDs")
    
    print("\n  Log Files:")
    print(f"    * Transmission log: {TRANSMISSION_LOG_PATH}")
    if TRANSMISSION_LOG_PATH.exists():
        # Count entries
        with open(TRANSMISSION_LOG_PATH, 'r') as f:
            entry_count = sum(1 for _ in f)
        size = TRANSMISSION_LOG_PATH.stat().st_size
        print(f"      ({entry_count} entries, {size:,} bytes)")
    else:
        print("      (not yet created)")
    
    audit_log = Path.home() / "security-agent" / "audit.log"
    print(f"    * Tool audit log: {audit_log}")
    if audit_log.exists():
        with open(audit_log, 'r') as f:
            entry_count = sum(1 for _ in f)
        size = audit_log.stat().st_size
        print(f"      ({entry_count} entries, {size:,} bytes)")
    else:
        print("      (not yet created)")
    
    print("\n  To view transmission log:")
    print(f"    cat {TRANSMISSION_LOG_PATH}")
    print()


def main():
    """Main interactive loop."""
    
    # Run security verification at startup
    if SECURITY_VERIFICATION_ON_START:
        print("\n[SECURITY] Running security verification...")
        verification_results = run_startup_verification()
        print_verification_report(verification_results)
        
        if not verification_results["passed"]:
            print("[WARN] Security verification found issues. Continue anyway? (y/N): ", end="")
            sys.stdout.flush()
            response = input().strip().lower()
            if response != 'y':
                print("Exiting due to security concerns.")
                sys.exit(1)
        
        if verification_results["warnings"]:
            print(f"\n[WARN] {len(verification_results['warnings'])} warning(s) detected.")
            print("Press Enter to continue or Ctrl+C to abort... ", end="")
            sys.stdout.flush()
            input()
    
    # Initialize client
    try:
        client = anthropic.Anthropic()
    except anthropic.AuthenticationError:
        print("\n[FAIL] Error: ANTHROPIC_API_KEY not set or invalid.")
        print("   Please set your API key:")
        print("   export ANTHROPIC_API_KEY='your-key-here'")
        sys.exit(1)
    
    print_banner()
    print(f"[CONFIG] Using model: {MODEL}")
    print(f"[CONFIG] Prompt caching: ENABLED (system + tools + conversation)")
    print(f"[CONFIG] Redaction: {'ENABLED' if REDACT_BEFORE_TRANSMISSION else 'DISABLED'}")
    print(f"[CONFIG] Transmission logging: {'ENABLED' if LOG_TRANSMISSIONS else 'DISABLED'}")
    print("=" * 68)
    
    while True:
        try:
            # Get user input
            print()
            user_input = input("You> ").strip()
            
            if not user_input:
                continue
            
            # Handle commands
            if user_input.lower() in ["quit", "exit", "q"]:
                print("\nGoodbye! Stay secure.\n")
                break
            
            elif user_input.lower() == "help":
                print_help()
                continue
            
            elif user_input.lower() == "tools":
                print_tools()
                continue
            
            elif user_input.lower() == "security":
                print_security_status()
                continue
            
            # Run the agent
            response = run_agent(user_input, client)
            
            # Print the response
            print("\n" + "-" * 60)
            print("FINDINGS:")
            print("-" * 60)
            print(response)
            print("-" * 60)
            
        except KeyboardInterrupt:
            print("\n\nInterrupted. Goodbye!\n")
            break
        except Exception as e:
            print(f"\n[ERROR] {e}")
            print("   Please try again or type 'quit' to exit.\n")


# ============================================================================
# SINGLE QUERY MODE
# ============================================================================

def run_single_query(query: str):
    """Run a single query and exit (for scripting)."""
    try:
        client = anthropic.Anthropic()
    except anthropic.AuthenticationError:
        print("Error: ANTHROPIC_API_KEY not set or invalid.", file=sys.stderr)
        sys.exit(1)
    
    response = run_agent(query, client)
    print(response)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Single query mode: python agent.py "your question here"
        query = " ".join(sys.argv[1:])
        run_single_query(query)
    else:
        # Interactive mode
        main()
