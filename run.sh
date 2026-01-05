#!/bin/bash
# Security Agent - Quick Start Script
# ====================================
# 
# Setup:
#   1. Create .env file: echo 'ANTHROPIC_API_KEY=your-key' > .env
#   2. Secure permissions: chmod 600 .env
#   3. Run: ./run.sh

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

# Check for virtual environment
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found."
    echo "   Run: python3 -m venv venv"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# ============================================================================
# LOAD .ENV FILE (SECURE API KEY STORAGE)
# ============================================================================

ENV_FILE="$SCRIPT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    # Security check: warn if .env has overly permissive permissions
    ENV_PERMS=$(stat -c "%a" "$ENV_FILE" 2>/dev/null || stat -f "%Lp" "$ENV_FILE" 2>/dev/null)
    
    if [ "$ENV_PERMS" != "600" ] && [ "$ENV_PERMS" != "400" ]; then
        echo "⚠️  WARNING: .env file has insecure permissions ($ENV_PERMS)"
        echo "   Recommended: chmod 600 .env"
        echo ""
    fi
    
    # Load .env file - export all variables
    # Ignores comments (#) and empty lines
    set -a  # Automatically export all variables
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        # Remove leading/trailing whitespace and quotes from value
        value="${value#"${value%%[![:space:]]*}"}"  # Leading whitespace
        value="${value%"${value##*[![:space:]]}"}"  # Trailing whitespace
        value="${value#[\"\']}"  # Leading quote
        value="${value%[\"\']}"  # Trailing quote
        # Export if key is valid
        if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            export "$key=$value"
        fi
    done < "$ENV_FILE"
    set +a
    
    echo "✓ Loaded environment from .env"
else
    echo "⚠️  No .env file found."
    echo ""
    echo "   To create one securely:"
    echo "   ┌────────────────────────────────────────────────────────┐"
    echo "   │  # Create .env with restricted permissions            │"
    echo "   │  install -m 600 /dev/null .env                        │"
    echo "   │                                                       │"
    echo "   │  # Add your API key                                   │"
    echo "   │  echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env          │"
    echo "   └────────────────────────────────────────────────────────┘"
    echo ""
fi

# ============================================================================
# DEPENDENCY CHECKS
# ============================================================================

# Check for anthropic package
if ! python -c "import anthropic" 2>/dev/null; then
    echo "❌ Anthropic SDK not installed."
    echo "   Run: pip install anthropic"
    exit 1
fi

# Check for python-dotenv (optional but recommended)
if ! python -c "import dotenv" 2>/dev/null; then
    echo "ℹ️  python-dotenv not installed (optional)."
    echo "   For better .env support: pip install python-dotenv"
fi

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "❌ ANTHROPIC_API_KEY not set."
    echo ""
    echo "   Option 1 (Recommended): Add to .env file"
    echo "   ─────────────────────────────────────────"
    echo "   install -m 600 /dev/null .env"
    echo "   echo 'ANTHROPIC_API_KEY=your-key-here' >> .env"
    echo ""
    echo "   Option 2: Export for this session only"
    echo "   ─────────────────────────────────────────"
    echo "   export ANTHROPIC_API_KEY='your-key-here'"
    echo "   ./run.sh"
    echo ""
    exit 1
fi

# Mask key for display (show first 10 and last 4 chars)
KEY_PREVIEW="${ANTHROPIC_API_KEY:0:10}...${ANTHROPIC_API_KEY: -4}"
echo "✓ API key loaded: $KEY_PREVIEW"

# ============================================================================
# RUN THE AGENT
# ============================================================================

echo ""

if [ $# -eq 0 ]; then
    # Interactive mode
    python agent.py
else
    # Single query mode
    python agent.py "$@"
fi
