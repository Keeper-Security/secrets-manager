#!/bin/bash
# Automated Test Runner Wrapper
# Runs all tests and generates coverage report

set -e

echo "🚀 Keeper Secret Manager Puppet Module - Automated Test Runner"
echo "================================================================"

# Check if we're in the right directory
if [ ! -f "files/ksm.py" ]; then
    echo "❌ Error: Please run this script from the keeper_secrets_manager_puppet directory"
    echo "   Current directory: $(pwd)"
    echo "   Expected files: files/ksm.py, files/install_ksm.sh, files/install_ksm.ps1"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not found"
    echo "   Please install Python 3 and try again"
    exit 1
fi

# Check if pytest is available
if ! python3 -c "import pytest" &> /dev/null; then
    echo "⚠️  Warning: pytest not found. Installing..."
    pip3 install pytest
fi

# Make test runner executable
chmod +x spec/files/test_runner.py

# Run the automated test runner
echo "🔍 Starting automated test run..."
python3 spec/files/test_runner.py

echo ""
echo "✅ Test run completed!"
echo ""
echo "📊 Quick Summary:"
echo "   - Python tests: Check output above"
echo "   - Shell tests: Check output above" 
echo "   - PowerShell tests: Check output above"
echo "   - Coverage details: See console output above" 