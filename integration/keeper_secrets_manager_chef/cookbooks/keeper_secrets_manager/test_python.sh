#!/bin/bash
set -e

echo "Running Python unit tests..."

# Check if Python tests exist
if [ ! -d "test/unit/python" ]; then
    echo "No Python unit tests found at test/unit/python/"
    echo "Creating basic Python syntax check instead..."
    
    # Basic Python syntax check
    if [ -f "files/default/ksm.py" ]; then
        echo "Checking Python script syntax..."
        python3 -m py_compile files/default/ksm.py
        echo "Python script syntax is valid"
    else
        echo "Python script not found"
        exit 1
    fi
    
    echo "Python checks completed!"
    exit 0
fi

# If Python tests exist, run them
echo "Found Python unit tests, running them..."

# Create virtual environment for testing
python3 -m venv test_env
source test_env/bin/activate

# Install required packages
pip install keeper-secrets-manager-core pytest

# Run Python unit tests
python -m pytest test/unit/python/ -v

# Clean up
deactivate
rm -rf test_env

echo "Python tests completed!"
