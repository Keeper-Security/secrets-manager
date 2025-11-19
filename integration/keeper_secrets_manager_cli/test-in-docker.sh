#!/bin/bash
# Simple script to run interpolate tests in Docker container
# No venv needed, clean environment every time

set -e

echo "Running KSM interpolate tests in Docker..."

# Run tests in official Python container
docker run --rm \
  -v "$(pwd):/app" \
  -w /app \
  python:3.11-slim \
  bash -c "
    echo 'Installing dependencies...'
    pip install -q pytest
    pip install -q -e .

    echo ''
    echo 'Running ALL tests...'
    echo '===================='
    python -m pytest tests/ -v --tb=short
  "

echo ""
echo "✅ Tests complete!"
