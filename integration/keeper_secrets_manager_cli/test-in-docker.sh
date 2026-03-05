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
echo "Running KSM keyring integration tests in Docker (Secret Service)..."

docker build -q -t ksm-cli-keyring-test -f tests/docker/Dockerfile.keyring-test .

docker run --rm ksm-cli-keyring-test \
  dbus-run-session -- bash -c "
    echo '' | gnome-keyring-daemon --unlock --components=secrets,keyring
    KSM_KEYRING_INTEGRATION=1 python3 -m pytest tests/keyring_integration_test.py -v --tb=short
  "

echo "Keyring integration tests complete."
echo ""
echo "All tests complete."
