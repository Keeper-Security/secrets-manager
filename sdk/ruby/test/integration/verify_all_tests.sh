#!/bin/bash

# Verify all tests pass in Docker
# This script runs each test on Ruby 3.2 to ensure they all work

echo "=== Verifying All Tests in Docker ==="
echo "Running on Ruby 3.2"
echo

TESTS=(
    "quick_test.rb"
    "test_error_handling.rb"
    "test_file_operations.rb"
    "test_totp.rb"
    "test_batch_operations.rb"
    "test_advanced_search.rb"
    "test_performance.rb"
)

FAILED=0
PASSED=0

for test in "${TESTS[@]}"; do
    echo -n "Testing $test... "
    
    if ruby test/integration/docker_test_suite.rb --version 3.2 --test "$test" > /dev/null 2>&1; then
        echo "✅ PASSED"
        ((PASSED++))
    else
        echo "❌ FAILED"
        ((FAILED++))
    fi
done

echo
echo "=== Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo
    echo "✅ All tests pass in Docker!"
    exit 0
else
    echo
    echo "❌ Some tests failed"
    exit 1
fi