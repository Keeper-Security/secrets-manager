#!/bin/bash

# Quick Docker test for Ruby SDK
# Tests core functionality on key Ruby versions

echo "=== Ruby SDK Docker Quick Test ==="
echo "Testing on Ruby 2.7, 3.0, and 3.2"
echo

# Test on key versions
for version in 2.7 3.0 3.2; do
    echo "Testing Ruby $version..."
    
    # Run the quick test
    ruby test/integration/docker_test_suite.rb \
        --version $version \
        --test quick_test.rb \
        --test test_error_handling.rb
    
    if [ $? -eq 0 ]; then
        echo "✅ Ruby $version: PASSED"
    else
        echo "❌ Ruby $version: FAILED"
    fi
    echo
done

echo "=== Quick test complete ==="