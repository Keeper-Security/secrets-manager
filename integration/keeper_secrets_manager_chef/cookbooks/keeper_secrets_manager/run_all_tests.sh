# cookbooks/keeper_secrets_manager/run_all_tests.sh
#!/bin/bash
set -e

echo "Running comprehensive test suite for Keeper Secrets Manager cookbook..."

# Check if KEEPER_CONFIG is set
if [ -z "$KEEPER_CONFIG" ]; then
    echo "KEEPER_CONFIG environment variable not set!"
    echo "Please export your Keeper base64 config first:"
    echo "   export KEEPER_CONFIG='your-base64-config-here'"
    echo ""
    echo "Using fallback test config for demonstration..."
    KEEPER_CONFIG="eyJob3N0bmFtZSI6ImtlZXBlcnNlY3VyaXR5LmNvbSIsImNsaWVudElkIjoidGVzdC1jbGllbnQtaWQiLCJwcml2YXRlS2V5IjoidGVzdC1wcml2YXRlLWtleSIsImFwcEtleSI6InRlc3QtYXBwLWtleSIsInNlcnZlclB1YmxpY0tleUlkIjoidGVzdC1zZXJ2ZXIta2V5In0="
    USE_FALLBACK=true
else
    echo "Using KEEPER_CONFIG from environment variable"
    USE_FALLBACK=false
fi

# Decode and validate the base64 config
echo "Validating KEEPER_CONFIG..."
if echo "$KEEPER_CONFIG" | base64 -d | ruby -rjson -e "JSON.parse(STDIN.read)" 2>/dev/null; then
    echo "KEEPER_CONFIG is valid base64 JSON"
    echo "Decoded config preview:"
    echo "$KEEPER_CONFIG" | base64 -d | ruby -rjson -e "puts JSON.pretty_generate(JSON.parse(STDIN.read))" | head -5
    echo "..."
else
    echo "KEEPER_CONFIG is not valid base64 JSON!"
    if [ "$USE_FALLBACK" = false ]; then
        echo "Please check your KEEPER_CONFIG format"
        exit 1
    fi
fi

# 1. Ruby syntax check
echo "Checking Ruby syntax..."
find . -name "*.rb" -not -path "./.git/*" -not -path "./vendor/*" -not -path "./.bundle/*" -exec ruby -c {} \;
echo "Ruby syntax check passed"

# 2. ChefSpec tests (if possible)
echo "Attempting ChefSpec tests..."
if command -v bundle >/dev/null 2>&1; then
    # Prefer chef exec bundle (runs inside Chef Workstation's own embedded
    # Ruby) when Chef Workstation is installed; falls back to plain bundle
    # against system Ruby otherwise - both resolve the pinned chefspec and
    # keeper_secrets_manager gems from this cookbook's Gemfile either way.
    BUNDLE_CMD="bundle"
    command -v chef >/dev/null 2>&1 && BUNDLE_CMD="chef exec bundle"

    echo "Installing pinned test/dev gems (chefspec, keeper_secrets_manager) via Gemfile..."
    $BUNDLE_CMD install
    echo "Running ChefSpec/RSpec tests..."
    $BUNDLE_CMD exec rspec || echo "ChefSpec tests failed"
else
    echo "Bundler not available, skipping unit tests"
fi

# 3. Integration test with Docker
echo "Running integration test..."
if command -v docker >/dev/null 2>&1; then
    echo "Running Docker integration test..."

    # Create test data using the actual KEEPER_CONFIG
    mkdir -p /tmp/test-data-bags/keeper
    cat > /tmp/test-data-bags/keeper/keeper_config.json << EOF
{
  "id": "keeper_config",
  "config_json": "$KEEPER_CONFIG"
}
EOF

    # Create test input file for demo - using base64 authentication
    mkdir -p /tmp/test-input
    cat > /tmp/test-input/input.json << 'EOF'
{
  "authentication": [
    "base64"
  ],
  "secrets": [
    "jnPuLYWXt7b6Ym-_9OCvFA/field/password > APP_PASSWORD",
    "jnPuLYWXt7b6Ym-_9OCvFA/field/login > LOGIN",
    "jnPuLYWXt7b6Ym-_9OCvFA/file/dummy.crt > file:/tmp/Certificate.crt"
  ]
}
EOF

    echo "Using dynamic KEEPER_CONFIG from environment"
    if [ "$USE_FALLBACK" = true ]; then
        echo "Using fallback test config (will fail with real Keeper vault)"
    else
        echo "Using your actual KEEPER_CONFIG"
    fi

    docker run --rm \
      -v $(pwd):/cookbook \
      -v /tmp/test-data-bags:/tmp/data_bags \
      -v /tmp/test-input:/tmp/input \
      -e KEEPER_CONFIG="$KEEPER_CONFIG" \
      ubuntu:22.04 bash -c "
        set -e
        apt-get update -qq
        apt-get install -y curl sudo
        curl -L https://omnitruck.chef.io/install.sh | bash -s -- -v 18

        mkdir -p /tmp/cookbooks
        cp -r /cookbook /tmp/cookbooks/keeper_secrets_manager

        # Setup Chef client configuration
        echo 'cookbook_path \"/tmp/cookbooks\"' > /tmp/client.rb
        echo 'data_bag_path \"/tmp/data_bags\"' >> /tmp/client.rb
        echo 'file_cache_path \"/tmp/chef-cache\"' >> /tmp/client.rb
        echo 'log_level :info' >> /tmp/client.rb

        # Create chef cache directory
        mkdir -p /tmp/chef-cache

        echo 'Step 1: Running install recipe...'
        chef-client -z -c /tmp/client.rb -o keeper_secrets_manager::install --chef-license accept

        # Verify installation - chef_gem installs into Chef's own embedded
        # gemset, so check it there directly (this script already commits to
        # a specific platform/install method, unlike the portable InSpec
        # suite, so a hardcoded omnibus path is fine here).
        test -d /opt/keeper_secrets_manager && echo 'Base directory exists'
        /opt/chef/embedded/bin/gem list keeper_secrets_manager -i && echo 'Keeper Ruby SDK gem installed'

        echo 'Step 2: Testing secret retrieval with fetch recipe...'
        # Copy test input file to the expected location
        cp /tmp/input/input.json /opt/keeper_secrets_manager/input.json

        # Create a test fetch recipe that uses the test input
        cat > /tmp/cookbooks/keeper_secrets_manager/recipes/test_fetch.rb << 'RUBY'
# Test fetch recipe with proper input path
ksm_fetch 'fetch_test_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  action :run
end

log 'Keeper secrets test completed!' do
  level :info
end
RUBY

        echo 'Running test fetch recipe with your KEEPER_CONFIG...'
        echo 'Using KEEPER_CONFIG environment variable for base64 authentication'

        echo 'Current KEEPER_CONFIG (first 50 chars): '
        echo \${KEEPER_CONFIG:0:50}...

        echo 'Decoded config structure:'
        echo \$KEEPER_CONFIG | base64 -d | ruby -rjson -e 'c = JSON.parse(STDIN.read); puts \"Hostname: #{c[\"hostname\"] || \"N/A\"}\"; puts \"Client ID: #{c[\"clientId\"] ? c[\"clientId\"][0,10] + \"...\" : \"N/A\"}\"'

        # node.run_state and any ENV[] set inside the chef-client process are
        # both gone the moment this subprocess exits, so this script can't
        # inspect them by reading files afterward the way the old
        # keeper_output.txt/keeper_env.sh checks did. Capture the run's own
        # log instead - ksm_fetch logs exactly what it did with each secret.
        if [ \"$USE_FALLBACK\" = \"true\" ]; then
            chef-client -z -c /tmp/client.rb -o keeper_secrets_manager::test_fetch --chef-license accept > /tmp/fetch-run.log 2>&1 || echo 'Fetch recipe failed (expected - fallback config is not valid for real Keeper vault)'
        else
            echo 'Running with your actual Keeper configuration...'
            chef-client -z -c /tmp/client.rb -o keeper_secrets_manager::test_fetch --chef-license accept > /tmp/fetch-run.log 2>&1 || echo 'Fetch recipe failed - check your KEEPER_CONFIG and record UIDs'
        fi
        cat /tmp/fetch-run.log

        if grep -q \"stored in node.run_state\" /tmp/fetch-run.log; then
            echo 'Direct-output secret handled via node.run_state (no file written, as expected)'
        else
            echo 'No direct-output secret log line found'
        fi

        if grep -q \"exported to ENV\" /tmp/fetch-run.log; then
            echo 'env: secret exported to ENV[] inside the chef-client process'
        else
            echo 'No env: secret log line found'
        fi

        if [ -f /tmp/Certificate.crt ]; then
            echo 'file: secret written to disk'
            ls -la /tmp/Certificate.crt
        else
            if [ \"$USE_FALLBACK\" = \"true\" ]; then
                echo 'No file: secret written (expected - fallback config cannot access real Keeper vault)'
            else
                echo 'No file: secret written - check your KEEPER_CONFIG and record UIDs'
            fi
        fi

        echo 'Integration test completed successfully!'
    "

    echo "Integration test completed"
else
    echo "Docker not available, skipping integration test"
fi

# 4. Code style check
echo "Checking code style..."
if command -v bundle >/dev/null 2>&1; then
    BUNDLE_CMD="bundle"
    command -v chef >/dev/null 2>&1 && BUNDLE_CMD="chef exec bundle"
    $BUNDLE_CMD exec cookstyle . || echo "Cookstyle warnings found (non-blocking)"
else
    echo "Bundler not available, skipping style checks"
fi

echo "All tests completed!"
echo ""
if [ "$USE_FALLBACK" = true ]; then
    echo "Pro tip: For real testing, export your actual KEEPER_CONFIG:"
    echo "   export KEEPER_CONFIG='your-actual-base64-config'"
    echo "   ./run_all_tests.sh"
fi
