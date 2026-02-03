# Ruby SDK Test Suite

This directory contains comprehensive tests for the Keeper Secrets Manager Ruby SDK.

## Test Organization

The Ruby SDK has two parallel test systems:

### 1. RSpec Tests (spec/) - **Automated CI/CD Testing**
Fast, repeatable tests that run on every commit

### 2. Manual Test Scripts (test/integration/) - **Developer Tools**
Interactive scripts for manual testing, debugging, and demonstration

## Running Tests

### Quick Start (Recommended)

```bash
# Install dependencies
bundle install

# Run all automated tests (unit + integration)
bundle exec rspec                    # 282 examples, ~3 seconds

# Run offline mock test (no config.base64 needed)
export KEEPER_MOCK_MODE=true
ruby -I lib test/integration/test_offline_mock.rb
```

### RSpec Tests (Automated)

```bash
# Run all RSpec tests (unit + integration)
bundle exec rspec                    # 282 examples

# Run only unit tests
bundle exec rspec spec/keeper_secrets_manager/unit      # 191 examples

# Run only integration tests
bundle exec rspec spec/keeper_secrets_manager/integration   # 91 examples

# Run specific test file
bundle exec rspec spec/keeper_secrets_manager/integration/totp_spec.rb
```

### Manual Integration Tests (Developer Tools)

```bash
# Offline testing (no config.base64 required)
export KEEPER_MOCK_MODE=true
ruby -I lib test/integration/test_offline_mock.rb

# Online testing (requires config.base64)
ruby -I lib test/integration/full_crud_test.rb
ruby -I lib test/integration/test_totp.rb
ruby -I lib test/integration/test_file_operations.rb

# Multi-version testing
ruby test/integration/docker_multi_version_test.rb
```

## Mock Testing

The SDK now supports comprehensive offline testing with proper AES-256-GCM encryption:

### RSpec Tests (Always Mock)
```bash
# RSpec tests use mock data by default (no config.base64 needed)
bundle exec rspec                     # All 282 examples run in mock mode
```

### Manual Integration Tests
```bash
# Offline mode (no config.base64 required)
export KEEPER_MOCK_MODE=true
ruby -I lib test/integration/test_offline_mock.rb

# Online mode (requires config.base64)
ruby -I lib test/integration/full_crud_test.rb
ruby -I lib test/integration/test_totp.rb
```