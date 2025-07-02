# Ruby SDK Test Suite

This directory contains comprehensive tests for the Keeper Secrets Manager Ruby SDK.

## Test Organization

```
test/
├── README.md                       # This file
├── test_all_features.rb           # Comprehensive feature test
├── integration/                    # Integration tests with API
│   ├── live_api_test.rb          # Live API testing
│   └── capture_responses.rb      # Capture real API responses for mocks
└── run_basic_tests.rb            # Basic unit test runner

spec/                              # RSpec tests (Ruby standard)
├── spec_helper.rb                 # RSpec configuration
├── fixtures/                      # Test data and mock responses
├── support/                       # Test helpers
│   └── mock_helpers.rb           # Mock data generators
└── keeper_secrets_manager/
    ├── unit/                      # Unit tests
    │   ├── dto_spec.rb           # DTO tests
    │   ├── storage_spec.rb       # Storage tests
    │   ├── crypto_spec.rb        # Crypto tests
    │   └── notation_spec.rb      # Notation parser tests
    └── integration/               # Integration tests
        └── secrets_manager_spec.rb # Full SDK integration tests
```

## Running Tests

### Unit Tests (No Dependencies)

```bash
# Run comprehensive feature tests
ruby -I lib test/test_all_features.rb

# Run basic unit tests
ruby -I lib test/run_basic_tests.rb
```

### RSpec Tests (Requires Bundle)

```bash
# Install dependencies
bundle install

# Run all RSpec tests
bundle exec rspec

# Run only unit tests
bundle exec rspec spec/keeper_secrets_manager/unit

# Run specific test file
bundle exec rspec spec/keeper_secrets_manager/unit/dto_spec.rb
```

### Integration Tests

```bash
# Run with real API (requires config.base64)
ruby -I lib test/integration/live_api_test.rb

# Capture API responses for offline testing
ruby -I lib test/integration/capture_responses.rb
```

## Test Coverage

The test suite covers:

1. **DTOs and Field Operations**
   - Record creation and manipulation
   - Dynamic field access
   - Complex field types
   - Custom fields

2. **Storage Implementations**
   - In-memory storage
   - File-based storage
   - Environment storage
   - Caching storage

3. **Notation Parser**
   - Simple selectors (type, title, notes)
   - Field selectors with arrays
   - Complex field property access
   - Custom field access
   - Escaped characters

4. **Field Type Helpers**
   - All standard field types
   - Complex object fields
   - Custom field creation

5. **Utilities**
   - Base64 encoding/decoding
   - URL-safe encoding
   - UID generation and validation
   - String conversions

6. **Crypto Functions**
   - Random byte generation
   - HMAC generation and verification
   - PKCS7 padding/unpadding
   - AES encryption (with CBC fallback for older Ruby)

## Mock Testing

The SDK supports both online and offline testing:

- **Online**: Tests run against real Keeper API
- **Offline**: Tests use mock data from `spec/fixtures/`

To run tests offline:
```bash
# Don't set KSM_TEST_LIVE environment variable
bundle exec rspec
```

To run tests online:
```bash
# Set environment variable
KSM_TEST_LIVE=1 bundle exec rspec
```

## Creating Test Data

Use the `capture_responses.rb` script to:
1. Create test records in various formats
2. Test all CRUD operations
3. Save responses for offline mock testing

## Ruby Version Compatibility

- Tests pass on Ruby 2.6+
- Full API functionality requires Ruby 2.7+ (for AES-GCM)
- SDK includes AES-CBC fallback for older Ruby versions