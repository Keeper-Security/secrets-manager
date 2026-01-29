# Ruby SDK Integration Tests

This directory contains comprehensive integration tests for the Keeper Secrets Manager Ruby SDK.

These are **manual test scripts** designed for developer testing, debugging, and SDK demonstration. For **automated CI/CD tests**, see the RSpec tests in `spec/keeper_secrets_manager/integration/`.

## Test Files

### Core Test Scripts

#### 1. `test_offline_mock.rb`
Comprehensive offline test using mock infrastructure - tests all SDK functionality without network access.

**Features:**
- Tests get_secrets, get_folders with proper AES-256-GCM encryption
- Tests notation parser, field types, TOTP, file operations
- Tests batch operations, search, error handling
- Runs completely offline without config.base64

**Requirements:**
- None! Runs in complete isolation

**Usage:**
```bash
export KEEPER_MOCK_MODE=true
ruby -I lib test/integration/test_offline_mock.rb
```

#### 2. `full_crud_test.rb`
Comprehensive test of all CRUD operations against the real Keeper API.

**Features:**
- Creates various types of records (login, complex records with all field types)
- Updates existing records
- Tests folder operations (create, update, delete)
- Tests notation access
- Tests search functionality
- Cleans up all test data after completion

**Requirements:**
- Valid `config.base64` file in the SDK root directory
- Ruby 3.1+ (with OpenSSL supporting AES-GCM)
- Network access to Keeper servers

**Usage:**
```bash
ruby test/integration/full_crud_test.rb
```

#### 3. `docker_multi_version_test.rb`
Tests the SDK across multiple Ruby versions using Docker containers.

**Features:**
- Tests Ruby versions: 3.1, 3.2, 3.3
- Verifies AES-GCM support in each version
- Tests all major SDK features
- Generates a comprehensive compatibility report

**Requirements:**
- Docker installed and running
- Internet connection (to pull Ruby Docker images)

**Usage:**
```bash
ruby test/integration/docker_multi_version_test.rb
```

### Feature-Specific Tests

#### 4. `test_totp.rb`
Tests TOTP (Time-based One-Time Password) functionality.

**Features:**
- Tests TOTP code generation with SHA1, SHA256, SHA512 algorithms
- Tests different time periods (30s, 60s, 90s)
- Tests TOTP validation with time windows
- Tests TOTP URL parsing and generation

**Requirements:**
- Valid `config.base64` file
- base32 gem installed

**Usage:**
```bash
ruby -I lib test/integration/test_totp.rb
```

#### 5. `test_file_operations.rb`
Tests file upload, download, and management operations.

**Features:**
- Tests single and multiple file uploads to same record
- Tests file download with retry for eventual consistency
- Tests large file handling (5MB+)
- Tests file metadata retrieval from records
- Demonstrates file deletion concept

**Requirements:**
- Valid `config.base64` file
- Network access to Keeper servers

**Usage:**
```bash
ruby -I lib test/integration/test_file_operations.rb
```

#### 6. `test_file_upload_download.rb`
Alternative file operation tests with different focus.

#### 7. `test_folder_operations.rb`
Tests folder hierarchy operations (create, update, delete, tree traversal).

#### 8. `test_notation_complete.rb`
Comprehensive notation parser tests with all selector types.

#### 9. `test_advanced_search.rb`
Tests advanced search functionality and filtering.

#### 10. `test_batch_operations.rb`
Tests batch create/update/delete operations (marked as TODO - API not implemented).

#### 11. `test_error_handling.rb`
Tests error scenarios and recovery mechanisms.

#### 12. `test_performance.rb`
Performance benchmarks and profiling tests.

#### 13. `test_token_auth.rb`
Tests one-time token binding and authentication.

### Utility Scripts

#### `mock_helper.rb`
Helper module for offline testing with proper AES-256-GCM encryption.

**Features:**
- Creates mock SecretsManager instances
- Implements proper AES-GCM encryption (not just Base64)
- Implements AES-CBC encryption for folder data
- Handles transmission key encryption/decryption
- Provides consistent mock app_key for deterministic testing

**Usage:**
```ruby
require_relative 'mock_helper'

# Create mock secrets manager (works without config.base64)
sm = MockHelper.create_mock_secrets_manager

# Use normally
records = sm.get_secrets
folders = sm.get_folders
```

#### `run_all_tests.rb`
Master test runner for selective test execution.

#### `quick_test.rb` and `quick_test_readonly.rb`
Quick verification scripts for basic SDK functionality.

#### `live_api_test.rb`
Quick API connectivity test to verify basic operations.

## Test Types

### Offline Tests (No config.base64 required)
- `test_offline_mock.rb` - Complete SDK functionality in mock mode

### Online Tests (Require config.base64)
- `full_crud_test.rb` - Comprehensive CRUD operations
- `test_totp.rb` - TOTP functionality
- `test_file_operations.rb` - File upload/download
- `test_folder_operations.rb` - Folder operations
- All other test_*.rb scripts

### Utility Tests
- `docker_multi_version_test.rb` - Multi-version Docker testing
- `run_all_tests.rb` - Selective test runner

## Configuration

**Most integration tests** require a valid Keeper configuration file (`config.base64`) in the SDK root directory:
- Valid credentials (clientId, privateKey, appKey)
- Proper server configuration

**Exception:** `test_offline_mock.rb` works without config.base64 in mock mode.

## Running Tests

### Offline (No API Access)
```bash
# Run comprehensive offline mock test
export KEEPER_MOCK_MODE=true
ruby -I lib test/integration/test_offline_mock.rb
```

### Online (With API Access)
```bash
# Run full CRUD tests (requires config.base64)
ruby -I lib test/integration/full_crud_test.rb

# Run TOTP tests
ruby -I lib test/integration/test_totp.rb

# Run file operation tests
ruby -I lib test/integration/test_file_operations.rb

# Run Docker multi-version tests
ruby test/integration/docker_multi_version_test.rb
```

## Test Safety

- All test records are created with unique identifiers
- Test data is automatically cleaned up after tests complete
- Tests use specific naming patterns to avoid conflicts with production data
- Failed tests attempt cleanup to prevent orphaned test data

## Expected Results

### Successful Test Output
```
SDK initialized successfully
Created login record with UID: xxx
Record updated successfully
Created complex record with UID: xxx
Created folder with UID: xxx
All tests completed. Result: PASSED
```

### Version Compatibility
- Ruby 3.1+: Full compatibility with OpenSSL 3.0 adaptations

## Troubleshooting

### Docker Tests Failing
1. Ensure Docker is running: `docker --version`
2. Check internet connection for image downloads
3. Verify no port conflicts

### API Tests Failing
1. Verify `config.base64` exists and is valid
2. Check network connectivity to Keeper servers
3. Ensure your account has permissions to create/delete records
4. Verify Ruby version supports AES-GCM: `ruby test_ruby_version.rb`

### Cleanup Issues
If tests fail and leave orphaned records:
1. Run the cleanup script manually
2. Look for records with test IDs in their titles
3. Delete them through the Keeper web interface if needed