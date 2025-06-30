# Ruby SDK Integration Tests

This directory contains comprehensive integration tests for the Keeper Secrets Manager Ruby SDK.

## Test Files

### 1. `docker_multi_version_test.rb`
Tests the SDK across multiple Ruby versions using Docker containers.

**Features:**
- Tests Ruby versions: 2.7, 3.0, 3.1, 3.2, 3.3, and latest
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

### 2. `full_crud_test.rb`
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
- Ruby 2.7+ (or Ruby with OpenSSL supporting AES-GCM)
- Network access to Keeper servers

**Usage:**
```bash
ruby test/integration/full_crud_test.rb
```

### 3. `live_api_test.rb`
Quick API connectivity test to verify basic operations.

**Usage:**
```bash
ruby test/integration/live_api_test.rb
```

## Configuration

All integration tests require a valid Keeper configuration file (`config.base64`) in the SDK root directory. This file should contain:
- Valid credentials (clientId, privateKey, appKey)
- Proper server configuration

## Running All Tests

To run all integration tests:

```bash
# Run Docker multi-version tests
ruby test/integration/docker_multi_version_test.rb

# Run full CRUD tests (requires config.base64)
ruby test/integration/full_crud_test.rb

# Run basic API test
ruby test/integration/live_api_test.rb
```

## Test Safety

- All test records are created with unique identifiers
- Test data is automatically cleaned up after tests complete
- Tests use specific naming patterns to avoid conflicts with production data
- Failed tests attempt cleanup to prevent orphaned test data

## Expected Results

### Successful Test Output
```
✅ SDK initialized successfully
✅ Created login record with UID: xxx
✅ Record updated successfully
✅ Created complex record with UID: xxx
✅ Created folder with UID: xxx
✅ All tests completed. Result: PASSED
```

### Version Compatibility
- Ruby 2.7+: Full compatibility (AES-GCM supported)
- Ruby 2.6: Limited compatibility (no AES-GCM support)
- Ruby 3.0+: Full compatibility with OpenSSL 3.0 adaptations

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