# Changelog

## [17.2.0] - 2025-11-14

### Fixed
- KSM-685: `CreateOptions.subfolder_uid` parameter is now correctly sent to API when creating records
- KSM-686: Implemented disaster recovery caching with `CachingPostFunction` to match other SDKs
  - API response caching now works for both `get_secret` and `get_folders` endpoints
  - Added `Cache` class for file-based encrypted cache storage
  - Removed unused `@cache` and `@cache_expiry` instance variables from `SecretsManager`
- Fixed example files to use correct SDK APIs:
  - `09_totp.rb`: Corrected class name from `Totp` to `TOTP` and method from `generate()` to `generate_code()`
  - `01_quick_start.rb`: Fixed field access to use dynamic getter (`secret.login`) instead of hash access
  - `10_custom_caching.rb`: Updated to use `Utils.bytes_to_base64` instead of `Base64.strict_encode64`
- Fixed badly anchored regular expression in `test/integration/test_totp.rb` that could cause false positives in test validation

### Added
- `KeeperSecretsManager.from_config(config_base64, options = {})` - Convenience method for initializing from base64 config string
  - Complements existing `from_token()` and `from_file()` convenience methods
  - Simplifies initialization from environment variables containing base64 config (e.g., `ENV['KSM_CONFIG']`)
  - Provides parity with .NET SDK's `GetVaultConfigFromConfigString()` pattern
- `KeeperSecretsManager::CachingPostFunction` - Built-in disaster recovery caching
- `KeeperSecretsManager::Cache` - File-based cache management (save, load, clear)
- Cache file location configurable via `KSM_CACHE_DIR` environment variable
- Comprehensive unit tests for caching functionality (17 new tests)
- Development console script (`bin/console`) for interactive SDK exploration using Pry REPL
- KSM-687: Complete SDK parity with other KSM SDKs - DTO fields and PAM transaction support
  - `links` field to KeeperRecord for linked records support
  - `is_editable` field to KeeperRecord to check edit permissions
  - `inner_folder_uid` field to KeeperRecord for folder location tracking
  - `thumbnail_url` and `last_modified` fields to KeeperFile
  - UpdateOptions class with `transaction_type` and `links_to_remove` support
  - `update_secret_with_options` method to support removing file links
  - `request_links` option to QueryOptions for fetching linked records
  - `download_thumbnail` method for downloading file thumbnails
  - `expires_on` field to SecretsManagerResponse
  - `complete_transaction(record_uid, rollback: false)` method for PAM rotation workflows
  - `CompleteTransactionPayload` DTO class for transaction completion
- KSM-692: HTTP proxy support for enterprise environments
  - `proxy_url` initialization parameter for explicit proxy configuration
  - HTTPS_PROXY environment variable support (automatic detection)
  - https_proxy (lowercase) environment variable support
  - Authenticated proxy support (username:password in URL)
  - Proxy applies to all HTTP operations (API calls, file downloads, file uploads)
- KSM-694: Convenience methods for improved developer experience
  - `upload_file_from_path(owner_record_uid, file_path, file_title: nil)` - Upload files directly from disk
  - `try_get_notation(notation_uri)` - Error-safe notation access (returns empty array on error)

### Changed
- Documentation: Added Ruby SDK to root repository SDK comparison table
- **Test Coverage Improvements:**
  - Added 5 new integration test files (test_pam_rotation.rb, test_proxy.rb, test_pam_linked_records.rb, test_caching.rb)
  - Added 27 unit tests for new features (CompleteTransactionPayload, QueryOptions, proxy configuration, convenience methods)
  - Enhanced test_file_operations.rb with thumbnail download and file link removal tests
  - Total test suite: 302 examples, 0 failures
- **Mock Infrastructure:** Implemented proper AES-256-GCM encryption in `mock_helper.rb`
  - Records now use proper AES-GCM encryption (was Base64 only)
  - Folders use correct AES-CBC encryption for data
  - Added transmission key encryption/decryption
  - Added mock endpoints for transaction completion (finalize_secret_update, rollback_secret_update)
  - Enabled complete offline testing without config.base64
- **Example Files:**
  - Added `11_pam_linked_records.rb` - PAM resources with linked credentials and transaction workflow
  - Added `12_proxy_usage.rb` - HTTP proxy configuration examples
  - Updated `06_files.rb` - Added upload_file_from_path convenience method example
  - Updated `08_notation.rb` - Added try_get_notation error-safe notation example
  - Removed emojis from all example files for professional appearance
- **Dependencies:** Added base32 gem to test dependencies for TOTP support

## [17.1.0] - 2025-01-06

### Changed
- **BREAKING**: Minimum Ruby version increased to 3.1.0 (from 2.6.0)
    - Users on older Ruby versions should upgrade or pin to keeper_secrets_manager <= 17.0.4

### Fixed
- ECC key generation now correctly returns 32-byte raw private keys (was returning 121-byte DER format)
- Client version now dynamically uses VERSION constant instead of hardcoded value
- Fixed Tests
- `update_secret` now correctly encrypts record data before sending to server
- `update_secret` now calls `finalize_secret_update` endpoint to persist changes
- Local record's revision number is automatically refreshed after successful update
- Consecutive updates on the same record object now work without manual refetching
- `download_file` now properly respects SSL certificate verification settings and disables CRL checking
- `upload_file` now uses correct `add_file` endpoint and includes required `ownerRecordRevision` in payload
- `create_folder` now properly encrypts folder key with AES-CBC and sets correct parent_uid (nil for root-level folders)
- Fixed AES-CBC encryption to not double-pad data (OpenSSL handles padding automatically)

## [17.0.4] - 2025-10-20

### Changed
- Maintenance release with internal improvements

## [17.0.3] - 2025-06-25

### Changed
- Cleaned up directory structure
- Removed development and debug files from distribution

## [17.0.2] - 2025-06-25

### Security
- Updated all examples to use environment variables or placeholders

## [17.0.1] - 2025-06-25

### Fixed
- Added missing files to gem package (folder_manager, notation_enhancements, totp)

## [17.0.0] - 2025-06-25

### Added
- Initial release of Keeper Secrets Manager Ruby SDK
- Ruby 2.6+ compatibility

### Security
- Zero-knowledge encryption using AES-GCM
- Secure key management
- SSL certificate verification

### Notes
- Version 17.0.0 to align with other Keeper SDKs
- No runtime dependencies (base32 is optional)

[17.2.0]: https://github.com/Keeper-Security/secrets-manager/compare/ruby-sdk-v17.1.0...ruby-sdk-v17.2.0