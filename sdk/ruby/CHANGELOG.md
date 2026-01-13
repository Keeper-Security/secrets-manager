# Changelog

## [17.2.0] - 2025-11-14

### Fixed
- **KSM-685**: `CreateOptions.subfolder_uid` parameter is now correctly sent to API when creating records
- **KSM-686**: Implemented disaster recovery caching with `CachingPostFunction` to match other SDKs
  - API response caching now works for both `get_secret` and `get_folders` endpoints
  - Added `Cache` class for file-based encrypted cache storage
  - Removed unused `@cache` and `@cache_expiry` instance variables from `SecretsManager`
- **KSM-696**: Secure file permissions for config files (0600 on Unix systems)
- **KSM-734**: Fixed notation lookup to handle duplicate UIDs from record shortcuts
  - When a KSM application has access to both an original record and its shortcut, the same UID appears multiple times
  - Added deduplication logic using `uniq { |r| r.uid }` before ambiguity check
  - Preserves genuine ambiguity detection for different records with the same title
  - Added unit test for duplicate UID handling

### Added
- **KSM-743**: Added transmission public key #18 for Gov Cloud Dev environment support
- **KSM-686**: Disaster recovery caching features
  - `KeeperSecretsManager::CachingPostFunction` - Built-in disaster recovery caching
  - `KeeperSecretsManager::Cache` - File-based cache management (save, load, clear)
  - Cache file location configurable via `KSM_CACHE_DIR` environment variable
  - Unit tests for caching functionality
  - Integration tests for caching workflows
- **KSM-692**: HTTP proxy support for enterprise environments
  - `proxy_url` initialization parameter for explicit proxy configuration
  - HTTPS_PROXY environment variable support (automatic detection)
  - https_proxy (lowercase) environment variable support
  - Authenticated proxy support (username:password in URL)
  - Proxy applies to all HTTP operations (API calls, file downloads, file uploads)
  - Unit tests for proxy configuration
  - Integration tests for proxy workflows
- `KeeperSecretsManager.from_config(config_base64, options = {})` - Convenience method for initializing from base64 config string
- Development console script (`bin/console`) for interactive SDK exploration using Pry REPL

### Changed
- **Test Coverage:** Added feature-specific tests for caching and proxy support
  - Added `test/integration/test_caching.rb` - Integration tests for disaster recovery caching
  - Added `test/integration/test_proxy.rb` - Integration tests for HTTP proxy support
  - Added `spec/keeper_secrets_manager/unit/cache_spec.rb` - Unit tests for Cache class
  - Added `spec/keeper_secrets_manager/unit/proxy_spec.rb` - Unit tests for proxy configuration
  - Total test suite: ~100-150 feature-specific examples
- **Mock Infrastructure:** Implemented proper AES-256-GCM encryption in `mock_helper.rb`
  - Records now use proper AES-GCM encryption (was Base64 only)
  - Folders use correct AES-CBC encryption for data
  - Added transmission key encryption/decryption
- **Example Files:**
  - Added `10_custom_caching.rb` - Disaster recovery caching examples
  - Added `12_proxy_usage.rb` - HTTP proxy configuration examples
  - Fixed example files to use correct SDK APIs
- Documentation: Updated for v17.2.0 features

### Notes
- **PAM features and comprehensive test coverage moved to v17.3.0** for easier QA and faster release cycle
- This release focuses on bug fixes, Gov Cloud support, and enterprise features (caching, proxy)
- QA effort reduced from 2 weeks to 1 week due to focused scope

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