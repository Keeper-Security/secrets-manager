# Changelog

## [17.1.1] - 2025-11-07

### Fixed
- KSM-685: `CreateOptions.subfolder_uid` parameter is now correctly sent to API when creating records
- KSM-686: Implemented disaster recovery caching with `CachingPostFunction` to match other SDKs
  - API response caching now works for both `get_secret` and `get_folders` endpoints
  - Added `Cache` class for file-based encrypted cache storage
  - Removed unused `@cache` and `@cache_expiry` instance variables from `SecretsManager`

### Added
- `KeeperSecretsManager::CachingPostFunction` - Built-in disaster recovery caching
- `KeeperSecretsManager::Cache` - File-based cache management (save, load, clear)
- Cache file location configurable via `KSM_CACHE_DIR` environment variable
- Comprehensive unit tests for caching functionality (17 new tests)
- KSM-687: Missing DTO fields for complete SDK parity with other ksm sdks
  - `links` field to KeeperRecord for linked records support
  - `is_editable` field to KeeperRecord to check edit permissions
  - `inner_folder_uid` field to KeeperRecord for folder location tracking
  - `thumbnail_url` and `last_modified` fields to KeeperFile
  - UpdateOptions class with `transaction_type` and `links_to_remove` support
  - `update_secret_with_options` method to support removing file links
  - `request_links` option to QueryOptions for fetching linked records
  - `download_thumbnail` method for downloading file thumbnails
  - `expires_on` field to SecretsManagerResponse

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