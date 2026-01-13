# Changelog

## [17.3.0] - TBD

### Added
- **KSM-687**: Complete SDK parity with other KSM SDKs - DTO fields and PAM transaction support
  - `links` field to KeeperRecord for linked records support
  - `is_editable` field to KeeperRecord to check edit permissions
  - `thumbnail_url` and `last_modified` fields to KeeperFile
  - UpdateOptions class with `transaction_type` and `links_to_remove` support
  - `update_secret_with_options` method to support removing file links
  - `request_links` option to QueryOptions for fetching linked records
  - `download_thumbnail` method for downloading file thumbnails
  - `expires_on` field to SecretsManagerResponse
  - `complete_transaction(record_uid, rollback: false)` method for PAM rotation workflows
  - `CompleteTransactionPayload` DTO class for transaction completion
- **KSM-694**: Convenience methods for improved developer experience
  - `upload_file_from_path(owner_record_uid, file_path, file_title: nil)` - Upload files directly from disk
  - `try_get_notation(notation_uri)` - Error-safe notation access (returns empty array on error)
- **KSM-697**: Comprehensive test coverage improvements (63.3% code coverage)
  - Added 343 unit tests for error handling module (`errors_spec.rb`) - 100% coverage
  - Added 733 unit tests for field types module (`field_types_spec.rb`) - 100% coverage
  - Added 603 unit tests for utilities module (`utils_spec.rb`) - 100% coverage
  - Added 479 unit tests for TOTP module (`totp_spec.rb`) - 100% coverage
  - Added 387 unit tests for core initialization (`core_spec.rb`)
  - Total: 358 new unit tests added
  - Overall coverage increased from 51.4% to 63.3%

### Changed
- **PAM Integration Test Files:**
  - Added `test_pam_rotation.rb` - Integration tests for PAM rotation workflows
  - Added `test_pam_linked_records.rb` - Integration tests for linked PAM resources
  - Enhanced `test_file_operations.rb` with thumbnail download and file link removal tests
- **PAM Unit Tests:**
  - Added unit tests for CompleteTransactionPayload
  - Added unit tests for QueryOptions filtering
  - Enhanced dto_spec.rb with PAM DTO field tests
- **Mock Infrastructure:** Enhanced `mock_helper.rb` for PAM testing
  - Added mock endpoints for transaction completion (finalize_secret_update, rollback_secret_update)
  - Enhanced AES-256-GCM encryption support for PAM records
- **Example Files:**
  - Added `11_pam_linked_records.rb` - PAM resources with linked credentials and transaction workflow
  - Updated `06_files.rb` - Added upload_file_from_path convenience method example
  - Updated `08_notation.rb` - Added try_get_notation error-safe notation example
- Total test suite: 569 examples, 0 failures (includes comprehensive coverage tests)

## [17.2.0] - TBD

### Fixed
- KSM-685: `CreateOptions.subfolder_uid` parameter is now correctly sent to API when creating records
- KSM-686: Implemented disaster recovery caching with `CachingPostFunction`
- KSM-696: Secure file permissions for config files (0600 on Unix)
- KSM-734: Fixed notation lookup to handle duplicate UIDs from record shortcuts

### Added
- KSM-743: Added transmission public key #18 for Gov Cloud Dev environment support
- KSM-686: Disaster recovery caching
  - `CachingPostFunction` - Built-in disaster recovery caching
  - `Cache` class for file-based encrypted cache storage
  - Cache file location configurable via `KSM_CACHE_DIR` environment variable
- KSM-692: HTTP proxy support for enterprise environments
  - `proxy_url` initialization parameter
  - HTTPS_PROXY environment variable support
  - Authenticated proxy support
- Feature-specific test coverage for caching and proxy (~100 tests)
- Example files: `10_custom_caching.rb`, `12_proxy_usage.rb`

### Changed
- Bug fixes and enterprise features only (PAM features moved to v17.3.0)
- Reduced test count for focused QA (feature-specific tests only)

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