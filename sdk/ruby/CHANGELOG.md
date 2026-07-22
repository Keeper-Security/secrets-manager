# Changelog

## [17.2.0]

### Fixed
- **KSM-1095**: `update_secret` now calls `complete_transaction` after staging the update, so changes are committed to the server rather than remaining in a staged state indefinitely; works for both `KeeperRecord` objects and plain hash inputs
- **KSM-1094**: `update_secret` no longer raises `NameError: undefined local variable 'record_uid'` when called with a `KeeperRecord` object; the revision refresh now correctly references `record.uid`
- **KSM-1096**: `download_thumbnail` no longer raises `NoMethodError` when passed a `KeeperFile` object; `KeeperFile` now exposes a `file_key` attribute and the method dispatches on type before attempting hash access
- **KSM-824**: `to_h` now always includes `custom` in the V3 API payload, even when the array is empty, matching Commander and Vault behavior
- **KSM-906**: Added IL5 region mapping (`IL5` → `il5.keepersecurity.us`) to `KEEPER_SERVERS`
- **KSM-987**: `url_safe_str_to_bytes` and `base64_to_bytes` in `Utils` now raise `Error` when passed `nil`; all Base64 decoding in `core.rb` routes through `Utils`
- **KSM-1090**: `base64` and `logger` are now declared as explicit runtime dependencies in the gemspec; Ruby 4.0 removed these from the default standard library, so any clean install on Ruby 4.0+ previously raised `LoadError` on `require 'keeper_secrets_manager'`. Also removed a dead `require 'ostruct'` from `dto.rb`.
- **KSM-1070**: Fixed silent AES-CBC fallback in `decrypt_aes_gcm`: an AES-GCM authentication-tag failure now raises `DecryptionError` immediately rather than retrying decryption as AES-CBC; tampered or wrong-key ciphertext previously could produce output without any error.
- **KSM-685**: `CreateOptions.subfolder_uid` parameter is now correctly sent to the API when creating records
- **KSM-686**: Disaster recovery caching with `CachingPostFunction` is now implemented to match other SDKs; API response caching works for both `get_secret` and `get_folders` endpoints, and unused `@cache` and `@cache_expiry` instance variables are removed from `SecretsManager`
- **KSM-696**: Config storage file is now written with `0600` permissions (owner read/write only), preventing other local users from reading stored credentials
- **KSM-734**: Fixed notation lookup to deduplicate record shortcuts via `uniq { |r| r.uid }` before the ambiguity check; preserves genuine duplicate-title detection while preventing false ambiguity errors when both an original record and its shortcut are in scope
- **KSM-1088**: `delete_secret` and `delete_folder` now log an error for each record/folder whose `responseCode` is not `"ok"`, surfacing partial-failure details that were previously silently discarded
- **KSM-1091**: Invalid `proxy_url` now raises `ArgumentError` at initialization with a descriptive message; a URL with no host previously silently bypassed the proxy, and a fully malformed URL raised `NetworkError` at request time instead
- **KSM-1098**: `get_value`, `get_totp_code`, and `download_file` in `notation_enhancements` no longer raise `NoMethodError` when passed `nil`, an empty string, or a non-String value; `parse` itself now checks `is_a?(String)` before `empty?` to avoid `NoMethodError` for non-String inputs. `notation_enhancements` is now properly required from the main entry point.
- Fixed example files to use correct SDK APIs: `09_totp.rb` corrects `Totp` to `TOTP` and `generate()` to `generate_code()`; `01_quick_start.rb` uses the `secret.login` dynamic getter instead of hash access; `10_custom_caching.rb` uses `Utils.bytes_to_base64`
- Fixed badly anchored regular expression in `test/integration/test_totp.rb` that could cause false positives in test validation

### Added
- **KSM-906**: `SecretsManager` now accepts the 4-part IL5 one-time token `IL5:clientKey:serverPublicKeyId:serverPublicKey`, registering the supplied EC P-256 server public key (keyId 20, outside the built-in 1–18 table) for ECIES transmission-key wrapping, and persists it as `serverPublicKey` in config so it survives restarts. Adds `server_public_key` / `server_public_key_id` constructor options (precedence: programmatic > token > config), a new `ConfigKeys::KEY_SERVER_PUBLIC_KEY`, malformed-OTT validation, and an actionable error when the backend rejects a configured custom key. Non-IL5 tokens are unchanged.
- **KSM-1013**: `KeeperRecordLink` (via `KeeperRecord#get_links`) wraps each raw `links` entry with never-raising typed accessors: permission booleans with an `allowedSettings` fallback (top-level wins), AES-256-GCM `get_decrypted_data`/`get_link_data`, and `meta`/`ai_settings`/`jit_settings` settings accessors. Adds a `request_links:` keyword to `get_secrets`. Purely additive; the raw `record.links` list is unchanged.
- **KSM-883**: On HTTP 403 `{"error":"throttled"}`, `post_query` now retries up to 5 times with exponentially increasing delays (11s, 22s, 44s, 88s, 176s) plus 0–25% jitter (one-sided), honoring `retry_after` from the response when present, and raises `ThrottledError` once retries are exhausted. Replaces the previous fixed 60-second sleep with no backoff, jitter, or retry cap.
- **KSM-1102**: Added `save(record, transaction_type: nil, links_to_remove: nil)` and `save_with_options(record, update_options)`: non-finalizing update aliases that use the stored record key without re-fetching and do not call `complete_transaction`
- **KSM-1101**: Added `inflate_field_value(uids, replace_fields)` and `get_inflate_ref_types(field_type)` for field-reference resolution; `addressRef` resolves to address fields, `cardRef` resolves to paymentCard/text/pinCode/address fields with recursive inflate
- **KSM-1100**: Added `get_notation_results` and `try_get_notation_results`: list-returning notation lookup that always returns `Array[String]`, returns all field values by default (no first-element shortcut), and JSON-serializes complex values
- **KSM-1099**: Added `create_secret_with_options(create_options, record_data, folders: nil)`: explicit options-based creation that accepts a pre-fetched folders list to avoid an extra `get_folders` network call; `create_secret` is unchanged
- **KSM-743**: Added transmission public key #18 for Gov Cloud Dev environment support
- **KSM-687**: Added DTO fields and PAM transaction support for complete SDK parity:
  - `links` field to `KeeperRecord` for linked records support
  - `is_editable` field to `KeeperRecord` to check edit permissions
  - `inner_folder_uid` field to `KeeperRecord` for folder location tracking
  - `thumbnail_url` and `last_modified` fields to `KeeperFile`
  - `UpdateOptions` class with `transaction_type` and `links_to_remove` support
  - `update_secret_with_options` method to support removing file links
  - `request_links` option to `QueryOptions` for fetching linked records
  - `download_thumbnail` method for downloading file thumbnails
  - `expires_on` field to `SecretsManagerResponse`
  - `complete_transaction(record_uid, rollback: false)` method for PAM rotation workflows
  - `CompleteTransactionPayload` DTO class for transaction completion
- **KSM-692**: HTTP proxy support for enterprise environments:
  - `proxy_url` initialization parameter for explicit proxy configuration
  - `HTTPS_PROXY` / `https_proxy` environment variable support (automatic detection)
  - Authenticated proxy support (username:password in URL)
  - Proxy applies to all HTTP operations (API calls, file downloads, file uploads)
- **KSM-694**: Convenience methods for improved developer experience:
  - `upload_file_from_path(owner_record_uid, file_path, file_title: nil)`: upload files directly from disk
  - `try_get_notation(notation_uri)`: error-safe notation access (returns empty array on error)
- `KeeperSecretsManager.from_config(config_base64, options = {})`: convenience method for initializing from a base64 config string; complements `from_token()` and `from_file()` and provides parity with the .NET SDK's `GetVaultConfigFromConfigString()` pattern
- `KeeperSecretsManager::CachingPostFunction`: built-in disaster recovery caching
- `KeeperSecretsManager::Cache`: file-based cache management (save, load, clear); location configurable via `KSM_CACHE_DIR` environment variable
- Development console script (`bin/console`) for interactive SDK exploration using Pry REPL

### Changed
- Documentation: Added Ruby SDK to root repository SDK comparison table
- **Test Coverage:**
  - Added 5 new integration test files (test_pam_rotation.rb, test_proxy.rb, test_pam_linked_records.rb, test_caching.rb)
  - Added 17 unit tests for caching functionality and 27 for new features (CompleteTransactionPayload, QueryOptions, proxy configuration, convenience methods)
  - Enhanced test_file_operations.rb with thumbnail download and file link removal tests
- **Mock Infrastructure:** Implemented proper AES-256-GCM encryption in `mock_helper.rb`:
  - Records now use proper AES-GCM encryption (was Base64 only)
  - Folders use correct AES-CBC encryption for data
  - Added transmission key encryption/decryption
  - Added mock endpoints for transaction completion (finalize_secret_update, rollback_secret_update)
  - Enabled complete offline testing without config.base64
- **Example Files:**
  - Added `11_pam_linked_records.rb`: PAM resources with linked credentials and transaction workflow
  - Added `12_proxy_usage.rb`: HTTP proxy configuration examples
  - Updated `06_files.rb`: added `upload_file_from_path` convenience method example
  - Updated `08_notation.rb`: added `try_get_notation` error-safe notation example
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