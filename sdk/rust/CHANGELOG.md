# Changelog

All notable changes to this project will be documented in this file.

## [17.1.0]

### Added

#### Core API Methods
- **`update_secret(record)`** - Standard record update method
  - Updates existing secret records with modified fields
  - Encrypts and sends updated data to server
  - Returns `Result<(), KSMRError>` on completion
- **`update_secret_with_transaction(record, transaction_type)`** - Transactional update support
  - Enables password rotation workflows with `UpdateTransactionType::Rotation`
  - Supports `General` and `Rotation` transaction types
  - Requires `complete_transaction()` call to finalize rotation transactions
- **`update_secret_with_options(record, update_options)`** - Advanced update with link management
  - Supports transaction types (General, Rotation)
  - Removes file links via `UpdateOptions.links_to_remove`
  - Automatically filters fileRef fields when links are removed
- **`complete_transaction(record_uid, rollback)`** - Transaction finalization
  - Commits transaction when `rollback = false`
  - Rolls back transaction when `rollback = true`
  - Uses `finalize_secret_update` or `rollback_secret_update` endpoints
- **`get_secrets_by_title(title)`** - Search all secrets by exact title match
  - Returns `Vec<Record>` with all matching records
  - Case-sensitive exact matching
  - Client-side filtering for efficiency
- **`get_secret_by_title(title)`** - Get first secret by title
  - Returns `Option<Record>` with first match
  - Returns `None` if no matches found

#### File Operations
- **`KeeperFile.get_thumbnail_data()`** - Download and decrypt file thumbnails
  - Returns `Option<Vec<u8>>` with decrypted thumbnail data
  - Returns `None` if thumbnail not available
  - Uses same encryption as regular file downloads

#### DTO Enhancements
- **`Record.links`** field - GraphSync linked records support
  - `Vec<HashMap<String, Value>>` for linked record metadata
  - Automatically parsed from API responses
  - Supports record relationships and dependencies
- **`KeeperFile.url`** field - Explicit download URL
  - `Option<String>` populated from API response
  - Falls back to `f` HashMap if not set
- **`KeeperFile.thumbnail_url`** field - Thumbnail image URL
  - `Option<String>` for thumbnail download endpoint
  - Enables thumbnail preview functionality
- **`QueryOptions.request_links`** field - Request linked records
  - `Option<bool>` to control GraphSync link retrieval
  - Added `with_links()` constructor method
- **`GetPayload.request_links`** field - API parameter for links
  - Serializes as `requestLinks` in JSON
  - Added `with_request_links()` constructor
- **`UpdatePayload.links2_remove`** field - Link removal support
  - `Option<Vec<String>>` for link UIDs to remove
  - Serializes as `links2Remove` in JSON
  - Added `set_links_to_remove()` method
- **`UpdateOptions`** struct - Advanced update configuration (NEW)
  - `transaction_type` - UpdateTransactionType enum
  - `links_to_remove` - Vec<String> for links to remove
  - Constructors: `new()`, `with_transaction_type()`, `with_links_removal()`, `default()`

#### Infrastructure
- **Custom HTTP Injection** - Testing and mocking support
  - `CustomPostFunction` type for function pointers
  - `ClientOptions.custom_post_function` field
  - `ClientOptions.set_custom_post_function()` method
  - `SecretsManager.custom_post_function` storage
  - Modified `post_query()` to use custom function when available
- **Caching Module** - `src/caching.rs` (295 lines)
  - `caching_post_function()` - Drop-in disaster recovery caching
  - `save_cache()` - Persist transmission key + encrypted response
  - `get_cached_data()` - Load cached data
  - `clear_cache()` - Remove cache file
  - `cache_exists()` - Check cache presence
  - `get_cache_file_path()` - Cache location from `KSM_CACHE_DIR` env var
  - `make_http_request()` - Standalone HTTP request function
  - Automatic fallback to cached data on network failure
- **Transmission Public Key #18** - Gov Cloud Dev environment support
  - Added public key #18 to `KEEPER_PUBLIC_KEYS` in `src/constants.rs`
  - Enables secure communication with Keeper Gov Cloud Dev servers
  - Required for signature verification in government cloud deployments

#### Testing
- **`tests/update_secret_tests.rs`** (362 lines) - 14 unit tests
  - Password field modification tests
  - Custom field modification tests
  - Multiple field update tests
  - Transaction type serialization/deserialization tests
  - Record revision tracking tests
  - Field retrieval and error handling tests
- **`tests/integration_tests.rs`** (772 lines) - 12 integration tests
  - End-to-end update workflows with mocked HTTP
  - Transaction completion tests (commit and rollback)
  - Full password rotation workflow tests
  - Error scenario tests
  - URL and endpoint validation tests
  - Sequential update tests
- **`tests/feature_validation_tests.rs`** - 17 validation tests
  - UpdateOptions struct validation
  - DTO field validation (links, is_editable, inner_folder_uid)
  - QueryOptions.request_links validation
  - Caching module functionality tests
  - Custom post function integration tests
  - All new features compilation tests

### Changed

#### Minimum Rust Version
- **Rust 1.87 or later** now required (enforced via `rust-version = "1.87"` in Cargo.toml)
  - Required for Edition 2024 dependencies and `is_multiple_of()` stabilization
  - Security patches necessitate newer Rust version
  - Previous minimum was Rust 1.56 (Edition 2021 requirement)

#### Refactored Internal Methods
- **`prepare_update_secret_payload()`** - Now delegates to `prepare_update_secret_payload_with_options()`
  - Maintains backward compatibility
  - Converts transaction_type to UpdateOptions internally
- **`prepare_update_secret_payload_with_options()`** - NEW internal method
  - Accepts `Option<UpdateOptions>` parameter
  - Applies transaction type from options
  - Applies links_to_remove from options
  - Generates UpdatePayload with all options set

#### Enhanced Existing Methods
- **`save()`** method - Updated to use refactored payload preparation
  - Behavior unchanged, internal implementation improved
- **`KeeperFile.get_url()`** - Enhanced to check url field first
  - Tries `self.url` field before falling back to `f` HashMap
  - Maintains backward compatibility
- **File removal logic** - Enhanced link removal support (core.rs:1761-1771)
  - Filters `fileRef` field values when `links_to_remove` is specified
  - Removes entire `fileRef` field when value array becomes empty

### Security
- **openssl**: Updated from 0.10.68 to 0.10.75
  - Fixes RUSTSEC-2025-0022 (CVE-2025-3416): Use-After-Free in `Md::fetch` and `Cipher::fetch`
  - Severity: MEDIUM
- **ring**: Updated from 0.17.8 to 0.17.14
  - Fixes RUSTSEC-2025-0009 (CVE-2025-4432): AES panic vulnerability
  - Severity: MEDIUM

### Fixed
- **KSM-769**: Custom field notation selector bug
  - Fixed `custom_field` notation selector always searching in wrong array
  - Rust SDK was searching in "fields" array for both `field` and `custom_field` selectors
  - Custom fields are stored in "custom" array, not "fields" array
  - Now correctly routes `custom_field` selector to "custom" array
  - Added integration tests with proper Keeper record structure to prevent regression
- **KSM-735**: Notation lookup with record shortcuts (duplicate UID bug)
  - Fixed notation queries returning incorrect record when vault contains shortcuts
  - Shortcuts create duplicate UIDs in secrets array (shortcut + original record)
  - Implemented stable deduplication: prioritizes non-shortcut records
  - Added 314 lines of comprehensive unit tests for all duplicate UID scenarios
  - Ensures `get_notation()` consistently returns data from correct record
- **KSM-639**: Key rotation bug - Handle `key_id` as both number and string in server responses
  - Server returns `key_id` as number but SDK expected string
  - Now correctly parses both formats for compatibility
  - Prevents key rotation failures
- **KSM-700**: File permissions for config files (secure 0600 on Unix)
- Resolved Clippy warnings for Rust beta compatibility
- **env_logger dependency** - Added missing `env_logger = "0.11"` to Cargo.toml
  - Fixes compilation error in `main.rs`
  - Allows binary target to compile successfully
- **KSM-774**: Missing UID logging in bad encryption error handling
  - Added record UID to "Error decrypting record data" message
  - Added folder UID to "Error decrypting folder key" message
  - Matches existing pattern from record key decryption error
  - Improves debugging when encryption issues occur
- **KSM-775**: Corrupt records with bad encryption returned blank data instead of being filtered
  - Fixed `Record::new_from_json()` to return `CryptoError` on decryption failures
  - Corrupt records now filtered out of results (not included with blank title/empty fields)
  - Error messages logged with record UID for debugging
- **KSM-779**: GraphSync `Record.links` always empty when fetching with `request_links=true`
  - Fixed `request_links` field on `GetPayload` not being public, blocking assignment from `core.rs`
  - Fixed `prepare_get_payload()` not transferring `request_links` from `QueryOptions` to `GetPayload`
  - Fixed `Record::new_from_json()` not parsing `links` array from server response envelope
  - All three bugs together prevented GraphSync linked records from working end-to-end
- **KSM-776**: File removal via `links2Remove` ignored when `UpdateTransactionType::General` specified
  - Backend ignores `links2Remove` parameter when `transactionType: "general"` is set
  - SDK now auto-overrides to `UpdateTransactionType::None` when `links_to_remove` is not empty
  - Ensures file removal works correctly regardless of transaction type specified by caller
  - Prevents silent failures where API returns 200 OK but files remain in vault

### Links

- [Repository](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust)
- [Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/rust-sdk)
- [crates.io](https://crates.io/crates/keeper-secrets-manager-core)
