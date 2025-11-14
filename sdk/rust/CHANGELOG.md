# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [17.1.0] - 2025-11-12

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
  - Matches pattern from Python, JavaScript, Java, Ruby, and .NET SDKs

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
- **`tests/feature_validation_tests.rs`** (317 lines) - 15 validation tests
  - UpdateOptions struct validation
  - DTO field validation (links, is_editable, inner_folder_uid)
  - QueryOptions.request_links validation
  - Caching module functionality tests
  - Custom post function integration tests
  - All new features compilation tests

### Changed

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

### Fixed
- **env_logger dependency** - Added missing `env_logger = "0.11"` to Cargo.toml
  - Fixes compilation error in `main.rs`
  - Allows binary target to compile successfully

### Links

- [Repository](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust)
- [Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/rust-sdk)
- [crates.io](https://crates.io/crates/keeper-secrets-manager-core)
