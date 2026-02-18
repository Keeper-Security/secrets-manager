# Changelog

All notable changes to this project will be documented in this file.

## [17.1.0]

### Added

#### Core API Methods
- **`update_secret(record)`** - Update an existing secret record
  - Encrypts and sends modified fields to the server
  - Returns `Result<(), KSMRError>`
- **`update_secret_with_transaction(record, transaction_type)`** - Transactional update for rotation workflows
  - Use `UpdateTransactionType::Rotation` for password rotation
  - Requires a follow-up `complete_transaction()` call to commit or roll back
- **`update_secret_with_options(record, update_options)`** - Update with file link removal
  - Accepts an `UpdateOptions` value to specify transaction type and links to remove
  - When `links_to_remove` is non-empty, the SDK automatically selects the correct transaction type to ensure the server honours the removal
- **`complete_transaction(record_uid, rollback)`** - Finalise or roll back a rotation transaction
  - Pass `rollback = false` to commit, `rollback = true` to abort
- **`get_secrets_by_title(title)`** - Return all records with an exact title match (`Vec<Record>`)
- **`get_secret_by_title(title)`** - Return the first record with an exact title match (`Option<Record>`)
- **`get_secrets_with_options(query_options)`** - Fetch secrets with additional request options
  - Set `QueryOptions.request_links` to retrieve GraphSync linked records; results are available on `Record.links`

#### File Operations
- **`download_file_by_title(records, title)`** - Download a file attachment by name instead of UID
  - Returns decrypted file data as `Vec<u8>`
- **`KeeperFile.get_thumbnail_data()`** - Download and decrypt a file's thumbnail
  - Returns `Option<Vec<u8>>`; `None` if no thumbnail is available

#### New Types and Fields
- **`UpdateOptions`** struct - Options for `update_secret_with_options()`
  - `transaction_type: UpdateTransactionType` (`General` or `Rotation`)
  - `links_to_remove: Vec<String>` - UIDs of file links to detach
  - Constructors: `new()`, `with_transaction_type()`, `with_links_removal()`, `default()`
- **`Record.links`** (`Vec<HashMap<String, Value>>`) - Linked records from a GraphSync response
- **`QueryOptions.request_links`** (`Option<bool>`) - Whether to request linked records; use the `QueryOptions::with_links()` constructor
- **`KeeperFile.url`** (`Option<String>`) - Explicit download URL populated from the API response
- **`KeeperFile.thumbnail_url`** (`Option<String>`) - Thumbnail download URL

#### Infrastructure
- **Proxy support** (KSM-584) - Route SDK traffic through an HTTP/HTTPS proxy
  - Configure via `ClientOptions.proxy_url` or the `HTTP_PROXY`/`HTTPS_PROXY` environment variables
  - Supports authenticated proxies: `http://user:pass@host:port`
  - Applied consistently to all HTTP paths: API calls, file uploads, file downloads, thumbnail downloads, and caching requests
  - The caching module reads the `KSM_PROXY_URL` environment variable when using `caching_post_function`
- **Caching module** - Disaster-recovery caching for offline operation
  - `caching_post_function()` is a drop-in replacement for the standard HTTP call; it automatically falls back to cached data when the server is unreachable
  - Cache location is configured via the `KSM_CACHE_DIR` environment variable
- **Custom HTTP injection** - Inject a custom HTTP handler for testing and mocking
  - Set via `ClientOptions.custom_post_function` / `ClientOptions.set_custom_post_function()`
- **Transmission public key #18** - Support for Keeper Gov Cloud Dev servers

### Changed

#### Minimum Rust Version
- **Rust 1.87 or later** is now required (previously 1.56)
  - Required for Edition 2024 dependencies and stabilised APIs used by security-patch upgrades

#### Enhanced Existing Methods
- **`KeeperFile.get_url()`** - Now checks the new `url` field before falling back to the `f` HashMap; backward compatible

### Security
- **openssl**: Updated from 0.10.68 to 0.10.75
  - Fixes RUSTSEC-2025-0022 (CVE-2025-3416): Use-After-Free in `Md::fetch` and `Cipher::fetch`
  - Severity: MEDIUM
- **ring**: Updated from 0.17.8 to 0.17.14
  - Fixes RUSTSEC-2025-0009 (CVE-2025-4432): AES panic vulnerability
  - Severity: MEDIUM

### Fixed
- **KSM-787**: `CryptoError` during offline cache fallback caused by a transmission key mismatch
  - Cached responses are now re-keyed for the current session before being returned to the caller
- **KSM-782**: Password generation ignored exact character-count mode
  - Negative values in `PasswordOptions` now correctly mean "exactly N of this character type" (e.g. `.lowercase(-8)` → exactly 8 lowercase characters)
  - In exact mode the password length is derived from the sum of the absolute values; the `length` parameter is ignored and a warning is logged
- **KSM-769**: `custom_field` notation selector searched the wrong array
  - Custom fields live in the `custom` array; the SDK was incorrectly searching `fields` for both selectors
- **KSM-735**: Notation lookup returned the wrong record when the vault contains shortcuts
  - Shortcuts produce duplicate UIDs in the secrets list; the SDK now deduplicates by preferring the original record over any shortcut
- **KSM-639**: Key rotation failed when the server returned `key_id` as a JSON number
  - Both number and string formats are now accepted
- **KSM-700**: Config files are now created with secure permissions (0600) on Unix
- **KSM-783**: SDK panicked when initialised with an empty JSON config (`{}`) and no token
  - Initialisation now returns a proper `Err` instead of panicking
- **KSM-775**: Corrupt records with bad encryption were returned with blank fields instead of being excluded
  - Corrupt records are now filtered from results; the record UID is logged for debugging
- **KSM-774**: Record and folder UIDs were missing from encryption error log messages, making failures hard to diagnose
- Resolved Clippy warnings for Rust beta compatibility
- Fixed missing `env_logger` dependency in `Cargo.toml` that caused a compilation error in `main.rs`

### Links

- [Repository](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust)
- [Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/rust-sdk)
- [crates.io](https://crates.io/crates/keeper-secrets-manager-core)
