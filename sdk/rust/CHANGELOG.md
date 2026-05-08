# Changelog

All notable changes to this project will be documented in this file.

## [17.2.0]

### Security

- **reqwest 0.12 → 0.13.3** (KSM-922): resolves four `rustls-webpki` advisories
  - GHSA-82J2-J2CH-GFR8 (High) — certificate validation bypass
  - GHSA-PWJX-7F5V-R8JG, GHSA-XGP8-6FX6-WHRG, GHSA-965H-77QH-FMWD (Low/Medium)
- **openssl 0.10.75 → 0.10.78**: resolves four Critical CVEs
  - CVE-2026-41676, CVE-2026-41677, CVE-2026-41678, CVE-2026-41681 (CVSS 9.1–9.8)
- **TLS backend**: reqwest 0.13 switches from ring-backed rustls to `aws-lc-rs`-backed rustls — the required foundation for FIPS 140-3 compliance in the Rust SDK

### Fixed

- **KSM-886**: File downloads and thumbnail downloads crashed with "builder error" when called from inside a tokio runtime
  - Root cause: `get_file_data()` and `get_thumbnail_data()` built a new `reqwest::blocking::Client` per call inside `tokio::spawn_blocking`, which creates a nested tokio runtime conflict
  - Fix: one `reqwest::blocking::Client` is built in `SecretsManager::new()` and propagated to all `KeeperFile` instances; file operations reuse it
  - See: [reqwest#1017](https://github.com/seanmonstar/reqwest/issues/1017)
- **KSM-812**: `get_folders()` consumed `SecretsManager` by value, preventing any subsequent call on the same instance without cloning first
  - Signature changed from `self` to `&mut self` to match `get_secrets()`, `create_secret()`, and the rest of the API
  - **Note**: this is a breaking change for callers that relied on the consuming signature (e.g. via turbofish or trait bounds); the fix is to remove any `.clone()` added to work around the original bug
- **KSM-925**: Three internal callsites (`update_folder`, `create_folder`, `create_secret`) were still calling `self.clone().get_folders()` after KSM-812 fixed the signature; each clone triggered a wasted extra network round-trip on a throwaway instance — removed
- **KSM-926**: `post_function` (every API call) and `upload_file_function` (multipart file upload) each built a new `reqwest::blocking::Client` per call, leaving the same nested-runtime panic risk under `tokio::spawn_blocking` that KSM-886 fixed for file downloads; both callsites now reuse the shared client built in `SecretsManager::new()`
- **KSM-926**: Resolved a long-standing semantic inversion of `verify_ssl_certs`: the field was assigned with two opposite conventions (constructor option vs. env var) and read with two opposite conventions (API path vs. multipart upload). The field now uniformly means "do verify", and all `danger_accept_invalid_certs` calls route through a single `skip_ssl_verify()` accessor. Net behavior change: `insecure_skip_verify=true` and `KSM_SKIP_VERIFY=true` now both correctly relax TLS verification on every HTTP path; the default (neither set) is now strict on every HTTP path
- Proxy configuration errors (malformed URL, unsupported scheme) now surface at `SecretsManager::new()` with a clear `SecretManagerCreationError` instead of silently bypassing the proxy and sending traffic direct
- Authenticated proxy URLs (`http://user:pass@host:port`) are now correctly applied when `KeeperFile` is used outside the standard `get_secrets()` fetch path (e.g. deserialized from storage)
- TLS initialisation failures now surface at `SecretsManager::new()` instead of deferring to the first API call
- **KSM-931**: `caching::caching_post_function` built a new `reqwest::blocking::Client` on every API call, leaving the same nested-runtime panic risk under `tokio::spawn_blocking` that KSM-886 / KSM-926 fixed for the standard paths
  - Fix: new `caching::make_caching_post_function(client)` factory captures a `reqwest::blocking::Client` built outside any async context and reuses it across all calls; the bare `caching_post_function` is retained for synchronous callers but its docs now warn against use under async runtimes
  - **Note**: `CustomPostFunction` is now `Arc<dyn Fn(...) + Send + Sync>` instead of a bare `fn` pointer — minor breaking change for callers that stored the alias directly; existing `options.set_custom_post_function(my_fn)` call sites compile unchanged because bare `fn` implements `Fn + Send + Sync + 'static`
  - See: [reqwest#1017](https://github.com/seanmonstar/reqwest/issues/1017)
- **KSM-933**: `get_secrets()` was propagating `SecretsManager.verify_ssl_certs` (positive-sense: `true` = strict) directly into `KeeperFile.skip_ssl_verify` (negative-sense: `true` = skip); in strict mode, every file attachment received `skip_ssl_verify=true` — the opposite of intended. Fix: both propagation sites (standalone record path and shared folder record path) now use the `skip_ssl_verify()` accessor, which correctly returns `!verify_ssl_certs`. Currently masked by the shared `http_client` path, but would have become a silent security regression on any future refactor.
- **KSM-936**: `RecordField::new` unconditionally wrapped the supplied `Value` in a single-element array, so callers passing a `Value::Array` (the documented way to create multi-value fields like `phone` and `securityQuestion`) produced `[[obj1, obj2]]` on the wire instead of `[obj1, obj2]`. The server stored the wrong shape, causing `keeper://UID/field/phone[1]` to return "idx out of range: 1" and records to appear single-valued to all other SDKs. Fix: input arrays pass through unchanged; `null` becomes `[]`; scalars and objects are wrapped as before.
- **KSM-937**: `examples/manual_tests/06_caching_function.rs` still used the deprecated bare `caching::caching_post_function` after KSM-934 updated the module doc and README. Users copying the example into a tokio app would intermittently hit the KSM-886 panic. Updated to build one `reqwest::blocking::Client` outside any async context and pass it to `caching::make_caching_post_function(client)`. Examples README updated to match.

### Changed

- `KeeperFile::http_client` and `KeeperFile::skip_ssl_verify` are now `pub(crate)`; they are internal propagation fields and were never part of the public API contract
- `hex` crate removed; hex encoding now uses `data-encoding` (already a direct dependency) — no public API change (KSM-924)

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
