# Keeper Secrets Manager Rust SDK

The Rust SDK for Keeper Secrets Manager provides type-safe, zero-knowledge access to secrets stored in Keeper's vault with comprehensive error handling.

## Features

- **Type-Safe API**: Leverages Rust's type system for compile-time safety
- **Never Panics**: All operations return `Result<T, KSMRError>` - no unwraps in library code
- **Multiple Storage Options**: File-based, in-memory, and caching support
- **Comprehensive Crypto**: AES-256-GCM, ECDH (P-256), ECDSA using industry-standard crates
- **Notation Support**: Access specific fields using `keeper://` URI notation
- **Password Rotation**: Transaction-based rotation with commit/rollback
- **GraphSync Support**: Linked record retrieval for managing relationships
- **Disaster Recovery Caching**: Automatic fallback to cached data on network failures
- **Rust 1.87+**: Modern Rust with async runtime (reqwest)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
keeper-secrets-manager-core = "17.1.0"
```

## Quick Start

### Initialize with One-Time Token

```rust
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    enums::KvStoreType,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    // Create file storage (saves config to keeper_config.json)
    let storage = FileKeyValueStorage::new(Some("keeper_config.json".to_string()))?;
    let config = KvStoreType::File(storage);

    // Initialize with one-time token
    let token = "US:ONE_TIME_TOKEN_HERE".to_string();
    let options = ClientOptions::new_client_options_with_token(token, config);
    let mut secrets_manager = SecretsManager::new(options)?;

    // Retrieve all secrets
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    for secret in secrets {
        println!("Title: {}", secret.title);
        if let Ok(password) = secret.get_standard_field_value("password", true) {
            println!("  Password: {}", password);
        }
    }

    Ok(())
}
```

### Initialize with Existing Configuration

```rust
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    enums::KvStoreType,
    storage::InMemoryKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    // From base64 config string (useful for serverless/Docker)
    let base64_config = std::env::var("KSM_CONFIG")
        .expect("KSM_CONFIG environment variable required");

    let storage = InMemoryKeyValueStorage::new(Some(base64_config))?;
    let config = KvStoreType::InMemory(storage);

    let options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(options)?;

    let secrets = secrets_manager.get_secrets(Vec::new())?;
    println!("Retrieved {} secrets", secrets.len());

    Ok(())
}
```

## Secret Retrieval

### Get All Secrets

```rust
// Get all secrets
let secrets = secrets_manager.get_secrets(Vec::new())?;

// Get specific secrets by UID
let uids = vec!["RECORD_UID_1".to_string(), "RECORD_UID_2".to_string()];
let secrets = secrets_manager.get_secrets(uids)?;
```

### Search by Title

```rust
// Get all secrets matching title (case-sensitive)
let matching = secrets_manager.get_secrets_by_title("Production Database")?;
println!("Found {} matching secrets", matching.len());

// Get first secret with title
if let Some(secret) = secrets_manager.get_secret_by_title("Production Database")? {
    println!("Found: UID {}", secret.uid);
}
```

### Get Secrets with GraphSync Links

```rust
use keeper_secrets_manager_core::dto::payload::QueryOptions;

// Request linked records
let query = QueryOptions::with_links(
    Vec::new(),  // all records
    Vec::new(),  // all folders
    true         // request_links
);

let secrets = secrets_manager.get_secrets_with_options(query)?;

// Access linked records
for secret in secrets {
    if !secret.links.is_empty() {
        println!("{} has {} linked records", secret.title, secret.links.len());
    }
}
```

## Accessing Field Values

### Standard Fields

```rust
use keeper_secrets_manager_core::enums::StandardFieldTypeEnum;

// Get single value (first occurrence)
let login = secret.get_standard_field_value("login", true)?;
let password = secret.get_standard_field_value("password", true)?;
let url = secret.get_standard_field_value("url", true)?;

// Get all values (returns array)
let emails = secret.get_standard_field_value("email", false)?;

// Using enum for type safety
let login = secret.get_standard_field_value(
    StandardFieldTypeEnum::LOGIN.get_type(),
    true
)?;
```

### Custom Fields

```rust
// Get custom field by label
let environment = secret.get_custom_field_value("Environment", true)?;
let api_key = secret.get_custom_field_value("API Key", true)?;
```

### Using Keeper Notation

```rust
// Access fields without retrieving full records
let password = secrets_manager.get_notation(
    "keeper://RECORD_UID/field/password".to_string()
)?;

// Access by title
let api_key = secrets_manager.get_notation(
    "keeper://Production API/custom_field/API Key".to_string()
)?;

// Access complex field properties
let hostname = secrets_manager.get_notation(
    "keeper://RECORD_UID/field/host[hostName]".to_string()
)?;

// Array indexing
let first_email = secrets_manager.get_notation(
    "keeper://RECORD_UID/field/email[0]".to_string()
)?;
```

## Creating Secrets

```rust
use keeper_secrets_manager_core::{
    dto::{dtos::RecordCreate, field_structs::{Login, Password}},
    enums::DefaultRecordType,
};

fn main() -> Result<(), KSMRError> {
    // ... initialize secrets_manager ...

    // Create new login record
    let mut new_record = RecordCreate::new(
        DefaultRecordType::Login.get_type().to_string(),
        "My Server Login".to_string(),
        Some("Production server credentials".to_string()),
    );

    // Add login field
    let login_field = Login::new(
        "admin@example.com".to_string(),
        None,    // required
        Some(false),  // privacyScreen
        Some(false),  // enforceGeneration
    );
    new_record.append_standard_fields(login_field);

    // Add password field
    let password_field = Password::new(
        "SecurePassword123!".to_string(),
        None,    // required
        Some(true),   // privacyScreen
        Some(false),  // enforceGeneration
        Some(true),   // complexity
        None,    // matchRegex
    )?;
    new_record.append_standard_fields(password_field);

    // Create in Keeper vault
    let folder_uid = "SHARED_FOLDER_UID".to_string();
    let record_uid = secrets_manager.create_secret(folder_uid, new_record)?;

    println!("Created secret with UID: {}", record_uid);
    Ok(())
}
```

## Updating Secrets

### Basic Update

```rust
use keeper_secrets_manager_core::enums::StandardFieldTypeEnum;

// Get secret to update
let mut secrets = secrets_manager.get_secrets(vec!["RECORD_UID".to_string()])?;
let mut record = secrets.into_iter().next()
    .ok_or_else(|| KSMRError::RecordNotFoundError("Record not found".to_string()))?;

// Modify password field
record.set_standard_field_value_mut(
    StandardFieldTypeEnum::PASSWORD.get_type(),
    "NewPassword123!".into()
)?;

// Save changes
secrets_manager.update_secret(record)?;
println!("Secret updated successfully");
```

### Password Rotation with Transactions

```rust
use keeper_secrets_manager_core::dto::payload::UpdateTransactionType;

// Get secret to rotate
let mut secrets = secrets_manager.get_secrets(vec!["RECORD_UID".to_string()])?;
let mut record = secrets.into_iter().next().unwrap();
let record_uid = record.uid.clone();

// Update password
record.set_standard_field_value_mut("password", "NewRotatedPassword123!".into())?;

// Start rotation transaction
secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::Rotation)?;

// Test the new password in your application...
println!("Testing new password...");

// Commit the transaction if successful
secrets_manager.complete_transaction(record_uid.clone(), false)?;

// Or rollback if testing failed:
// secrets_manager.complete_transaction(record_uid, true)?;

println!("Password rotation completed");
```

### Update with Link Removal

```rust
use keeper_secrets_manager_core::dto::payload::{UpdateOptions, UpdateTransactionType};

// Get secret
let mut secrets = secrets_manager.get_secrets(vec!["RECORD_UID".to_string()])?;
let mut record = secrets.into_iter().next().unwrap();

// Modify fields as needed...

// Remove file attachments
let options = UpdateOptions::new(
    UpdateTransactionType::General,
    vec!["FILE_UID_TO_REMOVE".to_string()]
);

secrets_manager.update_secret_with_options(record, options)?;
println!("Secret updated and file removed");
```

## File Operations

### Download Files

```rust
// Download file from a secret
for mut secret in secrets {
    for file in &secret.files {
        let file_uid = &file.file_uid;
        secret.download_file(file_uid, &format!("./downloads/{}", file.name))?;
        println!("Downloaded: {}", file.name);
    }
}
```

### Download File by Title

```rust
// Download file by name without knowing UID
let secrets = secrets_manager.get_secrets(Vec::new())?;

if let Some(file_data) = secrets_manager.download_file_by_title("Production Database", "backup.sql")? {
    std::fs::write("./backup.sql", file_data)?;
    println!("Downloaded backup.sql");
} else {
    println!("File not found");
}
```

### Download Thumbnails

```rust
for secret in secrets {
    for mut file in secret.files {
        if let Some(thumbnail_data) = file.get_thumbnail_data()? {
            let thumb_path = format!("./thumbnails/{}_thumb.jpg", file.name);
            std::fs::write(&thumb_path, thumbnail_data)?;
            println!("Downloaded thumbnail: {}", thumb_path);
        }
    }
}
```

### Upload Files

```rust
use keeper_secrets_manager_core::dto::dtos::KeeperFileUpload;

// Get secret to attach file to
let mut secrets = secrets_manager.get_secrets(vec!["RECORD_UID".to_string()])?;
let secret = secrets.into_iter().next().unwrap();

// Prepare file for upload
let file_upload = KeeperFileUpload::get_file_for_upload(
    "./document.pdf",           // file path
    Some("document.pdf"),        // file name in vault
    Some("Important Document"),  // file title
    None                         // auto-detect MIME type
)?;

// Upload to secret
let upload_status = secrets_manager.upload_file(secret, file_upload)?;
println!("Upload status: {}", upload_status);
```

## Password Generation

### Basic Password Generation

```rust
use keeper_secrets_manager_core::utils::generate_password;

let password = generate_password()?;
println!("Generated password: {}", password);  // 32 chars, mixed
```

### Custom Password Options

```rust
use keeper_secrets_manager_core::utils::{generate_password_with_options, PasswordOptions};

let options = PasswordOptions::new()
    .length(20)
    .lowercase(5)      // At least 5 lowercase
    .uppercase(5)      // At least 5 uppercase
    .digits(3)         // At least 3 digits
    .special_characters(2)  // At least 2 special chars
    .special_characterset("!@#$%".to_string());

let password = generate_password_with_options(options)?;
println!("Generated: {}", password);
```

### Exact Character Counts

Use negative values to specify exact counts instead of minimums:

```rust
let options = PasswordOptions::new()
    .lowercase(-8)     // Exactly 8 lowercase
    .uppercase(-8)     // Exactly 8 uppercase
    .digits(-4)        // Exactly 4 digits
    .special_characters(-4);  // Exactly 4 special chars
// Total length = 8+8+4+4 = 24 (length parameter ignored)

let password = generate_password_with_options(options)?;
println!("Generated 24-char password with exact counts: {}", password);
```

## TOTP Code Generation

```rust
use keeper_secrets_manager_core::utils::get_totp_code;
use keeper_secrets_manager_core::enums::StandardFieldTypeEnum;

// Get secret with TOTP
let mut secrets = secrets_manager.get_secrets(vec!["RECORD_UID".to_string()])?;
let secret = secrets.into_iter().next().unwrap();

// Get TOTP URL from field
let totp_value = secret.get_standard_field_value(
    StandardFieldTypeEnum::ONETIMECODE.get_type(),
    true
)?;

// Extract URL and generate code
if let serde_json::Value::Object(obj) = totp_value {
    if let Some(serde_json::Value::String(url)) = obj.get("url") {
        let totp_code = get_totp_code(url)?;
        println!("TOTP Code: {}", totp_code.get_code());
        println!("Time left: {} seconds", totp_code.get_time_left());
    }
}
```

## Folder Operations

### List Folders

```rust
let folders = secrets_manager.get_folders()?;

for folder in folders {
    println!("Folder: {} (UID: {})", folder.name, folder.folder_uid);
    if let Some(parent_uid) = &folder.parent_uid {
        println!("  Parent: {}", parent_uid);
    }
}
```

### Create Folder

```rust
use keeper_secrets_manager_core::dto::payload::CreateOptions;

let parent_folder_uid = "PARENT_FOLDER_UID".to_string();
let create_options = CreateOptions::new(parent_folder_uid, None);

let folder_uid = secrets_manager.create_folder(
    create_options,
    "My New Folder".to_string(),
    Vec::new()
)?;

println!("Created folder: {}", folder_uid);
```

### Update Folder

```rust
let folder_uid = "FOLDER_UID".to_string();

secrets_manager.update_folder(
    folder_uid,
    "Renamed Folder".to_string(),
    Vec::new()
)?;

println!("Folder renamed");
```

### Delete Folder

```rust
// Delete empty folder
secrets_manager.delete_folder(vec!["FOLDER_UID".to_string()], false)?;

// Force delete non-empty folder
secrets_manager.delete_folder(vec!["FOLDER_UID".to_string()], true)?;
```

## Advanced Features

### Disaster Recovery Caching

Automatically cache responses and fall back to cached data on network failures:

```rust
use keeper_secrets_manager_core::caching;

let storage = FileKeyValueStorage::new(Some("keeper_config.json".to_string()))?;
let config = KvStoreType::File(storage);

let token = "YOUR_TOKEN".to_string();
let mut options = ClientOptions::new_client_options_with_token(token, config);

// Enable disaster recovery caching
options.set_custom_post_function(caching::caching_post_function);

let mut secrets_manager = SecretsManager::new(options)?;

// First call: saves to cache (default: KSM_CACHE_DIR/ksm_cache.bin)
let secrets = secrets_manager.get_secrets(Vec::new())?;

// Subsequent calls: uses cache if network unavailable
println!("Retrieved {} secrets (with fallback)", secrets.len());
```

Cache location can be customized via `KSM_CACHE_DIR` environment variable.

### In-Memory Caching

```rust
use keeper_secrets_manager_core::cache::KSMRCache;

let storage = FileKeyValueStorage::new(Some("keeper_config.json".to_string()))?;
let config = KvStoreType::File(storage);

let cache = KSMRCache::new_file_cache(Some("./ksm_cache.bin"))?;

let token = "YOUR_TOKEN".to_string();
let mut options = ClientOptions::new_client_options_with_token(token, config);
options.set_cache(cache.into());

let mut secrets_manager = SecretsManager::new(options)?;

// Secrets cached for performance
let secrets = secrets_manager.get_secrets(Vec::new())?;
```

## Error Handling

The SDK uses a comprehensive `KSMRError` enum for all errors. All public methods return `Result`:

```rust
use keeper_secrets_manager_core::custom_error::KSMRError;

match secrets_manager.get_secrets(vec!["INVALID_UID".to_string()]) {
    Ok(secrets) => {
        println!("Retrieved {} secrets", secrets.len());
    }
    Err(KSMRError::RecordNotFoundError(msg)) => {
        eprintln!("Record not found: {}", msg);
    }
    Err(KSMRError::AuthenticationError(msg)) => {
        eprintln!("Authentication failed: {}", msg);
    }
    Err(KSMRError::HTTPError(msg)) => {
        eprintln!("Network error: {}", msg);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

**Common error types:**
- `RecordNotFoundError` - Record UID not found in vault
- `FieldNotFoundError` - Requested field doesn't exist
- `AuthenticationError` - Invalid token or credentials
- `InvalidTokenError` - Malformed token
- `CryptoError` - Encryption/decryption failure
- `HTTPError` - Network or API error
- `StorageError` - Config file I/O error
- `NotationError` - Invalid `keeper://` URI syntax

## Storage Options

### File Storage (Persistent)

```rust
use keeper_secrets_manager_core::storage::FileKeyValueStorage;
use keeper_secrets_manager_core::enums::KvStoreType;

// Default location: keeper_config.json
let storage = FileKeyValueStorage::new(None)?;

// Custom location
let storage = FileKeyValueStorage::new(Some("/path/to/config.json".to_string()))?;

let config = KvStoreType::File(storage);
```

**File permissions:**
- Automatically created with `0600` (owner read/write only) on Unix
- Secure ACLs on Windows (user + Administrator only)

### In-Memory Storage (Ephemeral)

```rust
use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
use keeper_secrets_manager_core::enums::KvStoreType;

// From base64 config string
let base64_config = "eyJ...".to_string();
let storage = InMemoryKeyValueStorage::new(Some(base64_config))?;

// Empty config (useful for one-time token initialization)
let storage = InMemoryKeyValueStorage::new(None)?;

let config = KvStoreType::InMemory(storage);
```

**Use cases:**
- Serverless/Lambda functions
- Docker containers
- CI/CD pipelines
- Applications without filesystem access

## Examples

See `examples/manual_tests/` for comprehensive runnable examples:

| Example | Description |
|---------|-------------|
| `01_initialize_and_get_secrets.rs` | Basic initialization and secret retrieval |
| `02_update_secret.rs` | Update secret fields |
| `03_password_rotation.rs` | Transaction-based password rotation |
| `04_search_by_title.rs` | Title-based secret search |
| `05_update_with_options.rs` | Advanced updates with link removal |
| `06_caching_function.rs` | Disaster recovery caching |
| `07_test_rotation_base64.rs` | Rotation with base64 config |
| `08_test_link_removal.rs` | File link removal |
| `09_check_fileref.rs` | File reference validation |
| `10_test_link_removal_debug.rs` | Debug link removal |
| `12_upload_and_remove_file.rs` | File upload and removal |

Run examples:
```bash
cargo run --example 01_initialize_and_get_secrets
```

See `examples/manual_tests/README.md` for detailed setup instructions.

## Configuration

### Environment Variables

- `KSM_CONFIG` - Base64-encoded JSON configuration (overrides file storage)
- `KSM_CACHE_DIR` - Cache directory for disaster recovery caching (default: current directory)
- `KSM_SKIP_VERIFY` - Skip SSL certificate verification (`true`/`false`)

### Client Options

```rust
use keeper_secrets_manager_core::core::ClientOptions;
use keeper_secrets_manager_core::cache::KSMCache;
use log::Level;

// Full control over initialization
let options = ClientOptions::new(
    "YOUR_TOKEN".to_string(),
    config,
    Level::Info,                // log level
    Some("keepersecurity.com".to_string()),  // hostname override
    Some(false),                // insecure_skip_verify
    KSMCache::None              // cache
);

// Or use convenience constructors
let options = ClientOptions::new_client_options_with_token(token, config);
let options = ClientOptions::new_client_options(config);
```

## Dependencies

- `aes-gcm` - AES-256-GCM encryption
- `p256` - ECDH and ECDSA on NIST P-256 curve
- `reqwest` - HTTP client (blocking mode)
- `serde` / `serde_json` - Serialization
- `base64` - Encoding
- `chrono` - Date/time handling
- `log` - Logging facade

**Development dependencies:**
- `mockall` - Mocking framework for tests
- `serial_test` - Sequential test execution
- `tempfile` - Temporary file handling in tests

## Testing

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test empty_config_test

# Run with output
cargo test -- --nocapture

# Run single test
cargo test test_empty_json_config_returns_error_not_panic

# Generate documentation
cargo doc --open
```

## Documentation

- **Official Docs**: https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/rust-sdk
- **Repository**: https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust
- **crates.io**: https://crates.io/crates/keeper-secrets-manager-core
- **API Docs**: https://docs.rs/keeper-secrets-manager-core

## License

MIT

## Support

For questions or issues:
- **Email**: sm@keepersecurity.com
- **GitHub Issues**: https://github.com/Keeper-Security/secrets-manager/issues
