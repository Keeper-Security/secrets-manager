# Keeper Secrets Manager Rust SDK

The Rust SDK for [Keeper Secrets Manager](https://docs.keeper.io/en/keeperpam/secrets-manager/overview) provides secure storage and retrieval of secrets for your Rust applications.

## Features

- Retrieve secrets from Keeper Vault
- Create, update, and delete secrets
- File upload and download support
- Folder management operations
- TOTP code generation
- Password generation utilities
- Keeper Notation support for field access
- Multiple storage backends (file-based and in-memory)
- Caching support for improved performance

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
keeper-secrets-manager-core = "17.0"
```

## Quick Start

```rust
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    storage::FileKeyValueStorage,
    custom_error::KSMRError,
};

fn main() -> Result<(), KSMRError> {
    // Initialize with a one-time token
    let token = "YOUR_ONE_TIME_TOKEN".to_string();
    let config = FileKeyValueStorage::new_config_storage("config.json".to_string())?;
    
    let client_options = ClientOptions::new_client_options(token, config);
    let mut secrets_manager = SecretsManager::new(client_options)?;
    
    // Retrieve all secrets
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    
    for secret in secrets {
        println!("Secret: {}", secret.title);
        // Access fields using standard field types
        let login = secret.get_standard_field_value("login", false)?;
        println!("Login: {}", login);
    }
    
    Ok(())
}
```

## Common Use Cases

### Retrieve Specific Secrets by UID

```rust
let mut record_uids = Vec::new();
record_uids.push("RECORD_UID".to_string());

let secrets = secrets_manager.get_secrets(record_uids)?;
```

### Access Fields Using Keeper Notation

```rust
// Get specific field from a record
let value = secrets_manager.get_notation("RECORD_UID/field/login".to_string())?;

// Get custom field by name
let custom_value = secrets_manager.get_notation("RECORD_UID/custom_field/api_key".to_string())?;
```

### Generate Passwords

```rust
use keeper_secrets_manager_core::utils::{generate_password_with_options, PasswordOptions};

let options = PasswordOptions::new()
    .length(32)
    .uppercase(8)
    .lowercase(8)
    .digits(8)
    .special_characters(8);

let password = generate_password_with_options(options)?;
```

### Create a New Secret

```rust
use keeper_secrets_manager_core::dto::{dtos::RecordCreate, field_structs::RecordField};
use serde_json::Value;

let mut new_record = RecordCreate::new(
    "login".to_string(),
    "My New Login".to_string(),
    Some("Notes about this login".to_string()),
);

// Add fields
let fields = vec![
    RecordField::new_record_field("login", Value::String("user@example.com".to_string()), None),
    RecordField::new_record_field("password", Value::String("secure_password".to_string()), None),
];

new_record.fields = Some(fields);

// Create the secret in a shared folder
let record_uid = secrets_manager.create_secret("FOLDER_UID".to_string(), new_record)?;
```

### Download Files

```rust
for secret in secrets {
    // Download file attached to a secret
    secret.download_file("attached_file.pdf", "./downloads/file.pdf")?;
}
```

### Generate TOTP Codes

```rust
use keeper_secrets_manager_core::{utils, enums::StandardFieldTypeEnum};

let totp_field = secret.get_standard_field_value(StandardFieldTypeEnum::ONETIMECODE.get_type(), false)?;
let url = utils::get_otp_url_from_value_obj(totp_field)?;
let totp_code = utils::get_totp_code(&url)?;
println!("Current TOTP: {}", totp_code.get_code());
```

## Storage Options

### File-based Storage (Recommended for persistent config)

```rust
use keeper_secrets_manager_core::storage::FileKeyValueStorage;

let config = FileKeyValueStorage::new_config_storage("config.json".to_string())?;
```

### In-Memory Storage (For temporary or secure environments)

```rust
use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;

let base64_config = "YOUR_BASE64_CONFIG_STRING".to_string();
let config = InMemoryKeyValueStorage::new_config_storage(Some(base64_config))?;
```

## Caching

Enable caching to reduce API calls and improve performance:

```rust
use keeper_secrets_manager_core::cache::KSMRCache;

let cache = KSMRCache::new_file_cache(Some("./cache.bin"))?;

let mut client_options = ClientOptions::new_client_options(token, config);
client_options.set_cache(cache.into());

let secrets_manager = SecretsManager::new(client_options)?;
```

## Documentation

For more detailed documentation and examples, visit:
- [Keeper Secrets Manager Documentation](https://docs.keeper.io/en/keeperpam/secrets-manager/overview)
- [API Reference](https://docs.rs/keeper-secrets-manager-core)

## License

This SDK is distributed under the MIT License. See [LICENSE](https://github.com/Keeper-Security/secrets-manager/blob/master/LICENSE) for more information.

## Support

For support, please visit our [GitHub repository](https://github.com/Keeper-Security/secrets-manager).