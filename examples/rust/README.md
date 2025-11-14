# Keeper Secrets Manager - Rust SDK Examples

This directory contains practical examples demonstrating how to use the Keeper Secrets Manager Rust SDK.

## Prerequisites

- Rust 1.70+ installed
- Active Keeper account with Secrets Manager enabled
- One-time token from Keeper application

## Installation

The examples will automatically download `keeper-secrets-manager-core` v17.1.0 from crates.io when you first run them.

No additional setup needed!

## Getting Started

### 1. Get Your One-Time Token

Generate a token from your Keeper application:
- Web Vault: https://app.keeper-security.com/secrets-manager
- Desktop App: Secrets Manager → Create Application → Generate Token

### 2. Run Quick Start (Required First Step)

This creates `keeper_config.json` that all other examples use:

```bash
cd examples/rust
export KSM_TOKEN='US:YOUR_ONE_TIME_TOKEN_HERE'
cargo run --bin 01_quick_start
```

After successful run, `keeper_config.json` is created and saved for reuse.

### 3. Run Other Examples

All subsequent examples use the saved `keeper_config.json`:

```bash
# No token needed - uses saved config
cargo run --bin 02_retrieve_secrets
cargo run --bin 03_update_secrets
cargo run --bin 04_password_rotation
cargo run --bin 05_files
cargo run --bin 06_caching
```

## Examples Overview

### 01_quick_start.rs ⭐ **START HERE**
The simplest way to connect and retrieve secrets. Creates `keeper_config.json` for other examples.

**What it demonstrates:**
- Token-based initialization
- First connection and token binding
- Basic secret retrieval
- Config file creation

### 02_retrieve_secrets.rs
Different methods for retrieving and filtering secrets.

**What it demonstrates:**
- Get all secrets
- Get specific secret by UID
- Get secret by title (exact match)
- Get all secrets with same title
- Using Keeper Notation
- Inspecting secret metadata

### 03_update_secrets.rs
How to modify secret fields.

**What it demonstrates:**
- Updating password fields
- Using `set_standard_field_value_mut()`
- Saving changes with `update_secret()`
- Verifying updates

### 04_password_rotation.rs
Safe password rotation using transactions.

**What it demonstrates:**
- Starting rotation transaction
- `update_secret_with_transaction()`
- Testing new password (simulation)
- Committing with `complete_transaction(false)`
- Rollback option with `complete_transaction(true)`

### 05_files.rs
Working with file attachments.

**What it demonstrates:**
- Listing file attachments
- Downloading and decrypting files
- Accessing file metadata (URL, thumbnail URL)
- Checking for thumbnail availability

### 06_caching.rs
Disaster recovery with automatic caching.

**What it demonstrates:**
- Enabling `caching_post_function`
- Automatic cache on successful API calls
- Cache file structure
- Cache management functions
- Offline access preparation

## Configuration

### Environment Variables

- **`KSM_TOKEN`** - One-time token (required for example 01 only)
- **`KSM_CACHE_DIR`** - Custom cache directory (default: current directory)
- **`RUST_LOG`** - Logging level (e.g., `debug`, `info`)

### Config File

After running example 01, `keeper_config.json` contains:
- Client ID (derived from token)
- Private key (for encryption)
- App key (for decryption)
- Server public key ID
- Hostname

**⚠️ Keep `keeper_config.json` secure** - it contains credentials for vault access.

## Running All Examples

```bash
cd examples/rust

# Step 1: Initialize (creates keeper_config.json)
export KSM_TOKEN='US:YOUR_TOKEN'
cargo run --bin 01_quick_start

# Step 2: Run all other examples
for example in 02_retrieve_secrets 03_update_secrets 04_password_rotation 05_files 06_caching; do
    echo "Running $example..."
    cargo run --bin $example
    echo "---"
done
```

## Troubleshooting

### "keeper_config.json not found"
Run `01_quick_start.rs` first with your `KSM_TOKEN` to create the config file.

### "Signature is invalid"
Your token may have expired or been consumed. Get a fresh token and rerun `01_quick_start.rs`.

### "No editable secrets found"
Ensure you have at least one secret in your vault with edit permissions enabled.

## Next Steps

After exploring these examples:

1. **Read the SDK documentation**: https://docs.keeper.io/secrets-manager/developer-sdk-library/rust-sdk
2. **Check the CHANGELOG**: `../../sdk/rust/CHANGELOG.md` for v17.1.0 features
3. **Review the API reference**: `../../sdk/rust/CLAUDE.md` for architecture details
4. **Explore advanced features**: Transaction types, link removal, GraphSync links

## Features Demonstrated

✅ Token initialization and binding
✅ Get secrets (all, filtered, by title)
✅ Update secrets with verification
✅ Password rotation with transactions
✅ Transaction commit and rollback
✅ File download and metadata
✅ Disaster recovery caching
✅ Keeper Notation queries
✅ Field manipulation
✅ Error handling patterns

## Additional Resources

- **SDK Source**: `../../sdk/rust/`
- **Documentation**: `../../sdk/rust/README.md`
- **Tests**: `../../sdk/rust/tests/`
- **CHANGELOG**: `../../sdk/rust/CHANGELOG.md`

## License

MIT License - See repository root for details.
