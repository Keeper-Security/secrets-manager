// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2024 Keeper Security Inc.
// Contact: sm@keepersecurity.com
//

//! # Keeper Secrets Manager Rust SDK
//!
//! Type-safe, zero-knowledge client library for accessing secrets stored in Keeper's vault.
//!
//! ## Features
//!
//! - **Type-Safe API** - Leverages Rust's type system for compile-time safety
//! - **Never Panics** - All operations return `Result<T, KSMRError>` with comprehensive error handling
//! - **Multiple Storage Options** - File-based, in-memory, and caching support
//! - **Zero-Knowledge Architecture** - All encryption/decryption happens client-side
//! - **Keeper Notation** - URI-based field access (`keeper://UID/field/password`)
//! - **Password Rotation** - Transaction-based rotation with commit/rollback
//! - **GraphSync Support** - Linked record retrieval for managing relationships
//! - **Disaster Recovery Caching** - Automatic fallback to cached data on network failures
//!
//! ## Quick Start
//!
//! ```no_run
//! use keeper_secrets_manager_core::{SecretsManager, ClientOptions, KSMRError, KvStoreType, FileKeyValueStorage};
//!
//! fn main() -> Result<(), KSMRError> {
//!     // Initialize with one-time token
//!     let storage = FileKeyValueStorage::new(Some("config.json".to_string()))?;
//!     let config = KvStoreType::File(storage);
//!     let token = "US:YOUR_ONE_TIME_TOKEN".to_string();
//!     let options = ClientOptions::new_client_options_with_token(token, config);
//!     let mut secrets_manager = SecretsManager::new(options)?;
//!
//!     // Retrieve secrets
//!     let secrets = secrets_manager.get_secrets(Vec::new())?;
//!     for secret in secrets {
//!         println!("Title: {}", secret.title);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! Or use the builder:
//!
//! ```no_run
//! use keeper_secrets_manager_core::{SecretsManager, ClientOptionsBuilder, KSMRError, KvStoreType, InMemoryKeyValueStorage};
//!
//! fn main() -> Result<(), KSMRError> {
//!     let config_b64 = std::env::var("KSM_CONFIG").expect("KSM_CONFIG required");
//!     let storage = InMemoryKeyValueStorage::new(Some(config_b64))?;
//!     let options = ClientOptionsBuilder::new(KvStoreType::InMemory(storage))
//!         .token("US:YOUR_ONE_TIME_TOKEN")
//!         .build();
//!     let mut sm = SecretsManager::new(options)?;
//!     let secrets = sm.get_secrets(Vec::new())?;
//!     println!("Found {} secrets", secrets.len());
//!     Ok(())
//! }
//! ```
//!
//! ## Modules
//!
//! - [`core`] - Main `SecretsManager` API and client configuration
//! - [`storage`] - Storage backends (File, InMemory)
//! - [`cache`] - Performance caching layer
//! - [`caching`] - Disaster recovery caching with network fallback
//! - [`crypto`] - Cryptographic operations (AES-GCM, ECDH, ECDSA)
//! - [`dto`] - Data transfer objects (Record, Folder, File, Payload types)
//! - [`utils`] - Utilities (password generation, TOTP, Base64 encoding)
//! - [`custom_error`] - Error types (`KSMRError` enum)
//! - [`enums`] - Type enums (field types, record types, storage types)
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `blocking` | yes | Enables `reqwest/blocking` HTTP client |
//! | `totp` | yes | TOTP code generation (`get_totp_code`) |
//! | `password-gen` | yes | Password generation (`generate_password`) |
//! | `tracing-init` | yes | `env_logger` initializer in the binary |

pub mod cache;
pub mod caching;
pub mod config_keys;
pub mod constants;
pub mod core;
pub mod crypto;
pub mod custom_error;
pub mod dto;
pub mod enums;
mod helpers;
pub mod keeper_globals;
pub mod storage;
mod tests;
pub mod utils;

// --- Flat re-exports for ergonomic top-level imports ---

pub use cache::KSMCache;
pub use core::core::{ClientOptions, ClientOptionsBuilder, SecretsManager};
pub use custom_error::KSMRError;
pub use dto::dtos::{KeeperRecordLink, Record};
pub use enums::{DefaultRecordType, KvStoreType, StandardFieldTypeEnum};
pub use storage::{FileKeyValueStorage, InMemoryKeyValueStorage, KeyValueStorage};

/// Convenient glob import for the most common types.
///
/// ```no_run
/// use keeper_secrets_manager_core::prelude::*;
/// ```
pub mod prelude {
    pub use crate::cache::KSMCache;
    pub use crate::core::core::{ClientOptions, ClientOptionsBuilder, SecretsManager};
    pub use crate::custom_error::KSMRError;
    pub use crate::dto::dtos::{KeeperRecordLink, Record};
    pub use crate::enums::{DefaultRecordType, KvStoreType, StandardFieldTypeEnum};
    pub use crate::storage::{FileKeyValueStorage, InMemoryKeyValueStorage, KeyValueStorage};
}
