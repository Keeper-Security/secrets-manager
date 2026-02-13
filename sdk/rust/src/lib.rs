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
//! use keeper_secrets_manager_core::{
//!     core::{ClientOptions, SecretsManager},
//!     custom_error::KSMRError,
//!     enums::KvStoreType,
//!     storage::FileKeyValueStorage,
//! };
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
//! ## Storage Options
//!
//! ### File Storage (Persistent)
//!
//! ```no_run
//! use keeper_secrets_manager_core::storage::FileKeyValueStorage;
//! use keeper_secrets_manager_core::enums::KvStoreType;
//! use keeper_secrets_manager_core::custom_error::KSMRError;
//!
//! fn example() -> Result<(), KSMRError> {
//!     let storage = FileKeyValueStorage::new(Some("keeper_config.json".to_string()))?;
//!     let config = KvStoreType::File(storage);
//!     // Config persisted to file with secure permissions (0600 on Unix)
//!     Ok(())
//! }
//! ```
//!
//! ### In-Memory Storage (Ephemeral)
//!
//! ```no_run
//! use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
//! use keeper_secrets_manager_core::enums::KvStoreType;
//! use keeper_secrets_manager_core::custom_error::KSMRError;
//!
//! fn example() -> Result<(), KSMRError> {
//!     let base64_config = std::env::var("KSM_CONFIG")
//!         .expect("KSM_CONFIG required");
//!     let storage = InMemoryKeyValueStorage::new(Some(base64_config))?;
//!     let config = KvStoreType::InMemory(storage);
//!     // Useful for serverless, Docker, CI/CD pipelines
//!     Ok(())
//! }
//! ```
//!
//! ## Examples
//!
//! See the [repository](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust/examples)
//! for comprehensive examples covering all SDK features.

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
