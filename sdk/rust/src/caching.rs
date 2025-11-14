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

//! Caching post function for disaster recovery
//!
//! This module provides a drop-in replacement for the default HTTP post function
//! that automatically caches successful API responses. On network failure, it falls
//! back to cached data to enable offline operation.
//!
//! # Usage
//!
//! ```rust,no_run
//! use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
//! use keeper_secrets_manager_core::storage::FileKeyValueStorage;
//! use keeper_secrets_manager_core::caching;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = FileKeyValueStorage::new_config_storage("config.json".to_string())?;
//! let mut client_options = ClientOptions::new_client_options(config);
//!
//! // Use caching post function for disaster recovery
//! client_options.set_custom_post_function(caching::caching_post_function);
//!
//! let mut secrets_manager = SecretsManager::new(client_options)?;
//!
//! // First call saves to cache
//! let secrets = secrets_manager.get_secrets(Vec::new())?;
//!
//! // If network fails, falls back to cached data
//! // let secrets = secrets_manager.get_secrets(Vec::new())?; // Uses cache on failure
//! # Ok(())
//! # }
//! ```

use crate::custom_error::KSMRError;
use crate::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
use log::{debug, warn};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Default cache file name
const DEFAULT_CACHE_FILE: &str = "ksm_cache.bin";

/// Get the cache file path from environment or default
pub fn get_cache_file_path() -> PathBuf {
    let cache_dir = env::var("KSM_CACHE_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&cache_dir).join(DEFAULT_CACHE_FILE)
}

/// Save cache data to disk
///
/// # Arguments
/// * `data` - The data to cache (transmission key + encrypted response)
///
/// # Errors
/// Silently fails on write errors (doesn't break the application)
pub fn save_cache(data: &[u8]) -> Result<(), KSMRError> {
    let cache_path = get_cache_file_path();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cache_path)
        .map_err(|e| KSMRError::CacheSaveError(format!("Failed to open cache file: {}", e)))?;

    file.write_all(data)
        .map_err(|e| KSMRError::CacheSaveError(format!("Failed to write cache: {}", e)))?;

    debug!("Cache saved to {:?}", cache_path);
    Ok(())
}

/// Load cache data from disk
///
/// # Returns
/// * `Option<Vec<u8>>` - Cached data if available, None otherwise
pub fn get_cached_data() -> Option<Vec<u8>> {
    let cache_path = get_cache_file_path();

    if !cache_path.exists() {
        return None;
    }

    let mut file = File::open(&cache_path).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;

    debug!("Cache loaded from {:?}", cache_path);
    Some(data)
}

/// Clear the cache file
pub fn clear_cache() -> Result<(), KSMRError> {
    let cache_path = get_cache_file_path();

    if cache_path.exists() {
        std::fs::remove_file(&cache_path)
            .map_err(|e| KSMRError::CacheRetrieveError(format!("Failed to delete cache: {}", e)))?;
    }

    Ok(())
}

/// Check if cache file exists
pub fn cache_exists() -> bool {
    get_cache_file_path().exists()
}

/// Caching post function for disaster recovery.
///
/// This function wraps the normal HTTP POST operation and:
/// 1. On success: Saves the response to cache (transmission key + encrypted data)
/// 2. On failure: Falls back to cached data if available
///
/// This matches the pattern used in Python, JavaScript, Java, Ruby, and .NET SDKs.
///
/// # Arguments
/// * `url` - The API endpoint URL
/// * `transmission_key` - The transmission key for encryption
/// * `encrypted_payload` - The encrypted payload with signature
///
/// # Returns
/// * `Result<KsmHttpResponse, KSMRError>` - Response object (from network or cache)
///
/// # Example
/// ```rust,no_run
/// use keeper_secrets_manager_core::core::ClientOptions;
/// use keeper_secrets_manager_core::caching::caching_post_function;
///
/// # fn main() {
/// let mut options = ClientOptions::new_client_options(keeper_secrets_manager_core::enums::KvStoreType::None);
/// options.set_custom_post_function(caching_post_function);
/// # }
/// ```
pub fn caching_post_function(
    url: String,
    transmission_key: TransmissionKey,
    encrypted_payload: EncryptedPayload,
) -> Result<KsmHttpResponse, KSMRError> {
    // Try network request first
    match make_http_request(url, transmission_key.clone(), encrypted_payload) {
        Ok(response) if response.status_code == 200 => {
            // On success, save to cache (transmission key + encrypted response body)
            let mut cache_data = transmission_key.key.clone();
            cache_data.extend_from_slice(&response.data);

            // Silently fail on cache write errors
            if let Err(e) = save_cache(&cache_data) {
                warn!("Failed to save cache: {}", e);
            }

            Ok(response)
        }
        Ok(response) => {
            // Non-200 response - don't cache, return error response
            Ok(response)
        }
        Err(network_error) => {
            // Network failed - try to load from cache
            warn!(
                "Network request failed: {}, attempting to use cached data",
                network_error
            );

            if let Some(cached_data) = get_cached_data() {
                if cached_data.len() > 32 {
                    // Extract cached transmission key and response data
                    // First 32 bytes are the transmission key, rest is encrypted response
                    let cached_transmission_key = cached_data[0..32].to_vec();
                    let cached_response_data = cached_data[32..].to_vec();

                    debug!("Using cached data ({} bytes)", cached_response_data.len());

                    // Create a new transmission key with cached key
                    let mut updated_transmission_key = transmission_key.clone();
                    updated_transmission_key.key = cached_transmission_key;

                    // Return cached response as if it came from network
                    return Ok(KsmHttpResponse {
                        status_code: 200,
                        data: cached_response_data,
                        http_response: Some("Cached response".to_string()),
                    });
                }
            }

            // No cache available - re-raise the original error
            Err(network_error)
        }
    }
}

/// Make HTTP request - extracted to be testable
///
/// This duplicates some logic from SecretsManager#process_post_request
/// because we need a standalone function for the caching pattern.
fn make_http_request(
    url: String,
    transmission_key: TransmissionKey,
    encrypted_payload: EncryptedPayload,
) -> Result<KsmHttpResponse, KSMRError> {
    let client = Client::new();

    // Build headers
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_str("Content-Type").unwrap(),
        HeaderValue::from_str("application/octet-stream").unwrap(),
    );
    headers.insert(
        HeaderName::from_str("PublicKeyId").unwrap(),
        HeaderValue::from_str(&transmission_key.public_key_id).unwrap(),
    );
    headers.insert(
        HeaderName::from_str("TransmissionKey").unwrap(),
        HeaderValue::from_str(&crate::utils::bytes_to_base64(
            &transmission_key.encrypted_key,
        ))
        .unwrap(),
    );
    headers.insert(
        HeaderName::from_str("Authorization").unwrap(),
        HeaderValue::from_str(&format!(
            "Signature {}",
            crate::utils::bytes_to_base64(&encrypted_payload.signature.to_bytes())
        ))
        .unwrap(),
    );

    // Make POST request
    let response = client
        .post(&url)
        .headers(headers)
        .body(encrypted_payload.encrypted_payload.clone())
        .send()
        .map_err(|e| KSMRError::HTTPError(format!("HTTP request failed: {}", e)))?;

    let status_code = response.status().as_u16();
    let response_body = response
        .bytes()
        .map_err(|e| KSMRError::HTTPError(format!("Failed to read response: {}", e)))?
        .to_vec();

    Ok(KsmHttpResponse {
        status_code,
        data: response_body,
        http_response: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_file_path() {
        let path = get_cache_file_path();
        assert!(path.to_str().unwrap().contains("ksm_cache.bin"));
    }

    #[test]
    fn test_cache_operations() {
        // Clear any existing cache
        let _ = clear_cache();

        // Initially no cache
        assert!(!cache_exists());
        assert!(get_cached_data().is_none());

        // Save some test data
        let test_data = b"test cache data";
        save_cache(test_data).ok();

        // Cache should now exist
        assert!(cache_exists());

        // Load cache
        let loaded = get_cached_data();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), test_data);

        // Clear cache
        clear_cache().ok();
        assert!(!cache_exists());
    }
}
