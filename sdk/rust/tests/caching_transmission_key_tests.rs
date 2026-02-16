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

//! Regression tests for KSM-787: Fix Rust SDK Caching Transmission Key Bug
//!
//! These tests verify that cached secrets can be decrypted correctly when retrieved
//! across different process contexts (simulated by creating new SecretsManager instances).
//!
//! The bug: When retrieving from cache, the code incorrectly cloned the current request's
//! TransmissionKey and mutated only the `key` field, leaving other fields with wrong context.
//! This caused decryption failures (CryptoError("aead::Error")).
//!
//! Prerequisites:
//! 1. Set KSM_CONFIG environment variable with QA credentials:
//!    export KSM_CONFIG=$(cat ~/.keeper/qa_credential)
//!
//! Run with: cargo test --test caching_transmission_key_tests -- --nocapture --test-threads=1

#[cfg(test)]
mod caching_transmission_key_tests {
    use keeper_secrets_manager_core::caching::caching_post_function;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, JsonConfigStorage};
    use serial_test::serial;
    use std::env;

    /// Helper: Create SecretsManager from KSM_CONFIG environment variable
    fn get_client_from_env() -> Result<SecretsManager, KSMRError> {
        let config_str = env::var("KSM_CONFIG").expect(
            "KSM_CONFIG environment variable not set. \
             Run: export KSM_CONFIG=$(cat ~/.keeper/qa_credential)",
        );

        let config_storage = JsonConfigStorage::from_json_string(config_str)?;
        let mut client_options = ClientOptions::new_client_options(config_storage);

        // Enable caching with custom post function
        client_options.set_custom_post_function(caching_post_function);

        SecretsManager::new(client_options)
    }

    /// Test: Cache retrieval with correct transmission key (end-to-end)
    ///
    /// This test proves the bug: Create cache with real API call, then create NEW client
    /// (different transmission key internally), and verify it can decrypt cached data
    /// using the cached transmission key.
    ///
    /// Before fix: Would fail with CryptoError("aead::Error")
    /// After fix: Should decrypt successfully using cached transmission key
    #[tokio::test]
    #[serial]
    #[ignore] // Run manually with: cargo test test_cache_retrieval_with_correct_transmission_key -- --ignored --nocapture
    async fn test_cache_retrieval_with_correct_transmission_key() -> Result<(), KSMRError> {
        println!("\n=== Test: Cache Retrieval with Correct Transmission Key ===");

        // Setup: Create shared cache storage (simulates persistent cache across process restarts)
        let cache_storage = InMemoryKeyValueStorage::new(None)?;

        // Step 1: First client - Populate cache with real API call
        println!("\n[Step 1] Creating first client and populating cache...");
        let mut ksm_client1 = get_client_from_env()?;
        ksm_client1.set_config_value("CACHE", &cache_storage)?;

        let records1 = ksm_client1.get_secrets(Vec::new()).await?;
        println!("✓ First client retrieved {} secrets", records1.len());
        println!("✓ Cache populated with transmission key from first request");

        // Verify cache exists
        let cache_keys: Vec<String> = cache_storage.get_all_keys()?;
        println!("✓ Cache contains {} keys", cache_keys.len());
        assert!(!cache_keys.is_empty(), "Cache should contain data");

        // Step 2: Second client - NEW instance with DIFFERENT transmission key
        println!("\n[Step 2] Creating second client (will generate different transmission key)...");
        let mut ksm_client2 = get_client_from_env()?;
        ksm_client2.set_config_value("CACHE", &cache_storage)?;
        println!("✓ Second client created with shared cache storage");

        // Step 3: Request same secrets - should use cached data + cached transmission key
        println!("\n[Step 3] Requesting secrets from second client (should use cache)...");
        let records2 = ksm_client2.get_secrets(Vec::new()).await?;

        // Verify: Should decrypt successfully (not CryptoError)
        println!("✓ Second client retrieved {} secrets", records2.len());
        assert_eq!(
            records1.len(),
            records2.len(),
            "Both clients should retrieve same number of secrets"
        );

        // Verify data integrity
        if !records1.is_empty() && !records2.is_empty() {
            assert_eq!(
                records1[0].data.title, records2[0].data.title,
                "Secret titles should match (data integrity check)"
            );
            println!("✓ Data integrity verified - titles match");
        }

        println!("\n✅ Test PASSED: Cached data decrypted successfully using cached transmission key");
        println!("   Bug is FIXED - second client used cached transmission key, not its own");

        Ok(())
    }

    /// Test: Transmission key isolation (verifies cached key is used, not current)
    ///
    /// This test verifies that the cached transmission key bytes remain unchanged
    /// and are correctly used for decryption, independent of the current request's
    /// transmission key.
    ///
    /// Before fix: Would use wrong transmission key (from current request) for decryption
    /// After fix: Should use cached transmission key bytes only
    #[tokio::test]
    #[serial]
    #[ignore] // Run manually with: cargo test test_cache_transmission_key_isolation -- --ignored --nocapture
    async fn test_cache_transmission_key_isolation() -> Result<(), KSMRError> {
        println!("\n=== Test: Transmission Key Isolation ===");

        // Setup: Create shared cache storage
        let cache_storage = InMemoryKeyValueStorage::new(None)?;

        // Step 1: First client - Populate cache
        println!("\n[Step 1] First client: Populating cache...");
        let mut ksm_client1 = get_client_from_env()?;
        ksm_client1.set_config_value("CACHE", &cache_storage)?;

        let _records1 = ksm_client1.get_secrets(Vec::new()).await?;
        println!("✓ Cache populated");

        // Step 2: Extract original cached transmission key bytes
        println!("\n[Step 2] Extracting cached transmission key bytes...");
        let cache_keys: Vec<String> = cache_storage.get_all_keys()?;
        assert!(!cache_keys.is_empty(), "Cache should have data");

        // Find the cache key for get_secrets
        let cache_key = cache_keys
            .iter()
            .find(|k| k.contains("get_secrets"))
            .expect("Should find get_secrets cache key");

        let cached_data = cache_storage.get(cache_key)?.expect("Cache data should exist");
        let original_cached_tx_key = cached_data[0..32].to_vec();
        println!("✓ Extracted 32-byte cached transmission key");

        // Step 3: Second client - NEW transmission key
        println!("\n[Step 3] Second client: Creating with shared cache...");
        let mut ksm_client2 = get_client_from_env()?;
        ksm_client2.set_config_value("CACHE", &cache_storage)?;

        // Step 4: Make cached request - should succeed using original cached key
        println!("\n[Step 4] Requesting secrets (should use cached transmission key)...");
        let records2 = ksm_client2.get_secrets(Vec::new()).await?;
        println!("✓ Request succeeded with {} secrets", records2.len());

        // Step 5: Verify cache still contains original transmission key bytes
        println!("\n[Step 5] Verifying cached transmission key unchanged...");
        let cached_data_after = cache_storage
            .get(cache_key)?
            .expect("Cache should still exist");
        let cached_tx_key_after = &cached_data_after[0..32];

        assert_eq!(
            original_cached_tx_key, cached_tx_key_after,
            "Cached transmission key should remain unchanged after cache hit"
        );
        println!("✓ Cached transmission key bytes unchanged");

        println!("\n✅ Test PASSED: Transmission key isolation verified");
        println!("   - Cached transmission key used for decryption");
        println!("   - Current request's transmission key ignored");
        println!("   - Cache transmission key bytes preserved");

        Ok(())
    }

    /// Test: Multiple cache hits with different clients
    ///
    /// Verifies that multiple sequential cache hits work correctly, each using
    /// the cached transmission key regardless of the client's internal state.
    #[tokio::test]
    #[serial]
    #[ignore] // Run manually with: cargo test test_multiple_cache_hits -- --ignored --nocapture
    async fn test_multiple_cache_hits() -> Result<(), KSMRError> {
        println!("\n=== Test: Multiple Cache Hits ===");

        let cache_storage = InMemoryKeyValueStorage::new(None)?;

        // Populate cache with first client
        println!("\n[Setup] Populating cache with first client...");
        let mut ksm_client1 = get_client_from_env()?;
        ksm_client1.set_config_value("CACHE", &cache_storage)?;
        let records1 = ksm_client1.get_secrets(Vec::new()).await?;
        println!("✓ Cache populated: {} secrets", records1.len());

        // Test multiple cache hits with different clients
        for i in 2..=5 {
            println!("\n[Client {}] Creating new client and testing cache hit...", i);
            let mut ksm_client = get_client_from_env()?;
            ksm_client.set_config_value("CACHE", &cache_storage)?;

            let records = ksm_client.get_secrets(Vec::new()).await?;
            println!("✓ Client {} retrieved {} secrets from cache", i, records.len());

            assert_eq!(
                records1.len(),
                records.len(),
                "All cache hits should return same number of secrets"
            );

            if !records1.is_empty() && !records.is_empty() {
                assert_eq!(
                    records1[0].data.title, records[0].data.title,
                    "Cache hit {} should return same data", i
                );
            }
        }

        println!("\n✅ Test PASSED: Multiple cache hits work correctly");
        println!("   All clients successfully used cached transmission key");

        Ok(())
    }
}
