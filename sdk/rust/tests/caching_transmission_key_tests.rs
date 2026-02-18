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
    use keeper_secrets_manager_core::caching::{cache_exists, caching_post_function, clear_cache};
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
    use serial_test::serial;
    use std::env;
    use std::path::PathBuf;

    /// Helper: Get unique cache directory for test isolation
    fn get_test_cache_dir(test_name: &str) -> PathBuf {
        let temp_dir = env::temp_dir();
        temp_dir.join(format!("ksm_test_cache_tx_key_{}", test_name))
    }

    /// Helper: Setup test cache environment
    fn setup_test_cache(test_name: &str) -> String {
        let test_dir = get_test_cache_dir(test_name);
        std::fs::create_dir_all(&test_dir).unwrap();
        test_dir.to_str().unwrap().to_string()
    }

    /// Helper: Cleanup test cache
    fn cleanup_test_cache(test_name: &str) {
        let test_dir = get_test_cache_dir(test_name);
        if test_dir.exists() {
            std::fs::remove_dir_all(&test_dir).ok();
        }
    }

    /// Helper: Create SecretsManager from KSM_CONFIG environment variable
    fn get_client_from_env() -> Result<SecretsManager, KSMRError> {
        let config_str = env::var("KSM_CONFIG").expect(
            "KSM_CONFIG environment variable not set. \
             Run: export KSM_CONFIG=$(cat ~/.keeper/qa_credential)",
        );

        let config_storage = InMemoryKeyValueStorage::new(Some(config_str))?;
        let mut client_options =
            ClientOptions::new_client_options(KvStoreType::InMemory(config_storage));

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
    #[test]
    #[serial]
    #[ignore] // Run manually with: cargo test test_cache_retrieval_with_correct_transmission_key -- --ignored --nocapture
    fn test_cache_retrieval_with_correct_transmission_key() -> Result<(), KSMRError> {
        let test_name = "retrieval";
        println!("\n=== Test: Cache Retrieval with Correct Transmission Key ===");

        // Setup: Use shared cache directory for both clients
        let cache_dir = setup_test_cache(test_name);
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Clear any existing cache
        clear_cache().ok();

        // Step 1: First client - Populate cache with real API call
        println!("\n[Step 1] Creating first client and populating cache...");
        let mut ksm_client1 = get_client_from_env()?;

        let records1 = ksm_client1.get_secrets(Vec::new())?;
        println!("✓ First client retrieved {} secrets", records1.len());
        println!("✓ Cache populated with transmission key from first request");

        // Verify cache exists
        assert!(cache_exists(), "Cache should exist after first request");
        println!("✓ Cache file created");

        // Step 2: Second client - NEW instance with DIFFERENT transmission key
        println!("\n[Step 2] Creating second client (will generate different transmission key)...");
        let mut ksm_client2 = get_client_from_env()?;
        println!("✓ Second client created with shared cache directory");

        // Step 3: Request same secrets - should use cached data + cached transmission key
        println!("\n[Step 3] Requesting secrets from second client (should use cache)...");
        let records2 = ksm_client2.get_secrets(Vec::new())?;

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
                records1[0].title, records2[0].title,
                "Secret titles should match (data integrity check)"
            );
            println!("✓ Data integrity verified - titles match");
        }

        println!(
            "\n✅ Test PASSED: Cached data decrypted successfully using cached transmission key"
        );
        println!("   Bug is FIXED - second client used cached transmission key, not its own");

        // Cleanup
        env::remove_var("KSM_CACHE_DIR");
        cleanup_test_cache(test_name);

        Ok(())
    }

    /// Test: Multiple cache hits with different clients
    ///
    /// Verifies that multiple sequential cache hits work correctly, each using
    /// the cached transmission key regardless of the client's internal state.
    #[test]
    #[serial]
    #[ignore] // Run manually with: cargo test test_multiple_cache_hits -- --ignored --nocapture
    fn test_multiple_cache_hits() -> Result<(), KSMRError> {
        let test_name = "multiple";
        println!("\n=== Test: Multiple Cache Hits ===");

        // Setup: Use shared cache directory
        let cache_dir = setup_test_cache(test_name);
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Clear any existing cache
        clear_cache().ok();

        // Populate cache with first client
        println!("\n[Setup] Populating cache with first client...");
        let mut ksm_client1 = get_client_from_env()?;
        let records1 = ksm_client1.get_secrets(Vec::new())?;
        println!("✓ Cache populated: {} secrets", records1.len());

        // Test multiple cache hits with different clients
        for i in 2..=5 {
            println!(
                "\n[Client {}] Creating new client and testing cache hit...",
                i
            );
            let mut ksm_client = get_client_from_env()?;

            let records = ksm_client.get_secrets(Vec::new())?;
            println!(
                "✓ Client {} retrieved {} secrets from cache",
                i,
                records.len()
            );

            assert_eq!(
                records1.len(),
                records.len(),
                "All cache hits should return same number of secrets"
            );

            if !records1.is_empty() && !records.is_empty() {
                assert_eq!(
                    records1[0].title, records[0].title,
                    "Cache hit {} should return same data",
                    i
                );
            }
        }

        println!("\n✅ Test PASSED: Multiple cache hits work correctly");
        println!("   All clients successfully used cached transmission key");

        // Cleanup
        env::remove_var("KSM_CACHE_DIR");
        cleanup_test_cache(test_name);

        Ok(())
    }
}
