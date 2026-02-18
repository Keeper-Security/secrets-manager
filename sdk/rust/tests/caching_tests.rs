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

//! Caching module tests
//!
//! Note: These tests modify environment variables and filesystem state.
//! Each test uses a unique cache directory to avoid conflicts.
//! If tests fail due to concurrency, run with: `cargo test --test caching_tests -- --test-threads=1`

#[cfg(test)]
mod caching_tests {
    use keeper_secrets_manager_core::caching::{
        cache_exists, clear_cache, get_cache_file_path, get_cached_data, save_cache,
    };
    use serial_test::serial;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    use std::sync::atomic::{AtomicU32, Ordering};
    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Helper: Generate unique cache directory for test isolation
    fn get_test_cache_dir() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let test_id = format!("{}_{}", std::process::id(), counter);
        let temp_dir = env::temp_dir();
        temp_dir.join(format!("ksm_test_cache_{}", test_id))
    }

    /// Helper: Setup test cache environment
    fn setup_test_cache() -> (String, PathBuf) {
        let test_dir = get_test_cache_dir();
        fs::create_dir_all(&test_dir).unwrap();
        let cache_dir_str = test_dir.to_str().unwrap().to_string();
        (cache_dir_str, test_dir)
    }

    /// Helper: Cleanup test cache
    fn cleanup_test_cache(test_dir: PathBuf) {
        if test_dir.exists() {
            fs::remove_dir_all(&test_dir).ok();
        }
    }

    /// Test: Save and retrieve cache data
    #[test]
    #[serial]
    fn test_save_and_get_cache() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        let test_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Save cache
        let save_result = save_cache(&test_data);
        assert!(save_result.is_ok());

        // Retrieve cache
        let cached_data = get_cached_data();
        assert!(cached_data.is_some());
        assert_eq!(cached_data.unwrap(), test_data);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache exists check
    #[test]
    #[serial]
    fn test_cache_exists() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Initially no cache
        assert!(!cache_exists());

        // Save some data
        let test_data = vec![1, 2, 3];
        save_cache(&test_data).unwrap();

        // Now cache should exist
        assert!(cache_exists());

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Clear cache
    #[test]
    #[serial]
    fn test_clear_cache() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Save some data
        let test_data = vec![1, 2, 3, 4, 5];
        save_cache(&test_data).unwrap();
        assert!(cache_exists());

        // Clear cache
        let clear_result = clear_cache();
        assert!(clear_result.is_ok());
        assert!(!cache_exists());

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Clear cache when no cache exists
    #[test]
    #[serial]
    fn test_clear_cache_when_not_exists() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // No cache exists
        assert!(!cache_exists());

        // Clear should still succeed
        let clear_result = clear_cache();
        assert!(clear_result.is_ok());

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Get cached data when no cache exists
    #[test]
    #[serial]
    fn test_get_cached_data_not_exists() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        let cached_data = get_cached_data();
        assert!(cached_data.is_none());

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Save empty data to cache
    #[test]
    #[serial]
    fn test_save_empty_cache() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        let empty_data = vec![];
        let save_result = save_cache(&empty_data);
        assert!(save_result.is_ok());

        let cached_data = get_cached_data();
        assert!(cached_data.is_some());
        assert_eq!(cached_data.unwrap().len(), 0);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Save large data to cache
    #[test]
    #[serial]
    fn test_save_large_cache() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // 1MB of data
        let large_data = vec![0u8; 1024 * 1024];
        let save_result = save_cache(&large_data);
        assert!(save_result.is_ok());

        let cached_data = get_cached_data();
        assert!(cached_data.is_some());
        assert_eq!(cached_data.unwrap().len(), 1024 * 1024);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache overwrite
    #[test]
    #[serial]
    fn test_cache_overwrite() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Save initial data
        let initial_data = vec![1, 2, 3];
        save_cache(&initial_data).unwrap();

        // Verify initial data
        let cached = get_cached_data().unwrap();
        assert_eq!(cached, initial_data);

        // Overwrite with new data
        let new_data = vec![4, 5, 6, 7, 8];
        save_cache(&new_data).unwrap();

        // Verify new data
        let cached = get_cached_data().unwrap();
        assert_eq!(cached, new_data);
        assert_ne!(cached, initial_data);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache file path respects KSM_CACHE_DIR environment variable
    #[test]
    #[serial]
    fn test_cache_file_path_custom_dir() {
        let custom_dir = "/custom/cache/dir";
        env::set_var("KSM_CACHE_DIR", custom_dir);

        let cache_path = get_cache_file_path();
        assert!(cache_path.to_str().unwrap().contains(custom_dir));
        assert!(cache_path.to_str().unwrap().contains("ksm_cache.bin"));

        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache file path uses default directory when env var not set
    #[test]
    #[serial]
    fn test_cache_file_path_default_dir() {
        env::remove_var("KSM_CACHE_DIR");

        let cache_path = get_cache_file_path();
        assert!(cache_path.to_str().unwrap().ends_with("ksm_cache.bin"));

        // Should use current directory (".")
        let expected_path = PathBuf::from(".").join("ksm_cache.bin");
        assert_eq!(cache_path, expected_path);
    }

    /// Test: Binary data roundtrip through cache
    #[test]
    #[serial]
    fn test_cache_binary_data_roundtrip() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        let binary_data = vec![
            0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        ];

        save_cache(&binary_data).unwrap();
        let cached = get_cached_data().unwrap();

        assert_eq!(cached, binary_data);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache data integrity with transmission key prefix
    #[test]
    #[serial]
    fn test_cache_transmission_key_format() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Simulate cache format: 32-byte transmission key + encrypted response
        let transmission_key = vec![0u8; 32]; // 32-byte key
        let encrypted_response = vec![1, 2, 3, 4, 5, 6, 7, 8]; // Response data

        let mut cache_data = transmission_key.clone();
        cache_data.extend_from_slice(&encrypted_response);

        // Save combined data
        save_cache(&cache_data).unwrap();

        // Retrieve and verify
        let cached = get_cached_data().unwrap();
        assert_eq!(cached.len(), 32 + 8); // Key + response
        assert_eq!(&cached[0..32], &transmission_key[..]);
        assert_eq!(&cached[32..], &encrypted_response[..]);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Multiple save operations (stress test)
    #[test]
    #[serial]
    fn test_cache_multiple_saves() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        for i in 0..10 {
            let data = vec![i as u8; 100];
            let save_result = save_cache(&data);
            assert!(save_result.is_ok());

            let cached = get_cached_data().unwrap();
            assert_eq!(cached, data);
        }

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache data with minimum size (transmission key only)
    #[test]
    #[serial]
    fn test_cache_minimum_size() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Minimum valid cache: 32-byte transmission key
        let minimum_data = vec![0u8; 32];
        save_cache(&minimum_data).unwrap();

        let cached = get_cached_data().unwrap();
        assert_eq!(cached.len(), 32);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache data with realistic size
    #[test]
    #[serial]
    fn test_cache_realistic_size() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        // Realistic cache size: 32-byte key + ~37KB response (from manual testing)
        let transmission_key = vec![0u8; 32];
        let encrypted_response = vec![1u8; 37_000];

        let mut cache_data = transmission_key;
        cache_data.extend_from_slice(&encrypted_response);

        save_cache(&cache_data).unwrap();
        let cached = get_cached_data().unwrap();

        assert_eq!(cached.len(), 32 + 37_000);

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache survives multiple clear operations
    #[test]
    #[serial]
    fn test_cache_multiple_clears() {
        let (cache_dir, test_dir) = setup_test_cache();
        env::set_var("KSM_CACHE_DIR", &cache_dir);

        let test_data = vec![1, 2, 3, 4, 5];
        save_cache(&test_data).unwrap();
        assert!(cache_exists());

        // Clear multiple times
        for _ in 0..5 {
            let clear_result = clear_cache();
            assert!(clear_result.is_ok());
            assert!(!cache_exists());
        }

        cleanup_test_cache(test_dir);
        env::remove_var("KSM_CACHE_DIR");
    }

    /// Test: Cache file path format
    #[test]
    #[serial]
    fn test_cache_file_path_format() {
        env::set_var("KSM_CACHE_DIR", "/tmp/test");

        let path = get_cache_file_path();
        let path_str = path.to_str().unwrap();

        assert!(path_str.contains("ksm_cache.bin"));
        assert!(path_str.contains("/tmp/test"));

        env::remove_var("KSM_CACHE_DIR");
    }
}
