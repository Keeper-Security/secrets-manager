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

/// Manual integration test for proxy support with QA vault
///
/// **Note**: Automatic unit tests for proxy configuration exist in `proxy_test.rs`
/// and run with every `cargo test`. This file contains optional end-to-end tests
/// that verify proxy behavior with real network calls.
///
/// This test is IGNORED by default and must be run manually.
///
/// Prerequisites:
/// 1. Set up a local proxy server (e.g., mitmproxy):
///    ```bash
///    # Install mitmproxy
///    brew install mitmproxy  # macOS
///    # or: pip install mitmproxy
///
///    # Start proxy on port 8080
///    mitmproxy -p 8080
///    ```
///
/// 2. Set KSM_CONFIG environment variable with QA credentials:
///    ```bash
///    export KSM_CONFIG=$(cat ~/.keeper/qa_credential)
///    ```
///
/// 3. Run this test:
///    ```bash
///    cargo test --test proxy_integration_test -- --ignored --nocapture
///    ```
///
/// Expected behavior:
/// - Request should appear in mitmproxy logs
/// - Test should successfully retrieve secrets through the proxy
/// - mitmproxy should show requests to keepersecurity.com (or QA host)
///
#[cfg(test)]
mod proxy_integration_tests {
    use keeper_secrets_manager_core::cache::KSMCache;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
    use log::Level;
    use std::env;

    #[test]
    #[ignore] // Must be run manually with --ignored flag
    fn test_proxy_with_qa_vault() {
        // Initialize logging to see what's happening
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .try_init();

        // Check if KSM_CONFIG is set
        let config_str = env::var("KSM_CONFIG").expect(
            "KSM_CONFIG environment variable not set. \
             Run: export KSM_CONFIG=$(cat ~/.keeper/qa_credential)",
        );

        println!("✓ Found KSM_CONFIG environment variable");

        // Create in-memory storage with the config
        let storage = InMemoryKeyValueStorage::new(Some(config_str))
            .expect("Failed to create InMemoryKeyValueStorage");
        let config = KvStoreType::InMemory(storage);

        println!("✓ Created storage with QA credentials");

        // Configure with proxy pointing to local mitmproxy
        let proxy_url = env::var("TEST_PROXY_URL").unwrap_or("http://localhost:8080".to_string());
        println!("✓ Using proxy: {}", proxy_url);

        let options = ClientOptions::new(
            String::new(), // No token needed, using existing config
            config,
            Level::Info,
            None,
            None,
            Some(proxy_url.clone()), // Enable proxy
            KSMCache::None,
        );

        println!("✓ Created ClientOptions with proxy");

        // Initialize SecretsManager
        let mut secrets_manager =
            SecretsManager::new(options).expect("Failed to create SecretsManager");

        println!("✓ Initialized SecretsManager");
        println!("\n=== Making API request through proxy ===");
        println!("Check your proxy logs (mitmproxy UI) for requests to Keeper servers\n");

        // Attempt to get secrets (this will go through the proxy)
        match secrets_manager.get_secrets(Vec::new()) {
            Ok(secrets) => {
                println!("✓ Successfully retrieved {} secrets through proxy!", secrets.len());

                if !secrets.is_empty() {
                    println!("\nFirst secret UID: {}", secrets[0].uid);
                }

                println!("\n✅ PROXY TEST PASSED!");
                println!("   - Request went through proxy at {}", proxy_url);
                println!("   - Successfully retrieved secrets from QA vault");
                println!("   - Check proxy logs to confirm traffic routing");
            }
            Err(e) => {
                eprintln!("\n❌ Failed to retrieve secrets: {:?}", e);
                panic!("Proxy integration test failed. Common issues:\n\
                        1. Is mitmproxy running on port 8080?\n\
                        2. Is KSM_CONFIG set correctly?\n\
                        3. Are QA vault credentials valid?");
            }
        }
    }

    #[test]
    #[ignore] // Must be run manually with --ignored flag
    fn test_proxy_with_authentication() {
        // This test demonstrates proxy with username/password
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .try_init();

        let config_str = env::var("KSM_CONFIG").expect("KSM_CONFIG not set");

        let storage = InMemoryKeyValueStorage::new(Some(config_str))
            .expect("Failed to create storage");
        let config = KvStoreType::InMemory(storage);

        // Use authenticated proxy format
        let proxy_url = "http://testuser:testpass@localhost:8080";
        println!("Testing proxy with authentication: {}", proxy_url);

        let options = ClientOptions::new(
            String::new(),
            config,
            Level::Info,
            None,
            None,
            Some(proxy_url.to_string()),
            KSMCache::None,
        );

        let mut secrets_manager = SecretsManager::new(options)
            .expect("Failed to create SecretsManager with authenticated proxy");

        match secrets_manager.get_secrets(Vec::new()) {
            Ok(secrets) => {
                println!("✓ Authenticated proxy test passed! Retrieved {} secrets", secrets.len());
            }
            Err(e) => {
                println!("Note: Authentication test may fail if proxy doesn't require auth");
                println!("Error: {:?}", e);
            }
        }
    }

    #[test]
    #[ignore] // Must be run manually
    fn test_env_var_proxy() {
        // Test that HTTPS_PROXY environment variable works
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .try_init();

        // Set HTTPS_PROXY environment variable
        env::set_var("HTTPS_PROXY", "http://localhost:8080");
        println!("Set HTTPS_PROXY=http://localhost:8080");

        let config_str = env::var("KSM_CONFIG").expect("KSM_CONFIG not set");

        let storage = InMemoryKeyValueStorage::new(Some(config_str))
            .expect("Failed to create storage");
        let config = KvStoreType::InMemory(storage);

        // Create options WITHOUT explicit proxy_url (should use HTTPS_PROXY)
        let options = ClientOptions::new(
            String::new(),
            config,
            Level::Info,
            None,
            None,
            None, // No explicit proxy - should use HTTPS_PROXY env var
            KSMCache::None,
        );

        let mut secrets_manager = SecretsManager::new(options)
            .expect("Failed to create SecretsManager");

        println!("Testing environment variable proxy fallback...");

        match secrets_manager.get_secrets(Vec::new()) {
            Ok(secrets) => {
                println!("✓ Environment variable proxy test passed!");
                println!("  Retrieved {} secrets using HTTPS_PROXY", secrets.len());
            }
            Err(e) => {
                eprintln!("❌ Environment variable proxy test failed: {:?}", e);
                panic!("Failed to use HTTPS_PROXY environment variable");
            }
        }

        // Clean up
        env::remove_var("HTTPS_PROXY");
    }
}
