// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2024-2026 Keeper Security Inc.
// Contact: sm@keepersecurity.com
//

#[cfg(test)]
mod empty_config_tests {
    use keeper_secrets_manager_core::cache::KSMCache;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
    use log::Level;

    /// Test: Empty JSON config ({}) without token returns Err, not panic (KSM-783)
    ///
    /// This is the primary regression test. Before the fix, initializing with
    /// an empty JSON config would panic at load_secret_key() due to
    /// None.unwrap() when no KeyClientKey exists in config.
    #[test]
    fn test_empty_json_config_returns_error_not_panic() {
        let storage = InMemoryKeyValueStorage::new(Some("{}".to_string()))
            .expect("InMemoryKeyValueStorage should accept empty JSON");
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            String::new(),
            config,
            Level::Error,
            None,
            None,
            KSMCache::None,
        );

        let result = SecretsManager::new(options);

        assert!(
            result.is_err(),
            "Empty config without token should return Err, not Ok"
        );

        if let Err(err) = &result {
            let err_msg = format!("{}", err);
            assert!(
                err_msg.contains("secret key") || err_msg.contains("One time password"),
                "Error should mention missing secret key or token, got: {}",
                err_msg
            );
        }
    }

    /// Test: Empty string config returns Err, not panic (KSM-783)
    #[test]
    fn test_empty_string_config_returns_error_not_panic() {
        let storage_result = InMemoryKeyValueStorage::new(Some(String::new()));

        // Empty string may fail at storage creation or at SecretsManager::new
        match storage_result {
            Ok(storage) => {
                let config = KvStoreType::InMemory(storage);
                let options = ClientOptions::new(
                    String::new(),
                    config,
                    Level::Error,
                    None,
                    None,
                    KSMCache::None,
                );

                let result = SecretsManager::new(options);
                assert!(
                    result.is_err(),
                    "Empty string config without token should return Err, not Ok"
                );
            }
            Err(_) => {
                // Also acceptable: storage creation itself returns Err for empty string
            }
        }
    }

    /// Test: None config (InMemoryKeyValueStorage::new(None)) returns Err, not panic (KSM-783)
    #[test]
    fn test_none_config_returns_error_not_panic() {
        let storage =
            InMemoryKeyValueStorage::new(None).expect("InMemoryKeyValueStorage should accept None");
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            String::new(),
            config,
            Level::Error,
            None,
            None,
            KSMCache::None,
        );

        let result = SecretsManager::new(options);

        assert!(
            result.is_err(),
            "None config without token should return Err, not Ok"
        );
    }
}
