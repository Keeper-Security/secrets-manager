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

#[cfg(test)]
mod proxy_tests {
    use keeper_secrets_manager_core::cache::KSMCache;
    use keeper_secrets_manager_core::core::ClientOptions;
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::InMemoryKeyValueStorage;
    use log::Level;

    #[test]
    fn test_proxy_url_configuration() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some("http://proxy.example.com:8080".to_string()),
            KSMCache::None,
        );

        assert_eq!(
            options.proxy_url,
            Some("http://proxy.example.com:8080".to_string())
        );
    }

    #[test]
    fn test_proxy_url_none_by_default() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new_client_options(config);

        assert_eq!(options.proxy_url, None);
    }

    #[test]
    fn test_proxy_url_with_authentication() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let proxy_url_with_auth = "http://user:password@proxy.example.com:8080".to_string();

        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some(proxy_url_with_auth.clone()),
            KSMCache::None,
        );

        assert_eq!(options.proxy_url, Some(proxy_url_with_auth));
    }

    #[test]
    fn test_proxy_url_with_token_constructor() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options =
            ClientOptions::new_client_options_with_token("test_token".to_string(), config);

        // Should default to None
        assert_eq!(options.proxy_url, None);
    }

    #[test]
    fn test_proxy_url_empty_string() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        // Some users might pass empty string instead of None
        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some("".to_string()),
            KSMCache::None,
        );

        // We allow empty strings (reqwest will handle validation)
        assert_eq!(options.proxy_url, Some("".to_string()));
    }

    #[test]
    fn test_proxy_url_https_scheme() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some("https://secure-proxy.example.com:8443".to_string()),
            KSMCache::None,
        );

        assert_eq!(
            options.proxy_url,
            Some("https://secure-proxy.example.com:8443".to_string())
        );
    }

    #[test]
    fn test_proxy_url_with_ipv4_address() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some("http://192.168.1.100:3128".to_string()),
            KSMCache::None,
        );

        assert_eq!(
            options.proxy_url,
            Some("http://192.168.1.100:3128".to_string())
        );
    }

    #[test]
    fn test_proxy_url_with_localhost() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let config = KvStoreType::InMemory(storage);

        let options = ClientOptions::new(
            "test_token".to_string(),
            config,
            Level::Error,
            None,
            None,
            Some("http://localhost:8888".to_string()),
            KSMCache::None,
        );

        assert_eq!(options.proxy_url, Some("http://localhost:8888".to_string()));
    }
}
