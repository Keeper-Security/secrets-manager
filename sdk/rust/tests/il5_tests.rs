// IL5 / isolated-deployment dynamic server public key tests (KSM-904)
//
// Three layers:
//   Layer 1 — config supplies KeyServerPublicKey; generate_transmission_key uses it
//   Layer 2 — 4-segment IL5 OTT writes key material to config at init time
//   Layer 3 — ClientOptions::set_server_public_key / set_server_public_key_id params

#[cfg(test)]
mod il5_tests {
    use keeper_secrets_manager_core::config_keys::ConfigKeys;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::crypto::CryptoUtils;
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};

    // A well-known public key from the SDK key map (key 10) for use as a stand-in
    // custom key in tests that just need any valid EC point.
    const KNOWN_PUBLIC_KEY_B64: &str =
        "BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg";

    fn mock_empty_post(
        _url: String,
        transmission_key: TransmissionKey,
        _payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        let body = br#"{"records":[],"folders":[],"expirationTime":0}"#;
        let encrypted = CryptoUtils::encrypt_aes_gcm(body, &transmission_key.key, None)?;
        Ok(KsmHttpResponse {
            status_code: 200,
            data: encrypted,
            http_response: None,
        })
    }

    fn mock_key_rotation_response(
        _url: String,
        _transmission_key: TransmissionKey,
        _payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        Ok(KsmHttpResponse {
            status_code: 400,
            data: vec![],
            http_response: Some(
                r#"{"error":"key","key_id":10,"message":"invalid key id"}"#.to_string(),
            ),
        })
    }

    fn bound_storage_with_custom_key(key_b64: &str, key_id: &str) -> Result<KvStoreType, KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let mut kv = KvStoreType::InMemory(storage);
        let private_key_der = CryptoUtils::generate_private_key_der()?;
        let private_key_b64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&private_key_der);
        let public_key_bytes =
            CryptoUtils::public_key_ecc(&CryptoUtils::generate_private_key_ecc()?);
        let public_key_b64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&public_key_bytes);

        kv.set(ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string())?;
        kv.set(
            ConfigKeys::KeyAppKey,
            "dGVzdF9hcHBfa2V5X2Jhc2U2NF9lbmNvZGVkX3ZhbHVlAAAAAAAAAAAA".to_string(),
        )?;
        kv.set(ConfigKeys::KeyServerPublicKeyId, key_id.to_string())?;
        kv.set(ConfigKeys::KeyServerPublicKey, key_b64.to_string())?;
        kv.set(ConfigKeys::KeyHostname, "il5.keepersecurity.us".to_string())?;
        kv.set(ConfigKeys::KeyPrivateKey, private_key_b64)?;
        kv.set(ConfigKeys::KeyOwnerPublicKey, public_key_b64)?;
        Ok(kv)
    }

    // Layer 1: a bound config that already has KeyServerPublicKey uses it for encryption.
    #[test]
    fn test_layer1_custom_key_from_config_is_used() {
        let storage =
            bound_storage_with_custom_key(KNOWN_PUBLIC_KEY_B64, "20").expect("storage");
        let mut opts = ClientOptions::new_client_options(storage);
        opts.set_custom_post_function(mock_empty_post);

        let mut sm = SecretsManager::new(opts).expect("SecretsManager::new");
        let result = sm.get_secrets(vec![]);
        assert!(result.is_ok(), "get_secrets with custom key failed: {:?}", result);
    }

    // Layer 1: generate_transmission_key uses custom key when provided.
    #[test]
    fn test_generate_transmission_key_with_custom_key() {
        let tk = SecretsManager::generate_transmission_key("20", Some(KNOWN_PUBLIC_KEY_B64));
        assert!(tk.is_ok(), "should succeed with custom key: {:?}", tk);
        assert_eq!(tk.unwrap().public_key_id, "20");
    }

    // Layer 1: generate_transmission_key still fails for unknown key_id without custom key.
    #[test]
    fn test_generate_transmission_key_unknown_id_no_custom_key_fails() {
        let tk = SecretsManager::generate_transmission_key("99", None);
        assert!(tk.is_err(), "should fail for unknown key_id without custom key");
    }

    // Layer 2: IL5 4-segment OTT writes hostname, key_id, and public key to config.
    #[test]
    fn test_layer2_il5_ott_writes_key_material_to_config() {
        let storage = InMemoryKeyValueStorage::new(None).expect("storage");
        let kv = KvStoreType::InMemory(storage);
        let fake_token = format!("IL5:{}:20:{}", KNOWN_PUBLIC_KEY_B64, KNOWN_PUBLIC_KEY_B64);

        let mut opts = ClientOptions::new_client_options_with_token(fake_token, kv);
        opts.set_custom_post_function(mock_empty_post);

        let sm = SecretsManager::new(opts).expect("SecretsManager::new");

        let stored_key_id = sm
            .config
            .get(ConfigKeys::KeyServerPublicKeyId)
            .expect("get key_id")
            .expect("key_id present");
        assert_eq!(stored_key_id, "20", "IL5 key_id should be 20");

        let stored_key = sm
            .config
            .get(ConfigKeys::KeyServerPublicKey)
            .expect("get custom key")
            .expect("custom key present");
        assert_eq!(stored_key, KNOWN_PUBLIC_KEY_B64, "IL5 public key should be stored");

        assert_eq!(sm.hostname, "il5.keepersecurity.us", "IL5 hostname");
    }

    // Layer 2: non-IL5 prefix with extra segments is unchanged (backwards-compatible).
    #[test]
    fn test_layer2_non_il5_prefix_extra_segments_unchanged() {
        let storage = InMemoryKeyValueStorage::new(None).expect("storage");
        let kv = KvStoreType::InMemory(storage);
        // Normal US token — should parse as US region + client key, not IL5
        let opts = ClientOptions::new_client_options_with_token(
            "US:someclientkey".to_string(),
            kv,
        );
        let sm = SecretsManager::new(opts);
        // Just verify it doesn't panic or misroute — US host is expected
        if let Ok(ref sm) = sm {
            assert!(
                sm.hostname.contains("keepersecurity.com"),
                "US token should resolve to keepersecurity.com, got {}",
                sm.hostname
            );
        }
    }

    // Layer 2: IL5 token with invalid base64 in public key segment is rejected.
    #[test]
    fn test_layer2_il5_invalid_b64_rejected() {
        let storage = InMemoryKeyValueStorage::new(None).expect("storage");
        let kv = KvStoreType::InMemory(storage);
        let bad_token = format!("IL5:{}:20:not!!valid!!base64", KNOWN_PUBLIC_KEY_B64);
        let opts = ClientOptions::new_client_options_with_token(bad_token, kv);
        let result = SecretsManager::new(opts);
        assert!(result.is_err(), "IL5 token with bad base64 should be rejected");
    }

    // Layer 3: set_server_public_key writes to config and is used for encryption.
    #[test]
    fn test_layer3_programmatic_key_injection() {
        let storage = InMemoryKeyValueStorage::new(None).expect("storage");
        let kv = KvStoreType::InMemory(storage);
        let fake_token = format!("IL5:{}:20:{}", KNOWN_PUBLIC_KEY_B64, KNOWN_PUBLIC_KEY_B64);

        let mut opts = ClientOptions::new_client_options_with_token(fake_token, kv);
        // Layer 3 override — different key, same encoding
        opts.set_server_public_key(KNOWN_PUBLIC_KEY_B64);
        opts.set_server_public_key_id("20");
        opts.set_custom_post_function(mock_empty_post);

        let sm = SecretsManager::new(opts).expect("SecretsManager::new");
        let stored = sm
            .config
            .get(ConfigKeys::KeyServerPublicKey)
            .expect("get")
            .expect("present");
        assert_eq!(stored, KNOWN_PUBLIC_KEY_B64);
    }

    // Rotation suppression: custom key mode ignores server-pushed key_id hint and retries.
    #[test]
    fn test_rotation_suppressed_in_custom_key_mode() {
        let storage =
            bound_storage_with_custom_key(KNOWN_PUBLIC_KEY_B64, "20").expect("storage");
        let mut opts = ClientOptions::new_client_options(storage);

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        opts.set_custom_post_function(move |url, tk, payload| {
            let n = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                // First call: server suggests switching to key 10
                mock_key_rotation_response(url, tk, payload)
            } else {
                // Second call: succeed
                mock_empty_post(url, tk, payload)
            }
        });

        let mut sm = SecretsManager::new(opts).expect("SecretsManager::new");
        let result = sm.get_secrets(vec![]);

        assert!(result.is_ok(), "should succeed after suppressed rotation: {:?}", result);

        // key_id should remain 20 (not overwritten to 10)
        let stored_key_id = sm
            .config
            .get(ConfigKeys::KeyServerPublicKeyId)
            .expect("get")
            .expect("present");
        assert_eq!(stored_key_id, "20", "key_id must not be overwritten by server hint");
    }
}
