// KSM-973: Tests for the SecretsManager bind lifecycle.
//
// SecretsManager::new() makes NO network calls. The one-time token is redeemed
// on the first get_secrets() call. Until that call completes the config storage
// is "unbound" — it is missing appKey and appOwnerPublicKey and cannot be used
// to construct a new SecretsManager on a later run.

#[cfg(test)]
mod bind_lifecycle_tests {
    use keeper_secrets_manager_core::config_keys::ConfigKeys;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::crypto::CryptoUtils;
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};

    // A fake one-time token whose base64 part (after "US:") has a length that is
    // a multiple of 4 — required for the SDK's internal base64 decoder.
    // Value is meaningless; it will never be sent to a server in these tests.
    const MOCK_TOKEN: &str = "US:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // ─── helpers ────────────────────────────────────────────────────────────

    /// Build a fully-bound storage (appKey + appOwnerPublicKey present) that
    /// SecretsManager::new() accepts without a token — simulates a persisted
    /// config loaded from a keychain / secrets-manager on a subsequent run.
    fn bound_storage() -> Result<KvStoreType, KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let mut kv = KvStoreType::InMemory(storage);

        let priv_der = CryptoUtils::generate_private_key_der()?;
        let priv_b64 = keeper_secrets_manager_core::utils::bytes_to_base64(&priv_der);
        let priv_key = CryptoUtils::generate_private_key_ecc()?;
        let pub_b64 = keeper_secrets_manager_core::utils::bytes_to_base64(
            &CryptoUtils::public_key_ecc(&priv_key),
        );

        kv.set(ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string())?;
        kv.set(
            ConfigKeys::KeyAppKey,
            "dGVzdF9hcHBfa2V5X2Jhc2U2NF9lbmNvZGVkX3ZhbHVlAAAAAAAAAAAA".to_string(),
        )?;
        kv.set(ConfigKeys::KeyOwnerPublicKey, pub_b64)?;
        kv.set(ConfigKeys::KeyPrivateKey, priv_b64)?;
        kv.set(ConfigKeys::KeyServerPublicKeyId, "10".to_string())?;
        kv.set(
            ConfigKeys::KeyHostname,
            "fake.keepersecurity.com".to_string(),
        )?;

        Ok(kv)
    }

    /// Mock HTTP handler that always returns an error — used in tests that must
    /// not reach the network.
    fn mock_no_network(
        _url: String,
        _tk: TransmissionKey,
        _ep: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        Err(KSMRError::HTTPError(
            "KSM-973 test: unexpected network call".to_string(),
        ))
    }

    // ─── tests ──────────────────────────────────────────────────────────────

    /// new() must NOT touch the network. We inject a mock that panics if called
    /// — if the test passes, new() never attempted a network request.
    #[test]
    fn test_new_does_not_perform_network_call() -> Result<(), KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let kv = KvStoreType::InMemory(storage);

        let mut options = ClientOptions::new_client_options_with_token(MOCK_TOKEN.to_string(), kv);
        options.set_custom_post_function(|_url, _tk, _ep| {
            panic!(
                "KSM-973: SecretsManager::new() must not make a network call. \
                 The token must only be redeemed on the first get_secrets() call."
            );
        });

        // If this panics, new() hit the network — the test will fail.
        let _sm = SecretsManager::new(options)?;
        Ok(())
    }

    /// Immediately after new() (before any get_secrets call) the storage must
    /// NOT contain appKey or appOwnerPublicKey — i.e. it is unbound.
    /// Persisting an unbound config produces a non-reloadable credential store.
    #[test]
    fn test_storage_is_unbound_after_new() -> Result<(), KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let kv = KvStoreType::InMemory(storage);

        let mut options = ClientOptions::new_client_options_with_token(MOCK_TOKEN.to_string(), kv);
        options.set_custom_post_function(mock_no_network);

        let sm = SecretsManager::new(options)?;

        let has_app_key = match &sm.config {
            KvStoreType::InMemory(s) => s.contains(ConfigKeys::KeyAppKey).unwrap_or(false),
            KvStoreType::File(s) => s.contains(ConfigKeys::KeyAppKey).unwrap_or(false),
            _ => false,
        };
        assert!(
            !has_app_key,
            "KSM-973: appKey must NOT be present before the first get_secrets() call. \
             Persisting config at this point produces an unbound (non-reloadable) config."
        );

        let has_owner_key = match &sm.config {
            KvStoreType::InMemory(s) => s.contains(ConfigKeys::KeyOwnerPublicKey).unwrap_or(false),
            KvStoreType::File(s) => s.contains(ConfigKeys::KeyOwnerPublicKey).unwrap_or(false),
            _ => false,
        };
        assert!(
            !has_owner_key,
            "KSM-973: appOwnerPublicKey must NOT be present before bind completes."
        );

        Ok(())
    }

    /// A fully-bound storage (appKey + appOwnerPublicKey present) must allow
    /// constructing a SecretsManager without a token. This is the "reload from
    /// persisted config" path that integrators use on every run after the first.
    #[test]
    fn test_bound_config_can_be_reloaded_without_token() -> Result<(), KSMRError> {
        let bound_kv = bound_storage()?;
        let mut options = ClientOptions::new_client_options(bound_kv);
        options.set_custom_post_function(mock_no_network);

        SecretsManager::new(options)
            .expect("KSM-973: a bound config must be reloadable without a token");

        Ok(())
    }

    /// The pre-bind keys written locally by new() (clientId, privateKey,
    /// hostname) must be present in storage after construction — these do not
    /// require a network call.
    #[test]
    fn test_pre_bind_keys_present_after_new() -> Result<(), KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let kv = KvStoreType::InMemory(storage);

        let mut options = ClientOptions::new_client_options_with_token(MOCK_TOKEN.to_string(), kv);
        options.set_custom_post_function(mock_no_network);

        let sm = SecretsManager::new(options)?;

        for key in &[
            ConfigKeys::KeyClientId,
            ConfigKeys::KeyPrivateKey,
            ConfigKeys::KeyHostname,
        ] {
            let present = match &sm.config {
                KvStoreType::InMemory(s) => s.contains(key.clone()).unwrap_or(false),
                KvStoreType::File(s) => s.contains(key.clone()).unwrap_or(false),
                _ => false,
            };
            assert!(
                present,
                "KSM-973: {:?} must be present in storage after new() — \
                 it is written locally without any network call.",
                key
            );
        }

        Ok(())
    }
}
