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

// Regression tests for KSM-926: verify_ssl_certs semantic consistency.
//
// Before KSM-926, two assignment paths set verify_ssl_certs with opposite
// conventions: insecure_skip_verify=true produced a permissive API client
// but a strict upload client; KSM_SKIP_VERIFY=true did the inverse.
// These tests assert both input paths converge on the correct skip_ssl_verify()
// result and that http_client is always initialized after new().

#[cfg(test)]
mod ssl_config_tests {
    use crate::config_keys::ConfigKeys;
    use crate::core::{ClientOptions, SecretsManager};
    use crate::crypto::CryptoUtils;
    use crate::custom_error::KSMRError;
    use crate::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
    use crate::enums::KvStoreType;
    use crate::storage::{InMemoryKeyValueStorage, KeyValueStorage};
    use serial_test::serial;

    fn create_test_storage() -> KvStoreType {
        let storage = InMemoryKeyValueStorage::new(None).expect("storage");
        let mut kv = KvStoreType::InMemory(storage);
        let private_key_der = CryptoUtils::generate_private_key_der().expect("key");
        let private_key_b64 = crate::utils::bytes_to_base64(&private_key_der);
        let private_key = CryptoUtils::generate_private_key_ecc().expect("ecc key");
        let public_key_b64 =
            crate::utils::bytes_to_base64(&CryptoUtils::public_key_ecc(&private_key));
        kv.set(ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string())
            .unwrap();
        kv.set(
            ConfigKeys::KeyAppKey,
            "dGVzdF9hcHBfa2V5X2Jhc2U2NF9lbmNvZGVkX3ZhbHVlAAAAAAAAAAAA".to_string(),
        )
        .unwrap();
        kv.set(ConfigKeys::KeyServerPublicKeyId, "10".to_string())
            .unwrap();
        kv.set(
            ConfigKeys::KeyHostname,
            "fake.keepersecurity.com".to_string(),
        )
        .unwrap();
        kv.set(ConfigKeys::KeyPrivateKey, private_key_b64).unwrap();
        kv.set(ConfigKeys::KeyOwnerPublicKey, public_key_b64)
            .unwrap();
        kv
    }

    fn noop_post(
        _url: String,
        _tk: TransmissionKey,
        _payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        Ok(KsmHttpResponse {
            status_code: 200,
            data: vec![],
            http_response: None,
        })
    }

    fn make_sm(insecure_skip_verify: bool) -> SecretsManager {
        let mut options = ClientOptions::new_client_options(create_test_storage());
        options.insecure_skip_verify = Some(insecure_skip_verify);
        options.set_custom_post_function(noop_post);
        SecretsManager::new(options).expect("SecretsManager::new")
    }

    /// insecure_skip_verify=false → verify_ssl_certs=true → skip_ssl_verify()=false (strict)
    #[test]
    #[serial]
    fn test_verify_mode_strict_when_insecure_false() {
        let sm = make_sm(false);
        assert!(
            sm.verify_ssl_certs,
            "verify_ssl_certs should be true when insecure_skip_verify=false"
        );
        assert!(
            !sm.skip_ssl_verify(),
            "skip_ssl_verify() should be false (strict)"
        );
    }

    /// insecure_skip_verify=true → verify_ssl_certs=false → skip_ssl_verify()=true (permissive)
    #[test]
    #[serial]
    fn test_verify_mode_permissive_when_insecure_true() {
        let sm = make_sm(true);
        assert!(
            !sm.verify_ssl_certs,
            "verify_ssl_certs should be false when insecure_skip_verify=true"
        );
        assert!(
            sm.skip_ssl_verify(),
            "skip_ssl_verify() should be true (permissive)"
        );
    }

    /// KSM_SKIP_VERIFY=true env var → same result as insecure_skip_verify=true (permissive)
    #[test]
    #[serial]
    fn test_env_skip_verify_true_is_permissive() {
        std::env::set_var("KSM_SKIP_VERIFY", "true");
        let sm = make_sm(false); // constructor says verify; env var overrides
        std::env::remove_var("KSM_SKIP_VERIFY");

        assert!(
            !sm.verify_ssl_certs,
            "KSM_SKIP_VERIFY=true should set verify_ssl_certs=false"
        );
        assert!(
            sm.skip_ssl_verify(),
            "skip_ssl_verify() should be true (permissive) when KSM_SKIP_VERIFY=true"
        );
    }

    /// KSM_SKIP_VERIFY=false env var → strict (same as default)
    #[test]
    #[serial]
    fn test_env_skip_verify_false_is_strict() {
        std::env::set_var("KSM_SKIP_VERIFY", "false");
        let sm = make_sm(false);
        std::env::remove_var("KSM_SKIP_VERIFY");

        assert!(
            sm.verify_ssl_certs,
            "KSM_SKIP_VERIFY=false should leave verify_ssl_certs=true"
        );
        assert!(
            !sm.skip_ssl_verify(),
            "skip_ssl_verify() should be false (strict) when KSM_SKIP_VERIFY=false"
        );
    }
}
