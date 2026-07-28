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

//! End-to-end tests for throttle retry with exponential backoff.
//!
//! Each test drives a real `update_secret` round-trip through `post_query` with a mocked
//! post function (returning HTTP 403 `{"error":"throttled"}` responses) and a recording
//! sleeper injected via `set_custom_sleep_function`, so no real time is spent sleeping.

#[cfg(test)]
mod throttle_tests {
    use keeper_secrets_manager_core::config_keys::ConfigKeys;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::crypto::CryptoUtils;
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::{
        EncryptedPayload, KsmHttpResponse, Record, TransmissionKey,
    };
    use keeper_secrets_manager_core::enums::KvStoreType;
    use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Minimal "already bound" in-memory config sufficient for `post_query` to build a
    /// transmission key, sign, and (on 200) decrypt the response.
    fn create_mock_storage() -> KvStoreType {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();
        let mut kv = KvStoreType::InMemory(storage);

        let private_key = CryptoUtils::generate_private_key_ecc().unwrap();
        let private_key_der = CryptoUtils::generate_private_key_der().unwrap();
        let private_key_base64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&private_key_der);
        let public_key_bytes = CryptoUtils::public_key_ecc(&private_key);
        let public_key_base64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&public_key_bytes);

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
        kv.set(ConfigKeys::KeyPrivateKey, private_key_base64)
            .unwrap();
        kv.set(ConfigKeys::KeyOwnerPublicKey, public_key_base64)
            .unwrap();
        kv
    }

    fn make_record() -> Record {
        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Throttle Test"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));

        Record {
            uid: "throttle-test-uid".to_string(),
            title: "Throttle Test".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: None,
            revision: Some(1),
            is_editable: true,
            folder_uid: "folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![0; 32],
            folder_key_bytes: None,
            links: vec![],
        }
    }

    /// A 200 response carrying an encrypted `{"status":"success"}` body (decryptable with the
    /// transmission key the SDK generated for that call) — makes `update_secret` succeed.
    fn encrypted_success(tk: &TransmissionKey) -> Result<KsmHttpResponse, KSMRError> {
        let data = CryptoUtils::encrypt_aes_gcm(
            &json!({"status":"success"}).to_string().into_bytes(),
            &tk.key,
            None,
        )?;
        Ok(KsmHttpResponse {
            status_code: 200,
            data,
            http_response: None,
        })
    }

    /// An HTTP 403 throttle response, optionally carrying a `retry_after` (seconds).
    fn throttle_403(retry_after: Option<i64>) -> KsmHttpResponse {
        let body = match retry_after {
            Some(ra) => json!({"error":"throttled","message":"throttled","retry_after":ra}),
            None => json!({"error":"throttled","message":"throttled"}),
        };
        KsmHttpResponse {
            status_code: 403,
            data: vec![],
            http_response: Some(body.to_string()),
        }
    }

    /// Build a `SecretsManager` with the given mock post function and a recording sleeper.
    fn sm_with<F>(mock: F) -> (SecretsManager, Arc<Mutex<Vec<Duration>>>)
    where
        F: Fn(String, TransmissionKey, EncryptedPayload) -> Result<KsmHttpResponse, KSMRError>
            + Send
            + Sync
            + 'static,
    {
        let mut opts = ClientOptions::new_client_options(create_mock_storage());
        opts.set_custom_post_function(mock);
        let mut sm = SecretsManager::new(opts).expect("SecretsManager::new");

        let sleeps = Arc::new(Mutex::new(Vec::<Duration>::new()));
        let recorder = sleeps.clone();
        sm.set_custom_sleep_function(move |d| recorder.lock().unwrap().push(d));
        (sm, sleeps)
    }

    #[test]
    fn throttle_then_success() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) = sm_with(move |_url, tk, _p| {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(throttle_403(None))
            } else {
                encrypted_success(&tk)
            }
        });

        let res = sm.update_secret(make_record());
        assert!(res.is_ok(), "should succeed after one throttle: {:?}", res);
        assert_eq!(sleeps.lock().unwrap().len(), 1, "exactly one backoff sleep");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn throttle_exhaustion_returns_throttled_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) = sm_with(move |_url, _tk, _p| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(throttle_403(None))
        });

        let res = sm.update_secret(make_record());
        assert!(
            matches!(res, Err(KSMRError::Throttled(_))),
            "exhaustion must surface KSMRError::Throttled, got {:?}",
            res
        );
        assert_eq!(
            sleeps.lock().unwrap().len(),
            5,
            "five backoff sleeps before giving up"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            6,
            "5 retries plus the final throttled response"
        );
    }

    #[test]
    fn retry_after_is_honored() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) = sm_with(move |_url, tk, _p| {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(throttle_403(Some(3)))
            } else {
                encrypted_success(&tk)
            }
        });

        assert!(sm.update_secret(make_record()).is_ok());
        let recorded = sleeps.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        // retry_after = 3s with +/-25% jitter -> [2.25, 3.75]; well below the exponential 11s base.
        let secs = recorded[0].as_secs_f64();
        assert!(
            (2.25..=3.75).contains(&secs),
            "retry_after should drive the delay, got {secs}s"
        );
    }

    #[test]
    fn non_throttle_403_not_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) = sm_with(move |_url, _tk, _p| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(KsmHttpResponse {
                status_code: 403,
                data: vec![],
                http_response: Some(json!({"error":"access_denied","message":"nope"}).to_string()),
            })
        });

        let res = sm.update_secret(make_record());
        assert!(res.is_err());
        assert!(
            !matches!(res, Err(KSMRError::Throttled(_))),
            "a non-throttle 403 must not become a throttle error"
        );
        assert_eq!(sleeps.lock().unwrap().len(), 0, "no retry for non-throttle");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_403_throttle_body_not_retried() {
        // A 502 that happens to carry a {"error":"throttled"} body must NOT be retried (403 gate).
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) = sm_with(move |_url, _tk, _p| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(KsmHttpResponse {
                status_code: 502,
                data: vec![],
                http_response: Some(json!({"error":"throttled"}).to_string()),
            })
        });

        let res = sm.update_secret(make_record());
        assert!(res.is_err());
        assert_eq!(
            sleeps.lock().unwrap().len(),
            0,
            "a 502 with a throttled body must not be retried"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn throttle_then_key_rotation_compose() {
        // 403 throttle -> 401 key rotation (key_id 9) -> 200 success.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (mut sm, sleeps) =
            sm_with(move |_url, tk, _p| match c.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(throttle_403(None)),
                1 => Ok(KsmHttpResponse {
                    status_code: 401,
                    data: vec![],
                    http_response: Some(
                        json!({"key_id":9,"error":"key","message":"invalid key id"}).to_string(),
                    ),
                }),
                _ => encrypted_success(&tk),
            });

        let res = sm.update_secret(make_record());
        assert!(
            res.is_ok(),
            "throttle and key-rotation retries should compose: {:?}",
            res
        );
        assert_eq!(
            sleeps.lock().unwrap().len(),
            1,
            "only the throttle sleeps; key rotation retries immediately"
        );
        assert_eq!(
            sm.config
                .get(ConfigKeys::KeyServerPublicKeyId)
                .unwrap()
                .as_deref(),
            Some("9"),
            "key rotation must still persist the rotated key id"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
