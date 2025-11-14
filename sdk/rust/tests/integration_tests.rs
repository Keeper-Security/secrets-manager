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
mod integration_tests {
    use keeper_secrets_manager_core::config_keys::ConfigKeys;
    use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
    use keeper_secrets_manager_core::crypto::CryptoUtils;
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::payload::UpdateTransactionType;
    use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
    use keeper_secrets_manager_core::enums::{KvStoreType, StandardFieldTypeEnum};
    use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Helper function to create a mock storage with initialized config
    fn create_mock_storage() -> Result<KvStoreType, KSMRError> {
        let storage = InMemoryKeyValueStorage::new(None)?;
        let mut kv_store = KvStoreType::InMemory(storage);

        // Generate a real private key using the SDK's crypto utilities
        let private_key = CryptoUtils::generate_private_key_ecc()?;
        let private_key_der = CryptoUtils::generate_private_key_der()?; // Generate new DER-encoded private key
        let private_key_base64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&private_key_der);

        // Generate corresponding public key
        let public_key_bytes = CryptoUtils::public_key_ecc(&private_key); // Returns Vec<u8>
        let public_key_base64 =
            keeper_secrets_manager_core::utils::bytes_to_base64(&public_key_bytes);

        // Set up minimal config for testing
        kv_store.set(ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string())?;
        kv_store.set(
            ConfigKeys::KeyAppKey,
            "dGVzdF9hcHBfa2V5X2Jhc2U2NF9lbmNvZGVkX3ZhbHVlAAAAAAAAAAAA".to_string(), // base64 encoded 32-byte key
        )?;
        kv_store.set(ConfigKeys::KeyServerPublicKeyId, "10".to_string())?;
        kv_store.set(
            ConfigKeys::KeyHostname,
            "fake.keepersecurity.com".to_string(),
        )?;
        kv_store.set(ConfigKeys::KeyPrivateKey, private_key_base64)?;
        kv_store.set(ConfigKeys::KeyOwnerPublicKey, public_key_base64)?;

        Ok(kv_store)
    }

    /// Mock response generator for successful update operations
    fn mock_update_success_response(
        _url: String,
        transmission_key: TransmissionKey,
        _encrypted_payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        // Simulate successful update response (empty encrypted response)
        let response_data = json!({
            "status": "success"
        });
        let response_bytes = response_data.to_string().into_bytes();
        let encrypted_response =
            CryptoUtils::encrypt_aes_gcm(&response_bytes, &transmission_key.key, None)?;

        Ok(KsmHttpResponse {
            status_code: 200,
            data: encrypted_response,
            http_response: None,
        })
    }

    /// Mock response generator for successful transaction completion
    fn mock_transaction_success_response(
        _url: String,
        transmission_key: TransmissionKey,
        _encrypted_payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        // Simulate successful transaction completion (empty response)
        let encrypted_response = CryptoUtils::encrypt_aes_gcm(&[], &transmission_key.key, None)?;

        Ok(KsmHttpResponse {
            status_code: 200,
            data: encrypted_response,
            http_response: None,
        })
    }

    /// Mock response generator that simulates errors
    fn mock_error_response(
        _url: String,
        transmission_key: TransmissionKey,
        _encrypted_payload: EncryptedPayload,
    ) -> Result<KsmHttpResponse, KSMRError> {
        let error_data = json!({
            "error": "access_denied",
            "message": "Invalid record UID"
        });
        let error_bytes = error_data.to_string().into_bytes();
        let error_string = String::from_utf8(error_bytes.clone()).unwrap();
        let encrypted_error =
            CryptoUtils::encrypt_aes_gcm(&error_bytes, &transmission_key.key, None)?;

        Ok(KsmHttpResponse {
            status_code: 403,
            data: encrypted_error,
            http_response: Some(error_string),
        })
    }

    #[test]
    fn test_update_secret_integration_success() {
        // Integration test for update_secret with mocked HTTP
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_update_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Create a test record to update
        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Test Record"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert(
            "fields".to_string(),
            json!([
                {
                    "type": "password",
                    "value": ["OldPassword123"]
                }
            ]),
        );

        let mut record = keeper_secrets_manager_core::dto::Record {
            uid: "test-uid-123".to_string(),
            title: "Test Record".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: Some("OldPassword123".to_string()),
            revision: Some(1),
            is_editable: true,
            folder_uid: "folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ], // 32-byte key
            folder_key_bytes: None,
            links: vec![],
        };

        // Modify the password
        record
            .set_standard_field_value_mut(
                StandardFieldTypeEnum::PASSWORD.get_type(),
                Value::String("NewPassword456!".to_string()),
            )
            .expect("Failed to set password");

        // Update the record - this should succeed with our mock
        let result = secrets_manager.update_secret(record);

        assert!(
            result.is_ok(),
            "update_secret should succeed with mock: {:?}",
            result
        );
    }

    #[test]
    fn test_update_secret_with_transaction_type() {
        // Integration test for update_secret_with_transaction
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_update_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Create a test record
        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Test Record"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert(
            "fields".to_string(),
            json!([{"type": "password", "value": ["OldPassword"]}]),
        );

        let mut record = keeper_secrets_manager_core::dto::Record {
            uid: "test-uid-456".to_string(),
            title: "Test Record".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: Some("OldPassword".to_string()),
            revision: Some(2),
            is_editable: true,
            folder_uid: "folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![0; 32],
            folder_key_bytes: None,
            links: vec![],
        };

        // Modify password
        record
            .set_standard_field_value_mut("password", Value::String("NewRotatedPass!".to_string()))
            .expect("Failed to set password");

        // Update with rotation transaction type
        let result =
            secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::Rotation);

        assert!(
            result.is_ok(),
            "update_secret_with_transaction should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_complete_transaction_commit() {
        // Integration test for complete_transaction (commit)
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_transaction_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Complete a transaction (commit)
        let result = secrets_manager.complete_transaction("test-record-uid".to_string(), false);

        assert!(
            result.is_ok(),
            "complete_transaction (commit) should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_complete_transaction_rollback() {
        // Integration test for complete_transaction (rollback)
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_transaction_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Complete a transaction (rollback)
        let result = secrets_manager.complete_transaction("test-record-uid".to_string(), true);

        assert!(
            result.is_ok(),
            "complete_transaction (rollback) should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_update_secret_integration_error_handling() {
        // Integration test for update_secret error handling
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_error_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Create a test record
        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Test Record"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));

        let record = keeper_secrets_manager_core::dto::Record {
            uid: "invalid-uid".to_string(),
            title: "Test Record".to_string(),
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
        };

        // Update should fail with 403 error
        let result = secrets_manager.update_secret(record);

        assert!(
            result.is_err(),
            "update_secret should fail with error response"
        );
    }

    #[test]
    fn test_password_rotation_workflow() {
        // End-to-end test for password rotation workflow
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);

        // Use a counter to track which endpoint is being called
        thread_local! {
            static CALL_COUNT: RefCell<usize> = RefCell::new(0);
        }

        // Custom post function that handles both update and transaction endpoints
        fn rotation_workflow_mock(
            _url: String,
            transmission_key: TransmissionKey,
            _encrypted_payload: EncryptedPayload,
        ) -> Result<KsmHttpResponse, KSMRError> {
            thread_local! {
                static CALL_NUMBER: AtomicUsize = AtomicUsize::new(0);
            }

            let call_num = CALL_NUMBER.with(|c| c.fetch_add(1, Ordering::SeqCst));

            // First call: update_secret (rotation)
            // Second call: finalize_secret_update
            let response_data = if call_num == 0 {
                // Update response
                json!({"status": "pending"})
            } else {
                // Complete transaction response
                json!({"status": "success"})
            };

            let response_bytes = response_data.to_string().into_bytes();
            let encrypted_response =
                CryptoUtils::encrypt_aes_gcm(&response_bytes, &transmission_key.key, None)?;

            Ok(KsmHttpResponse {
                status_code: 200,
                data: encrypted_response,
                http_response: None,
            })
        }

        client_options.set_custom_post_function(rotation_workflow_mock);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Create a test record
        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Password Rotation Test"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert(
            "fields".to_string(),
            json!([{"type": "password", "value": ["OldPassword123"]}]),
        );

        let mut record = keeper_secrets_manager_core::dto::Record {
            uid: "rotation-test-uid".to_string(),
            title: "Password Rotation Test".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: Some("OldPassword123".to_string()),
            revision: Some(5),
            is_editable: true,
            folder_uid: "folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![0; 32],
            folder_key_bytes: None,
            links: vec![],
        };

        let record_uid = record.uid.clone();

        // Step 1: Update password with rotation transaction
        record
            .set_standard_field_value_mut(
                "password",
                Value::String("NewRotatedPassword!".to_string()),
            )
            .expect("Failed to set password");

        let update_result =
            secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::Rotation);

        assert!(
            update_result.is_ok(),
            "Rotation update should succeed: {:?}",
            update_result
        );

        // Step 2: Finalize the transaction
        let finalize_result = secrets_manager.complete_transaction(record_uid, false);

        assert!(
            finalize_result.is_ok(),
            "Transaction finalization should succeed: {:?}",
            finalize_result
        );
    }

    #[test]
    fn test_password_rotation_with_rollback() {
        // Test password rotation with rollback scenario
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_transaction_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Simulate rolling back a transaction (testing failed, revert to old password)
        let result = secrets_manager.complete_transaction("test-rollback-uid".to_string(), true);

        assert!(
            result.is_ok(),
            "Transaction rollback should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_update_with_general_transaction() {
        // Test update with General transaction type
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);
        client_options.set_custom_post_function(mock_update_success_response);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("General Update Test"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));

        let record = keeper_secrets_manager_core::dto::Record {
            uid: "general-update-uid".to_string(),
            title: "General Update Test".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: None,
            revision: Some(3),
            is_editable: true,
            folder_uid: "folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![0; 32],
            folder_key_bytes: None,
            links: vec![],
        };

        // Update with General transaction type
        let result =
            secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::General);

        assert!(
            result.is_ok(),
            "General transaction update should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_update_secret_validates_encryption() {
        // Test that update_secret properly encrypts the record data
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);

        // Custom validator that checks if payload is encrypted
        fn validate_encryption_mock(
            _url: String,
            transmission_key: TransmissionKey,
            encrypted_payload: EncryptedPayload,
        ) -> Result<KsmHttpResponse, KSMRError> {
            // Verify encrypted payload is not empty
            assert!(
                !encrypted_payload.encrypted_payload.is_empty(),
                "Encrypted payload should not be empty"
            );

            // Note: Signature is an ecdsa::Signature type and is always present
            // (the type system guarantees this)

            // Return success response
            let encrypted_response =
                CryptoUtils::encrypt_aes_gcm(&[], &transmission_key.key, None)?;
            Ok(KsmHttpResponse {
                status_code: 200,
                data: encrypted_response,
                http_response: None,
            })
        }

        client_options.set_custom_post_function(validate_encryption_mock);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("Encryption Test"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));

        let record = keeper_secrets_manager_core::dto::Record {
            uid: "encryption-test-uid".to_string(),
            title: "Encryption Test".to_string(),
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
        };

        // Update should trigger validation in our mock
        let result = secrets_manager.update_secret(record);

        assert!(
            result.is_ok(),
            "Update with encryption validation should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_multiple_sequential_updates() {
        // Test multiple updates to the same record
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);

        // Counter for tracking multiple calls
        thread_local! {
            static UPDATE_COUNT: AtomicUsize = AtomicUsize::new(0);
        }

        fn multi_update_mock(
            _url: String,
            transmission_key: TransmissionKey,
            _encrypted_payload: EncryptedPayload,
        ) -> Result<KsmHttpResponse, KSMRError> {
            let count = UPDATE_COUNT.with(|c| c.fetch_add(1, Ordering::SeqCst));

            // Each update succeeds
            let response_data = json!({
                "status": "success",
                "update_number": count
            });
            let response_bytes = response_data.to_string().into_bytes();
            let encrypted_response =
                CryptoUtils::encrypt_aes_gcm(&response_bytes, &transmission_key.key, None)?;

            Ok(KsmHttpResponse {
                status_code: 200,
                data: encrypted_response,
                http_response: None,
            })
        }

        client_options.set_custom_post_function(multi_update_mock);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        // Perform multiple updates
        for i in 1..=3 {
            let mut record_dict = std::collections::HashMap::new();
            record_dict.insert("title".to_string(), json!(format!("Update {}", i)));
            record_dict.insert("type".to_string(), json!("login"));
            record_dict.insert("fields".to_string(), json!([]));

            let record = keeper_secrets_manager_core::dto::Record {
                uid: "multi-update-uid".to_string(),
                title: format!("Update {}", i),
                record_type: "login".to_string(),
                files: vec![],
                raw_json: serde_json::to_string(&record_dict).unwrap(),
                record_dict,
                password: None,
                revision: Some(i),
                is_editable: true,
                folder_uid: "folder-uid".to_string(),
                inner_folder_uid: None,
                record_key_bytes: vec![0; 32],
                folder_key_bytes: None,
                links: vec![],
            };

            let result = secrets_manager.update_secret(record);
            assert!(result.is_ok(), "Update {} should succeed: {:?}", i, result);
        }

        // Verify 3 updates were performed
        let final_count = UPDATE_COUNT.with(|c| c.load(Ordering::SeqCst));
        assert_eq!(final_count, 3, "Should have made 3 update calls");
    }

    #[test]
    fn test_custom_post_function_receives_correct_url() {
        // Test that custom post function receives the correct URL for each operation
        let storage = create_mock_storage().expect("Failed to create storage");
        let mut client_options = ClientOptions::new_client_options(storage);

        // Capture the URL to verify it's correct
        thread_local! {
            static CAPTURED_URL: RefCell<String> = RefCell::new(String::new());
        }

        fn url_capture_mock(
            url: String,
            transmission_key: TransmissionKey,
            _encrypted_payload: EncryptedPayload,
        ) -> Result<KsmHttpResponse, KSMRError> {
            // Store the URL for assertion
            CAPTURED_URL.with(|captured| {
                *captured.borrow_mut() = url.clone();
            });

            // Return success response
            let encrypted_response =
                CryptoUtils::encrypt_aes_gcm(&[], &transmission_key.key, None)?;
            Ok(KsmHttpResponse {
                status_code: 200,
                data: encrypted_response,
                http_response: None,
            })
        }

        client_options.set_custom_post_function(url_capture_mock);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        let mut record_dict = std::collections::HashMap::new();
        record_dict.insert("title".to_string(), json!("URL Test"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));

        let record = keeper_secrets_manager_core::dto::Record {
            uid: "url-test-uid".to_string(),
            title: "URL Test".to_string(),
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
        };

        secrets_manager.update_secret(record).ok();

        // Verify the URL contains update_secret endpoint
        let url = CAPTURED_URL.with(|captured| captured.borrow().clone());
        assert!(
            url.contains("update_secret"),
            "URL should contain update_secret endpoint, got: {}",
            url
        );
        assert!(
            url.contains("fake.keepersecurity.com"),
            "URL should contain hostname, got: {}",
            url
        );
    }

    #[test]
    fn test_transaction_endpoints_correct() {
        // Test that complete_transaction uses correct endpoints for finalize/rollback
        let storage = create_mock_storage().expect("Failed to create storage");

        thread_local! {
            static CAPTURED_URLS: RefCell<Vec<String>> = RefCell::new(Vec::new());
        }

        fn endpoint_capture_mock(
            url: String,
            transmission_key: TransmissionKey,
            _encrypted_payload: EncryptedPayload,
        ) -> Result<KsmHttpResponse, KSMRError> {
            CAPTURED_URLS.with(|urls| {
                urls.borrow_mut().push(url.clone());
            });

            let encrypted_response =
                CryptoUtils::encrypt_aes_gcm(&[], &transmission_key.key, None)?;
            Ok(KsmHttpResponse {
                status_code: 200,
                data: encrypted_response,
                http_response: None,
            })
        }

        // Test finalize endpoint
        let mut client_options = ClientOptions::new_client_options(storage.clone());
        client_options.set_custom_post_function(endpoint_capture_mock);

        let mut secrets_manager =
            SecretsManager::new(client_options).expect("Failed to create SecretsManager");

        secrets_manager
            .complete_transaction("test-uid-1".to_string(), false)
            .ok();

        let finalize_url = CAPTURED_URLS.with(|urls| urls.borrow()[0].clone());
        assert!(
            finalize_url.contains("finalize_secret_update"),
            "Commit should use finalize_secret_update endpoint, got: {}",
            finalize_url
        );

        // Reset and test rollback endpoint
        CAPTURED_URLS.with(|urls| urls.borrow_mut().clear());

        let storage2 = create_mock_storage().expect("Failed to create storage");
        let mut client_options2 = ClientOptions::new_client_options(storage2);
        client_options2.set_custom_post_function(endpoint_capture_mock);

        let mut secrets_manager2 =
            SecretsManager::new(client_options2).expect("Failed to create SecretsManager");

        secrets_manager2
            .complete_transaction("test-uid-2".to_string(), true)
            .ok();

        let rollback_url = CAPTURED_URLS.with(|urls| urls.borrow()[0].clone());
        assert!(
            rollback_url.contains("rollback_secret_update"),
            "Rollback should use rollback_secret_update endpoint, got: {}",
            rollback_url
        );
    }
}
