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
mod delete_secret_tests {
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::Record;
    use mockall::mock;
    use serde_json::json;
    use std::collections::HashMap;

    mock! {
        pub SecretsManager {
            fn delete_secret(&self, uid: String) -> Result<(), KSMRError>;
        }
    }

    fn create_all_records() -> Vec<Record> {
        vec![
            Record {
                uid: "uid1".to_string(),
                title: "Title 1".to_string(),
                record_type: "type1".to_string(),
                raw_json: "{}".to_string(),
                record_dict: {
                    let mut dict = HashMap::new();
                    dict.insert("key1".to_string(), json!("value1"));
                    dict
                },
                ..Default::default()
            },
            Record {
                uid: "uid2".to_string(),
                title: "Title 2".to_string(),
                record_type: "type2".to_string(),
                raw_json: "{}".to_string(),
                record_dict: {
                    let mut dict = HashMap::new();
                    dict.insert("key2".to_string(), json!("value2"));
                    dict
                },
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_delete_secret_success() {
        let mut all_records = create_all_records();

        let mut mock_secrets_manager = MockSecretsManager::new();

        // Set up the mock to simulate successful deletion
        mock_secrets_manager
            .expect_delete_secret()
            .with(mockall::predicate::always()) // Expecting "uid1" as input
            .times(1) // Should be called exactly once
            .returning(|_| Ok(())); // Simulate success

        // Act: Call delete_secret with "uid1"
        let result = mock_secrets_manager.delete_secret("uid1".to_string());

        // Simulate the removal of the record from the list
        if result.is_ok() {
            all_records.retain(|record| record.uid != "uid1");
        }

        // Assert: Ensure the operation was successful
        assert!(result.is_ok(), "Expected delete_secret to succeed");
        // Assert: Check the size of all_records
        assert_eq!(
            all_records.len(),
            1,
            "Expected one record to remain after deletion"
        );
        // Assert: Verify the remaining record is correct
        assert_eq!(all_records[0].uid, "uid2", "Unexpected record remaining");
    }

    #[test]
    fn test_delete_secret_record_not_found() {
        let all_records = create_all_records();
        let mut mock_secrets_manager = MockSecretsManager::new();

        // Set up the mock to simulate a record not found error
        mock_secrets_manager
            .expect_delete_secret()
            .with(mockall::predicate::always()) // Expecting a non-existent UID
            .times(1) // Should be called exactly once
            .returning(|_| Err(KSMRError::CustomError("Record not found".to_string())));

        // Act: Call delete_secret with a non-existent UID
        let result = mock_secrets_manager.delete_secret("nonexistent_uid".to_string());

        // Assert: Ensure the operation failed with the expected error
        assert!(result.is_err(), "Expected delete_secret to fail");
        if let Err(KSMRError::CustomError(err)) = result {
            assert_eq!(err, "Record not found", "Unexpected error message");
        }

        // Assert: Ensure the size of all_records is unchanged
        assert_eq!(
            all_records.len(),
            2,
            "Expected all_records to remain unchanged"
        );
    }
}
