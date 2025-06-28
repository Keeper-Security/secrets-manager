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
mod get_secrets_tests {
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::Record;
    use mockall::mock;
    use serde_json::json;
    use std::collections::HashMap;

    mock! {
        pub SecretsManager {
            fn get_secrets(&self, record_uids: Vec<String>) -> Result<Vec<Record>, KSMRError>;
            fn get_secrets_by_title(&self, title: String) -> Result<Vec<Record>, KSMRError>;
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
            Record {
                uid: "uid3".to_string(),
                title: "Title 1".to_string(),
                record_type: "type3".to_string(),
                raw_json: "{}".to_string(),
                record_dict: {
                    let mut dict = HashMap::new();
                    dict.insert("key3".to_string(), json!("value3"));
                    dict
                },
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_get_secrets_empty_input_returns_all_records() {
        let all_records = create_all_records();

        // Create a mock instance of SecretsManager
        let mut mock_secrets_manager = MockSecretsManager::new();

        // Clone the records to avoid moving them
        let all_records_clone = all_records.clone();

        // Define the behavior of the mock: when get_secrets is called with an empty vector, return all records
        mock_secrets_manager
            .expect_get_secrets()
            .with(mockall::predicate::eq(vec![])) // Expecting an empty vector as input
            .times(1) // This method should be called exactly once
            .returning(move |_| Ok(all_records_clone.clone())); // Clone all_records when returning

        // Act: Call get_secrets with an empty vector (no UIDs passed)
        let result = mock_secrets_manager.get_secrets(vec![]).unwrap();

        // Assert: Verify that all records are returned
        assert_eq!(
            result.len(),
            all_records.len(),
            "Expected all records to be returned"
        );
        for (record, expected_record) in result.iter().zip(all_records.iter()) {
            assert_eq!(record.uid, expected_record.uid, "Mismatch in UID");
            assert_eq!(record.title, expected_record.title, "Mismatch in Title");
            assert_eq!(
                record.record_type, expected_record.record_type,
                "Mismatch in Record Type"
            );
            assert_eq!(
                record.raw_json, expected_record.raw_json,
                "Mismatch in Raw JSON"
            );
            assert_eq!(
                record.record_dict, expected_record.record_dict,
                "Mismatch in Record Dict"
            );
        }
    }

    #[test]
    fn test_get_secrets_with_uids_returns_correct_records() {
        let all_records = create_all_records();

        // Create a mock instance of SecretsManager
        let mut mock_secrets_manager = MockSecretsManager::new();

        // Clone the records to avoid moving them
        let all_records_clone = all_records.clone();

        // Define the behavior of the mock: when get_secrets is called with specific UIDs, return those records
        mock_secrets_manager
            .expect_get_secrets()
            .with(mockall::predicate::eq(vec![
                "uid1".to_string(),
                "uid3".to_string(),
            ])) // Expecting a specific vector of UIDs
            .times(1) // This method should be called exactly once
            .returning(move |uids| {
                // Filter the records based on the UIDs passed and return them
                let filtered_records: Vec<Record> = all_records_clone
                    .iter()
                    .filter(|r| uids.contains(&r.uid))
                    .cloned()
                    .collect();
                Ok(filtered_records)
            });

        // Act: Call get_secrets with a vector of specific UIDs
        let result = mock_secrets_manager
            .get_secrets(vec!["uid1".to_string(), "uid3".to_string()])
            .unwrap();

        // Assert: Verify that only the correct records are returned
        assert_eq!(result.len(), 2, "Expected 2 records to be returned");
        assert_eq!(result[0].uid, "uid1", "Expected UID1 to be returned");
        assert_eq!(result[1].uid, "uid3", "Expected UID3 to be returned");
    }

    #[test]
    fn test_get_secrets_by_title_returns_correct_records() {
        let all_records = create_all_records();
        let mut mock_secrets_manager = MockSecretsManager::new();
        let all_records_clone = all_records.clone();

        mock_secrets_manager
            .expect_get_secrets_by_title()
            .with(mockall::predicate::eq("Title 1".to_string())) // Expecting a single title input
            .times(1)
            .returning(move |title| {
                // Filter the records based on the title and return them
                let filtered_records: Vec<Record> = all_records_clone
                    .iter()
                    .filter(|r| r.title == title)
                    .cloned()
                    .collect();
                Ok(filtered_records)
            });

        // Act: Call get_secrets_by_title with the title "Title 1"
        let result = mock_secrets_manager
            .get_secrets_by_title("Title 1".to_string())
            .unwrap();

        // Assert: Verify that all records with the title "Title 1" are returned
        assert_eq!(
            result.len(),
            2,
            "Expected 2 records to be returned with Title 1"
        );
        assert_eq!(
            result[0].title, "Title 1",
            "Expected Title 1 to be returned"
        );
        assert_eq!(
            result[1].title, "Title 1",
            "Expected Title 1 to be returned"
        );
    }
}
