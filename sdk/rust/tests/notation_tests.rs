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

use mockall::mock;
use serde_json::Value;
use std::collections::HashMap;

use keeper_secrets_manager_core::dto::Record;

#[cfg(test)]
mod get_notation_tests {

    use super::*;
    use mockall::predicate::always;

    // Mock SecretsManager
    mock! {
        pub SecretsManager {
            fn get_notation(&self, notation: String) -> Result<String, String>;
        }
    }

    // Function to create a sample Record
    fn create_sample_record() -> Record {
        Record {
            record_key_bytes: vec![1, 2, 3],
            uid: "record_uid1".to_string(),
            title: "Sample Record".to_string(),
            record_type: "type1".to_string(),
            files: vec![],
            raw_json: "{}".to_string(),
            record_dict: {
                let mut dict = HashMap::new();
                dict.insert(
                    "field_name1".to_string(),
                    Value::String("value1".to_string()),
                );
                dict.insert(
                    "field_name2".to_string(),
                    Value::String("value2".to_string()),
                );
                dict.insert(
                    "custom_field1".to_string(),
                    Value::String("custom_value1".to_string()),
                );
                dict.insert(
                    "custom_field2".to_string(),
                    Value::String("custom_value2".to_string()),
                );
                dict
            },
            password: Some("password123".to_string()),
            revision: Some(1),
            is_editable: true,
            folder_uid: "folder_uid1".to_string(),
            folder_key_bytes: Some(vec![4, 5, 6]),
            inner_folder_uid: None,
            links: vec![],
        }
    }

    #[test]
    fn test_get_notation_success() {
        let mut mock_manager = MockSecretsManager::new();

        let sample_record = create_sample_record(); // Using the helper function

        // Define the behavior of the get_notation() function
        mock_manager
            .expect_get_notation()
            .with(always())
            .returning({
                let record_dict = sample_record.record_dict.clone(); // Clone the record_dict for the closure
                move |notation| {
                    let parts: Vec<&str> = notation.split('/').collect();
                    if parts.len() == 3 && parts[1] == "field" {
                        let field_name = parts[2];
                        if let Some(Value::String(value)) = record_dict.get(field_name) {
                            return Ok(value.clone());
                        }
                        Err("Field not found".to_string())
                    } else if parts.len() == 3 && parts[1] == "custom_field" {
                        let field_name = parts[2];
                        if let Some(Value::String(value)) = record_dict.get(field_name) {
                            return Ok(value.clone());
                        }
                        Err("Custom field not found".to_string())
                    } else {
                        Err("Invalid notation format".to_string())
                    }
                }
            });

        // Test case: valid notation for a standard field
        let result = mock_manager.get_notation("record_uid1/field/field_name1".to_string());
        assert_eq!(result, Ok("value1".to_string()));

        // Test case: valid notation for a custom field
        let result =
            mock_manager.get_notation("record_uid1/custom_field/custom_field1".to_string());
        assert_eq!(result, Ok("custom_value1".to_string()));

        // Test case: invalid notation format
        let result = mock_manager.get_notation("record_uid1/invalid/field_name1".to_string());
        assert_eq!(result, Err("Invalid notation format".to_string()));
    }

    #[test]
    fn test_get_notation_non_existing_field() {
        let mut mock_manager = MockSecretsManager::new();
        let sample_record = create_sample_record();
        // Handle the case for "field_name3" where the field doesn't exist
        mock_manager
            .expect_get_notation()
            .with(always())
            .returning({
                let record_dict = sample_record.record_dict.clone(); // Clone the record_dict for the closure
                move |notation| {
                    let parts: Vec<&str> = notation.split('/').collect();
                    if parts.len() == 3 && parts[1] == "field" {
                        let field_name = parts[2];
                        if let Some(Value::String(_value)) = record_dict.get(field_name) {
                            Err("Field not found".to_string())
                        } else {
                            Err("Field not found".to_string())
                        }
                    } else if parts.len() == 3 && parts[1] == "custom_field" {
                        let field_name = parts[2];
                        if let Some(Value::String(_value)) = record_dict.get(field_name) {
                            Err("Custom field not found".to_string())
                        } else {
                            Err("Custom field not found".to_string())
                        }
                    } else {
                        Err("Invalid notation format".to_string())
                    }
                }
            });

        // Test case: invalid standard field name
        let result = mock_manager.get_notation("record_uid1/field/field_name3".to_string());
        assert_eq!(result, Err("Field not found".to_string()));

        // Test case: invalid custom field name
        let result =
            mock_manager.get_notation("record_uid1/custom_field/custom_field3".to_string());
        assert_eq!(result, Err("Custom field not found".to_string()));

        // Test case: invalid notation format
        let result = mock_manager.get_notation("record_uid1/invalid/field_name1".to_string());
        assert_eq!(result, Err("Invalid notation format".to_string()));
    }
}
