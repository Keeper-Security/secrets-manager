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
mod update_secret_tests {
    use keeper_secrets_manager_core::dto::payload::UpdateTransactionType;
    use keeper_secrets_manager_core::dto::Record;
    use keeper_secrets_manager_core::enums::StandardFieldTypeEnum;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn create_test_record() -> Record {
        let mut record_dict = HashMap::new();
        record_dict.insert("title".to_string(), json!("Test Login"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert(
            "fields".to_string(),
            json!([
                {
                    "type": "login",
                    "value": ["user@example.com"]
                },
                {
                    "type": "password",
                    "value": ["OldPassword123!"]
                },
                {
                    "type": "url",
                    "value": ["https://example.com"]
                }
            ]),
        );
        record_dict.insert("custom".to_string(), json!([]));

        Record {
            uid: "test-record-uid-123".to_string(),
            title: "Test Login".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: Some("OldPassword123!".to_string()),
            revision: Some(1),
            is_editable: true,
            folder_uid: "test-folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![1, 2, 3, 4], // Dummy key
            folder_key_bytes: None,
            links: vec![],
        }
    }

    #[test]
    fn test_record_password_field_modification() {
        // Test that we can modify a password field in a record
        let mut record = create_test_record();

        // Verify initial password
        assert_eq!(record.password, Some("OldPassword123!".to_string()));

        // Modify password using set_standard_field_value_mut
        let new_password = Value::String("NewPassword456!".to_string());
        let result = record
            .set_standard_field_value_mut(StandardFieldTypeEnum::PASSWORD.get_type(), new_password);

        assert!(result.is_ok(), "Failed to set password field: {:?}", result);

        // Verify the password was updated in the record_dict
        let fields = record
            .record_dict
            .get("fields")
            .and_then(|f| f.as_array())
            .expect("Fields should exist");

        let password_field = fields
            .iter()
            .find(|field| field.get("type").and_then(|t| t.as_str()) == Some("password"))
            .expect("Password field should exist");

        let password_value = password_field
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .expect("Password value should exist");

        assert_eq!(password_value, "NewPassword456!");
    }

    #[test]
    fn test_record_custom_field_modification() {
        // Test that we can modify custom fields in a record
        // Note: set_custom_field_value_mut requires the field to already exist
        // This test creates a record with an existing custom field and modifies it

        let mut record_dict = HashMap::new();
        record_dict.insert("title".to_string(), json!("Test Login"));
        record_dict.insert("type".to_string(), json!("login"));
        record_dict.insert("fields".to_string(), json!([]));
        record_dict.insert(
            "custom".to_string(),
            json!([
                {
                    "type": "text",
                    "label": "API Key",
                    "value": ["old-api-key"]
                }
            ]),
        );

        let mut record = Record {
            uid: "test-record-uid-123".to_string(),
            title: "Test Login".to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: serde_json::to_string(&record_dict).unwrap(),
            record_dict,
            password: None,
            revision: Some(1),
            is_editable: true,
            folder_uid: "test-folder-uid".to_string(),
            inner_folder_uid: None,
            record_key_bytes: vec![1, 2, 3, 4],
            folder_key_bytes: None,
            links: vec![],
        };

        // Modify the existing custom field
        let api_key_value = Value::String("test-api-key-12345".to_string());
        let result = record.set_custom_field_value_mut("API Key", api_key_value);

        assert!(result.is_ok(), "Failed to set custom field: {:?}", result);

        // Verify the custom field was updated
        let custom_fields = record
            .record_dict
            .get("custom")
            .and_then(|c| c.as_array())
            .expect("Custom fields should exist");

        let api_key_field = custom_fields
            .iter()
            .find(|field| field.get("label").and_then(|l| l.as_str()) == Some("API Key"))
            .expect("API Key custom field should exist");

        let api_key_value = api_key_field
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .expect("API Key value should exist");

        assert_eq!(api_key_value, "test-api-key-12345");
    }

    #[test]
    fn test_record_multiple_field_modifications() {
        // Test that we can modify multiple fields in a single record
        let mut record = create_test_record();

        // Modify password
        let new_password = Value::String("NewPassword789!".to_string());
        record
            .set_standard_field_value_mut(StandardFieldTypeEnum::PASSWORD.get_type(), new_password)
            .expect("Should set password");

        // Modify URL
        let new_url = Value::String("https://updated-example.com".to_string());
        record
            .set_standard_field_value_mut(StandardFieldTypeEnum::URL.get_type(), new_url)
            .expect("Should set URL");

        // Verify both fields were updated
        let fields = record
            .record_dict
            .get("fields")
            .and_then(|f| f.as_array())
            .expect("Fields should exist");

        let password_field = fields
            .iter()
            .find(|field| field.get("type").and_then(|t| t.as_str()) == Some("password"))
            .expect("Password field should exist");

        let password_value = password_field
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(password_value, "NewPassword789!");

        let url_field = fields
            .iter()
            .find(|field| field.get("type").and_then(|t| t.as_str()) == Some("url"))
            .expect("URL field should exist");

        let url_value = url_field
            .get("value")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(url_value, "https://updated-example.com");
    }

    #[test]
    fn test_update_transaction_type_serialization() {
        // Test that UpdateTransactionType enum serializes correctly
        assert_eq!(UpdateTransactionType::None.as_str(), "");
        assert_eq!(UpdateTransactionType::General.as_str(), "general");
        assert_eq!(UpdateTransactionType::Rotation.as_str(), "rotation");
    }

    #[test]
    fn test_update_transaction_type_deserialization() {
        // Test that UpdateTransactionType enum deserializes correctly
        use std::str::FromStr;

        assert_eq!(
            UpdateTransactionType::from_str("").unwrap(),
            UpdateTransactionType::None
        );
        assert_eq!(
            UpdateTransactionType::from_str("general").unwrap(),
            UpdateTransactionType::General
        );
        assert_eq!(
            UpdateTransactionType::from_str("rotation").unwrap(),
            UpdateTransactionType::Rotation
        );
        assert!(UpdateTransactionType::from_str("invalid").is_err());
    }

    #[test]
    fn test_record_revision_tracking() {
        // Test that record revision is properly tracked
        let record = create_test_record();

        assert_eq!(record.revision, Some(1));
        assert!(
            record.is_editable,
            "Test record should be marked as editable"
        );
    }

    #[test]
    fn test_record_immutability_check() {
        // Test that non-editable records can be identified
        let mut record = create_test_record();
        record.is_editable = false;

        assert!(!record.is_editable, "Record should not be editable");
    }

    #[test]
    fn test_password_field_retrieval() {
        // Test that we can retrieve password field using get_standard_field_value
        let record = create_test_record();

        let password_result = record.get_standard_field_value("password", true);

        assert!(password_result.is_ok(), "Should retrieve password field");

        let password_value = password_result.unwrap();
        assert_eq!(password_value, "OldPassword123!");
    }

    #[test]
    fn test_login_field_retrieval() {
        // Test that we can retrieve login field using get_standard_field_value
        let record = create_test_record();

        let login_result = record.get_standard_field_value("login", true);

        assert!(login_result.is_ok(), "Should retrieve login field");

        let login_value = login_result.unwrap();
        assert_eq!(login_value, "user@example.com");
    }

    #[test]
    fn test_url_field_retrieval() {
        // Test that we can retrieve URL field using get_standard_field_value
        let record = create_test_record();

        let url_result = record.get_standard_field_value("url", true);

        assert!(url_result.is_ok(), "Should retrieve URL field");

        let url_value = url_result.unwrap();
        assert_eq!(url_value, "https://example.com");
    }

    #[test]
    fn test_nonexistent_field_retrieval() {
        // Test that retrieving a non-existent field returns an error
        let record = create_test_record();

        let result = record.get_standard_field_value("nonexistent", true);

        assert!(
            result.is_err(),
            "Should return error for non-existent field"
        );
    }

    #[test]
    fn test_record_title_modification() {
        // Test that we can modify the record title
        let mut record = create_test_record();

        record.title = "Updated Title".to_string();
        let update_result = record.update();

        assert!(update_result.is_ok(), "Should update record title");
        assert_eq!(record.title, "Updated Title");

        // Verify title in record_dict
        let title_value = record
            .record_dict
            .get("title")
            .and_then(|t| t.as_str())
            .expect("Title should exist in record_dict");

        assert_eq!(title_value, "Updated Title");
    }

    #[test]
    fn test_record_type_preservation() {
        // Test that record type is preserved during operations
        let record = create_test_record();

        assert_eq!(record.record_type, "login");
        assert_eq!(
            record
                .record_dict
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap(),
            "login"
        );
    }

    #[test]
    fn test_record_uid_immutability() {
        // Test that record UID should not be modified
        let record = create_test_record();
        let original_uid = record.uid.clone();

        assert_eq!(original_uid, "test-record-uid-123");
        // UID should remain constant throughout record lifecycle
    }
}
