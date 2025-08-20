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
mod create_secret_tests {
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::dtos::RecordCreate;
    use mockall::mock;

    mock! {
        pub SecretsManager {
            fn create_secret(&self, parent_folder_uid: String, record_to_create: RecordCreate) -> Result<String, KSMRError>;
        }
    }

    #[test]
    fn test_create_secret_success() {
        // Create mock instance of SecretsManager
        let mut mock_secrets_manager = MockSecretsManager::new();

        // Define the parent_folder_uid and record to create
        let parent_folder_uid = "sample_parent_uid".to_string();
        let record_to_create = RecordCreate::new(
            "Login".to_string(),
            "Test record creation".to_string(),
            None,
        );

        // Mock the behavior of create_secret
        mock_secrets_manager
            .expect_create_secret()
            .with(
                mockall::predicate::eq(parent_folder_uid.clone()),
                mockall::predicate::function(|record: &RecordCreate| {
                    // Here, you can add specific checks for the fields of `record`
                    record.title == "Test record creation"
                }),
            )
            .returning(|_, _| Ok("mocked-uid".to_string()));

        // Call the create_secret function
        let created_record: Result<String, KSMRError> =
            mock_secrets_manager.create_secret(parent_folder_uid, record_to_create);

        // Assert the outcome
        match created_record {
            Ok(data) => {
                assert_eq!(
                    data, "mocked-uid",
                    "The returned record UID should be 'mocked-uid'"
                );
            }
            Err(err) => {
                panic!("Record creation failed with error: {}", err);
            }
        }
    }

    #[test]
    fn test_create_secret_failure() {
        let mut mock_secrets_manager = MockSecretsManager::new();
        let parent_folder_uid = "sample_parent_uid".to_string();
        let record_to_create = RecordCreate::new(
            "Login".to_string(),
            "Test record creation".to_string(),
            None,
        );

        // Simulate an error scenario (e.g., invalid data)
        mock_secrets_manager
            .expect_create_secret()
            .with(
                mockall::predicate::eq(parent_folder_uid.clone()),
                mockall::predicate::function(|record: &RecordCreate| {
                    record.title == "Test record creation"
                }),
            )
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Failed to create secret".to_string(),
                ))
            });

        let created_record =
            mock_secrets_manager.create_secret(parent_folder_uid, record_to_create);
        assert!(created_record.is_err());
    }

    // Test case: Invalid parent_folder_uid
    #[test]
    fn test_create_secret_invalid_parent_folder_uid() {
        let mut mock_secrets_manager = MockSecretsManager::new();
        let invalid_parent_folder_uid = "InvalidUid".to_string();
        let record_to_create = RecordCreate::new(
            "Login".to_string(),
            "Test record creation".to_string(),
            None,
        );

        // Simulate a failure due to invalid parent_folder_uid
        mock_secrets_manager
            .expect_create_secret()
            .with(
                mockall::predicate::eq(invalid_parent_folder_uid.clone()),
                mockall::predicate::function(|record: &RecordCreate| {
                    record.title == "Test record creation"
                }),
            )
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Invalid parent folder UID".to_string(),
                ))
            });

        let created_record =
            mock_secrets_manager.create_secret(invalid_parent_folder_uid, record_to_create);
        assert!(created_record.is_err());
    }

    // Test case: Missing required fields
    #[test]
    fn test_create_secret_missing_required_fields() {
        let mut mock_secrets_manager = MockSecretsManager::new();
        let parent_folder_uid = "sample_parent_uid".to_string();
        let missing_fields_record = RecordCreate::new("Login".to_string(), "".to_string(), None); // Missing title or other required fields

        // Simulate an error due to missing required fields
        mock_secrets_manager
            .expect_create_secret()
            .with(
                mockall::predicate::eq(parent_folder_uid.clone()),
                mockall::predicate::function(|record: &RecordCreate| record.title.is_empty()),
            )
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Missing required fields".to_string(),
                ))
            });

        let created_record =
            mock_secrets_manager.create_secret(parent_folder_uid, missing_fields_record);
        assert!(created_record.is_err());
    }
}
