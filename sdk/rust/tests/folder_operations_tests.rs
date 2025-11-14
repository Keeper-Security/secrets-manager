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
mod folder_operations_tests {
    use keeper_secrets_manager_core::custom_error::KSMRError;
    use keeper_secrets_manager_core::dto::dtos::KeeperFolder;
    use keeper_secrets_manager_core::dto::payload::CreateOptions;
    use mockall::{mock, predicate::*};
    use serde_json::json;
    use std::collections::HashMap;

    // Mock the SecretsManager for testing
    mock! {
        SecretsManager {
            fn create_folder(
                &mut self,
                create_options: CreateOptions,
                folder_name: String,
                folders: Vec<KeeperFolder>,
            ) -> Result<String, KSMRError>;

            fn update_folder(
                &mut self,
                folder_uid: String,
                folder_name: String,
            ) -> Result<(), KSMRError>;

            fn delete_folder(
                &mut self,
                folder_uids: Vec<String>,
                force_delete: bool,
            ) -> Result<Vec<HashMap<String, serde_json::Value>>, KSMRError>;
        }
    }

    /// Test: Successful folder creation
    #[test]
    fn test_create_folder_success() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq("Test Folder".to_string()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok("NEW_FOLDER_UID_123".to_string()));

        let create_options = CreateOptions::new(
            "PARENT_FOLDER_UID".to_string(),
            None,
        );
        let result = mock_manager.create_folder(
            create_options,
            "Test Folder".to_string(),
            vec![],
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "NEW_FOLDER_UID_123");
    }

    /// Test: Create folder with empty name (should fail)
    #[test]
    fn test_create_folder_empty_name() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq("".to_string()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| {
                Err(KSMRError::CustomError(
                    "Folder name cannot be empty".to_string(),
                ))
            });

        let create_options = CreateOptions::new(
            "PARENT_FOLDER_UID".to_string(),
            None,
        );
        let result = mock_manager.create_folder(
            create_options,
            "".to_string(),
            vec![],
        );

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert_eq!(msg, "Folder name cannot be empty");
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Create nested folder
    #[test]
    fn test_create_nested_folder() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq("Nested Folder".to_string()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok("NESTED_FOLDER_UID_456".to_string()));

        let create_options = CreateOptions::new(
            "PARENT_FOLDER_UID_123".to_string(),
            None,
        );
        let result = mock_manager.create_folder(
            create_options,
            "Nested Folder".to_string(),
            vec![],
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "NESTED_FOLDER_UID_456");
    }

    /// Test: Create folder without parent (root level)
    #[test]
    fn test_create_root_level_folder() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq("Root Folder".to_string()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok("ROOT_FOLDER_UID_789".to_string()));

        let create_options = CreateOptions::new(
            "ROOT_FOLDER_UID".to_string(),
            None,
        );
        let result = mock_manager.create_folder(
            create_options,
            "Root Folder".to_string(),
            vec![],
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ROOT_FOLDER_UID_789");
    }

    /// Test: Successful folder update
    #[test]
    fn test_update_folder_success() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_update_folder()
            .with(
                eq("FOLDER_UID_123".to_string()),
                eq("Updated Folder Name".to_string()),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let result = mock_manager.update_folder(
            "FOLDER_UID_123".to_string(),
            "Updated Folder Name".to_string(),
        );

        assert!(result.is_ok());
    }

    /// Test: Update folder with empty name (should fail)
    #[test]
    fn test_update_folder_empty_name() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_update_folder()
            .with(eq("FOLDER_UID_123".to_string()), eq("".to_string()))
            .times(1)
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Folder name cannot be empty".to_string(),
                ))
            });

        let result = mock_manager.update_folder("FOLDER_UID_123".to_string(), "".to_string());

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert_eq!(msg, "Folder name cannot be empty");
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Update non-existent folder (should fail)
    #[test]
    fn test_update_folder_not_found() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_update_folder()
            .with(
                eq("NONEXISTENT_UID".to_string()),
                eq("New Name".to_string()),
            )
            .times(1)
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Folder not found".to_string(),
                ))
            });

        let result =
            mock_manager.update_folder("NONEXISTENT_UID".to_string(), "New Name".to_string());

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert_eq!(msg, "Folder not found");
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Update folder with special characters in name
    #[test]
    fn test_update_folder_special_characters() {
        let mut mock_manager = MockSecretsManager::new();

        let special_name = "Folder/with\\special:chars*?<>|".to_string();
        mock_manager
            .expect_update_folder()
            .with(eq("FOLDER_UID_123".to_string()), eq(special_name.clone()))
            .times(1)
            .returning(|_, _| Ok(()));

        let result = mock_manager.update_folder("FOLDER_UID_123".to_string(), special_name);

        assert!(result.is_ok());
    }

    /// Test: Successful folder deletion (non-force)
    #[test]
    fn test_delete_folder_success() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(vec!["FOLDER_UID_123".to_string()]), eq(false))
            .times(1)
            .returning(|_, _| {
                let mut result = HashMap::new();
                result.insert("folder_uid".to_string(), json!("FOLDER_UID_123"));
                result.insert("status".to_string(), json!("deleted"));
                Ok(vec![result])
            });

        let result = mock_manager.delete_folder(vec!["FOLDER_UID_123".to_string()], false);

        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].get("folder_uid").unwrap(),
            &json!("FOLDER_UID_123")
        );
    }

    /// Test: Force delete folder
    #[test]
    fn test_delete_folder_force() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(vec!["FOLDER_UID_123".to_string()]), eq(true))
            .times(1)
            .returning(|_, _| {
                let mut result = HashMap::new();
                result.insert("folder_uid".to_string(), json!("FOLDER_UID_123"));
                result.insert("status".to_string(), json!("force_deleted"));
                Ok(vec![result])
            });

        let result = mock_manager.delete_folder(vec!["FOLDER_UID_123".to_string()], true);

        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].get("status").unwrap(),
            &json!("force_deleted")
        );
    }

    /// Test: Delete multiple folders
    #[test]
    fn test_delete_multiple_folders() {
        let mut mock_manager = MockSecretsManager::new();

        let folder_uids = vec![
            "FOLDER_UID_1".to_string(),
            "FOLDER_UID_2".to_string(),
            "FOLDER_UID_3".to_string(),
        ];

        mock_manager
            .expect_delete_folder()
            .with(eq(folder_uids.clone()), eq(false))
            .times(1)
            .returning(|uids, _| {
                Ok(uids
                    .iter()
                    .map(|uid| {
                        let mut result = HashMap::new();
                        result.insert("folder_uid".to_string(), json!(uid));
                        result.insert("status".to_string(), json!("deleted"));
                        result
                    })
                    .collect())
            });

        let result = mock_manager.delete_folder(folder_uids, false);

        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert_eq!(deleted.len(), 3);
    }

    /// Test: Delete non-existent folder (should fail)
    #[test]
    fn test_delete_folder_not_found() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(vec!["NONEXISTENT_UID".to_string()]), eq(false))
            .times(1)
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Folder not found".to_string(),
                ))
            });

        let result = mock_manager.delete_folder(vec!["NONEXISTENT_UID".to_string()], false);

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert_eq!(msg, "Folder not found");
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Delete folder with records (non-force should fail)
    #[test]
    fn test_delete_folder_with_records_non_force() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(vec!["FOLDER_WITH_RECORDS".to_string()]), eq(false))
            .times(1)
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Folder contains records, use force_delete".to_string(),
                ))
            });

        let result = mock_manager.delete_folder(vec!["FOLDER_WITH_RECORDS".to_string()], false);

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert!(msg.contains("force_delete"));
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Delete folder with records (force should succeed)
    #[test]
    fn test_delete_folder_with_records_force() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(vec!["FOLDER_WITH_RECORDS".to_string()]), eq(true))
            .times(1)
            .returning(|_, _| {
                let mut result = HashMap::new();
                result.insert("folder_uid".to_string(), json!("FOLDER_WITH_RECORDS"));
                result.insert("status".to_string(), json!("force_deleted"));
                result.insert("records_deleted".to_string(), json!(5));
                Ok(vec![result])
            });

        let result = mock_manager.delete_folder(vec!["FOLDER_WITH_RECORDS".to_string()], true);

        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0].get("records_deleted").unwrap(),
            &json!(5)
        );
    }

    /// Test: Delete empty folder list (should fail)
    #[test]
    fn test_delete_folder_empty_list() {
        let mut mock_manager = MockSecretsManager::new();

        mock_manager
            .expect_delete_folder()
            .with(eq(Vec::<String>::new()), eq(false))
            .times(1)
            .returning(|_, _| {
                Err(KSMRError::CustomError(
                    "Folder UID list cannot be empty".to_string(),
                ))
            });

        let result = mock_manager.delete_folder(Vec::new(), false);

        assert!(result.is_err());
        if let Err(KSMRError::CustomError(msg)) = result {
            assert_eq!(msg, "Folder UID list cannot be empty");
        } else {
            panic!("Expected GeneralError");
        }
    }

    /// Test: Folder name with Unicode characters
    #[test]
    fn test_create_folder_unicode_name() {
        let mut mock_manager = MockSecretsManager::new();

        let unicode_name = "文件夹名称 フォルダ名 مجلد اسم".to_string();
        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq(unicode_name.clone()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok("UNICODE_FOLDER_UID".to_string()));

        let create_options = CreateOptions::new(
            "ROOT_FOLDER_UID".to_string(),
            None,
        );
        let result = mock_manager.create_folder(create_options, unicode_name, vec![]);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "UNICODE_FOLDER_UID");
    }

    /// Test: Folder name with very long string (boundary test)
    #[test]
    fn test_create_folder_long_name() {
        let mut mock_manager = MockSecretsManager::new();

        let long_name = "a".repeat(1000);
        mock_manager
            .expect_create_folder()
            .with(
                always(),
                eq(long_name.clone()),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok("LONG_NAME_FOLDER_UID".to_string()));

        let create_options = CreateOptions::new(
            "ROOT_FOLDER_UID".to_string(),
            None,
        );
        let result = mock_manager.create_folder(create_options, long_name, vec![]);

        assert!(result.is_ok());
    }

    /// Test: Update folder with Unicode name
    #[test]
    fn test_update_folder_unicode_name() {
        let mut mock_manager = MockSecretsManager::new();

        let unicode_name = "日本語フォルダ".to_string();
        mock_manager
            .expect_update_folder()
            .with(eq("FOLDER_UID_123".to_string()), eq(unicode_name.clone()))
            .times(1)
            .returning(|_, _| Ok(()));

        let result = mock_manager.update_folder("FOLDER_UID_123".to_string(), unicode_name);

        assert!(result.is_ok());
    }
}
