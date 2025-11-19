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
mod file_key_value_tests {
    use crate::config_keys::ConfigKeys;
    use crate::custom_error::KSMRError;
    use crate::storage::{FileKeyValueStorage, KeyValueStorage};

    use std::collections::HashMap;
    use std::fs::remove_file;

    // Helper function to create a temporary config file
    fn setup_temp_config_file(
        function_name: &str,
    ) -> Result<(FileKeyValueStorage, String), KSMRError> {
        let file_name = format!("{}-temp-config.json", function_name); // Create the file name
        let storage_result = FileKeyValueStorage::new(Some(file_name.to_string()))
            .map_err(|err| KSMRError::StorageError(format!("Failed to create storage: {}", err)))?;
        let _ = storage_result
            .create_config_file_if_missing()
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create config file: {}", err))
            })?;
        Ok((storage_result, file_name.clone())) // Return the storage and the file name as a tuple
    }

    #[test]
    fn test_read_storage() {
        let (mut storage, file_name) = setup_temp_config_file("read_storage")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test reading from an empty file
        let config = storage.read_storage().unwrap();
        assert!(config.is_empty());

        // Test reading after writing to the file
        let mut config: HashMap<ConfigKeys, String> = HashMap::new();
        config.insert(ConfigKeys::KeyAppKey, "SomeValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);
        run_cleanup(file_name)
    }

    #[test]
    fn test_save_storage() {
        let (mut storage, file_name) = setup_temp_config_file("save_storage")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test saving a configuration
        let mut config: HashMap<ConfigKeys, String> = HashMap::new();
        config.insert(ConfigKeys::KeyAppKey, "SomeValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        // Test reading back the saved configuration
        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);

        // Test overwriting the configuration
        config.insert(ConfigKeys::KeyClientId, "AnotherValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);
        run_cleanup(file_name);
    }

    #[test]
    fn test_get() {
        let (mut storage, file_name) = setup_temp_config_file("test_get")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test getting a non-existent key
        let value = storage.get(ConfigKeys::KeyAppKey).unwrap();
        assert_eq!(value, None);

        // Test getting an existing key after setting it
        storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        let value = storage.get(ConfigKeys::KeyAppKey).unwrap();
        assert_eq!(value, Some("SomeValue".to_string()));
        run_cleanup(file_name);
    }

    #[test]
    fn test_set() {
        let (mut storage, file_name) = setup_temp_config_file("test_set")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test setting a new key-value pair
        let updated_config = storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        assert_eq!(
            updated_config.get(&ConfigKeys::KeyAppKey),
            Some(&"SomeValue".to_string())
        );

        // Test updating an existing key
        storage
            .set(ConfigKeys::KeyAppKey, "NewValue".to_string())
            .unwrap();
        let updated_config = storage.get(ConfigKeys::KeyAppKey).unwrap();
        assert_eq!(updated_config, Some("NewValue".to_string()));

        // Test updating an non-existing key
        let key = ConfigKeys::get_enum("someRandomString");
        assert!(
            key.is_none(),
            "Expected no valid ConfigKeys enum for 'someRandomString'"
        ); // Attempt to set a value for a non-existing key
        run_cleanup(file_name);
    }

    #[test]
    fn test_delete() {
        let (mut storage, file_name) = setup_temp_config_file("test_delete")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test deleting a non-existent key
        let updated_config = storage.delete(ConfigKeys::KeyAppKey).unwrap();
        assert!(updated_config.is_empty());

        // Test deleting an existing key
        storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        let updated_config = storage.delete(ConfigKeys::KeyAppKey).unwrap();
        assert!(updated_config.get(&ConfigKeys::KeyAppKey).is_none());
        run_cleanup(file_name);
    }

    #[test]
    fn test_delete_all() {
        let (mut storage, file_name) = setup_temp_config_file("test_delete_all")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test deleting all from an empty storage
        let updated_config = storage.delete_all().unwrap();
        assert!(updated_config.is_empty());

        // Test deleting all after adding some entries
        let mut config: HashMap<ConfigKeys, String> = HashMap::new();
        config.insert(ConfigKeys::KeyAppKey, "SomeValue".to_string());
        config.insert(ConfigKeys::KeyClientId, "AnotherValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        let updated_config = storage.delete_all().unwrap();
        assert!(updated_config.is_empty());
        run_cleanup(file_name);
    }

    #[test]
    fn test_contains() {
        let (mut storage, file_name) = setup_temp_config_file("test_contains")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();

        // Test checking for a non-existent key
        assert!(!storage.contains(ConfigKeys::KeyAppKey).unwrap());

        // Test checking for an existing key
        storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        assert!(storage.contains(ConfigKeys::KeyAppKey).unwrap());
        run_cleanup(file_name);
    }

    #[test]
    fn test_is_empty() {
        let (mut storage, file_name) = setup_temp_config_file("test_is_empty")
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to create unit test storage: {}", err))
            })
            .unwrap();
        // Test checking if a newly created storage is empty
        assert!(storage.is_empty().unwrap());

        // Test checking if storage is not empty after adding an entry
        storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        assert!(!storage.is_empty().unwrap());
        run_cleanup(file_name);
    }

    fn run_cleanup(file_name: String) {
        let _ = remove_file(file_name);
    }
}

#[cfg(test)]
mod in_memory_storage_tests {
    use crate::{
        config_keys::ConfigKeys,
        storage::{InMemoryKeyValueStorage, KeyValueStorage},
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::collections::HashMap;

    #[test]
    fn test_read_storage() {
        let mut storage = InMemoryKeyValueStorage::new(None).unwrap();

        // Test reading from an empty storage
        let config = storage.read_storage().unwrap();
        assert!(config.is_empty());

        // Test saving to storage
        let mut config: HashMap<ConfigKeys, String> = HashMap::new();
        config.insert(ConfigKeys::KeyAppKey, "SomeValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);
    }

    #[test]
    fn test_save_storage() {
        let mut storage = InMemoryKeyValueStorage::new(None).unwrap();

        // Test saving a configuration
        let mut config: HashMap<ConfigKeys, String> = HashMap::new();
        config.insert(ConfigKeys::KeyAppKey, "SomeValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        // Check that storage reflects saved state
        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);

        // Test overwriting the configuration
        config.insert(ConfigKeys::KeyClientId, "AnotherValue".to_string());
        storage.save_storage(config.clone()).unwrap();

        let read_config = storage.read_storage().unwrap();
        assert_eq!(read_config, config);
    }

    #[test]
    fn test_get() {
        let storage = create_initialized_storage();

        // Test getting a non-existent key
        let value = storage.get(ConfigKeys::KeyHostname).unwrap();
        assert_eq!(value, None);

        // Test getting an existing key after setting it
        let value = storage.get(ConfigKeys::KeyAppKey).unwrap();
        assert_eq!(value, Some("myAppKey".to_string()));
    }

    #[test]
    fn test_set() {
        let mut storage = create_initialized_storage();

        // Test setting a new key-value pair
        let updated_config = storage
            .set(ConfigKeys::KeyAppKey, "SomeValue".to_string())
            .unwrap();
        assert_eq!(
            updated_config.get(&ConfigKeys::KeyAppKey),
            Some(&"SomeValue".to_string())
        );

        // Test updating an existing key
        storage
            .set(ConfigKeys::KeyAppKey, "NewValue".to_string())
            .unwrap();
        let updated_value = storage.get(ConfigKeys::KeyAppKey).unwrap();
        assert_eq!(updated_value, Some("NewValue".to_string()));

        // Test setting a value for a non-existing key
        let non_existing_key = ConfigKeys::get_enum("someRandomString");
        assert!(non_existing_key.is_none());
    }

    #[test]
    fn test_delete() {
        let mut storage = create_initialized_storage();

        // Test deleting a non-existent key
        let updated_config = storage.delete(ConfigKeys::KeyHostname).unwrap();
        assert!(updated_config
            .get_key_value(&ConfigKeys::KeyHostname)
            .is_none());

        // Test deleting an existing key
        let updated_config = storage.delete(ConfigKeys::KeyAppKey).unwrap();
        assert!(updated_config.get(&ConfigKeys::KeyAppKey).is_none());
    }

    #[test]
    fn test_delete_all() {
        let mut storage = InMemoryKeyValueStorage::new(None).unwrap();

        // Test deleting all from an empty storage
        let updated_config = storage.delete_all().unwrap();
        assert!(updated_config.is_empty());

        // Test deleting all after adding some entries
        let mut storage_second = create_initialized_storage();
        let updated_config = storage_second.delete_all().unwrap();
        assert!(updated_config.is_empty());
    }

    #[test]
    fn test_contains() {
        let storage = create_initialized_storage();

        // Test checking for a non-existent key
        assert!(!storage.contains(ConfigKeys::KeyHostname).unwrap());

        // Test checking for an existing key
        assert!(storage.contains(ConfigKeys::KeyAppKey).unwrap());
    }

    #[test]
    fn test_is_empty() {
        let storage = InMemoryKeyValueStorage::new(None).unwrap();

        // Test checking if newly created storage is empty
        assert!(storage.is_empty().unwrap());

        // Test checking if storage is not empty after adding an entry
        let storage_second = create_initialized_storage();
        assert!(!storage_second.is_empty().unwrap());
    }

    // tests to create a InMemoryKeyValueStorage object with a string config
    #[test]
    fn test_create_storage_from_json() {
        let json_config = r#"{
            "url": "https://example.com",
            "clientId": "myClientId",
            "clientKey": "myClientKey",
            "appKey": "myAppKey",
            "appOwnerPublicKey": "ownerPublicKey",
            "privateKey": "clientPrivateKey",
            "serverPublicKeyId": "serverPublicKeyId",
            "bat": "bindingToken",
            "bindingKey": "bindingKey",
            "hostname": "localhost"
        }"#;

        let storage = InMemoryKeyValueStorage::new(Some(json_config.to_string())).unwrap();

        // Test retrieving values using the get method
        assert_eq!(
            storage.get(ConfigKeys::KeyUrl).unwrap(),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyClientId).unwrap(),
            Some("myClientId".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyClientKey).unwrap(),
            Some("myClientKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyAppKey).unwrap(),
            Some("myAppKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyOwnerPublicKey).unwrap(),
            Some("ownerPublicKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyPrivateKey).unwrap(),
            Some("clientPrivateKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyServerPublicKeyId).unwrap(),
            Some("serverPublicKeyId".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyBindingToken).unwrap(),
            Some("bindingToken".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyBindingKey).unwrap(),
            Some("bindingKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyHostname).unwrap(),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_create_storage_from_base64_json() {
        let storage = create_initialized_storage();
        // Test retrieving values using the get method
        assert_eq!(
            storage.get(ConfigKeys::KeyUrl).unwrap(),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyClientId).unwrap(),
            Some("myClientId".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyClientKey).unwrap(),
            Some("myClientKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyAppKey).unwrap(),
            Some("myAppKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyOwnerPublicKey).unwrap(),
            Some("ownerPublicKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyPrivateKey).unwrap(),
            Some("clientPrivateKey".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyServerPublicKeyId).unwrap(),
            Some("serverPublicKeyId".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyBindingToken).unwrap(),
            Some("bindingToken".to_string())
        );
        assert_eq!(
            storage.get(ConfigKeys::KeyBindingKey).unwrap(),
            Some("bindingKey".to_string())
        );
    }

    #[test]
    fn test_create_storage_with_invalid_json() {
        let invalid_json = r#"{
            "url": "https://example.com",
            "clientId": "myClientId",
            "clientKey": "myClientKey",
            "invalidKey": "value"
        }"#; // This key is not valid

        let result = InMemoryKeyValueStorage::new(Some(invalid_json.to_string()));
        assert!(result.is_err()); // Expecting an error due to invalid key
    }

    #[test]
    fn test_create_storage_with_empty_string() {
        let storage = InMemoryKeyValueStorage::new(Some("".to_string())).unwrap();
        assert!(storage.is_empty().unwrap()); // Expecting storage to be empty
    }

    #[test]
    fn test_get_nonexistent_key() {
        let json_config = r#"{
            "url": "https://example.com"
        }"#;

        let storage = InMemoryKeyValueStorage::new(Some(json_config.to_string())).unwrap();

        // Test getting a key that doesn't exist
        assert_eq!(storage.get(ConfigKeys::KeyClientId).unwrap(), None);
    }

    fn create_initialized_storage() -> InMemoryKeyValueStorage {
        // This function provides an InMemoryStorage  object with all configKeys keys setup except localhost.
        let json_config = r#"{
            "url": "https://example.com",
            "clientId": "myClientId",
            "clientKey": "myClientKey",
            "appKey": "myAppKey",
            "appOwnerPublicKey": "ownerPublicKey",
            "privateKey": "clientPrivateKey",
            "serverPublicKeyId": "serverPublicKeyId",
            "bat": "bindingToken",
            "bindingKey": "bindingKey"
        }"#;

        let base64_config = STANDARD.encode(json_config);

        let storage = InMemoryKeyValueStorage::new(Some(base64_config)).unwrap();
        return storage;
    }
}
