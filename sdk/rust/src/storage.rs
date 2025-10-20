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

use crate::config_keys::ConfigKeys;
use crate::custom_error::KSMRError;
use crate::enums::KvStoreType;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use serde_json::{self};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::{env, fs};

pub trait KeyValueStorage {
    fn read_storage(&self) -> Result<HashMap<ConfigKeys, String>, KSMRError>;
    fn save_storage(
        &mut self,
        updated_config: HashMap<ConfigKeys, String>,
    ) -> Result<bool, KSMRError>;
    fn get(&self, key: ConfigKeys) -> Result<Option<String>, KSMRError>;
    fn set(
        &mut self,
        key: ConfigKeys,
        value: String,
    ) -> Result<HashMap<ConfigKeys, String>, KSMRError>;
    fn delete(&mut self, key: ConfigKeys) -> Result<HashMap<ConfigKeys, String>, KSMRError>;
    fn delete_all(&mut self) -> Result<HashMap<ConfigKeys, String>, KSMRError>;
    fn contains(&self, key: ConfigKeys) -> Result<bool, KSMRError>;
    fn create_config_file_if_missing(&self) -> Result<(), KSMRError>;
    fn is_empty(&self) -> Result<bool, KSMRError>;
}

#[derive(Clone)]
pub struct FileKeyValueStorage {
    config_file_location: String,
}

impl FileKeyValueStorage {
    const DEFAULT_CONFIG_FILE_LOCATION: &str = "client-config.json";
    pub fn new(config_file_location: Option<String>) -> Result<Self, KSMRError> {
        let location = config_file_location
            .or_else(|| env::var("KSM_CONFIG_FILE").ok())
            .unwrap_or_else(|| Self::DEFAULT_CONFIG_FILE_LOCATION.to_string());

        Ok(FileKeyValueStorage {
            config_file_location: location,
        })
    }

    pub fn new_config_storage(file_name: String) -> Result<KvStoreType, KSMRError> {
        let file_storage = FileKeyValueStorage::new(Some(file_name.to_string()))?;
        Ok(KvStoreType::File(file_storage))
    }
}

impl KeyValueStorage for FileKeyValueStorage {
    fn read_storage(&self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        // Check if the config file exists, create it if necessary
        self.create_config_file_if_missing().map_err(|err| {
            KSMRError::StorageError(format!("Failed to ensure config file exists: {}", err))
        })?;

        // Check if the file can be opened
        let file = File::open(&self.config_file_location).map_err(|err| {
            KSMRError::StorageError(format!(
                "Unable to open config file {}: {}",
                self.config_file_location, err
            ))
        })?;

        // Read file contents into buffer
        let mut reader = BufReader::new(file);
        let mut contents = String::new();
        reader
            .read_to_string(&mut contents)
            .map_err(|err| KSMRError::StorageError(format!("Failed to read file: {}", err)))?;

        // Deserialize the string to JSON
        let config_result: Result<HashMap<ConfigKeys, String>, KSMRError> =
            serde_json::from_str(&contents)
                .map_err(|err| KSMRError::StorageError(format!("Failed to parse JSON: {}", err)));

        match config_result {
            Ok(config) => Ok(config),
            Err(err) => {
                // Print the error details in case JSON parsing fails
                eprintln!("Failed to parse JSON: {}", err);
                Err(KSMRError::StorageError(format!(
                    "Failed to parse JSON: {}",
                    err
                )))
            }
        }
    }

    fn save_storage(
        &mut self,
        updated_config: HashMap<ConfigKeys, String>,
    ) -> Result<bool, KSMRError> {
        // Ensure the config file exists, create it if missing
        self.create_config_file_if_missing().map_err(|err| {
            KSMRError::StorageError(format!("Failed to ensure config file exists: {}", err))
        })?;

        // Open the file in write mode and truncate it
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true) // Clear the file before writing
            .open(&self.config_file_location)
            .map_err(|err| {
                KSMRError::StorageError(format!("Failed to open config file for writing: {}", err))
            })?;

        // Serialize the updated config to JSON
        let json_data = serde_json::to_string_pretty(&updated_config).map_err(|err| {
            KSMRError::StorageError(format!("Failed to serialize config to JSON: {}", err))
        })?;

        // Write the JSON data to the file
        file.write_all(json_data.as_bytes()).map_err(|err| {
            KSMRError::StorageError(format!("Failed to write JSON to config file: {}", err))
        })?;

        Ok(true)
    }

    fn get(&self, key: ConfigKeys) -> Result<Option<String>, KSMRError> {
        let config: HashMap<ConfigKeys, String> = self
            .read_storage()
            .map_err(|err| KSMRError::StorageError(format!("Failed to Read storage: {}", err)))?;

        // Return the value corresponding to the key, cloning the String to give ownership
        Ok(config.get(&key).cloned())
    }

    fn set(
        &mut self,
        key: ConfigKeys,
        value: String,
    ) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        // Check if the key is valid
        if ConfigKeys::get_enum(key.value()).is_none() {
            return Err(KSMRError::StorageError(format!("Invalid key: {:?}", key)));
        }

        // Read the current configuration
        let mut config = self
            .read_storage()
            .map_err(|err| KSMRError::StorageError(format!("Failed to read storage: {}", err)))?;

        // Update the value for the given key
        config.insert(key, value);

        // Save the updated configuration
        self.save_storage(config.clone()).map_err(|err| {
            KSMRError::StorageError(format!("Failed to save updated config: {}", err))
        })?;

        Ok(config) // Return the updated config
    }

    fn delete(&mut self, key: ConfigKeys) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        // Read the current configuration
        let mut config = self
            .read_storage()
            .map_err(|err| KSMRError::StorageError(format!("Failed to read storage: {}", err)))?;

        // Check if the key exists in the config and remove it
        if config.remove(&key).is_some() {
            log::debug!("Removed key {}", key);
        } else {
            log::debug!("No key {} was found in config", key);
        }

        // Save the updated configuration
        self.save_storage(config.clone()).map_err(|err| {
            KSMRError::StorageError(format!("Failed to save updated config: {}", err))
        })?;

        Ok(config) // Return the updated config
    }

    fn delete_all(&mut self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        // Check if we are able to read storage and read from storage
        let mut config = self
            .read_storage()
            .map_err(|e| KSMRError::StorageError(format!("Failed to read storage: {}", e)))?;

        // Clear the configuration
        config.clear();

        // Save the cleared configuration
        self.save_storage(config.clone()).map_err(|e| {
            KSMRError::StorageError(format!("Failed to save cleared config: {}", e))
        })?;

        Ok(config) // Return the cleared config
    }

    fn contains(&self, key: ConfigKeys) -> Result<bool, KSMRError> {
        // Read the current configuration
        let config = self
            .read_storage()
            .map_err(|e| KSMRError::StorageError(format!("Failed to read storage: {}", e)))?;

        // Check if the key exists in the config
        Ok(config.contains_key(&key))
    }

    fn create_config_file_if_missing(&self) -> Result<(), KSMRError> {
        // Check if parent directory exists, if not, create it.
        if let Some(parent) = Path::new(&self.config_file_location).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KSMRError::DirectoryCreationError(parent.display().to_string(), e))?;
        }

        // Check if the configuration file exists, if not, create it.
        let config_path = Path::new(&self.config_file_location);
        if !config_path.exists() {
            let mut file = File::create(config_path)
                .map_err(|e| KSMRError::FileCreationError(config_path.display().to_string(), e))?;

            // Attempt to write an empty JSON object to the file
            let empty_json_string = b"{}";
            file.write_all(empty_json_string)
                .map_err(|e| KSMRError::FileWriteError(config_path.display().to_string(), e))?;
        }

        Ok(())
    }

    fn is_empty(&self) -> Result<bool, KSMRError> {
        // Attempt to read the storage and handle errors using custom KSMRError
        let config = self
            .read_storage()
            .map_err(|e| KSMRError::StorageError(format!("Failed to read storage: {}", e)))?;

        // Check if the config is empty and return the result
        Ok(config.is_empty())
    }
}

#[derive(Clone)]
pub struct InMemoryKeyValueStorage {
    config: HashMap<ConfigKeys, String>,
}

impl InMemoryKeyValueStorage {
    pub fn new(config: Option<String>) -> Result<Self, KSMRError> {
        let mut config_map: HashMap<ConfigKeys, String> = HashMap::new();

        if let Some(cfg) = config {
            if Self::is_base64(&cfg) {
                // Try decoding as padded, then un-padded
                let decoded_bytes = STANDARD
                    .decode(&cfg)
                    .or_else(|_| STANDARD_NO_PAD.decode(&cfg))
                    .map_err(|e| {
                        KSMRError::DecodeError(format!("Failed to decode Base64 string: {}", e))
                    })?;

                let decoded_string = String::from_utf8(decoded_bytes).map_err(|e| {
                    KSMRError::StringConversionError(format!(
                        "Failed to convert decoded bytes to string: {}",
                        e
                    ))
                })?;

                config_map = Self::json_to_dict(&decoded_string)?;
            } else {
                // Directly parse the JSON string
                config_map = Self::json_to_dict(&cfg)?;
            }
        }
        Ok(InMemoryKeyValueStorage { config: config_map })
    }

    pub fn new_config_storage(config: Option<String>) -> Result<KvStoreType, KSMRError> {
        let in_memory = InMemoryKeyValueStorage::new(config)?;
        Ok(KvStoreType::InMemory(in_memory))
    }

    fn is_base64(s: &str) -> bool {
        // Accept either padded or un-padded Base64
        STANDARD.decode(s).is_ok() || STANDARD_NO_PAD.decode(s).is_ok()
    }

    pub fn json_to_dict(json_str: &str) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        // Handle empty string as an empty JSON object
        let json_str = if json_str.is_empty() { "{}" } else { json_str };

        // Deserialize the JSON string
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| KSMRError::SerializationError(format!("Failed to parse JSON: {}", e)))?;

        let mut result = HashMap::new();

        // Ensure we are dealing with a JSON object
        if let serde_json::Value::Object(obj) = value {
            for (k, v) in obj {
                if let serde_json::Value::String(s) = v {
                    // Attempt to convert the key to a ConfigKeys enum
                    if let Some(key) = ConfigKeys::get_enum(&k) {
                        result.insert(key, s);
                    } else {
                        return Err(KSMRError::SerializationError(format!(
                            "Invalid key in JSON: {}",
                            k
                        )));
                    }
                } else {
                    return Err(KSMRError::SerializationError(format!(
                        "Expected string value for key: {}",
                        k
                    )));
                }
            }
        } else {
            return Err(KSMRError::SerializationError(
                "Expected JSON object".to_string(),
            ));
        }

        Ok(result) // Return the populated HashMap
    }
}

impl KeyValueStorage for InMemoryKeyValueStorage {
    fn read_storage(&self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        Ok(self.config.clone()) // Return a clone of the in-memory storage
    }

    fn save_storage(
        &mut self,
        _updated_config: HashMap<ConfigKeys, String>,
    ) -> Result<bool, KSMRError> {
        // Since this is in-memory, we just replace the storage
        self.config = _updated_config;
        Ok(true)
    }

    fn get(&self, key: ConfigKeys) -> Result<Option<String>, KSMRError> {
        Ok(self.config.get(&key).cloned()) // Get the value for the given key
    }

    fn set(
        &mut self,
        key: ConfigKeys,
        value: String,
    ) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.config.insert(key, value.clone()); // Insert or update the key
        Ok(self.config.clone()) // Return the updated storage
    }

    fn delete(&mut self, key: ConfigKeys) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.config.remove(&key); // Remove the key if it exists
        Ok(self.config.clone()) // Return the updated storage
    }

    fn delete_all(&mut self) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
        self.config.clear(); // Clear all entries
        Ok(self.config.clone()) // Return the cleared storage
    }

    fn contains(&self, key: ConfigKeys) -> Result<bool, KSMRError> {
        Ok(self.config.contains_key(&key)) // Check if the key exists
    }

    fn create_config_file_if_missing(&self) -> Result<(), KSMRError> {
        // No file to create for in-memory storage
        Ok(())
    }

    fn is_empty(&self) -> Result<bool, KSMRError> {
        Ok(self.config.is_empty()) // Check if storage is empty
    }
}
