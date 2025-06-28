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

use serde::Serialize;
use serde_json;
use std::collections::HashMap;
use strum_macros::{Display, EnumString};

use crate::custom_error::KSMRError;

#[derive(Debug, Clone, Display, EnumString, Eq, PartialEq, Hash, serde::Deserialize, Serialize)]
pub enum ConfigKeys {
    KeyUrl, // base url for the Secrets Manager service
    KeyClientId,
    KeyClientKey, // The key that is used to identify the client before public key. This is token.
    KeyAppKey,    // The application key with which all secrets are encrypted
    KeyOwnerPublicKey, // The application owner public key, to create records
    KeyPrivateKey, // The client's private key
    KeyServerPublicKeyId, // Which public key should be using?

    KeyBindingToken,
    KeyBindingKey,
    KeyHostname,
}

impl ConfigKeys {
    /// Returns the string value associated with the enum variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::config_keys::ConfigKeys;
    /// let key = ConfigKeys::KeyUrl;
    /// assert_eq!(key.value(), "url");
    /// ```
    ///
    /// # Panics
    ///
    /// This method does not panic under normal circumstances. However, if you modify
    /// the match statement without providing all cases, it could lead to a panic.
    pub fn value(&self) -> &str {
        match self {
            ConfigKeys::KeyUrl => "url",
            ConfigKeys::KeyClientId => "clientId",
            ConfigKeys::KeyClientKey => "clientKey",
            ConfigKeys::KeyAppKey => "appKey",
            ConfigKeys::KeyOwnerPublicKey => "appOwnerPublicKey",
            ConfigKeys::KeyPrivateKey => "privateKey",
            ConfigKeys::KeyServerPublicKeyId => "serverPublicKeyId",
            ConfigKeys::KeyBindingToken => "bat",
            ConfigKeys::KeyBindingKey => "bindingKey",
            ConfigKeys::KeyHostname => "hostname",
        }
    }

    /// Returns an optional `ConfigKeys` enum variant corresponding to the provided string value.
    ///
    /// # Parameters
    ///
    /// - `value`: The string representation of the key.
    ///
    /// # Returns
    ///
    /// An `Option<ConfigKeys>` that will be `Some` if the string corresponds to a valid key,
    /// and `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::config_keys::ConfigKeys;
    /// assert_eq!(ConfigKeys::key_from_str("url"), Some(ConfigKeys::KeyUrl));
    /// assert_eq!(ConfigKeys::key_from_str("unknown"), None);
    /// ```
    pub fn key_from_str(value: &str) -> Option<Self> {
        match value {
            "url" => Some(ConfigKeys::KeyUrl),
            "clientId" => Some(ConfigKeys::KeyClientId),
            "clientKey" => Some(ConfigKeys::KeyClientKey),
            "appKey" => Some(ConfigKeys::KeyAppKey),
            "appOwnerPublicKey" => Some(ConfigKeys::KeyOwnerPublicKey),
            "privateKey" => Some(ConfigKeys::KeyPrivateKey),
            "serverPublicKeyId" => Some(ConfigKeys::KeyServerPublicKeyId),
            "bat" => Some(ConfigKeys::KeyBindingToken),
            "bindingKey" => Some(ConfigKeys::KeyBindingKey),
            "hostname" => Some(ConfigKeys::KeyHostname),
            _ => None,
        }
    }

    /// Returns an optional `ConfigKeys` enum variant from a string value,
    /// allowing for additional variants using both the key name and the enum variant name.
    ///
    /// # Parameters
    ///
    /// - `value`: The string representation of the key.
    ///
    /// # Returns
    ///
    /// An `Option<ConfigKeys>` that will be `Some` if the string corresponds to a valid key,
    /// and `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::config_keys::ConfigKeys;
    /// assert_eq!(ConfigKeys::get_enum("url"), Some(ConfigKeys::KeyUrl));
    /// assert_eq!(ConfigKeys::get_enum("KeyClientId"), Some(ConfigKeys::KeyClientId));
    /// assert_eq!(ConfigKeys::get_enum("invalidKey"), None);
    /// ```
    pub fn get_enum(value: &str) -> Option<Self> {
        match value {
            "url" | "KeyUrl" => Some(ConfigKeys::KeyUrl),
            "clientId" | "KeyClientId" => Some(ConfigKeys::KeyClientId),
            "clientKey" | "KeyClientKey" => Some(ConfigKeys::KeyClientKey),
            "appKey" | "KeyAppKey" => Some(ConfigKeys::KeyAppKey),
            "appOwnerPublicKey" | "KeyOwnerPublicKey" => Some(ConfigKeys::KeyOwnerPublicKey),
            "privateKey" | "KeyPrivateKey" => Some(ConfigKeys::KeyPrivateKey),
            "serverPublicKeyId" | "KeyServerPublicKeyId" => Some(ConfigKeys::KeyServerPublicKeyId),
            "bat" | "KeyBindingToken" => Some(ConfigKeys::KeyBindingToken),
            "bindingKey" | "KeyBindingKey" => Some(ConfigKeys::KeyBindingKey),
            "hostname" | "KeyHostname" => Some(ConfigKeys::KeyHostname),
            _ => None,
        }
    }
}

/// Custom deserialization function for a `HashMap<ConfigKeys, String>`.
///
/// This function deserializes a map from a JSON string into a `HashMap` where the keys
/// are of type `ConfigKeys`. If an invalid key is encountered, it returns an error.
///
/// # Parameters
///
/// - `json_data`: A string containing the JSON structure that represents the map.
///
/// # Returns
///
/// A `Result<HashMap<ConfigKeys, String>, serde_json::Error>` that contains the deserialized
/// `HashMap` if successful, or an error if an invalid key is found or if the input JSON is invalid.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::config_keys::{ConfigKeys, deserialize_map_from_str};
/// use std::collections::HashMap;
///
/// let json_data = r#"{"url": "http://example.com"}"#;
///
/// // Use the function to deserialize the JSON string directly into a HashMap<ConfigKeys, String>
/// let result: HashMap<ConfigKeys, String> = deserialize_map_from_str(json_data).unwrap();
/// assert_eq!(result.get(&ConfigKeys::KeyUrl), Some(&"http://example.com".to_string()));
/// ```
///
/// # Errors
///
/// This function will return a `serde_json::Error` if any key in the input map is not valid
/// according to the `ConfigKeys` enum or if the JSON structure is malformed.
///
/// # Panics
///
/// This function does not panic under normal circumstances.
pub fn deserialize_map_from_str(json_data: &str) -> Result<HashMap<ConfigKeys, String>, KSMRError> {
    let map: HashMap<String, String> = serde_json::from_str(json_data)
        .map_err(|e| KSMRError::SerializationError(format!("JSON deserialization error: {}", e)))?;
    let mut result = HashMap::new();

    for (key, value) in map {
        if let Some(enum_key) = ConfigKeys::key_from_str(&key) {
            result.insert(enum_key, value);
        } else {
            return Err(KSMRError::SerializationError(format!(
                "Failed to parse JSON: {}",
                key
            )));
        }
    }
    Ok(result)
}
