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
mod tests {
    use std::collections::HashMap;

    use crate::config_keys::{deserialize_map_from_str, ConfigKeys};
    use serde_json::json;

    #[test]
    fn test_value() {
        assert_eq!(ConfigKeys::KeyUrl.value(), "url");
        assert_eq!(ConfigKeys::KeyClientId.value(), "clientId");
        assert_eq!(ConfigKeys::KeyAppKey.value(), "appKey");
    }

    #[test]
    fn test_key_from_str() {
        assert_eq!(ConfigKeys::key_from_str("url"), Some(ConfigKeys::KeyUrl));
        assert_eq!(
            ConfigKeys::key_from_str("clientId"),
            Some(ConfigKeys::KeyClientId)
        );
        assert_eq!(ConfigKeys::key_from_str("unknown"), None);
    }

    #[test]
    fn test_get_enum() {
        assert_eq!(ConfigKeys::get_enum("url"), Some(ConfigKeys::KeyUrl));
        assert_eq!(
            ConfigKeys::get_enum("clientId"),
            Some(ConfigKeys::KeyClientId)
        );
        assert_eq!(ConfigKeys::get_enum("invalidKey"), None);
    }

    #[test]
    fn test_deserialize_map() {
        let json_data = json!({
            "url": "http://example.com",
            "clientId": "12345"
        });

        // Create a Deserializer from the JSON data
        let binding = json_data.to_string();

        // Use the deserialize_map function to convert to HashMap<ConfigKeys, String>
        let result: Result<HashMap<ConfigKeys, String>, _> = deserialize_map_from_str(&binding);

        // Assertions
        let result = result.unwrap(); // Unwrap the result to get the HashMap

        assert_eq!(
            result.get(&ConfigKeys::KeyUrl),
            Some(&"http://example.com".to_string())
        );
        assert_eq!(
            result.get(&ConfigKeys::KeyClientId),
            Some(&"12345".to_string())
        );
    }

    #[test]
    fn test_deserialize_map_invalid_key() {
        use serde_json::json;
        use serde_json::Value;

        let json_data: Value = json!({
            "invalidKey": "someValue"
        });

        let result: Result<HashMap<ConfigKeys, String>, _> =
            deserialize_map_from_str(&json_data.to_string());

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "JSON serialization/deserialization failed: Failed to parse JSON: invalidKey"
        );
    }
}
