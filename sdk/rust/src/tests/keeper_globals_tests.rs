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
    use crate::keeper_globals::{get_client_version, KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID};

    #[test]
    fn test_get_client_version_hardcode_true() {
        // Test the behavior when hardcode is true, it should return the hardcoded version.
        let version = get_client_version(true);

        // Assert that the version returned matches the hardcoded version
        assert_eq!(version, "17.0.0");
    }

    #[test]
    fn test_get_client_version_hardcode_false_empty_metadata() {
        // Test the behavior when hardcode is false, it should still return the hardcoded version.
        let version = get_client_version(false);

        // Should return the hardcoded version "17.0.0"
        assert_eq!(version, "17.0.0");
    }

    #[test]
    fn test_full_client_id() {
        // Test that the full client ID is "mr17.0.0"
        let client_id = &*KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID;
        assert_eq!(client_id, "mr17.0.0");
    }
}
