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
    fn test_get_client_version_returns_cargo_version() {
        // Test that the version matches CARGO_PKG_VERSION (dynamic versioning)
        let version = get_client_version(false);
        let expected_version = env!("CARGO_PKG_VERSION");

        // Assert that the version returned matches the Cargo.toml version
        assert_eq!(version, expected_version);
    }

    #[test]
    fn test_get_client_version_ignores_hardcode_parameter() {
        // Test that hardcode parameter is ignored (always returns actual version)
        let version_true = get_client_version(true);
        let version_false = get_client_version(false);
        let expected_version = env!("CARGO_PKG_VERSION");

        // Both should return the same actual version
        assert_eq!(version_true, expected_version);
        assert_eq!(version_false, expected_version);
    }

    #[test]
    fn test_full_client_id_format() {
        // Test that the full client ID has correct format: "mr<version>"
        let client_id = &*KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID;
        let expected_version = env!("CARGO_PKG_VERSION");
        let expected_client_id = format!("mr{}", expected_version);

        assert_eq!(client_id, &expected_client_id);
    }

    #[test]
    fn test_client_id_starts_with_mr_prefix() {
        // Test that the client ID has the correct "mr" prefix for Rust SDK
        let client_id = &*KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID;
        assert!(client_id.starts_with("mr"));
    }
}
