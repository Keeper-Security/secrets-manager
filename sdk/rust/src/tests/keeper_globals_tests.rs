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
    use crate::keeper_globals::get_client_version;

    #[test]
    fn test_get_client_version_hardcode_true() {
        // Test the behavior when hardcode is true, it should return the SDK version directly.
        let version = get_client_version(true);

        // Assert that the version returned matches the SDK version
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_get_client_version_hardcode_false_empty_metadata() {
        // Simulate an environment where cargo metadata command fails or returns nothing
        // This test will just verify the fallback mechanism if metadata retrieval fails.

        // You could potentially use something like a temp Cargo.toml for testing.
        let version = get_client_version(false);

        // If metadata fails, it should fall back to the default version, which is `SDK_VERSION`
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }
}
