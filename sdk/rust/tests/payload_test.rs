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
use keeper_secrets_manager_core::core::SecretsManager;

mod payload_test {

    #[test]
    fn test_transmission_key() {
        use super::*;

        let key_nums = [1, 2, 3, 4, 5, 6];

        for &key_num in key_nums.iter() {
            let transmission_key =
                SecretsManager::generate_transmission_key(&key_num.to_string()).unwrap();

            assert_eq!(
                key_num.to_string(),
                transmission_key.public_key_id,
                "public key id does not match the key num"
            );
            assert_eq!(
                32,
                transmission_key.key.len(),
                "The transmission key is not 32 bytes long"
            );
            assert_eq!(
                125,
                transmission_key.encrypted_key.len(),
                "The transmission encryptedKey is not 125 bytes long"
            );
        }
    }
}
