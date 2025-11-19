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
mod full_test_aes {
    use keeper_secrets_manager_core::crypto::CryptoUtils;
    #[test]
    fn test_happy_path_test() {
        let key = [0u8; 32];
        let data = b"Hello, World!";

        // Encrypt the data
        let result = CryptoUtils::encrypt_aes_gcm(data, &key, None);
        assert!(result.is_ok());
        let encrypted_data = result.unwrap();

        // Decrypt the data
        let result_data = CryptoUtils::decrypt_aes(&encrypted_data, &key);
        assert!(result_data.is_ok());
        let decrypted_data = result_data.unwrap();
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_happy_path_test_cbc() {
        let key = [0u8; 32];
        let data = b"Hello, World!";

        // Encrypt the data
        let result = CryptoUtils::encrypt_aes_cbc(data, &key, None);
        assert!(result.is_ok());
        let encrypted_data = result.unwrap();

        // Decrypt the data
        let result_data = CryptoUtils::decrypt_aes_cbc(&encrypted_data, &key);
        assert!(result_data.is_ok());
        let decrypted_data = result_data.unwrap();
        assert_ne!(decrypted_data, data);
        let unpadded_decrypted_data = CryptoUtils::unpad_binary(&decrypted_data).unwrap();
        assert_eq!(unpadded_decrypted_data, data);
    }
}
