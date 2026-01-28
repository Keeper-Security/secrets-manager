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
mod pad_binary_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_pad_binary() {
        let data = b"Hello, World!";
        let padded = CryptoUtils::pad_binary(data);
        assert_eq!(padded.len(), data.len() + (16 - (data.len() % 16))); // Check length after padding
        assert_eq!(&padded[data.len()..], &[3, 3, 3]); // Assuming PKCS7 padding
    }
}

#[cfg(test)]
mod unpad_binary_tests {
    use crate::{crypto::CryptoUtils, custom_error::KSMRError};

    #[test]
    fn test_unpad_binary() {
        let data = b"Hello, World!\x03\x03\x03"; // Example with PKCS7 padding
        let unpadded = CryptoUtils::unpad_binary(data).unwrap();
        assert_eq!(&unpadded, b"Hello, World!");
    }

    #[test]
    fn test_unpad_binary_invalid() {
        let data = b"Hello, World!\x05\x05\x05\x05"; // Invalid padding
        let result = CryptoUtils::unpad_binary(data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::CryptoError("Invalid data length".to_string())
        );
    }

    #[test]
    fn test_unpad_binary_invalid_pad_length() {
        let data = b"Hello, World!\x05\x05\x05"; // Invalid padding
        let result = CryptoUtils::unpad_binary(data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::CryptoError("Invalid padding".to_string())
        );
    }
}

#[cfg(test)]
mod unpad_char_tests {
    use crate::{crypto::CryptoUtils, custom_error::KSMRError};

    #[test]
    fn test_unpad_char() {
        let data = b"Hello, World!\x04\x04\x04\x04"; // Example with padding
        let unpadded = CryptoUtils::unpad_char(data).unwrap();
        assert_eq!(&unpadded, b"Hello, World!");
    }

    #[test]
    fn test_unpad_char_invalid() {
        let data = b"Hello, World!\x05\x05\x05\x05"; // Invalid padding
        let result = CryptoUtils::unpad_char(data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::CryptoError("Invalid padding".to_string())
        );
    }
}

#[cfg(test)]
mod pad_data_tests {
    use crate::crypto::pad_data;

    #[test]
    fn test_pad_data_basic() {
        let data = b"Hello";
        let block_size = 8; // Block size of 8 bytes
        let padded = pad_data(data, block_size);

        // Check length
        assert_eq!(padded.len(), 8);
        // Check content
        assert_eq!(&padded[..5], data); // Original data
        assert_eq!(&padded[5..], &[3, 3, 3]); // Padding bytes
    }

    #[test]
    fn test_pad_data_exact_block_size() {
        let data: Vec<u8> = b"Hello!!!".to_vec(); // 8 bytes
        let mut data_clone = data.clone();
        let block_size = 8;
        let padded = pad_data(&data, block_size);
        let expected_padding: Vec<u8> = vec![8, 8, 8, 8, 8, 8, 8, 8];
        let _expected_data = data_clone.extend(expected_padding);

        // Check length
        assert_eq!(padded.len(), data.len() + block_size);
        // Check content (full padding should be added)
        assert_eq!(&padded[..], data_clone); // Original data
    }

    #[test]
    fn test_pad_data_multiple_blocks() {
        let data = b"Hello, World!"; // 13 bytes
        let block_size = 16;
        let padded = pad_data(data, block_size);

        // Check length
        assert_eq!(padded.len(), 16);
        // Check content
        assert_eq!(&padded[..13], data); // Original data
        assert_eq!(&padded[13..], &[3, 3, 3]); // Padding bytes
    }

    #[test]
    fn test_pad_data_small_data() {
        let data = b"Hi"; // 2 bytes
        let block_size = 4;
        let padded = pad_data(data, block_size);

        // Check length
        assert_eq!(padded.len(), 4);
        // Check content
        assert_eq!(&padded[..2], data); // Original data
        assert_eq!(&padded[2..], &[2, 2]); // Padding bytes
    }

    #[test]
    fn test_pad_data_empty_data() {
        let data: &[u8] = b""; // 0 bytes
        let block_size = 16;
        let padded = pad_data(data, block_size);

        // Check length
        assert_eq!(padded.len(), 16);
        // Check content (all padding)
        assert_eq!(&padded[..], &[16; 16]); // All padding bytes should be 16
    }
}

#[cfg(test)]
mod unpad_data_tests {
    use crate::{crypto::unpad_data, custom_error::KSMRError};

    #[test]
    fn test_unpad_data_valid() {
        let data = b"YELLOW SUBMA\x04\x04\x04\x04"; // Valid padding
        let result = unpad_data(data).unwrap();
        assert_eq!(&result, b"YELLOW SUBMA"); // Check unpadded data
    }

    #[test]
    fn test_unpad_data_valid_empty_padding() {
        let data = b"Hello!\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A"; // Valid padding of 1
        let result = unpad_data(data).unwrap();
        assert_eq!(&result, b"Hello!"); // Check unpadded data
    }

    #[test]
    fn test_unpad_data_empty_input() {
        let data: &[u8] = b""; // Empty input
        let result = unpad_data(data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::CryptoError("Data is empty".to_string())
        );
    }

    #[test]
    fn test_unpad_data_invalid_padding_length() {
        let data = b"Hello!\x05\x05\x05"; // Invalid padding
        let result = unpad_data(data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::CryptoError("Invalid padding bytes".to_string())
        );
    }

    #[test]
    fn test_unpad_data_excessive_padding() {
        let data = b"Hello!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"; // Padding exceeds block size
        let result = unpad_data(data);
        assert!(!result.is_err());
    }

    #[test]
    fn test_unpad_data_correct_padding_bytes_wrong_padding_length() {
        let data = b"Hello, World!\x02\x02"; // Invalid padding bytes
        let result = unpad_data(data);
        assert!(!result.is_err());
    }
}

#[cfg(test)]
mod bytes_to_int_tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use crate::{crypto::CryptoUtils, custom_error::KSMRError};

    #[test]
    fn test_valid_input() {
        assert_eq!(
            CryptoUtils::bytes_to_int(&[0, 0, 0, 0, 0, 0, 0, 1]),
            Ok(BigUint::from(1u16))
        );
        assert_eq!(
            CryptoUtils::bytes_to_int(&[0, 0, 0, 0, 0, 0, 1, 0]),
            Ok(BigUint::from(256u64))
        );
        assert_eq!(
            CryptoUtils::bytes_to_int(&[0, 1, 2, 3]),
            Ok(BigUint::from(66051u64))
        ); // 0x00010203
    }

    #[test]
    fn test_max_length() {
        // Maximum value for u128 is 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        let expected = BigUint::from(u128::MAX) + BigUint::from(1u128);

        // Create a byte array representing the maximum u128 value
        let bytes = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // This is 16 bytes of 0xFF

        // Assert that the conversion from bytes to u128 is correct
        assert_eq!(CryptoUtils::bytes_to_int(&bytes), Ok(expected));
    }

    #[test]
    fn test_too_long_input() {
        // Assert that input longer than 16 bytes does not return an error - this is the ideal case
        // We are just left shifting using a modulo, hence we wont encounter this issue and we wont trigger the overflow flag this way
        assert_eq!(
            CryptoUtils::bytes_to_int(&[1; 17]),
            Ok(BigUint::from_str("341616807575530379006368233343265341697").unwrap())
        ); // 17 bytes
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(
            CryptoUtils::bytes_to_int(&[]),
            Err(KSMRError::InsufficientBytes("Input is empty".to_string()))
        ); // Should return 0 for empty input
    }
}

#[cfg(test)]
mod url_safe_string_to_bytes_tests {
    use crate::crypto::CryptoUtils;
    use crate::custom_error::KSMRError;

    #[test]
    fn test_valid_input() {
        let encoded_str = "ZHVtbXkxMjM";
        let result = CryptoUtils::url_safe_str_to_bytes(encoded_str);
        assert_eq!(result, Ok(vec![100, 117, 109, 109, 121, 49, 50, 51]));
    }

    #[test]
    fn test_invalid_input() {
        let encoded_str = "abc#def$ghi"; // Invalid Base64 string since it has # and $
        let result = CryptoUtils::url_safe_str_to_bytes(encoded_str);
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid symbol 35, offset 3.".to_string()
            ))
        ); // Expect `InvalidBase64` error for invalid characters
    }
}

#[cfg(test)]
mod generate_random_bytes_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_generate_random_bytes_length() {
        let length = 16;
        let bytes = CryptoUtils::generate_random_bytes(length);
        assert_eq!(
            bytes.len(),
            length,
            "The length of the generated bytes should be {}",
            length
        );
    }

    #[test]
    fn test_generate_random_bytes_non_empty() {
        let length = 16;
        let bytes = CryptoUtils::generate_random_bytes(length);
        assert!(!bytes.is_empty(), "The generated bytes should not be empty");
    }

    #[test]
    fn test_generate_random_bytes_unique() {
        let length = 16;
        let bytes1 = CryptoUtils::generate_random_bytes(length);
        let bytes2 = CryptoUtils::generate_random_bytes(length);
        assert_ne!(
            bytes1, bytes2,
            "Generated byte arrays should not be the same"
        );
    }

    #[test]
    fn test_generate_random_bytes_varied_lengths() {
        for &length in &[1, 8, 16, 32, 64] {
            let bytes = CryptoUtils::generate_random_bytes(length);
            assert_eq!(
                bytes.len(),
                length,
                "The length of the generated bytes should be {}",
                length
            );
        }
    }
}

#[cfg(test)]
mod generate_encryption_key_bytes_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_generate_encryption_key_bytes_length() {
        let key = CryptoUtils::generate_encryption_key_bytes();
        // Check that the generated key is exactly 32 bytes long
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_encryption_key_bytes_randomness() {
        let key1 = CryptoUtils::generate_encryption_key_bytes();
        let key2 = CryptoUtils::generate_encryption_key_bytes();
        // Check that two consecutive keys are not the same
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_encryption_key_bytes_non_empty() {
        let key = CryptoUtils::generate_encryption_key_bytes();
        // Ensure the generated key is not empty
        assert!(!key.is_empty());
    }
}

#[cfg(test)]
mod bytes_to_url_safe_string_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_empty_bytes() {
        let input: &[u8] = &[];
        let result = CryptoUtils::bytes_to_url_safe_str(input);
        assert_eq!(result, "");
    }

    #[test]
    fn test_single_byte() {
        let input = &[1];
        let result = CryptoUtils::bytes_to_url_safe_str(input);
        assert_eq!(result, "AQ");
    }

    #[test]
    fn test_multiple_bytes() {
        let input = &[1, 2, 3, 4, 5];
        let result = CryptoUtils::bytes_to_url_safe_str(input);
        assert_eq!(result, "AQIDBAU");
    }

    #[test]
    fn test_url_safe() {
        let input = b"Hello, World!";
        let result = CryptoUtils::bytes_to_url_safe_str(input);
        assert_eq!(result, "SGVsbG8sIFdvcmxkIQ");
    }

    #[test]
    fn test_padding_removal() {
        let input = &[0b11111111, 0b11111111]; // FF
        let result = CryptoUtils::bytes_to_url_safe_str(input);
        assert_eq!(result, "__8"); // Example of URL-safe encoding
    }
}

#[cfg(test)]
mod url_safe_string_to_int_tests {
    use num_bigint::BigUint;

    use crate::crypto::CryptoUtils;

    #[test]
    fn test_valid_input() {
        let encoded_str = "ZHVtbXkxMjM"; // This should decode to valid bytes representing a u64
        let result = CryptoUtils::url_safe_str_to_int(encoded_str);
        assert_eq!(result, Ok(BigUint::from(7238812293020070451u64)));
    }
}

#[cfg(test)]
mod generate_ecc_keys_tests {
    use crate::crypto::CryptoUtils;
    use crate::custom_error::KSMRError;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, VerifyingKey};

    #[test]
    fn test_generate_ecc_keys() {
        // Generate ECC keys
        let signing_key = CryptoUtils::generate_ecc_keys()
            .map_err(|err| KSMRError::CryptoError(err.to_string()))
            .unwrap();

        // Create a verifying key from the signing key
        let verifying_key = VerifyingKey::from(&signing_key);

        // Ensure that we can create a signature with the generated key
        let message = b"Test message";
        let signature: Signature = signing_key.sign(message);

        // Verify that the signature is valid
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_encryption_key_bytes_length() {
        // Check the length of the generated encryption key bytes
        let encryption_key_bytes = CryptoUtils::generate_encryption_key_bytes();
        assert_eq!(
            encryption_key_bytes.len(),
            32,
            "Expected encryption key bytes to be of length 32"
        );
    }

    #[test]
    fn test_bytes_to_url_safe_str() {
        let bytes = b"Test data";
        let url_safe_str = CryptoUtils::bytes_to_url_safe_str(bytes);

        // Ensure that the resulting string is valid URL-safe Base64
        assert!(!url_safe_str.is_empty());
    }

    #[test]
    fn test_url_safe_str_to_int() {
        let bytes = b"Test data";
        let url_safe_str = CryptoUtils::bytes_to_url_safe_str(bytes);

        let result = CryptoUtils::url_safe_str_to_int(&url_safe_str);

        assert!(result.is_ok(), "Expected conversion to succeed");

        // Verify that we can convert back to bytes and then to int
        let int_value = result.unwrap();
        assert_eq!(
            int_value,
            CryptoUtils::bytes_to_int(bytes).unwrap(),
            "The integer values should match"
        );
    }
}

#[cfg(test)]
mod public_key_ecc_tests {
    use crate::crypto::CryptoUtils;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_public_key_ecc() {
        // Generate a random private key
        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);

        // Get the public key bytes
        let public_key_bytes = CryptoUtils::public_key_ecc(&private_key);

        // Ensure the public key bytes are not empty
        assert!(
            !public_key_bytes.is_empty(),
            "Public key bytes should not be empty"
        );

        // The public key should be in the uncompressed format (65 bytes)
        assert_eq!(
            public_key_bytes.len(),
            65,
            "Public key bytes length should be 65 for uncompressed format"
        );

        // Verify that the first byte is 0x04 (indicating an uncompressed point)
        assert_eq!(
            public_key_bytes[0], 0x04,
            "First byte should indicate uncompressed format"
        );
    }

    #[test]
    fn test_public_key_ecc_with_fixed_private_key() {
        // Fixed private key for consistent testing (hex representation)
        let private_key_bytes: [u8; 32] = [
            0x1E, 0x90, 0x68, 0xE4, 0xA7, 0xBF, 0x4D, 0x77, 0x3A, 0x46, 0x23, 0xB2, 0xAA, 0x45,
            0xA2, 0x4E, 0xB3, 0xD5, 0x6A, 0x92, 0x7F, 0x5A, 0x84, 0xC1, 0x7F, 0xC7, 0x7C, 0xE1,
            0x7A, 0x73, 0x36, 0x1D,
        ];
        let private_key = SigningKey::from_bytes((&private_key_bytes).into()).unwrap();

        // Get the public key bytes
        let public_key_bytes = CryptoUtils::public_key_ecc(&private_key);

        // Check the expected public key bytes
        let expected_public_key_bytes: [u8; 65] = [
            4, 114, 157, 21, 90, 252, 246, 174, 130, 152, 121, 99, 41, 136, 127, 198, 106, 226, 37,
            182, 222, 212, 74, 102, 55, 227, 126, 239, 129, 7, 55, 253, 34, 111, 213, 201, 10, 206,
            162, 86, 175, 83, 69, 153, 145, 48, 111, 12, 223, 36, 113, 42, 167, 82, 136, 18, 140,
            37, 140, 102, 74, 152, 35, 146, 2,
        ];

        assert_eq!(
            public_key_bytes.as_slice(),
            &expected_public_key_bytes,
            "Public key bytes do not match expected values"
        );
    }
}

#[cfg(test)]
mod generate_private_key_ecc_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_generate_private_key_ecc_length() {
        let signing_key = CryptoUtils::generate_private_key_ecc().unwrap();
        let key_bytes = signing_key.to_bytes();
        assert_eq!(
            key_bytes.len(),
            32,
            "The generated key should be 32 bytes long."
        );
    }

    #[test]
    fn test_generate_private_key_ecc_non_zero() {
        let signing_key = CryptoUtils::generate_private_key_ecc().unwrap();
        let key_bytes = signing_key.to_bytes();
        assert!(
            key_bytes.iter().any(|&byte| byte != 0),
            "The generated key should not be all zeros."
        );
    }

    #[test]
    fn test_generate_multiple_private_keys() {
        let key1 = CryptoUtils::generate_private_key_ecc().unwrap();
        let key2 = CryptoUtils::generate_private_key_ecc().unwrap();
        assert_ne!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Generated keys should be different."
        );
    }

    #[test]
    fn test_key_bytes_conversion() {
        let signing_key = CryptoUtils::generate_private_key_ecc().unwrap();
        let key_bytes = signing_key.to_bytes();
        let expected_length = 32;

        assert_eq!(
            key_bytes.len(),
            expected_length,
            "Key bytes should be the expected length."
        );
    }

    #[test]
    fn test_url_safe_conversion() {
        let signing_key = CryptoUtils::generate_private_key_ecc().unwrap();
        let key_bytes = signing_key.to_bytes();

        let private_key_str = CryptoUtils::bytes_to_url_safe_str(&key_bytes);
        let encryption_key_int = CryptoUtils::url_safe_str_to_int(&private_key_str)
            .expect("Failed to convert URL-safe Base64 string to integer");

        // Convert the encryption_key_int to bytes
        let int_bytes = encryption_key_int.to_bytes_be();
        let mut concatenated_bytes: [u8; 32] = [0u8; 32];
        // Handle leading zeros - pad from the right for big-endian
        let offset = 32 - int_bytes.len();
        concatenated_bytes[offset..].copy_from_slice(&int_bytes[..]);
        // Make sure the lengths match before comparison
        assert_eq!(
            concatenated_bytes.len(),
            key_bytes.len(),
            "Byte lengths should match."
        );

        // Compare the two slices (key_bytes needs to be converted to &[u8])
        let key_bytes_fixed: &[u8] = &key_bytes; // this will work if key_bytes is a GenericArray
        assert_eq!(
            &concatenated_bytes[..],
            key_bytes_fixed,
            "Converted integer bytes should match original key bytes."
        );
    }

    #[test]
    fn test_generate_private_key_ecc_reproducibility() {
        let key1 = CryptoUtils::generate_private_key_ecc().unwrap();
        let key2 = CryptoUtils::generate_private_key_ecc().unwrap();

        assert_ne!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Keys generated in two calls should be different."
        );
    }
}

#[cfg(test)]
mod generate_private_key_der_tests {
    use crate::crypto::CryptoUtils;
    use p256::ecdsa::VerifyingKey;

    #[test]
    fn test_generate_private_key_ecc() {
        let signing_key = CryptoUtils::generate_private_key_ecc().unwrap();

        // Ensure the key is not null and has the expected length
        assert!(
            signing_key.to_bytes().len() == 32,
            "SigningKey should be 32 bytes long."
        );

        // Optionally check if the corresponding public key can be derived
        let verifying_key: VerifyingKey = signing_key.verifying_key().clone();
        assert!(
            verifying_key.to_encoded_point(false).as_ref().len() > 0,
            "Public key should be derivable."
        );
    }

    #[test]
    fn test_generate_private_key_der() {
        let private_key_der = CryptoUtils::generate_private_key_der().unwrap();

        // Check that the returned DER is not empty
        assert!(
            !private_key_der.is_empty(),
            "Private key DER should not be empty."
        );

        // You can also check that the length is greater than some minimum size expected for DER encoded keys
        assert!(
            private_key_der.len() > 64,
            "Private key DER should be greater than 64 bytes."
        );
    }

    #[test]
    fn test_invalid_key_conversion() {
        let invalid_key = "invalid_key_format";
        let result = CryptoUtils::url_safe_str_to_int(invalid_key);
        assert!(
            result.is_err(),
            "Invalid key format should return an error."
        );
    }

    #[test]
    fn test_generate_random_bytes() {
        let bytes = CryptoUtils::generate_random_bytes(32);

        // Ensure that the generated bytes have the correct length
        assert_eq!(
            bytes.len(),
            32,
            "Generated random bytes should have length of 32."
        );

        // Ensure that two calls produce different results
        let another_bytes = CryptoUtils::generate_random_bytes(32);
        assert_ne!(
            bytes, another_bytes,
            "Consecutive random byte generations should not produce the same result."
        );
    }

    // You can add more tests as needed for other methods in CryptoUtils
}

#[cfg(test)]
mod generate_new_ecc_key_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_generate_new_ecc_key() {
        let key = CryptoUtils::generate_new_ecc_key();

        // Verify that the generated key is not empty
        assert!(
            !key.to_bytes().is_empty(),
            "Generated key should not be empty."
        );

        // Verify that the key can be used to create a public key
        let public_key = key.verifying_key();
        assert!(
            public_key.to_encoded_point(false).as_ref().len() > 0,
            "Public key should be valid and non-empty."
        );
    }

    #[test]
    fn test_generate_multiple_keys() {
        let key1 = CryptoUtils::generate_new_ecc_key();
        let key2 = CryptoUtils::generate_new_ecc_key();

        // Verify that generating two keys results in different keys
        assert_ne!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Two generated keys should be different."
        );
    }
}

#[cfg(test)]
mod encrypt_aes_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_encrypt_aes_gcm_success() {
        let key = [0u8; 32];
        let data = b"Hello, World!";

        // Encrypt the data
        let result = CryptoUtils::encrypt_aes_gcm(data, &key, None);

        // Ensure encryption was successful
        assert!(result.is_ok());

        // Check that the output has the expected length
        let encrypted_data = result.unwrap();
        assert!(encrypted_data.len() > data.len()); // Encrypted data should be longer than original
    }

    #[test]
    fn test_encrypt_aes_gcm_invalid_key_length() {
        let invalid_key = [0u8; 16]; // 16 bytes instead of 32
        let data = b"Hello, World!";

        // Attempt to encrypt with an invalid key length
        let result = CryptoUtils::encrypt_aes_gcm(data, &invalid_key, None);

        // Ensure it returns an error
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Cryptography module Error: Invalid key size"
        );
    }

    #[test]
    fn test_encrypt_aes_gcm_with_nonce() {
        let key = [0u8; 32]; // Replace with a secure random key in a real scenario
        let data = b"Hello, World!";
        let nonce = [0u8; 12]; // Replace with a secure random nonce in a real scenario

        // Encrypt the data using the provided nonce
        let result = CryptoUtils::encrypt_aes_gcm(data, &key, Some(&nonce));

        // Ensure encryption was successful
        assert!(result.is_ok());

        // Check that the output has the expected length
        let encrypted_data = result.unwrap();
        assert!(encrypted_data.len() > data.len()); // Encrypted data should be longer than original
    }

    #[test]
    fn test_encrypt_aes_gcm_failure() {
        let key = [0u8; 32];
        let data = b"";

        // Encrypt empty data
        let result = CryptoUtils::encrypt_aes_gcm(data, &key, None);

        // Ensure encryption was successful
        assert!(result.is_ok());

        // Check the length of the result
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 12 + 16); // Only nonce+tag should be returned
    }

    #[test]
    fn test_encrypt_aes_gcm_failure_2() {
        let key = [0u8; 32];
        let data = b"";
        let nonce = [0u8; 12]; // Replace with a secure random nonce in a real scenario

        // Encrypt empty data
        let result = CryptoUtils::encrypt_aes_gcm(data, &key, Some(&nonce));

        // Ensure encryption was successful
        assert!(result.is_ok());

        // Check the length of the result
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 12 + data.len() + 16);
    }
}

#[cfg(test)]
mod decrypt_aes_tests {
    use crate::crypto::CryptoUtils;
    use rand::Rng;

    #[test]
    fn test_decrypt_aes_success() {
        let key_bytes = [0u8; 32]; // Example key (32 bytes for AES-256)
        let data = b"Hello, world!"; // Example plaintext

        // Encrypt the data to generate valid encrypted output
        let nonce: [u8; 12] = rand::thread_rng().gen(); // Random nonce
        let encrypted_data = CryptoUtils::encrypt_aes_gcm(data, &key_bytes, Some(&nonce)).unwrap();

        // Now decrypt the encrypted data
        let decrypted_data = CryptoUtils::decrypt_aes(&encrypted_data, &key_bytes).unwrap();

        // Assert that the decrypted data matches the original plaintext
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_decrypt_aes_invalid_key_size() {
        let invalid_key_bytes = [0u8; 16]; // Invalid key size (16 bytes)
        let data = b"Hello, world!"; // Example plaintext

        // Encrypt the data first
        let nonce: [u8; 12] = rand::thread_rng().gen();
        let encrypted_data = CryptoUtils::encrypt_aes_gcm(data, &[0u8; 32], Some(&nonce)).unwrap();

        // Attempt to decrypt with an invalid key size
        let result = CryptoUtils::decrypt_aes(&encrypted_data, &invalid_key_bytes);

        // Assert that an error is returned
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Cryptography module Error: Invalid key size"
        );
    }

    #[test]
    fn test_decrypt_aes_invalid_data() {
        let key_bytes = [0u8; 32]; // Valid key
        let invalid_data = b"Invalid data"; // Not a valid encrypted output

        // Attempt to decrypt invalid data
        let result = CryptoUtils::decrypt_aes(invalid_data, &key_bytes);

        // Assert that an error is returned
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Cryptography module Error: aead::Error"
        );
    }

    #[test]
    fn test_decrypt_aes_empty_data() {
        let key_bytes = [0u8; 32]; // Example key

        // Attempt to decrypt empty data
        let result = CryptoUtils::decrypt_aes(b"", &key_bytes);

        // Assert that an error is returned
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Cryptography module Error: Data too short to contain nonce"
        );
    }
}

#[cfg(test)]
mod encrypt_aes_cbc_tests {
    use crate::crypto::CryptoUtils;

    #[test]
    fn test_encrypt_aes_cbc() {
        let key = b"verysecretkey!!!verysecretkey!!!"; // 16 bytes for AES-128
        let data = b"Hello, World!";

        let encrypted = CryptoUtils::encrypt_aes_cbc(data, key, None).unwrap();
        assert_ne!(encrypted, data);
        assert!(encrypted.len() > data.len());
    }

    #[test]
    fn test_encrypt_aes_cbc_kd() {
        let key = b"\xd6\x98\xc1\xde\x0f\xeb\xdf\xb8C\xbe\x88\x10\xc5.\x17\xf5Pro0[x\x888i[\xe1\xdd\x0f<\xfcm"; // 16 bytes for AES-128
        let data =
            b"~\xf9\xd9\xaa*\xb1\x069\xec\xdei4\x8e['#  '\x0c%\x94\xbfm/\xf1Q\xc6\xf3\x89\xef)";
        let nonce = b"R\x00\xd2u7\x01\xae\x91\xe5h\x05\x82r\x90\xfc\xaa";
        let result_expected =b"R\x00\xd2u7\x01\xae\x91\xe5h\x05\x82r\x90\xfc\xaaX\xcb\xed\n\x91\x7f\xe6\xe6w\xa3\x04z)\xdd[G\xef\xc5\x90\x97\xa5\x9a\x8d\xc8O/\x88\x1f\xe8+\xce,\tQ\xc9-r\x85_\x14\xd1D#\x14\xe1u\x8d\x02";

        let encrypted = CryptoUtils::encrypt_aes_cbc(data, key, Some(nonce)).unwrap();
        assert!(encrypted.len() > data.len());
        assert_eq!(encrypted, result_expected);
        assert_eq!(encrypted.len(), result_expected.len());
    }

    #[test]
    fn test_encrypt_with_specific_iv() {
        let key = b"verysecretkey!!!verysecretkey!!!"; // 16 bytes for AES-128
        let data = b"Hello, World!";
        let iv = b"uniqueiv12345678"; // 16 bytes IV

        let encrypted = CryptoUtils::encrypt_aes_cbc(data, key, Some(iv)).unwrap();
        assert_ne!(encrypted, data);
        assert!(encrypted.len() > data.len());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = b"verysecretkey!!!verysecretkey!!!";
        let data: &[u8] = b"";

        let encrypted = CryptoUtils::encrypt_aes_cbc(data, key, None).unwrap();
        assert_ne!(encrypted, data);
        assert!(encrypted.len() > 0);
    }

    #[test]
    fn test_encrypt_with_invalid_key() {
        let key = b"shortkey!"; // Invalid key length
        let data = b"Hello, World!";

        let result = CryptoUtils::encrypt_aes_cbc(data, key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = b"verysecretkey!!!verysecretkey!!!";
        let data =
            b"This is a longer piece of data that we are going to encrypt with AES CBC mode.";

        let encrypted = CryptoUtils::encrypt_aes_cbc(data, key, None).unwrap();
        assert_ne!(encrypted, data);
        assert!(encrypted.len() > data.len());
    }

    #[test]
    fn test_encrypt_repeated_calls() {
        let key = b"verysecretkey!!!verysecretkey!!!";
        let data = b"Hello, World!";

        let encrypted1 = CryptoUtils::encrypt_aes_cbc(data, key, None).unwrap();
        let encrypted2 = CryptoUtils::encrypt_aes_cbc(data, key, None).unwrap();

        // Ensure different results on repeated calls
        assert_ne!(encrypted1, encrypted2);
    }
}

#[cfg(test)]
mod decrypt_aes_cbc_tests {
    use crate::crypto::{unpad_data, CryptoUtils};

    const TEST_KEY: [u8; 32] = [0u8; 32]; // Example key for testing

    #[test]
    fn test_decrypt_aes_cbc_valid() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let data = b"Hello, World! This is a test!";
        let encrypted_data = CryptoUtils::encrypt_aes_cbc(data, &key, Some(&iv)).unwrap();
        let decrypted_data = CryptoUtils::decrypt_aes_cbc(&encrypted_data, &key).unwrap();
        let unpad_decrypted_data = unpad_data(&decrypted_data).unwrap();

        // Compare with the original data
        assert_eq!(unpad_decrypted_data, unpad_decrypted_data.to_vec()); // Convert `data` to Vec<u8>
    }

    #[test]
    fn test_decrypt_aes_cbc_invalid_key_size() {
        let data = b"Hello, World!";
        let result = CryptoUtils::decrypt_aes_cbc(data, &[0u8; 16]); // Invalid key size
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_aes_cbc_data_too_short() {
        let result = CryptoUtils::decrypt_aes_cbc(&[], &TEST_KEY); // Empty data
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_aes_cbc_invalid_data_length() {
        let result = CryptoUtils::decrypt_aes_cbc(b"short", &TEST_KEY); // Data is too short to contain IV
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_aes_cbc_with_invalid_padding() {
        // Prepare a ciphertext with invalid padding
        let invalid_padded_data = [0u8; 16]; // Invalid data that wouldn't decrypt correctly
        let result = CryptoUtils::decrypt_aes_cbc(&invalid_padded_data, &TEST_KEY);
        assert!(!result.is_err());
    }
}

#[cfg(test)]
#[cfg(test)]
mod public_encrypt_tests {

    use crate::crypto::CryptoUtils;
    use aes_gcm::aead::rand_core;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng; // Make sure to include rand_core for the random number generator

    #[test]
    fn test_public_encrypt_success() {
        let data = b"Hello, world!";
        let mut rng = OsRng; // Create a random number generator
        let server_private_key = SigningKey::random(&mut rng); // Generate a server private key
        let server_public_key = server_private_key.verifying_key().to_encoded_point(false);

        // Call the public_encrypt method
        let encrypted_result = CryptoUtils::public_encrypt(data, server_public_key.as_ref(), None);

        assert!(encrypted_result.is_ok());
        let result = encrypted_result.unwrap();
        assert!(!result.is_empty()); // Ensure some data was returned
        assert!(result.len() > server_public_key.len()); // Check that the result is longer than the public key
    }

    #[test]
    fn test_public_encrypt_with_idz() {
        let data = b"Hello, world!";
        let mut rng = OsRng; // Create a random number generator
        let server_private_key = SigningKey::random(&mut rng); // Generate a server private key
        let server_public_key = server_private_key.verifying_key().to_encoded_point(false);
        let idz = b"additional_data";

        // Call the public_encrypt method
        let encrypted_result =
            CryptoUtils::public_encrypt(data, server_public_key.as_ref(), Some(idz));

        assert!(encrypted_result.is_ok());
        let result = encrypted_result.unwrap();
        assert!(!result.is_empty());
        assert!(result.len() > server_public_key.len());
    }

    #[test]
    fn test_public_encrypt_invalid_key() {
        let data = b"Hello, world!";
        let invalid_public_key = [0u8; 65]; // An invalid public key (not a valid sec1 byte array)

        // Call the public_encrypt method with an invalid public key
        let encrypted_result = CryptoUtils::public_encrypt(data, &invalid_public_key, None);

        assert!(encrypted_result.is_err());
    }

    #[test]
    fn test_public_encrypt_empty_data() {
        let data = b"";
        let mut rng = OsRng; // Create a random number generator
        let server_private_key = SigningKey::random(&mut rng); // Generate a server private key
        let server_public_key = server_private_key.verifying_key().to_encoded_point(false);

        // Call the public_encrypt method with empty data
        let encrypted_result = CryptoUtils::public_encrypt(data, server_public_key.as_ref(), None);

        assert!(encrypted_result.is_ok());
        let result = encrypted_result.unwrap();
        assert!(!result.is_empty());
    }
}

#[cfg(test)]
mod hash_of_string_tests {
    use crate::{crypto::CryptoUtils, custom_error::KSMRError};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_valid_base64_string() {
        let input = "VGVzdCBkYXRh"; // Base64 for "Test data"
        let expected_hash = [
            226, 124, 130, 20, 190, 139, 124, 245, 188, 204, 124, 8, 36, 126, 60, 176, 193, 81, 74,
            72, 238, 31, 99, 25, 127, 228, 239, 62, 245, 29, 126, 111,
        ]; // Expected hash value for "Test data"

        let result = CryptoUtils::hash_of_string(input).unwrap();
        assert_eq!(result, expected_hash);
    }

    #[test]
    fn test_empty_string() {
        let input = ""; // Empty Base64 string
        let expected_hash = Sha256::digest(b""); // Expected hash for an empty byte array

        let result = CryptoUtils::hash_of_string(input).unwrap();
        assert_eq!(result, expected_hash.to_vec());
    }

    #[test]
    fn test_base64_with_padding() {
        let input = "SGVsbG8="; // Base64 for "Hello"
        let _expected_hash = Sha256::digest(b"Hello");

        let result = CryptoUtils::hash_of_string(input);
        assert_eq!(
            result,
            Err(KSMRError::CryptoError(
                "Base64 decoding failed: Invalid padding".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_base64_string() {
        let input = "InvalidBase64@String"; // Invalid Base64

        let result = CryptoUtils::hash_of_string(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_base64_string() {
        let input = "Not a Base64 string"; // Non-Base64 input

        let result = CryptoUtils::hash_of_string(input);
        assert!(result.is_err());
    }
}

#[cfg(test)]
#[cfg(test)]
mod decrypt_record_tests {
    use crate::crypto::CryptoUtils;
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn test_decrypt_record_valid_base64() {
        // Setup
        let secret_key = CryptoUtils::generate_random_bytes(32); // Generate a dummy secret key
        let original_data = b"Hello, World!";
        let encrypted_data =
            CryptoUtils::encrypt_aes_gcm(original_data, &secret_key, None).unwrap();
        let base64_encoded = BASE64_URL_SAFE_NO_PAD.encode(&encrypted_data);

        // Act
        let result = CryptoUtils::decrypt_record(base64_encoded.as_bytes(), &secret_key).unwrap();

        // Assert
        assert_eq!(result, "Hello, World!");
    }

    #[test]
    fn test_decrypt_record_invalid_base64() {
        // Setup
        let secret_key = CryptoUtils::generate_random_bytes(32); // Generate a dummy secret key
        let invalid_base64 = "!!!invalid_base64!!!";

        // Act & Assert
        let result = CryptoUtils::decrypt_record(invalid_base64.as_bytes(), &secret_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_record_raw_bytes() {
        // Setup
        let secret_key = CryptoUtils::generate_random_bytes(32); // Generate a dummy secret key
        let original_data = b"Raw byte data";
        let encrypted_data =
            CryptoUtils::encrypt_aes_gcm(original_data, &secret_key, None).unwrap();

        // Act
        let result = CryptoUtils::decrypt_record(&encrypted_data, &secret_key).unwrap();

        // Assert
        assert_eq!(result, "Raw byte data");
    }

    #[test]
    fn test_decrypt_record_invalid_utf8() {
        // Setup
        let secret_key = CryptoUtils::generate_random_bytes(32); // Generate a dummy secret key
        let raw_bytes: Vec<u8> = vec![0, 159, 146, 150]; // Invalid UTF-8 byte sequence
        let encrypted_data = CryptoUtils::encrypt_aes_gcm(&raw_bytes, &secret_key, None).unwrap();

        // Act
        let result = CryptoUtils::decrypt_record(&encrypted_data, &secret_key);

        // Assert
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod der_base64_private_key_to_private_key_tests {
    use crate::{crypto::CryptoUtils, custom_error::KSMRError};

    const VALID_DER_BASE64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgndw7rAhuJt5SxssfKPnP0Z3cO6wIbibeUsbLHyj5z9GhRANCAAQCwRNo15jaVxkYQM8WjMffSWxgT4OyieQ91V5WuAemZKKrV2+fV6No21GQihFs6F8pbYvRfYf8Z8i2wsXKeQW5"; // Replace with actual valid Base64-encoded DER

    #[test]
    fn test_valid_der_base64() {
        let result = CryptoUtils::der_base64_private_key_to_private_key(VALID_DER_BASE64);
        assert!(result.is_ok());

        let private_key = result.unwrap();
        println!("{:?}", private_key);
    }

    #[test]
    fn test_invalid_base64() {
        let invalid_base64 = "!!!invalid_base64!!!";
        let result = CryptoUtils::der_base64_private_key_to_private_key(invalid_base64);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_input() {
        let result = CryptoUtils::der_base64_private_key_to_private_key("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Cryptography module Error: Failed to convert DER to SecretKey: PKCS#8 ASN.1 error: ASN.1 DER message is incomplete: expected 1, actual 0 at DER byte 0");
    }

    #[test]
    fn test_whitespace_input() {
        let result = CryptoUtils::der_base64_private_key_to_private_key("   ");
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid symbol 32, offset 0.".to_string()
            ))
        );
    }

    #[test]
    fn test_non_base64_chars() {
        let non_base64 = "abcde@#%$!"; // Contains non-Base64 characters
        let result = CryptoUtils::der_base64_private_key_to_private_key(non_base64);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid symbol 64, offset 5.".to_string()
            ))
        );
    }

    #[test]
    fn test_incomplete_base64() {
        let incomplete_base64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ"; // Missing padding
        let result = CryptoUtils::der_base64_private_key_to_private_key(incomplete_base64);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(KSMRError::DecodeError("Invalid padding".to_string()))
        );
    }

    #[test]
    fn test_large_input() {
        let large_base64 = "A".repeat(10000); // Very large Base64 string
        let result = CryptoUtils::der_base64_private_key_to_private_key(&large_base64);
        assert!(result.is_err());
        assert_eq!(result,Err(KSMRError::CryptoError("Failed to convert DER to SecretKey: PKCS#8 ASN.1 error: unknown/unsupported ASN.1 DER tag: 0x00".to_string())));
    }

    #[test]
    fn test_valid_der_key_length() {
        let valid_length_base64 = VALID_DER_BASE64; // Replace with a valid DER key with correct length
        let result = CryptoUtils::der_base64_private_key_to_private_key(valid_length_base64);
        assert!(result.is_ok());

        let private_key = result.unwrap();
        println!("{:?}", private_key);
    }

    #[test]
    fn test_invalid_der_key_format() {
        let invalid_der_base64 = "MIIBVwIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ..."; // Replace with an actual Base64 string not conforming to expected DER format
        let result = CryptoUtils::der_base64_private_key_to_private_key(invalid_der_base64);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid symbol 46, offset 48.".to_string()
            ))
        );
    }
}

#[cfg(test)]
mod extract_public_key_bytes_tests {
    use crate::{crypto::CryptoUtils, custom_error::KSMRError};
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const VALID_DER_BASE64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgndw7rAhuJt5SxssfKPnP0Z3cO6wIbibeUsbLHyj5z9GhRANCAAQCwRNo15jaVxkYQM8WjMffSWxgT4OyieQ91V5WuAemZKKrV2+fV6No21GQihFs6F8pbYvRfYf8Z8i2wsXKeQW5"; // Replace with actual valid Base64-encoded DER

    #[test]
    fn test_valid_der_base64() {
        let public_key_bytes = CryptoUtils::extract_public_key_bytes(VALID_DER_BASE64);
        assert!(public_key_bytes.is_ok());

        let bytes = public_key_bytes.unwrap();
        assert_eq!(bytes.len(), 65); // Length of an uncompressed public key
        assert_eq!(bytes[0], 0x04); // Check if it starts with 0x04 (indicating uncompressed point)
    }

    #[test]
    fn test_invalid_base64() {
        let result = CryptoUtils::extract_public_key_bytes("invalid_base64");
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(KSMRError::DecodeError("Invalid padding".to_string()))
        );
    }

    #[test]
    fn test_empty_string() {
        let result = CryptoUtils::extract_public_key_bytes("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Cryptography module Error: Failed to load private key: PKCS#8 ASN.1 error: ASN.1 DER message is incomplete: expected 1, actual 0 at DER byte 0");
    }

    #[test]
    fn test_invalid_der_format() {
        // Using a valid base64 but not a valid DER key
        let invalid_der_base64 = STANDARD.encode(&[0u8; 10]); // Just an example, it won't be a valid key
        let result = CryptoUtils::extract_public_key_bytes(&invalid_der_base64);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Cryptography module Error: Failed to load private key: PKCS#8 ASN.1 error: unknown/unsupported ASN.1 DER tag: 0x00");
    }

    #[test]
    fn test_valid_private_key() {
        let private_key_der_base64 = VALID_DER_BASE64; // Use a valid DER private key here
        let public_key_bytes = CryptoUtils::extract_public_key_bytes(private_key_der_base64);
        assert!(public_key_bytes.is_ok());

        let bytes = public_key_bytes.unwrap();
        assert_eq!(bytes.len(), 65); // Length of an uncompressed public key
        assert_eq!(bytes[0], 0x04); // Check if it starts with 0x04 (indicating uncompressed point)
    }
}

#[cfg(test)]
mod sign_tests {
    use crate::crypto::CryptoUtils;
    use aes_gcm::aead::rand_core;
    use ecdsa::VerifyingKey;
    use p256::{
        ecdsa::{signature::Verifier, SigningKey},
        SecretKey,
    };
    use rand_core::OsRng;

    // Test data for signing
    const TEST_DATA: &[u8] = b"test data to sign";
    pub fn _public_key_from_private(private_key: &SecretKey) -> VerifyingKey<p256::NistP256> {
        let signing_key = SigningKey::from(private_key);
        let public_key = VerifyingKey::from(&signing_key);
        return public_key;
    }

    #[test]
    fn test_sign_with_valid_private_key() {
        // Generate a valid private key
        let mut rng = OsRng {};
        let private_key = SecretKey::random(&mut rng);
        // Sign the data
        let signature = CryptoUtils::sign_data(TEST_DATA, private_key.clone());
        assert!(signature.is_ok());

        // Verify the signature
        let signature = signature.unwrap();
        let signing_key = SigningKey::from(&private_key);
        let public_key = VerifyingKey::from(&signing_key);
        assert!(public_key.verify(TEST_DATA, &signature).is_ok());
    }

    #[test]
    fn test_sign_with_empty_data() {
        // Generate a valid private key
        let mut rng = OsRng {};
        let private_key = SecretKey::random(&mut rng);

        // Sign empty data
        let signature = CryptoUtils::sign_data(b"", private_key.clone());
        assert!(signature.is_ok());

        // Verify the signature
        let signature = signature.unwrap();
        let public_key = _public_key_from_private(&private_key);
        assert!(public_key.verify(b"", &signature).is_ok());
    }

    #[test]
    fn test_sign_with_large_data() {
        // Generate a valid private key
        let mut rng = OsRng {};
        let private_key = SecretKey::random(&mut rng);

        // Create large data to sign
        let large_data = vec![b'a'; 1000]; // 1000 bytes of 'a'

        // Sign the large data
        let signature = CryptoUtils::sign_data(&large_data, private_key.clone());
        assert!(signature.is_ok());

        // Verify the signature
        let signature = signature.unwrap();
        let public_key = _public_key_from_private(&private_key);
        assert!(public_key.verify(&large_data, &signature).is_ok());
    }
}
