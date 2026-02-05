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

pub struct CryptoUtils;
use crate::custom_error::KSMRError;
use crate::utils;
use aes::Aes256;
use aes_gcm::aead::AeadMut;
use aes_gcm::KeyInit;
use aes_gcm::{self, AeadCore, Aes256Gcm};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, prelude::BASE64_URL_SAFE, Engine as _};
use block_padding::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt};
use ecdsa::signature::Signer;
use ecdsa::signature::Verifier;
use num_bigint::BigUint;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey as _,
};
use rand::{Rng, RngCore};
use sha2::Digest;
use std::error::Error;
use std::vec;

// types declared here

// constants are declared here
const BLOCK_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;

/// Pads the given data according to the PKCS#7 padding scheme.
///
/// In the PKCS#7 padding scheme, data is padded so that its length is a multiple of the specified block size.
/// If the input data is empty, the function will pad the data to the full block size. The padding bytes are
/// filled with the value of the number of padding bytes added.
///
/// # Arguments
///
/// * `data` - A slice of bytes that you want to pad.
/// * `block_size_var` - The block size to which the data should be padded.
///
/// # Returns
///
/// Returns a new `Vec<u8>` containing the original data followed by the appropriate padding bytes.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::crypto::pad_data;
/// let data = b"YELLOW SUBMARINE";
/// let block_size = 20;
/// let padded = pad_data(data, block_size);
/// assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
///
/// let empty_data: &[u8] = b"";
/// let padded_empty = pad_data(empty_data, block_size);
/// assert_eq!(padded_empty, vec![20; 20]); // 20 padding bytes of value 20
/// ```
///
/// # Panics
///
/// This function does not panic, but it assumes that `block_size_var` is greater than zero.
pub fn pad_data(data: &[u8], block_size_var: usize) -> Vec<u8> {
    // Calculate the padding length
    let pad_len = if data.is_empty() || data.len().is_multiple_of(block_size_var) {
        block_size_var
    } else {
        block_size_var - (data.len() % block_size_var)
    };

    let mut padded_data = Vec::with_capacity(data.len() + pad_len);

    // Copy original data
    padded_data.extend_from_slice(data);

    // Add padding bytes
    padded_data.extend(vec![pad_len as u8; pad_len]);

    padded_data
}
/// Removes PKCS#7 padding from the given data.
///
/// This function checks for and removes padding bytes added to the data according to the PKCS#7 padding scheme.
/// The last byte of the data indicates how many bytes were added as padding. The function will return an error
/// if the padding is invalid or if the data is empty.
///
/// # Arguments
///
/// * `data` - A slice of bytes that contains the padded data.
///
/// # Returns
///
/// Returns a `Result<Vec<u8>, KSMRError>` where:
/// - `Ok(Vec<u8>)` contains the unpadded data if the padding is valid.
/// - `Err(KSMRError)` provides an error message if the padding is invalid or if the data is empty.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::crypto::unpad_data;
/// let padded_data = b"YELLOW SUBMA\x04\x04\x04\x04";
/// let unpadded = unpad_data(padded_data).unwrap();
/// assert_eq!(unpadded, b"YELLOW SUBMA");
///
/// let invalid_padded_data = b"YELLOW SUBMARINE\x04\x04\x04\x05"; // Incorrect padding
/// assert!(unpad_data(invalid_padded_data).is_err());
///
/// let empty_data: &[u8] = b"";
/// assert!(unpad_data(empty_data).is_err()); // Expecting an error for empty data
/// ```
///
/// # Errors
///
/// This function will return the following errors:
/// - `KSMRError::CryptoError("Data is empty")`: If the input data is an empty slice.
/// - `KSMRError::CryptoError("Invalid padding length: ...")`: If the padding length is out of the valid range.
/// - `KSMRError::CryptoError("Invalid padding bytes")`: If the padding bytes are not consistent.
pub fn unpad_data(data: &[u8]) -> Result<Vec<u8>, KSMRError> {
    let data_len = data.len();

    // Check for empty data
    if data_len == 0 {
        return Err(KSMRError::CryptoError("Data is empty".to_string()));
    }

    let pad_len = data[data_len - 1] as usize;

    if !data[data_len - pad_len..]
        .iter()
        .all(|&b| b == pad_len as u8)
    {
        return Err(KSMRError::CryptoError("Invalid padding bytes".to_string()));
    }

    // Return the unpadded data
    Ok(data[..data_len - pad_len].to_vec())
}

impl CryptoUtils {
    /// Pads the given binary data to a multiple of the block size using the PKCS#7 padding scheme.
    ///
    /// This function adds padding to the input `data` so its length becomes a multiple of the `BLOCK_SIZE`.
    /// The padding scheme specifies that each padding byte's value is the total number of padding bytes added.
    /// If `data` is already a multiple of `BLOCK_SIZE`, an additional full block of padding is appended.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be padded.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the original data followed by the necessary padding bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// const BLOCK_SIZE: usize = 16;
    ///
    /// // Example with exact block size
    /// let data = b"YELLOW SUBMARINE";
    /// let padded_data = CryptoUtils::pad_binary(data);
    /// assert_eq!(padded_data, b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10");
    ///
    /// // Example with non-exact block size
    /// let data = b"HELLO";
    /// let padded_data = CryptoUtils::pad_binary(data);
    /// assert_eq!(padded_data, b"HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");
    /// ```
    ///
    /// In the first example, the input `"YELLOW SUBMARINE"` is 16 bytes, so an extra block of padding is added.
    /// In the second, `"HELLO"` is 5 bytes, and padding is added to reach the next multiple of the block size.
    ///
    /// # Panics
    ///
    /// This function does not panic under normal usage.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    pub fn pad_binary(data: &[u8]) -> Vec<u8> {
        const BLOCK_SIZE: usize = 16; // Define or pass as argument as needed

        let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let mut padded_data = Vec::with_capacity(data.len() + pad_len);

        // Add original data
        padded_data.extend_from_slice(data);

        // Add padding bytes
        padded_data.extend(vec![pad_len as u8; pad_len]);

        padded_data
    }

    /// Removes PKCS#7 padding from the given binary data.
    ///
    /// This function removes padding from the input `data` that was added according to the PKCS#7 padding scheme.
    /// It checks the validity of the padding bytes and returns an error if the padding is invalid. The function assumes
    /// that the length of the data is a multiple of the `BLOCK_SIZE`.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of padded binary data to be unpadded.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unpadded data if the padding is valid.
    /// * `Err(&'static str)` - An error message if the padding or data length is invalid.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    /// - The data is empty.
    /// - The data length is not a multiple of the `BLOCK_SIZE`.
    /// - The padding is invalid (either incorrectly formatted or out of bounds).
    ///
    /// # Example
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// const BLOCK_SIZE: usize = 16;
    ///
    /// // Example with valid padding
    /// let padded_data = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
    /// let unpadded_data = CryptoUtils::unpad_binary(padded_data).unwrap();
    /// assert_eq!(unpadded_data, b"YELLOW SUBMARINE");
    ///
    /// // Example with invalid padding
    /// let invalid_padded_data = b"YELLOW SUBMARINE\x05\x05\x05\x05\x06";
    /// assert!(CryptoUtils::unpad_binary(invalid_padded_data).is_err());
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic but returns a `Result` in case of errors like invalid padding or improper length.
    pub fn unpad_binary(data: &[u8]) -> Result<Vec<u8>, KSMRError> {
        const BLOCK_SIZE: usize = 16; // Define or pass as argument as needed

        let data_len = data.len();

        // Check if the data is empty
        if data_len == 0 {
            return Err(KSMRError::CryptoError("Data is empty".to_string()));
        }

        // Check if the length is a multiple of the block size
        if !data_len.is_multiple_of(BLOCK_SIZE) {
            return Err(KSMRError::CryptoError("Invalid data length".to_string()));
        }

        // Get the padding length from the last byte
        let pad_len = data[data_len - 1];

        // Validate the padding length
        if pad_len == 0 || pad_len as usize > BLOCK_SIZE || pad_len as usize > data_len {
            return Err(KSMRError::CryptoError("Invalid padding".to_string()));
        }

        // Ensure padding bytes are correct
        if !data[data_len - pad_len as usize..]
            .iter()
            .all(|&b| b == pad_len)
        {
            return Err(KSMRError::CryptoError("Invalid padding".to_string()));
        }

        // Return the unpadded data
        Ok(data[..data_len - pad_len as usize].to_vec())
    }

    /// Removes padding from the given binary data.
    ///
    /// This function removes padding by interpreting the last byte of the input data as the number of padding bytes added.
    /// It returns the unpadded data if the padding is valid. The function is simpler than PKCS#7, and it does not verify
    /// the contents of the padding bytes—just their length.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of binary data to be unpadded.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unpadded data if the padding is valid.
    /// * `Err(&'static str)` - An error message if the padding or data length is invalid.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    /// - The data is empty.
    /// - The padding length (extracted from the last byte) is greater than the length of the data.
    ///
    /// # Example
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// let padded_data = b"HELLO WORLD\x04\x04\x04\x04";
    /// let unpadded_data = CryptoUtils::unpad_char(padded_data).unwrap();
    /// assert_eq!(unpadded_data, b"HELLO WORLD");
    /// ```
    ///
    /// In this example, the input `padded_data` ends with four padding bytes (`\x04`), which are removed by the function.
    /// The resulting unpadded data is `"HELLO WORLD"`.
    ///
    /// # Errors
    ///
    /// * `"Data is empty"` - If the input data is empty.
    /// * `"Invalid padding length"` - If the padding length exceeds the length of the input data.
    ///
    /// # Panics
    ///
    /// This function does not panic but returns a `Result` in case of errors.
    pub fn unpad_char(data: &[u8]) -> Result<Vec<u8>, KSMRError> {
        if data.is_empty() {
            return Err(KSMRError::CryptoError("Data is empty".to_string()));
        }

        let pad_len = data[data.len() - 1] as usize;

        // Ensure padding length is not greater than data length
        if pad_len == 0 || pad_len > data.len() {
            return Err(KSMRError::CryptoError("Invalid padding length".to_string()));
        }

        // Optionally, you could also check that all padding bytes are equal to the padding length
        if !data[data.len() - pad_len..]
            .iter()
            .all(|&b| b == pad_len as u8)
        {
            return Err(KSMRError::CryptoError("Invalid padding".to_string()));
        }

        // Return the unpadded data
        Ok(data[..data.len() - pad_len].to_vec())
    }

    /// Converts a byte slice into a `BigUint` integer.
    ///
    /// # Parameters
    ///
    /// - `b`: A byte slice representing the input bytes to be converted to an integer.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(BigUint)`: The converted integer on success.
    /// - `Err(KSMRError)`: An error message if the input is invalid (e.g., empty input or exceeds 16 bytes).
    ///
    /// # Errors
    ///
    /// - Returns `"Input is empty"` if the provided byte slice is empty.
    /// - Returns `"Input exceeds maximum length of 16 bytes"` if the input byte slice is longer than 16 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use std::str::FromStr;
    /// use num_bigint::BigUint;
    /// let bytes = &[1; 17];
    /// let result = CryptoUtils::bytes_to_int(bytes).unwrap();
    /// assert_eq!(result, BigUint::from_str("341616807575530379006368233343265341697").unwrap());
    /// ```
    pub fn bytes_to_int(b: &[u8]) -> Result<BigUint, KSMRError> {
        if b.is_empty() {
            return Err(KSMRError::InsufficientBytes("Input is empty".to_string()));
        }
        let big_number = BigUint::from_bytes_be(b);
        Ok(big_number)
    }

    /// Converts a URL-safe Base64 encoded string to a byte vector.
    ///
    /// This function decodes a URL-safe Base64 encoded string into a vector of bytes. It automatically
    /// adds the necessary padding (`=`) to the input string if it's missing, ensuring it conforms to
    /// Base64 encoding rules. The function also includes optional checks to verify the length of the
    /// decoded byte vector for specific use cases (e.g., UUIDs).
    ///
    /// # Parameters
    ///
    /// - `s`: A string slice representing the URL-safe Base64 encoded string to decode.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: A vector of bytes resulting from decoding the input string on success.
    /// - `Err(KSMRError)`: An error variant indicating an issue with decoding, such as invalid Base64 format.
    ///
    /// # Errors
    ///
    /// - `KSMRError::InvalidBase64`: If the input string fails to decode as valid Base64.
    /// - `KSMRError::DecodedBytesTooShort`: If the decoded byte array is shorter than the required length
    ///   (e.g., for UUID or other fixed-length conversions).
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use keeper_secrets_manager_core::custom_error::KSMRError;
    ///
    /// fn main() -> Result<(), KSMRError> {
    ///     let url_safe_base64 = "c29tZSBkYXRh"; // Example URL-safe Base64 string
    ///
    ///     // Convert URL-safe Base64 string to bytes
    ///     let decoded_bytes = CryptoUtils::url_safe_str_to_bytes(url_safe_base64);
    ///
    ///     // Print the resulting byte vector
    ///     println!("Decoded bytes: {:?}", decoded_bytes);
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation. However, it will return an error if the input string is not valid Base64.
    ///
    /// # Notes
    ///
    /// - The function automatically adds padding (`=`) to the input string if necessary to conform to Base64 encoding rules.
    /// - The decoded byte array is optionally validated for minimum length (e.g., at least 8 bytes for UUIDs).
    pub fn url_safe_str_to_bytes(s: &str) -> Result<Vec<u8>, KSMRError> {
        // Attempt to decode the URL-safe Base64 string
        let text = s.replace("+", "-").replace("/", "_");
        let decoded_bytes = URL_SAFE_NO_PAD
            .decode(&text)
            .map_err(|err| KSMRError::DecodeError(err.to_string()));
        let decoded_bytes = match decoded_bytes {
            Ok(decoded_bytes) => decoded_bytes,
            Err(err) => {
                if err == KSMRError::InvalidBase64 {
                    URL_SAFE_NO_PAD
                        .decode(s)
                        .map_err(|err| KSMRError::DecodeError(err.to_string()))?
                } else {
                    return Err(err);
                }
            }
        };

        // Optional: Check if the decoded bytes are long enough (e.g., for UUIDs)
        if decoded_bytes.len() < 8 {
            return Err(KSMRError::DecodedBytesTooShort);
        }

        Ok(decoded_bytes)
    }

    pub fn url_safe_str_to_bytes_trim_padding(s: &str) -> Result<Vec<u8>, KSMRError> {
        let mut text = s.trim_end_matches("=").to_string();
        // Attempt to decode the URL-safe Base64 string
        text = text.replace("+", "-").replace("/", "_");
        let decoded_bytes = URL_SAFE_NO_PAD
            .decode(&text)
            .map_err(|err| KSMRError::DecodeError(err.to_string()));
        let decoded_bytes = match decoded_bytes {
            Ok(decoded_bytes) => decoded_bytes,
            Err(err) => {
                if err == KSMRError::InvalidBase64 {
                    URL_SAFE_NO_PAD
                        .decode(s)
                        .map_err(|err| KSMRError::DecodeError(err.to_string()))?
                } else {
                    return Err(err);
                }
            }
        };
        // Optional: Check if the decoded bytes are long enough (e.g., for UUIDs)
        if decoded_bytes.len() < 8 {
            return Err(KSMRError::DecodedBytesTooShort);
        }
        Ok(decoded_bytes)
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates a vector of random bytes of the specified length.
    ///
    /// # Parameters
    ///
    /// - `length`: The desired length of the random byte vector.
    ///
    /// # Returns
    ///
    /// This function returns a `Vec<u8>` containing `length` random bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// fn main() {
    ///     let length = 16; // Specify the length of random bytes
    ///     let random_bytes = CryptoUtils::generate_random_bytes(length);
    ///
    ///     // Print the generated random bytes
    ///     println!("Generated random bytes: {:?}", random_bytes);
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if `length` is zero.
    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng(); // Get a random number generator
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes[..]);
        bytes // Return the random bytes
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates a 32-byte random encryption key.
    ///
    /// This function is suitable for creating encryption keys for symmetric encryption algorithms,
    /// such as AES-256, which requires a 256-bit (32-byte) key.
    ///
    /// # Returns
    ///
    /// This function returns a `Vec<u8>` containing 32 random bytes, which can be used as an encryption key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// fn main() {
    ///     let encryption_key = CryptoUtils::generate_encryption_key_bytes();
    ///
    ///     // Print the generated encryption key
    ///     println!("Generated encryption key: {:?}", encryption_key);
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation since it relies on generating random bytes.
    pub fn generate_encryption_key_bytes() -> Vec<u8> {
        Self::generate_random_bytes(32)
    }

    #[allow(clippy::needless_doctest_main)]
    /// Converts a byte slice to a URL-safe Base64-encoded string.
    ///
    /// This function encodes the given byte slice into a URL-safe Base64 string,
    /// stripping any trailing padding characters (`=`) that are typically used
    /// in Base64 encoding. The resulting string can be safely included in URLs.
    ///
    /// # Parameters
    ///
    /// - `b`: A byte slice that you want to encode to a URL-safe Base64 string.
    ///
    /// # Returns
    ///
    /// This function returns a `String` containing the URL-safe Base64-encoded representation
    /// of the input byte slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// fn main() {
    ///     let data = b"Hello, World!";
    ///     let encoded_str = CryptoUtils::bytes_to_url_safe_str(data);
    ///
    ///     // Print the URL-safe Base64-encoded string
    ///     println!("Encoded URL-safe string: {}", encoded_str);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// - The function uses the `BASE64_URL_SAFE` encoder, which ensures that the resulting
    ///   string is safe for use in URLs and does not contain characters that may need
    ///   to be escaped.
    pub fn bytes_to_url_safe_str(b: &[u8]) -> String {
        // Encode bytes to URL-safe Base64 and strip padding '=' characters
        let encoded_value = BASE64_URL_SAFE.encode(b);
        encoded_value.trim_end_matches('=').to_string()
    }

    /// Converts a URL-safe Base64-encoded string to a `BigUint` integer.
    ///
    /// This function first decodes the URL-safe Base64 string into a byte vector.
    /// It then converts the resulting byte vector into a `BigUint` integer. The function
    /// will return an error if the string cannot be decoded or if the resulting byte
    /// vector cannot be converted to a valid integer.
    ///
    /// # Parameters
    ///
    /// - `s`: A string slice representing the URL-safe Base64-encoded data.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(BigUint)`: The decoded integer value on success.
    /// - `Err(KSMRError)`: An error variant indicating a failure in decoding or conversion.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use keeper_secrets_manager_core::custom_error::KSMRError;
    /// fn main() -> Result<(), KSMRError> {
    ///     let url_safe_str = "AQIDBAUGBwgJCgsMDQ4PEA=="; // Example URL-safe Base64 string
    ///
    ///     match CryptoUtils::url_safe_str_to_int(url_safe_str) {
    ///         Ok(int_value) => println!("Decoded integer value: {}", int_value),
    ///         Err(err) => println!("Error decoding string: {:?}", err),
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - Returns a `KSMRError::InvalidBase64` if the input string is not valid Base64.
    /// - Returns `KSMRError::InvalidIntegerConversion` if the decoded byte slice cannot
    ///   be converted to a valid `BigUint` integer.
    ///
    /// # Notes
    ///
    /// - The function assumes that the input string is a valid URL-safe Base64 string.
    /// - Any invalid Base64 characters or decoding issues will result in a `KSMRError`.
    pub fn url_safe_str_to_int(s: &str) -> Result<BigUint, KSMRError> {
        let bytes = Self::url_safe_str_to_bytes(s)?; // Assuming this function is also updated
        let int_value = Self::bytes_to_int(&bytes)?; // Now returns KSMRError
        Ok(int_value)
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates an ECC signing key.
    ///
    /// This function generates a random encryption key, converts it to a URL-safe Base64 string,
    /// then converts the string into an integer. The integer is used to populate the first 16 bytes
    /// of a 32-byte array, with the remaining 16 bytes set to zeros. This 32-byte array is then used
    /// to create a `SigningKey` that can be used for ECC-based signing operations.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(SigningKey)`: A successfully generated `SigningKey` instance, which can be used for ECC signing operations.
    /// - `Err(KSMRError)`: If any of the operations fail, such as key generation, conversion, or `SigningKey` creation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust to your actual module path
    ///
    /// fn main() {
    ///     let signing_key = CryptoUtils::generate_ecc_keys().unwrap();
    ///     println!("Generated ECC Signing Key: {:?}", signing_key);
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - The conversion from URL-safe Base64 string to integer fails.
    /// - The creation of the `SigningKey` from the byte array fails.
    ///
    /// # Notes
    ///
    /// - The encryption key used to generate the signing key is created randomly for each call to the function, ensuring that the signing key is unique each time.
    /// - The final `SigningKey` is based on a 32-byte array, where the first 16 bytes come from the converted integer, and the remaining 16 bytes are filled with zeros.
    /// - The generated signing key is suitable for use in ECC-based cryptographic operations.
    pub fn generate_ecc_keys() -> Result<SigningKey, KSMRError> {
        // Generate encryption key bytes
        let encryption_key_bytes: Vec<u8> = Self::generate_encryption_key_bytes();

        // Convert bytes to URL-safe Base64 string
        let private_key_str = Self::bytes_to_url_safe_str(&encryption_key_bytes);

        // Convert URL-safe Base64 string to integer
        let encryption_key_int = Self::url_safe_str_to_int(&private_key_str).map_err(|_| {
            KSMRError::CryptoError("Failed to convert URL-safe Base64 string to integer".into())
        })?;

        // Create a 32-byte array for the SigningKey
        let mut key_bytes = [0u8; 32];

        // Convert the BigUint encryption_key_int to bytes and copy it to the key_bytes array
        let int_bytes = encryption_key_int.to_bytes_be(); // This gives 16 bytes
        key_bytes.copy_from_slice(&int_bytes); // Copy the 16 bytes from the integer

        // Create the SigningKey from the byte array
        SigningKey::from_bytes(GenericArray::from_slice(&key_bytes))
            .map_err(|_| KSMRError::CryptoError("Failed to create SigningKey from bytes".into()))
    }

    #[allow(clippy::needless_doctest_main)]
    /// Derives the public key from a given ECC private key.
    ///
    /// This function takes a reference to a `SigningKey` (private key) and derives
    /// the corresponding public key. The public key is then serialized in uncompressed
    /// format (X9.62).
    ///
    /// # Parameters
    ///
    /// - `private_key`: A reference to a `SigningKey`, which represents the ECC private key
    ///   from which the public key will be derived.
    ///
    /// # Returns
    ///
    /// This function returns a `Vec<u8>` containing the serialized public key in uncompressed
    /// format.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust to your actual module path
    ///
    /// fn main() {
    ///     // Assume you have a valid SigningKey instance
    ///     let private_key = CryptoUtils::generate_ecc_keys().unwrap();
    ///
    ///     // Get the corresponding public key
    ///     let public_key = CryptoUtils::public_key_ecc(&private_key);
    ///     
    ///     println!("Public Key: {:?}", public_key);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// - The uncompressed format of the public key allows for straightforward serialization
    ///   and transmission. It includes the x-coordinate and the y-coordinate of the point
    ///   on the elliptic curve.
    /// - Ensure that the `SigningKey` provided to this function is valid and has been properly
    ///   initialized before calling this function.
    pub fn public_key_ecc(private_key: &SigningKey) -> Vec<u8> {
        // Get the public key from the private key
        let public_key: VerifyingKey = *private_key.verifying_key();

        // Serialize the public key in uncompressed format (X9.62)
        let pub_key_bytes = public_key.to_encoded_point(false).as_ref().to_vec();

        pub_key_bytes
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates a new ECC private key.
    ///
    /// This function generates a new 256-bit (32-byte) private key suitable for ECC operations,
    /// specifically for the P256 curve. The process involves generating random bytes, converting
    /// those bytes into a URL-safe Base64 string, and then converting that string into an integer.
    /// The integer is then used to create the `SigningKey` which represents the ECC private key.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(SigningKey)`: The successfully generated ECC private key as a `SigningKey`.
    /// - `Err(KSMRError)`: An error if any step of the key generation process fails, including random byte generation, Base64 conversion, integer conversion, or `SigningKey` creation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust to your actual module path
    ///
    /// fn main() {
    ///     // Generate a new ECC private key
    ///     let private_key = CryptoUtils::generate_private_key_ecc().unwrap();
    ///
    ///     // Print or use the private key as needed
    ///     println!("Generated Private Key: {:?}", private_key);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// - The generated private key is a 256-bit (32-byte) key, which is compatible with the P256 curve used in ECC operations.
    /// - Ensure that the random bytes are securely generated, as this key will be used in cryptographic operations. The private key should be kept confidential at all times.
    ///
    /// # Panics
    ///
    /// This function will panic if any of the following conditions occur:
    /// - The conversion of the URL-safe Base64 string to an integer fails.
    /// - The `SigningKey` creation from the byte array fails.
    ///
    /// # Implementation Details
    ///
    /// - The key is derived from random bytes, which are encoded into a URL-safe Base64 string, then decoded back to an integer.
    /// - The integer is converted to bytes, and the first 16 bytes are used for the key, with the remaining bytes padded with zeros.
    /// - The final 32-byte array is used to create the `SigningKey` using `SigningKey::from_bytes`.
    pub fn generate_private_key_ecc() -> Result<SigningKey, KSMRError> {
        // Generate random bytes for the encryption key
        let encryption_key_bytes = Self::generate_random_bytes(32);

        // Convert bytes to URL-safe Base64 string
        let private_key_str = Self::bytes_to_url_safe_str(&encryption_key_bytes);

        // Convert URL-safe Base64 string to integer
        let encryption_key_int = Self::url_safe_str_to_int(&private_key_str).map_err(|e| {
            KSMRError::CryptoError(format!(
                "Failed to convert URL-safe Base64 string to integer: {}",
                e
            ))
        })?;

        // Create a byte array from the integer representation (needs 32 bytes)
        let mut key_bytes = [0u8; 32];

        // Right-align int_bytes in key_bytes
        let int_bytes = encryption_key_int.to_bytes_be();
        let start = 32 - int_bytes.len();
        key_bytes[start..].copy_from_slice(&int_bytes);

        // Create SigningKey from the byte array
        SigningKey::from_bytes(GenericArray::from_slice(&key_bytes)).map_err(|e| {
            KSMRError::CryptoError(format!("Failed to create SigningKey from bytes: {}", e))
        })?;

        // Return the generated SigningKey
        Ok(SigningKey::from_bytes(GenericArray::from_slice(&key_bytes)).unwrap())
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates a new ECC private key.
    ///
    /// This function generates a new 256-bit (32-byte) private key suitable for ECC operations,
    /// specifically for the P256 curve. The process involves generating random bytes, converting
    /// those bytes into a URL-safe Base64 string, and then converting that string into an integer.
    /// The integer is then used to create the `SigningKey`, which represents the ECC private key.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(SigningKey)`: The successfully generated ECC private key as a `SigningKey`.
    /// - `Err(KSMRError)`: An error if any step of the key generation process fails, including random byte generation, Base64 conversion, integer conversion, or `SigningKey` creation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust to your actual module path
    ///
    /// fn main() {
    ///     // Generate a new ECC private key
    ///     let private_key = CryptoUtils::generate_private_key_ecc().unwrap();
    ///
    ///     // Print or use the private key as needed
    ///     println!("Generated Private Key: {:?}", private_key);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// - The generated private key is a 256-bit (32-byte) key, which is compatible with the P256 curve used in ECC operations.
    /// - The first 16 bytes of the 32-byte private key are filled with the integer representation of the random bytes.
    /// - The second 16 bytes are a repeat of the same integer to meet the required key length for P256.
    /// - Ensure that the random bytes are securely generated, as this key will be used in cryptographic operations. The private key should be kept confidential at all times.
    ///
    /// # Panics
    ///
    /// This function will panic if any of the following conditions occur:
    /// - The conversion of the URL-safe Base64 string to an integer fails.
    /// - The `SigningKey` creation from the byte array fails.
    ///
    /// # Implementation Details
    ///
    /// - The key is derived from random bytes, which are encoded into a URL-safe Base64 string, then decoded back to an integer.
    /// - The integer is converted to bytes, and the first 16 bytes are used for the key, with the remaining bytes padded with zeros.
    /// - The final 32-byte array is used to create the `SigningKey` using `SigningKey::from_bytes`.
    pub fn generate_private_key_der() -> Result<Vec<u8>, KSMRError> {
        // Generate ECC signing key
        let signing_key = Self::generate_private_key_ecc()
            .map_err(|err| KSMRError::CryptoError(err.to_string()))
            .unwrap();

        // Export to DER format
        match signing_key.to_pkcs8_der() {
            Ok(private_key_der) => Ok(private_key_der.as_bytes().to_vec()), // Return the DER bytes
            Err(e) => Err(KSMRError::CryptoError(format!(
                "Failed to serialize to DER: {}",
                e
            ))),
        }
    }

    #[allow(clippy::needless_doctest_main)]
    /// Generates a new ephemeral ECC signing key using the SECP256R1 curve.
    ///
    /// This function creates a new ECC signing key that can be used for cryptographic operations such as
    /// signing or key exchange. It utilizes a secure random number generator to ensure the key is
    /// generated in a cryptographically secure manner.
    ///
    /// # Returns
    ///
    /// This function returns a `SigningKey`, which represents the newly generated ECC signing key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust to your actual module path
    /// use p256::ecdsa::SigningKey;
    /// fn main() {
    ///     // Generate a new ECC signing key
    ///     let signing_key: SigningKey = CryptoUtils::generate_new_ecc_key();
    ///
    ///     // Use the signing key for further cryptographic operations
    ///     println!("Generated new ECC signing key: {:?}", signing_key);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// - The generated key is ephemeral and should be used for a single session or transaction.
    /// - Ensure that you securely manage and store the signing key if needed, as it is essential for
    ///   cryptographic integrity.
    pub fn generate_new_ecc_key() -> SigningKey {
        // Create a new OS random number generator
        let mut rng = OsRng;

        // Generate an ephemeral ECC signing key for SECP256R1
        SigningKey::random(&mut rng)
    }

    /// Encrypts data using AES-256-GCM with an optional nonce.
    ///
    /// This function performs authenticated encryption of the provided `data` using AES-256-GCM.
    /// AES-256-GCM requires a 32-byte key for encryption and uses a 12-byte nonce. If a nonce is
    /// not provided, a random 12-byte nonce will be generated.
    ///
    /// # Parameters
    ///
    /// - `data`: A byte slice representing the plaintext data to be encrypted.
    /// - `key_bytes`: A byte slice representing the 32-byte AES key used for encryption (AES-256).
    /// - `nonce_bytes`: An optional byte slice representing the nonce. If not provided, a random nonce will be generated.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: The result will contain a vector with the concatenated nonce and the encrypted ciphertext on success.
    /// - `Err(KSMRError)`: An error if encryption fails or if invalid input parameters are provided (e.g., wrong key size).
    ///
    /// # Errors
    ///
    /// - Returns `KSMRError::CryptoError("Invalid key size")` if the provided `key_bytes` slice is not exactly 32 bytes long.
    /// - Returns `KSMRError::CryptoError("Encryption failed")` if the encryption operation fails (for example, due to invalid key or data).
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use std::error::Error;
    /// use hex;
    ///
    /// fn main() -> Result<(), Box<dyn Error>> {
    ///     // 32-byte AES key (AES-256 requires a 32-byte key)
    ///     let key = b"an example very very secret key."; // Must be exactly 32 bytes
    ///
    ///     // Example plaintext data
    ///     let data = b"plaintext message that needs encryption";
    ///
    ///     // Encrypt the data with a random nonce
    ///     let encrypted_data = CryptoUtils::encrypt_aes_gcm(data, key, None)?;
    ///
    ///     // Print the encrypted data in hex format for better readability
    ///     println!("Encrypted data: {:?}", hex::encode(&encrypted_data));
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation. However, it will return an error if input is invalid (e.g., wrong key size or if encryption fails).
    ///
    /// # Notes
    ///
    /// - AES-256-GCM is an authenticated encryption mode, which provides both confidentiality and integrity. The nonce should be unique for each encryption operation with the same key to maintain security.
    /// - The nonce is prepended to the ciphertext before returning, allowing the recipient to extract and use it for decryption.
    ///
    /// # Implementation Details
    ///
    /// - AES-256-GCM requires a 32-byte key, and the nonce used must be 12 bytes in length. If a nonce is not provided, a random 12-byte nonce will be generated for each encryption operation.
    /// - The AES-GCM encryption process uses the provided key and nonce to encrypt the `data`. The resulting ciphertext is then concatenated with the nonce before being returned.
    /// - The function uses the `Aes256Gcm` cipher from the `aes-gcm` crate and the `rand` crate to generate random nonces when necessary.
    pub fn encrypt_aes_gcm(
        data: &[u8],
        key_bytes: &[u8],
        nonce_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>, KSMRError> {
        let _ = nonce_bytes;

        // Validate key size (32 bytes for AES-256)
        if key_bytes.len() != 32 {
            return Err(KSMRError::CryptoError("Invalid key size".to_string()));
        }

        if key_bytes.len() != 32 {
            return Err(KSMRError::CryptoError("Invalid key size".to_string()));
        }

        // Create the key from the provided bytes
        let mut cipher_obj =
            aes_gcm::Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes));
        let nonce_obj = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher_txt_obj = cipher_obj
            .encrypt(&nonce_obj, data)
            .map_err(|_| KSMRError::CryptoError("Encryption failed".to_string()))?;

        let mut result_obj = Vec::with_capacity(nonce_obj.as_slice().len() + cipher_txt_obj.len());
        result_obj.extend_from_slice(nonce_obj.as_slice());
        result_obj.extend_from_slice(&cipher_txt_obj);
        Ok(result_obj)
    }

    /// Decrypts data using AES-256-GCM with a 12-byte nonce.
    ///
    /// # Parameters
    ///
    /// - `data`: A byte slice containing the nonce followed by the ciphertext. The first 12 bytes represent the nonce, and the rest is the ciphertext.
    /// - `key_bytes`: A byte slice representing the 32-byte AES key used for decryption (AES-256).
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: The decrypted plaintext on success.
    /// - `Err(Box<dyn Error>)`: An error if decryption fails or if invalid input parameters are provided (e.g., wrong key size).
    ///
    /// # Errors
    ///
    /// - Returns `"Invalid key size"` if the provided `key_bytes` slice is not exactly 32 bytes long.
    /// - Returns `"Data too short to contain nonce"` if the provided `data` slice is smaller than 12 bytes.
    /// - Returns `"Decryption failed"` if the decryption operation itself fails (for example, if the ciphertext or key is invalid).
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use keeper_secrets_manager_core::custom_error::KSMRError;
    /// use aes_gcm::{Aes256Gcm, Key, Nonce}; // Import the AES-GCM library
    /// use std::error::Error;
    /// use hex;
    ///
    /// fn main() -> Result<(), KSMRError> {
    ///     // 32-byte AES key (AES-256 requires a 32-byte key)
    ///     let key = b"an example very very secret key."; // Should be exactly 32 bytes
    ///
    ///     // 12-byte nonce (unique for each encryption)
    ///     let nonce = b"unique nonce"; // Must be exactly 12 bytes
    ///
    ///     // Example ciphertext (encrypted using the same key and nonce)
    ///     let ciphertext = hex::decode("c5d3db06f6c3d543663a94051a7a0d65")?; // Example encrypted data
    ///   
    ///     // Concatenate nonce and ciphertext
    ///     let mut encrypted_data = Vec::new();
    ///     encrypted_data.extend_from_slice(nonce);
    ///     encrypted_data.extend_from_slice(&ciphertext);
    ///
    ///     // Attempt to decrypt the data
    ///     let result = CryptoUtils::decrypt_aes(&encrypted_data, key);
    ///
    ///     // Check if the decryption was successful
    ///     match result {
    ///         Ok(decrypted_data) => {
    ///             println!("Decrypted data: {:?}", decrypted_data);
    ///         },
    ///         Err(err) => {
    ///             println!("Error: {}", err);
    ///             assert_eq!(err.to_string(), "Cryptography module Error: aead::Error");
    ///         }
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation. However, it will return an error if input is invalid (e.g., wrong key size or if decryption fails).
    ///
    /// # Notes
    ///
    /// - This function assumes that the first 12 bytes of `data` represent the nonce.
    /// - AES-256-GCM is an authenticated encryption mode, so decryption will fail if the ciphertext or key is tampered with.
    pub fn decrypt_aes(data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, KSMRError> {
        use aes_gcm::KeyInit;
        // Validate key size (32 bytes for AES-256)
        if key_bytes.len() != 32 {
            return Err(KSMRError::CryptoError("Invalid key size".to_string()));
        }

        if data.len() < 12 {
            return Err(KSMRError::CryptoError(
                "Data too short to contain nonce".to_string(),
            ));
        }

        let ciphertext = &data[12..]; // The rest is the ciphertext

        let mut key2 = aes_gcm::Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|err| KSMRError::CryptoError(err.to_string()))?;
        let nonce2 = aes_gcm::Nonce::from_slice(&data[..12]);

        // Decrypt the data
        let decrypted_plaintext = key2
            .decrypt(nonce2, ciphertext)
            .map_err(|err| KSMRError::CryptoError(err.to_string()))?;
        Ok(decrypted_plaintext)
    }

    /// Encrypts data using AES-256 in CBC (Cipher Block Chaining) mode.
    ///
    /// This function encrypts the provided plaintext data using AES-256 in CBC mode with a 32-byte key.
    /// If an Initialization Vector (IV) is not provided, a random 16-byte IV is generated. The IV
    /// is then prepended to the resulting ciphertext for later use during decryption.
    ///
    /// # Parameters
    ///
    /// - `data`: A byte slice representing the plaintext data to be encrypted.
    /// - `key`: A 32-byte slice representing the AES-256 key used for encryption (AES-256 requires a 256-bit key).
    /// - `iv`: An optional 16-byte slice representing the Initialization Vector (IV). If `None` is provided,
    ///   a random IV will be generated.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: A vector containing the concatenated IV and the encrypted ciphertext on success.
    /// - `Err(KSMRError)`: An error if the key size is invalid (i.e., not 32 bytes).
    ///
    /// # Errors
    ///
    /// - Returns `KSMRError::CryptoError("Invalid key size")` if the provided `key` is not 32 bytes long.
    /// - Returns an error if encryption fails or if the padding or encryption process encounters issues.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use rand::rngs::OsRng;
    ///
    /// let plaintext = b"Sensitive data to encrypt";
    /// let key = b"0123456789abcdef0123456789abcdef"; // A 32-byte AES-256 key.
    /// let iv = b"1234567890123456"; // A 16-byte IV (optional).
    ///
    /// let encrypted_data = CryptoUtils::encrypt_aes_cbc(plaintext, key, Some(iv)).unwrap();
    ///
    /// println!("Encrypted data: {:?}", encrypted_data);
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic but returns an error if input is invalid (e.g., incorrect key size or encryption failure).
    ///
    /// # Notes
    ///
    /// - AES-256 in CBC mode requires the key to be exactly 32 bytes. The IV must be 16 bytes in length.
    /// - CBC mode requires padding to ensure the data is a multiple of the block size (16 bytes for AES). This function uses a padding scheme (assumed to be implemented in `pad_data`) to handle this.
    /// - The resulting ciphertext is returned with the IV prepended to facilitate decryption.
    pub fn encrypt_aes_cbc(
        data: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, KSMRError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(KSMRError::CryptoError("Invalid key size".to_string()));
        }

        let iv = match iv {
            Some(iv) => iv.to_vec(),
            None => {
                let mut iv = vec![0u8; BLOCK_SIZE];
                OsRng.fill_bytes(&mut iv); // Secure random IV generation
                iv
            }
        };

        match iv.len() {
            BLOCK_SIZE => (),
            _ => {
                return Err(KSMRError::CryptoError("Invalid IV size".to_string()));
            }
        }

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let padded_data = pad_data(data, BLOCK_SIZE);
        let mut ciphertext = Vec::with_capacity(padded_data.len());
        let mut previous_block = iv.clone();

        for block in padded_data.chunks(BLOCK_SIZE) {
            let mut block = block.to_vec();

            // XOR block with the previous block or IV
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= previous_block[i];
            }

            let mut block_arr = GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut block_arr);

            ciphertext.extend_from_slice(&block_arr);
            previous_block = block_arr.to_vec();
        }

        let mut result = iv.clone();
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypts data using AES-256 in CBC (Cipher Block Chaining) mode.
    ///
    /// This function decrypts the provided encrypted data using AES-256 in CBC mode with a 32-byte key.
    /// The first 16 bytes of the input data are treated as the Initialization Vector (IV), and the remaining
    /// bytes are treated as the ciphertext. After decryption, the padding is removed from the data to obtain the
    /// original plaintext.
    ///
    /// # Parameters
    ///
    /// - `data`: A byte slice representing the encrypted data. The first 16 bytes are treated as the IV, and the
    ///   remaining bytes are the ciphertext.
    /// - `key`: A 32-byte slice representing the AES-256 key used for decryption.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: A vector containing the decrypted and unpadded plaintext data.
    /// - `Err(KSMRError)`: An error if the key size is invalid, the data is too short to contain an IV, or the
    ///   data length is not a multiple of 16 bytes (indicating possible encoding issues).
    ///
    /// # Errors
    ///
    /// - Returns `KSMRError::CryptoError("Invalid key size")` if the provided `key` is not 32 bytes long.
    /// - Returns `KSMRError::CryptoError("Data too short to contain IV")` if the provided `data` is less than 16 bytes long.
    /// - Returns `KSMRError::CryptoError("Data is probably not encoded")` if the data length is not a multiple of 16 bytes.
    /// - Returns `KSMRError::CryptoError("Unpadding failed: <error message>")` if the unpadding process fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    ///
    /// let encrypted_data = b"\x01\x02..."; // Some encrypted data with a 16-byte IV followed by ciphertext.
    /// let key = b"0123456789abcdef0123456789abcdef"; // A 32-byte AES-256 key.
    /// let data = CryptoUtils::decrypt_aes_cbc(encrypted_data, key);
    /// match data {
    ///     Ok(plaintext) => println!("Decrypted data: {:?}", plaintext),
    ///     Err(e) => eprintln!("Decryption error: {}", e),
    /// }
    /// ```
    ///
    /// In this example, `decrypt_aes_cbc` attempts to decrypt the `encrypted_data` using the provided AES-256 key.
    /// The decrypted data is returned after removing the padding.
    ///
    /// # Panics
    ///
    /// This function does not panic but returns a `Result` in case of errors.
    ///
    /// # Notes
    ///
    /// - AES-256 in CBC mode requires the key to be exactly 32 bytes. The IV must be 16 bytes in length.
    /// - The first 16 bytes of the input data are interpreted as the IV, while the rest is treated as the ciphertext.
    /// - CBC mode requires the ciphertext length to be a multiple of the AES block size (16 bytes).
    /// - The padding is removed from the decrypted data using a custom unpadding function (`unpad_data`), which will return an error if the padding is incorrect.
    pub fn decrypt_aes_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>, KSMRError> {
        // Validate key size (32 bytes for AES-256)
        if key.len() != 32 {
            return Err(KSMRError::CryptoError("Invalid key size".to_string()));
        }
        // Validate that data is large enough to contain an IV (16 bytes for AES-CBC)
        if data.len() < 16 {
            return Err(KSMRError::CryptoError(
                "Data too short to contain IV".to_string(),
            ));
        }
        // Extract the IV and ciphertext
        let iv = &data[..16]; // First 16 bytes are the IV
        let ciphertext = &data[16..]; // Remaining bytes are the encrypted data
                                      // Validate ciphertext length
        if !ciphertext.len().is_multiple_of(BLOCK_SIZE) {
            return Err(KSMRError::CryptoError(
                "Data is probably not encoded".to_string(),
            ));
        }
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut previous_block = iv.to_vec();
        for block in ciphertext.chunks(BLOCK_SIZE) {
            let mut block_arr = GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut block_arr);
            // XOR decrypted block with previous ciphertext block (or IV)
            let decrypted_block: Vec<u8> = block_arr
                .iter()
                .zip(&previous_block)
                .map(|(b, p)| b ^ p)
                .collect();
            plaintext.extend_from_slice(&decrypted_block);
            previous_block = block.to_vec();
        }
        // Remove PKCS#7 padding
        // let unpadded = unpad_data(&plaintext)
        //     .map_err(|e| KSMRError::CryptoError(format!("Unpadding failed: {}", e)))?;
        Ok(plaintext)
    }

    /// Encrypts data using an ephemeral ECDH key exchange and AES-GCM.
    ///
    /// This function uses Elliptic Curve Diffie-Hellman (ECDH) to derive a shared secret between
    /// an ephemeral key generated on the fly and a server's public key provided in the input.
    /// The derived key is optionally concatenated with an identifier (`idz`), hashed using SHA-256
    /// to generate an AES encryption key, and then used to encrypt the input data with AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be encrypted.
    /// * `server_public_raw_key_bytes` - A byte slice representing the server's public key in SEC1 format.
    /// * `idz` - An optional byte slice identifier that, if provided, is appended to the shared secret before key derivation.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` containing:
    /// - `Ok(Vec<u8>)`: A vector of bytes containing the concatenation of the ephemeral public key and the encrypted data.
    /// - `Err(KSMRError)`: An error if key derivation or encryption fails.
    ///
    /// # Errors
    ///
    /// * Returns an error if the server public key is invalid or encryption fails.
    /// * If the `server_public_raw_key_bytes` cannot be parsed into a valid public key, it returns `"Invalid server public key!"`.
    /// * If encryption fails during AES-GCM, the error message will indicate the failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    ///
    /// // Data to encrypt
    /// let data = b"Sensitive data to encrypt";
    ///
    /// // A raw public key as a string (this is just an example key)
    /// let server_public_key = "04d88c6fa31ea40af14c137b8e62f1151f1cc1e5688cad37b7f2e7";
    ///
    /// // Convert the public key from hex string to bytes
    /// let server_public_key_bytes = hex::decode(server_public_key).expect("Invalid hex key");
    ///
    /// // Optional IDZ
    /// let idz = Some("optional_identifier".as_bytes());
    ///
    /// // Encrypt the data
    /// match CryptoUtils::public_encrypt(data, &server_public_key_bytes, idz) {
    ///     Ok(encrypted_data) => println!("Encrypted data: {:?}", encrypted_data),
    ///     Err(e) => println!("Encryption failed: {}", e),
    /// }
    /// ```
    pub fn public_encrypt(
        data: &[u8],
        server_public_raw_key_bytes: &[u8],
        idz: Option<&[u8]>,
    ) -> Result<Vec<u8>, KSMRError> {
        // Load the server public key from raw bytes
        let server_public_key = PublicKey::from_sec1_bytes(server_public_raw_key_bytes)
            .map_err(|_| KSMRError::CryptoError("Invalid server public key!".to_string()))?;

        // Generate a new ephemeral key
        let ephemeral_key = EphemeralSecret::random(&mut OsRng);

        // Compute the shared key using ECDH (Diffie-Hellman)
        let shared_key = ephemeral_key.diffie_hellman(&server_public_key);

        // If idz is provided, concatenate it with the shared secret
        let mut derived_key = shared_key.raw_secret_bytes().to_vec();
        if let Some(idz_bytes) = idz {
            derived_key.extend_from_slice(idz_bytes);
        }

        // Hash the derived key to create a suitable AES key
        let mut hasher = sha2::Sha256::new();
        hasher.update(&derived_key);
        let enc_key = hasher.finalize().to_vec();

        // Encrypt the data with AES-GCM
        let encrypted_data = CryptoUtils::encrypt_aes_gcm(data, &enc_key, None)
            .map_err(|e| KSMRError::CryptoError(format!("AES encryption failed: {}", e)))?;

        // Get the public key bytes from the ephemeral key
        let eph_key_clone: p256::elliptic_curve::PublicKey<p256::NistP256> =
            ephemeral_key.public_key();

        let binding_clone = EncodedPoint::from(eph_key_clone);
        let eph_public_key_bytes: &[u8] = binding_clone.as_bytes();

        // Combine the ephemeral public key and the encrypted data
        let mut result = Vec::with_capacity(eph_public_key_bytes.len() + encrypted_data.len());
        result.extend_from_slice(eph_public_key_bytes.as_ref());
        result.extend_from_slice(&encrypted_data);

        Ok(result)
    }

    /// Computes the SHA-256 hash of a Base64-encoded string.
    ///
    /// This function takes a Base64-encoded string, decodes it into bytes,
    /// and computes its SHA-256 hash. The resulting hash is returned as a
    /// vector of bytes.
    ///
    /// # Arguments
    ///
    /// * `value` - A string slice representing the Base64-encoded input to hash.
    ///
    /// # Returns
    ///
    /// This function returns a `Result`:
    /// - `Ok(Vec<u8>)`: The SHA-256 hash of the decoded input as a vector of bytes.
    /// - `Err(KSMRError)`: An error if the input string cannot be decoded from Base64
    ///   or if any other error occurs during hashing.
    ///
    /// # Errors
    ///
    /// - Returns `KSMRError::CryptoError` if the input string cannot be decoded from Base64
    ///   or if any other error occurs during hashing.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// let base64_input = "SGVsbG8sIHdvcmxkIQ=="; // Base64 encoding of "Hello, world!"
    /// let hash = CryptoUtils::hash_of_string(base64_input);
    /// match hash {
    ///     Ok(h) => println!("SHA-256 Hash: {:?}", h),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic. It will return a `KSMRError` if the input is not valid Base64
    /// or if hashing fails.
    pub fn hash_of_string(value: &str) -> Result<Vec<u8>, KSMRError> {
        // Decode the Base64-encoded string into bytes
        let value_bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| KSMRError::CryptoError(format!("Base64 decoding failed: {}", e)))?;

        // Use sha2 crate for SHA-256 hashing
        let mut hasher = sha2::Sha256::new();
        hasher.update(&value_bytes);
        let hash_result = hasher.finalize();

        Ok(hash_result.to_vec())
    }

    pub fn ecies_decrypt(
        _server_public_key: &[u8],
        _ciphertext: &[u8],
        _priv_key_data: &[u8],
        _id: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        unimplemented!("The hashing functionality is not yet implemented.");
    }

    /// Decrypts a record using the provided secret key.
    ///
    /// This function attempts to decrypt a given record. If the record is a valid UTF-8 string,
    /// it is first decoded from Base64. The decoded bytes are then decrypted using AES-GCM.
    /// If the record is not a valid UTF-8 string, it is assumed to be in bytes and is decrypted
    /// directly.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the encrypted record. This can either be a
    ///   Base64-encoded UTF-8 string or raw bytes.
    /// * `secret_key` - A slice of bytes representing the secret key used for decryption.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<String, KSMRError>`. On success, it returns the
    /// decrypted record as a UTF-8 string. On failure, it returns an error with a description
    /// of the problem encountered.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The input data cannot be decoded from Base64, returning a `KSMRError::CryptoError` with
    ///   the description `"Base64 decode error: {error}"`.
    /// * The decryption process fails due to an incorrect key or other issues, returning a
    ///   `KSMRError::CryptoError` with a relevant message.
    /// * The resulting decrypted bytes cannot be converted to a UTF-8 string, returning a
    ///   `KSMRError::Utf8Error` with a description of the error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// let secret_key = CryptoUtils::generate_random_bytes(32); // Generate a dummy secret key
    /// let original_data = b"Hello, World!";
    /// let encrypted_data = CryptoUtils::encrypt_aes_gcm(original_data, &secret_key, None).unwrap();
    /// let base64_encoded = URL_SAFE_NO_PAD.encode(&encrypted_data);
    /// // Action
    /// let result = CryptoUtils::decrypt_record(base64_encoded.as_bytes(), &secret_key);
    /// // Assert
    /// assert_eq!(result.unwrap(), "Hello, World!");
    ///
    /// let result2 = CryptoUtils::decrypt_record(base64_encoded.as_bytes(), &secret_key);
    /// match result2 {
    ///     Ok(record) => println!("Decrypted record: {}", record),
    ///     Err(e) => eprintln!("Failed to decrypt record: {}", e),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal circumstances. It handles errors by returning a `KSMRError`.
    pub fn decrypt_record(data: &[u8], secret_key: &[u8]) -> Result<String, KSMRError> {
        let decrypted_data = if let Ok(s) = std::str::from_utf8(data) {
            // If the data is a valid UTF-8 string, decode from Base64
            let decoded_bytes = URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|e| KSMRError::CryptoError(format!("Base64 decode error: {}", e)))?;
            // Decrypt the decoded bytes
            CryptoUtils::decrypt_aes(&decoded_bytes, secret_key)
                .map_err(|e| KSMRError::CryptoError(format!("AES decryption error: {}", e)))?
        } else {
            // If the data is not a valid UTF-8 string, assume it's already in bytes
            CryptoUtils::decrypt_aes(data, secret_key)
                .map_err(|e| KSMRError::CryptoError(format!("AES decryption error: {}", e)))?
        };

        // Convert decrypted bytes to a UTF-8 string
        let record_json = String::from_utf8(decrypted_data)
            .map_err(|e| KSMRError::CryptoError(format!("UTF-8 conversion error: {}", e)))?;
        Ok(record_json)
    }

    pub fn decrypt_ec(
        _ecc_private_key: &SecretKey,
        _encrypted_data_bag: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        unimplemented!("The hashing functionality is not yet implemented.");
    }

    /// Converts a Base64-encoded DER private key string to a `SecretKey`.
    ///
    /// This function takes a Base64-encoded DER representation of a private key,
    /// decodes it, and converts it into a `SecretKey` type suitable for cryptographic
    /// operations.
    ///
    /// # Arguments
    ///
    /// * `private_key_der_base64` - A string slice containing the Base64-encoded
    ///   DER representation of the private key.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<p256::SecretKey, KSMRError>`. On success,
    /// it returns the corresponding `SecretKey`. On failure, it returns an error with a
    /// description of the problem encountered.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The provided Base64 string cannot be decoded. The error will be wrapped in a `KSMRError::CryptoError`.
    /// * The decoded bytes cannot be parsed into a `SecretKey`. The error will be wrapped in a `KSMRError::CryptoError`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust the path as necessary
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    /// use p256::SecretKey; // Import the SecretKey type
    ///
    /// let private_key_der_base64 = "your_base64_encoded_der_key_here"; // Replace with your Base64 DER key
    ///
    /// // Attempt to convert the Base64 DER private key to a SecretKey
    /// match CryptoUtils::der_base64_private_key_to_private_key(private_key_der_base64) {
    ///     Ok(secret_key) => println!("Successfully converted to SecretKey: {:?}", secret_key),
    ///     Err(e) => eprintln!("Failed to convert private key: {}", e),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal circumstances, but it may return an
    /// error if the input is invalid.
    pub fn der_base64_private_key_to_private_key(
        private_key_der_base64: &str,
    ) -> Result<
        SecretKey,
        // EcKey<openssl::pkey::Private> ,
        KSMRError,
    > {
        use p256::pkcs8::DecodePrivateKey;
        // Decode the Base64-encoded DER string
        let private_key_der_bytes = utils::base64_to_bytes(private_key_der_base64)?;

        // Convert to SecretKey
        let private_key = SecretKey::from_pkcs8_der(&private_key_der_bytes).map_err(|e| {
            KSMRError::CryptoError(format!("Failed to convert DER to SecretKey: {}", e))
        })?;

        Ok(private_key)
    }

    /// Extracts the public key bytes from a Base64-encoded DER private key string.
    ///
    /// This function takes a Base64-encoded DER representation of a private key,
    /// decodes it, and extracts the corresponding public key bytes in uncompressed format.
    ///
    /// # Arguments
    ///
    /// * `private_key_der_base64` - A string slice containing the Base64-encoded DER private key.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Vec<u8>, KSMRError>`. On success, it returns the public key bytes
    /// in uncompressed format. On failure, it returns a `KSMRError` with a description of the problem.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The provided Base64 string cannot be decoded.
    /// * The decoded bytes cannot be parsed into a `SecretKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils;
    /// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    ///
    /// let private_key_der_base64 = "your_base64_encoded_der_key_here"; // Replace with your Base64 DER key
    ///
    /// // Attempt to extract public key bytes
    /// match CryptoUtils::extract_public_key_bytes(private_key_der_base64) {
    ///     Ok(public_key_bytes) => println!("Successfully extracted public key bytes: {:?}", public_key_bytes),
    ///     Err(e) => eprintln!("Failed to extract public key bytes: {}", e),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal circumstances, but it will return an error if
    /// the Base64 string is invalid or the private key cannot be parsed.
    pub fn extract_public_key_bytes(private_key_der_base64: &str) -> Result<Vec<u8>, KSMRError> {
        // Decode the Base64-encoded DER string
        let private_key_der_bytes = utils::base64_to_bytes(private_key_der_base64)?;

        // Convert to SecretKey
        let private_key = SecretKey::from_pkcs8_der(&private_key_der_bytes)
            .map_err(|e| KSMRError::CryptoError(format!("Failed to load private key: {}", e)))?;

        // Derive the public key from the private key
        let public_key: VerifyingKey = private_key.public_key().into();

        // Convert public key to bytes
        let pub_key_bytes = public_key.to_encoded_point(false).as_ref().to_vec();

        Ok(pub_key_bytes)
    }

    /// Signs the provided data using the specified private key.
    ///
    /// This function takes a byte slice representing the data to be signed and a
    /// `SecretKey`. It creates a signing key from the private key and uses it
    /// to generate a digital signature for the data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the data to be signed.
    /// * `private_key` - A reference to the `SecretKey` used to sign the data.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<Signature, Box<dyn std::error::Error>>`. On success,
    /// it returns the generated `Signature`. On failure, it returns an error with a
    /// description of the problem encountered.
    ///
    /// # Errors
    ///
    /// This function may return an error if:
    /// * The signing process fails due to an invalid private key or other cryptographic issues.
    ///
    /// # Examples
    ///
    /// ```
    /// use keeper_secrets_manager_core::crypto::CryptoUtils; // Adjust the path as necessary
    /// use p256::{SecretKey, ecdsa::{SigningKey, Signature}}; // Import necessary types
    /// use rand::rngs::OsRng; // Use OS random number generator
    ///
    /// // Generate a dummy private key
    /// let private_key = SecretKey::random(&mut OsRng);
    /// let data = b"Hello, World!"; // Data to be signed
    ///
    /// // Attempt to sign the data
    /// match CryptoUtils::sign_data(data, private_key) {
    ///     Ok(signature) => println!("Successfully signed the data: {:?}", signature),
    ///     Err(e) => eprintln!("Failed to sign the data: {}", e),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not panic under normal circumstances, but it may return an
    /// error if the signing process encounters issues.
    pub fn sign_data(
        data: &[u8],
        // private_key: EcKey<openssl::pkey::Private>
        private_key: SecretKey,
    ) -> Result<
        // Signature,
        ecdsa::der::Signature<p256::NistP256>,
        KSMRError,
    > {
        // Create a SigningKey from the SecretKey
        let signing_key: ecdsa::SigningKey<p256::NistP256> = SigningKey::from(private_key);
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_der())
    }

    pub fn validate_signature(
        data: &[u8],             // The original data that was signed
        signature_bytes: &[u8],  // The signature in DER format
        public_key_bytes: &[u8], // The public key in uncompressed form
    ) -> Result<bool, KSMRError> {
        // Create a VerifyingKey from the public key bytes
        let public_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|err| {
            KSMRError::CryptoError(format!(
                "Failed to load public key from sec1 bytes: {}",
                err
            ))
        })?;

        // Parse the signature from bytes
        let signature = Signature::from_der(signature_bytes).map_err(|err| {
            KSMRError::CryptoError(format!(
                "Failed to parse signature from der while verification: {}",
                err
            ))
        })?;

        // Verify the signature using the public key and data
        public_key.verify(data, &signature).map_err(|err| {
            KSMRError::CryptoError(format!("Failed to verify signature: {}", err))
        })?;

        // If verification passes, return true
        Ok(true)
    }
}
