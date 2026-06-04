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

use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KSMRError {
    #[error("Invalid Base64 encoding")]
    InvalidBase64,
    #[error("Decoded byte array is too short")]
    DecodedBytesTooShort,
    #[error("Not implemented functionality: {0}")]
    NotImplemented(String),
    #[error("Invalid length: {0}")]
    InvalidLength(String),
    #[error("Insufficient bytes in input: {0}")]
    InsufficientBytes(String),
    #[error("Save Error: {0}")]
    CacheSaveError(String),
    #[error("Retrieve Error: {0}")]
    CacheRetrieveError(String),
    #[error("Purge Error: {0}")]
    CachePurgeError(String),
    #[error("Secret manager creation Error: {0}")]
    SecretManagerCreationError(String),
    #[error("Storage Error: {0}")]
    StorageError(String),
    #[error("Directory Creation failed: {0}: {1}")]
    DirectoryCreationError(String, #[source] std::io::Error),
    #[error("File Creation failed: {0}: {1}")]
    FileCreationError(String, #[source] std::io::Error),
    #[error("File Write failed: {0}: {1}")]
    FileWriteError(String, #[source] std::io::Error),
    #[error("JSON serialization/deserialization failed: {0}")]
    SerializationError(String),
    #[error("Deserialization Error: {0}")]
    DeserializationError(String),
    #[error("Error sending or receiving data from keeper servers. Exact message includes : {0}")]
    HTTPError(String),
    #[error("Data Conversion Error: {0}")]
    DataConversionError(String),
    #[error("{0}")]
    CustomError(String),
    #[error("Decode Error: {0}")]
    DecodeError(String),
    #[error("String Conversion Error: {0}")]
    StringConversionError(String),
    #[error("Cryptography module Error: {0}")]
    CryptoError(String),
    #[error("Record data error: {0}")]
    RecordDataError(String),
    #[error("payload doesn't belong to any of these types: {0}")]
    InvalidPayloadError(String),
    #[error("IO Error: {0}")]
    IOError(String),
    #[error("Path Error: {0}")]
    PathError(String),
    #[error("Key not found: {0}")]
    KeyNotFoundError(String),
    #[error("File Error: {0}")]
    FileError(String),
    #[error("Password creation Error: {0}")]
    PasswordCreationError(String),
    #[error("TOTP Error: {0}")]
    TOTPError(String),
    #[error("Notation Error: {0}")]
    NotationError(String),
    // v17.1.0: Additional error types for better error handling
    #[error("Record not found: {0}")]
    RecordNotFoundError(String), // Specific error when record doesn't exist
    #[error("Field not found: {0}")]
    FieldNotFoundError(String), // When a field doesn't exist in a record
    #[error("Authentication failed: {0}")]
    AuthenticationError(String), // Authentication/authorization failures
    #[error("Invalid token: {0}")]
    InvalidTokenError(String), // Invalid or expired one-time token
    #[error("Transaction error: {0}")]
    TransactionError(String), // Transaction operation failures (commit/rollback)
    #[error("Configuration error: {0}")]
    ConfigurationError(String), // Configuration validation errors
}

impl PartialEq for KSMRError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (KSMRError::InvalidBase64, KSMRError::InvalidBase64) => true,
            (KSMRError::DecodedBytesTooShort, KSMRError::DecodedBytesTooShort) => true,
            (KSMRError::InvalidLength(msg1), KSMRError::InvalidLength(msg2)) => msg1 == msg2,
            (KSMRError::InsufficientBytes(msg1), KSMRError::InsufficientBytes(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::CacheSaveError(msg1), KSMRError::CacheSaveError(msg2)) => msg1 == msg2,
            (KSMRError::PasswordCreationError(msg1), KSMRError::PasswordCreationError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::CacheRetrieveError(msg1), KSMRError::CacheRetrieveError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::CachePurgeError(msg1), KSMRError::CachePurgeError(msg2)) => msg1 == msg2,
            (
                KSMRError::SecretManagerCreationError(msg1),
                KSMRError::SecretManagerCreationError(msg2),
            ) => msg1 == msg2,
            (KSMRError::KeyNotFoundError(msg1), KSMRError::KeyNotFoundError(msg2)) => msg1 == msg2,
            (KSMRError::FileError(msg1), KSMRError::FileError(msg2)) => msg1 == msg2,
            (KSMRError::StorageError(msg1), KSMRError::StorageError(msg2)) => msg1 == msg2,
            (
                KSMRError::DirectoryCreationError(msg1, _),
                KSMRError::DirectoryCreationError(msg2, _),
            ) => msg1 == msg2,
            (KSMRError::FileCreationError(msg1, _), KSMRError::FileCreationError(msg2, _)) => {
                msg1 == msg2
            }
            (KSMRError::PathError(msg1), KSMRError::PathError(msg2)) => msg1 == msg2,
            (KSMRError::FileWriteError(msg1, _), KSMRError::FileWriteError(msg2, _)) => {
                msg1 == msg2
            }
            (KSMRError::SerializationError(msg1), KSMRError::SerializationError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::DeserializationError(msg1), KSMRError::DeserializationError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::DecodeError(msg1), KSMRError::DecodeError(msg2)) => msg1 == msg2,
            (KSMRError::StringConversionError(msg1), KSMRError::StringConversionError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::CryptoError(msg1), KSMRError::CryptoError(msg2)) => msg1 == msg2,
            (KSMRError::RecordDataError(msg1), KSMRError::RecordDataError(msg2)) => msg1 == msg2,
            (KSMRError::DataConversionError(msg1), KSMRError::DataConversionError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::NotImplemented(_), KSMRError::NotImplemented(_)) => true,
            (KSMRError::IOError(msg1), KSMRError::IOError(msg2)) => msg1 == msg2,
            (KSMRError::TOTPError(msg1), KSMRError::TOTPError(msg2)) => msg1 == msg2,
            (KSMRError::NotationError(msg1), KSMRError::NotationError(msg2)) => msg1 == msg2,
            // v17.1.0: New error types
            (KSMRError::RecordNotFoundError(msg1), KSMRError::RecordNotFoundError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::FieldNotFoundError(msg1), KSMRError::FieldNotFoundError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::AuthenticationError(msg1), KSMRError::AuthenticationError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::InvalidTokenError(msg1), KSMRError::InvalidTokenError(msg2)) => {
                msg1 == msg2
            }
            (KSMRError::TransactionError(msg1), KSMRError::TransactionError(msg2)) => msg1 == msg2,
            (KSMRError::ConfigurationError(msg1), KSMRError::ConfigurationError(msg2)) => {
                msg1 == msg2
            }
            _ => false,
        }
    }
}

impl From<serde_json::Error> for KSMRError {
    fn from(error: serde_json::Error) -> Self {
        if error.is_data() {
            KSMRError::DeserializationError(error.to_string())
        } else {
            KSMRError::SerializationError(error.to_string())
        }
    }
}

impl From<FromHexError> for KSMRError {
    fn from(error: FromHexError) -> Self {
        KSMRError::CryptoError(format!("Hex decode error: {}", error))
    }
}
