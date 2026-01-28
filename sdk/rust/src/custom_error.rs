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
use std::error::Error;
use std::fmt::{self};

#[derive(Debug)]
pub enum KSMRError {
    InvalidBase64,
    DecodedBytesTooShort,
    NotImplemented(String),
    InvalidLength(String),
    InsufficientBytes(String),
    CacheSaveError(String),
    CacheRetrieveError(String),
    CachePurgeError(String),
    SecretManagerCreationError(String),
    StorageError(String),
    DirectoryCreationError(String, std::io::Error),
    FileCreationError(String, std::io::Error),
    FileWriteError(String, std::io::Error),
    SerializationError(String),
    DeserializationError(String),
    HTTPError(String),
    DataConversionError(String),
    CustomError(String),
    DecodeError(String),
    StringConversionError(String),
    CryptoError(String),
    RecordDataError(String),
    InvalidPayloadError(String),
    IOError(String),
    PathError(String),
    KeyNotFoundError(String),
    FileError(String),
    PasswordCreationError(String),
    TOTPError(String),
    NotationError(String),
    // v17.1.0: Additional error types for better error handling
    RecordNotFoundError(String), // Specific error when record doesn't exist
    FieldNotFoundError(String),  // When a field doesn't exist in a record
    AuthenticationError(String), // Authentication/authorization failures
    InvalidTokenError(String),   // Invalid or expired one-time token
    TransactionError(String),    // Transaction operation failures (commit/rollback)
    ConfigurationError(String),  // Configuration validation errors
}

impl fmt::Display for KSMRError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KSMRError::InvalidBase64 => write!(f, "Invalid Base64 encoding"),
            KSMRError::DecodedBytesTooShort => write!(f, "Decoded byte array is too short"),
            KSMRError::NotImplemented(msg) => write!(f, "Not implemented functionality: {}", msg),
            KSMRError::InsufficientBytes(msg) => write!(f, "Insufficient bytes in input: {}", msg),
            KSMRError::CacheSaveError(msg) => write!(f, "Save Error: {}", msg),
            KSMRError::CacheRetrieveError(msg) => write!(f, "Retrieve Error: {}", msg),
            KSMRError::CachePurgeError(msg) => write!(f, "Purge Error: {}", msg),
            KSMRError::FileError(msg) => write!(f, "File Error: {}", msg),
            KSMRError::SecretManagerCreationError(msg) => {
                write!(f, "Secret manager creation Error: {}", msg)
            }
            KSMRError::PasswordCreationError(msg) => write!(f, "Password creation Error: {}", msg),
            KSMRError::StorageError(msg) => write!(f, "Storage Error: {}", msg),
            KSMRError::DirectoryCreationError(er, error) => {
                write!(f, "Directory Creation failed: {}: {}", er, error)
            }
            KSMRError::FileCreationError(er, error) => {
                write!(f, "File Creation failed: {}: {}", er, error)
            }
            KSMRError::FileWriteError(er, error) => {
                write!(f, "File Write failed: {}: {}", er, error)
            }
            KSMRError::SerializationError(er) => {
                write!(f, "JSON serialization/deserialization failed: {}", er)
            }
            KSMRError::DecodeError(er) => write!(f, "Decode Error: {}", er),
            KSMRError::StringConversionError(er) => write!(f, "String Conversion Error: {}", er),
            KSMRError::DataConversionError(er) => write!(f, "Data Conversion Error: {}", er),
            KSMRError::CustomError(err) => write!(f, "{}", err),
            KSMRError::CryptoError(msg) => write!(f, "Cryptography module Error: {}", msg),
            KSMRError::InvalidLength(msg) => write!(f, "Invalid length: {}", msg),
            KSMRError::RecordDataError(msg) => write!(f, "Record data error: {}", msg),
            KSMRError::DeserializationError(msg) => write!(f, "Deserialization Error: {}", msg),
            KSMRError::HTTPError(msg) => write!(
                f,
                "Error sending or receiving data from keeper servers. Exact message includes : {}",
                msg
            ),
            KSMRError::InvalidPayloadError(msg) => {
                write!(f, "payload doesn't belong to any of these types: {}", msg)
            }
            KSMRError::IOError(error) => {
                write!(f, "IO Error: {}", error)
            }
            KSMRError::PathError(string) => {
                write!(f, "Path Error: {}", string)
            }
            KSMRError::KeyNotFoundError(string) => {
                write!(f, "Key not found: {}", string)
            }
            KSMRError::TOTPError(string) => write!(f, "TOTP Error: {}", string),
            KSMRError::NotationError(string) => write!(f, "Notation Error: {}", string),
            // v17.1.0: New error types
            KSMRError::RecordNotFoundError(string) => write!(f, "Record not found: {}", string),
            KSMRError::FieldNotFoundError(string) => write!(f, "Field not found: {}", string),
            KSMRError::AuthenticationError(string) => {
                write!(f, "Authentication failed: {}", string)
            }
            KSMRError::InvalidTokenError(string) => write!(f, "Invalid token: {}", string),
            KSMRError::TransactionError(string) => write!(f, "Transaction error: {}", string),
            KSMRError::ConfigurationError(string) => write!(f, "Configuration error: {}", string),
        }
    }
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

impl Error for KSMRError {}
