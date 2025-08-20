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

use crate::{
    crypto::{unpad_data, CryptoUtils},
    custom_error::KSMRError,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    prelude::BASE64_URL_SAFE,
    Engine as _,
};
use chrono::Utc;
use core::str;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use log::warn;
use num_bigint::BigUint;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    thread_rng,
};
use serde::Serialize;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::process::Output;
use std::{collections::HashMap, option::Option};
use std::{env, io};
use url::{form_urlencoded::parse, Url};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "windows")]
use log::debug;
use std::fs::File;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(unix)]
use std::fs;

/// Allowed Windows configuration administrators.
pub const ALLOWED_WINDOWS_CONFIG_ADMINS: [&[u8]; 2] = [b"Administrators", b"SYSTEM"];

/// Encoding format.
pub const ENCODING: &str = "UTF-8";

/// Special characters used in passwords or other contexts.
pub const SPECIAL_CHARACTERS: &str = r#"""!@#$%()+;<>=?[]{}^.,"""#;

/// Default password length.
pub const DEFAULT_PASSWORD_LENGTH: usize = 32;

/// Converts a string representation of truth to a boolean value.
///
/// The function accepts string values that represent true or false:
/// - True values: "y", "yes", "t", "true", "on", "1"
/// - False values: "n", "no", "f", "false", "off", "0"
///
/// # Errors
///
/// Returns an error if the input string does not match any of the valid
/// truth values.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::str_to_bool;
/// let true_value = str_to_bool("yes").unwrap();
/// assert_eq!(true_value, true);
///
/// let false_value = str_to_bool("no").unwrap();
/// assert_eq!(false_value, false);
///
/// let invalid_value = str_to_bool("maybe");
/// assert!(invalid_value.is_err());
/// ```
pub fn str_to_bool(val: &str) -> Result<bool, String> {
    let val = val.to_lowercase();
    match val.as_str() {
        "y" | "yes" | "t" | "true" | "on" | "1" => Ok(true),
        "n" | "no" | "f" | "false" | "off" | "0" => Ok(false),
        _ => Err(format!("invalid truth value {:?}", val)),
    }
}

/// Gets the name of the operating system.
///
/// This function returns a string slice that indicates the current
/// operating system. The possible return values are:
///
/// - `"linux"` for Linux operating systems.
/// - `"macOS"` for macOS.
/// - The value of `std::env::consts::OS` for any other operating systems.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::get_os;
/// let os_name = get_os();
/// println!("Operating System: {}", os_name);
/// ```
pub fn get_os() -> &'static str {
    determine_os(env::consts::OS)
}

// Helper function for testability
pub(crate) fn determine_os(os: &str) -> &str {
    match os {
        "linux" => "linux",
        "macos" => "macOS",
        "windows" => {
            if cfg!(target_os = "windows") {
                "win32"
            } else {
                "win64"
            }
        }
        _ => os,
    }
}

/// Converts a byte slice to a String using the specified encoding.
///
/// # Arguments
///
/// * `b` - A byte slice (`&[u8]`) that needs to be converted to a String.
///
/// # Returns
///
/// A `Result<String, std::str::Utf8Error>` where:
/// - `Ok(String)` contains the decoded string if successful.
/// - `Err(std::str::Utf8Error)` if the byte slice is not valid UTF-8.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::bytes_to_string;
/// let bytes = b"Hello, world!";
/// let result = bytes_to_string(bytes);
/// assert_eq!(result.unwrap(), "Hello, world!");
/// ```
pub fn bytes_to_string(b: &[u8]) -> Result<String, KSMRError> {
    // let bytes_sorted = unpad_data(b)?;
    let string_of_bytes: String = str::from_utf8(b)
        .map_err(|e| KSMRError::DecodeError(e.to_string()))?
        .to_string();
    Ok(string_of_bytes)
}

pub fn bytes_to_string_unpad(b: &[u8]) -> Result<String, KSMRError> {
    let bytes_sorted = unpad_data(b)?;
    let string_of_bytes: String = str::from_utf8(&bytes_sorted)
        .map_err(|e| KSMRError::DecodeError(e.to_string()))?
        .to_string();
    Ok(string_of_bytes)
}

/// Converts a byte slice to an integer using big-endian byte order.
///
/// # Arguments
///
/// * `b` - A byte slice (`&[u8]`) that needs to be converted to an integer.
///
/// # Returns
///
/// An `Option<u64>` where:
/// - `Some(u64)` contains the converted integer if successful.
/// - `None` if the byte slice is empty or too long to fit in a u64.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::bytes_to_int;
/// use num_bigint::BigUint;
/// let bytes = [0x00, 0x01, 0x02, 0x03];
/// let result = bytes_to_int(&bytes);
/// assert_eq!(result.unwrap(), BigUint::from(66051u64));
/// ```
pub fn bytes_to_int(b: &[u8]) -> Result<BigUint, KSMRError> {
    Ok(BigUint::from_bytes_be(b))
}

/// Converts a byte slice to a Base64-encoded string.
///
/// # Arguments
///
/// * `b` - A byte slice (`&[u8]`) that needs to be converted to a Base64 string.
///
/// # Returns
///
/// A `String` containing the Base64-encoded representation of the input byte slice.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::bytes_to_base64;
/// let bytes = b"Hello, world!";
/// let result = bytes_to_base64(bytes);
/// assert_eq!(result, "SGVsbG8sIHdvcmxkIQ==");
/// ```
pub fn bytes_to_base64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Converts a Base64-encoded string to a byte vector.
///
/// # Arguments
///
/// * `s` - A string slice (`&str`) that contains the Base64-encoded data.
///
/// # Returns
///
/// A `Result<Vec<u8>, base64::DecodeError>` where:
/// - `Ok(Vec<u8>)` contains the decoded byte vector if successful.
/// - `Err(base64::DecodeError)` if the input string is not valid Base64.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::base64_to_bytes;
/// let encoded = "SGVsbG8sIHdvcmxkIQ==";
/// let result = base64_to_bytes(encoded);
/// assert_eq!(result.unwrap(), b"Hello, world!");
/// ```
pub fn base64_to_bytes(s: &str) -> Result<Vec<u8>, KSMRError> {
    let decode_confed_str = s.to_string().replace("+", "-").replace("/", "_");

    let decoded_bytes = BASE64_URL_SAFE
        .decode(decode_confed_str)
        .map_err(|e| KSMRError::DecodeError(e.to_string()))?;

    Ok(decoded_bytes)
}

/// Converts a Base64-encoded string to a UTF-8 string.
///
/// # Arguments
///
/// * `b64s` - A string slice (`&str`) containing the Base64-encoded data.
///
/// # Returns
///
/// A `Result<String, KSMRError>` where:
/// - `Ok(String)` contains the decoded UTF-8 string if successful.
/// - `Err(KSMRError)` if there is an error during decoding.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::base64_to_string;
///  use base64::{ engine::general_purpose::STANDARD, Engine as _};
/// let encoded = STANDARD.encode("hello");
/// let result = base64_to_string(&encoded.to_string());
/// assert_eq!(result.unwrap(), "hello");
/// ```
pub fn base64_to_string(b64s: &str) -> Result<String, KSMRError> {
    let decoded_bytes = STANDARD
        .decode(b64s)
        .map_err(|_| KSMRError::DecodeError("Failed to decode Base64 string".to_string()))?;

    let decoded_string = String::from_utf8(decoded_bytes)
        .map_err(|_| KSMRError::DecodeError("Failed to convert bytes to UTF-8".to_string()))?;

    Ok(decoded_string)
}

pub fn base64_to_string_lossy(b64s: &str) -> Result<String, KSMRError> {
    let decoded_bytes = STANDARD
        .decode(b64s)
        .map_err(|_| KSMRError::DecodeError("Failed to decode Base64 string".to_string()))?;

    let decoded_string = String::from_utf8_lossy(&decoded_bytes).to_string();

    Ok(decoded_string)
}

/// Converts a string to a byte vector using UTF-8 encoding.
///
/// # Arguments
///
/// * `s` - A string slice (`&str`) to be converted to bytes.
///
/// # Returns
///
/// A `Vec<u8>` containing the UTF-8 encoded bytes of the input string.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::string_to_bytes;
/// let input = "Hello, world!";
/// let bytes = string_to_bytes(input);
/// assert_eq!(bytes, b"Hello, world!");
/// ```
pub fn string_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec() // Convert the string slice to a byte vector
}

/// Converts a URL-safe Base64-encoded string to a byte vector.
///
/// # Arguments
///
/// * `s` - A string slice (`&str`) containing the URL-safe Base64-encoded data.
///
/// # Returns
///
/// A `Result<Vec<u8>, base64::DecodeError>` where:
/// - `Ok(Vec<u8>)` contains the decoded byte vector if successful.
/// - `Err(base64::DecodeError)` if the input string is not valid Base64.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::url_safe_str_to_bytes;
/// let encoded = "SGVsbG8sIFdvcmxkIQ"; // URL-safe Base64 string
/// let result = url_safe_str_to_bytes(encoded);
/// assert_eq!(result.unwrap(), b"Hello, World!");
/// ```
pub fn url_safe_str_to_bytes(s: &str) -> Result<Vec<u8>, crate::custom_error::KSMRError> {
    // // Add padding manually if necessary
    // let padded_str = if s.len() % 4 != 0 {
    //     format!("{}{}", s, "=".repeat(4 - s.len() % 4))
    // } else {
    //     s.to_string()
    // };
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| KSMRError::DecodeError(e.to_string()))
}

/// Converts a URL-safe Base64-encoded string to a u64 integer.
///
/// # Arguments
///
/// * `s` - A string slice (`&str`) containing the URL-safe Base64-encoded data.
///
/// # Returns
///
/// A `Result<u64, String>` where:
/// - `Ok(u64)` contains the converted integer if successful.
/// - `Err(String)` if the input string is not valid Base64 or if the conversion fails.
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::url_safe_str_to_int;
/// use num_bigint::BigUint;
/// let encoded = "4oCU"; // URL-safe Base64 string
/// let decoded = url_safe_str_to_int(encoded).unwrap();
/// assert_eq!(decoded, BigUint::from(14844052u64));
pub fn url_safe_str_to_int(s: &str) -> Result<BigUint, KSMRError> {
    let bytes_of_str = url_safe_str_to_bytes(s)?;
    bytes_to_int(bytes_of_str.as_slice()).map_err(|e| KSMRError::DecodeError(e.to_string()))
}

/// Generates a vector of random bytes.
///
/// # Arguments
///
/// * `length` - The number of random bytes to generate.
///
/// # Returns
///
/// A `Vec<u8>` containing the generated random bytes.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::generate_random_bytes;
/// let random_bytes = generate_random_bytes(16);
/// assert_eq!(random_bytes.len(), 16); // Should be 16 bytes long
/// ```
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    CryptoUtils::generate_random_bytes(length)
}

/// Generates UID bytes with specific bit conditions.
///
/// # Returns
///
/// A `Vec<u8>` containing the generated UID bytes.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::generate_uid_bytes;
/// let uid = generate_uid_bytes();
/// assert_eq!(uid.len(), 16); // Should generate a UID of 16 bytes
/// // Further checks can be added based on expected UID properties
/// ```
pub fn generate_uid_bytes() -> Vec<u8> {
    let dash = [0xf8, 0x7f]; // Represents [11111000, 01111111]
    let mut uid_bytes: Vec<u8> = Vec::new();

    for _ in 0..8 {
        uid_bytes = generate_random_bytes(16);
        if dash[0] & uid_bytes[0] != dash[0] {
            break;
        }
    }

    if dash[0] & uid_bytes[0] == dash[0] {
        uid_bytes[0] &= dash[1];
    }

    uid_bytes
}

pub fn generate_uid() -> String {
    let uid_bytes = generate_uid_bytes();
    CryptoUtils::bytes_to_url_safe_str(&uid_bytes)
}

/// Converts a dictionary to a JSON string with pretty formatting.
///
/// # Arguments
///
/// * `dictionary` - A reference to a serializable object that can be converted to JSON.
///
/// # Returns
///
/// A `Result<String, serde_json::Error>` containing the formatted JSON string if successful,
/// or an error if serialization fails.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::dict_to_json;
/// let dictionary = [("key1", "value1"), ("key2", "value2")].iter().cloned().collect::<std::collections::HashMap<_, _>>();
/// let json = dict_to_json(&dictionary).unwrap();
/// println!("{}", json); // Outputs the JSON representation of the dictionary
/// ```
pub fn dict_to_json<T: Serialize>(dictionary: &T) -> serde_json::Result<String> {
    serde_json::to_string_pretty(dictionary)
}

/// Converts a JSON string to a dictionary (HashMap).
///
/// # Arguments
///
/// * `json_str` - A string slice containing the JSON data.
///
/// # Returns
///
/// An `Option<Value>` which will be `Some(Value)` containing the parsed JSON
/// if successful, or `None` if parsing fails.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::json_to_dict;
/// let json_str = r#"{"key1": "value1", "key2": "value2"}"#;
/// let dict = json_to_dict(json_str);
/// assert!(dict.is_some());
/// ```
pub fn json_to_dict(json_str: &str) -> Option<HashMap<String, Value>> {
    let return_value = serde_json::from_str(json_str).map_err(|err| {
        warn!("JSON decode error: {}", err);
    });
    // return Some(return_value);
    match return_value {
        Ok(map) => Some(map),
        Err(err) => {
            warn!("JSON decode error: {:?}", err);
            None
        }
    }
}

/// Returns the current time in milliseconds since the Unix epoch.
///
/// This function retrieves the current UTC time and converts it into
/// milliseconds since January 1, 1970 (the Unix epoch).
///
/// # Returns
///
/// An `i64` representing the current time in milliseconds.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::now_milliseconds;
/// let millis = now_milliseconds();
/// println!("Current time in milliseconds: {}", millis);
/// ```
///
/// In the example above, the function returns the current time in milliseconds,
/// which can be used for timestamping events or measuring time intervals.
pub fn now_milliseconds() -> i64 {
    Utc::now().timestamp_millis()
}
/// Represents a TOTP code along with its time left and period.
#[derive(Debug, Clone)]
pub struct TotpCode {
    code: String,
    time_left: u64, // Assuming time_left is in seconds
    period: u64,    // Assuming period is also in seconds
}

impl TotpCode {
    /// Creates a new `TotpCode`.
    ///
    /// # Arguments
    ///
    /// * `code` - A string representing the TOTP code.
    /// * `time_left` - The time left until the code expires, in seconds.
    /// * `period` - The period for which the TOTP code is valid, in seconds.
    ///
    /// # Returns
    ///
    /// A new instance of `TotpCode`.
    pub fn new(code: String, time_left: u64, period: u64) -> Self {
        TotpCode {
            code,
            time_left,
            period,
        }
    }

    /// Returns the TOTP code.
    pub fn get_code(&self) -> &str {
        &self.code
    }

    /// Returns the time left.
    pub fn get_time_left(&self) -> u64 {
        self.time_left
    }

    /// Returns the period.\
    pub fn get_period(&self) -> u64 {
        self.period
    }
}

/// Generates a TOTP code from a given otp auth URL.
///
/// # Arguments
///
/// * `url` - A string slice containing the otp auth URL.
///
/// # Returns
///
/// A `Result<TotpCode, String>` which contains the generated TOTP code
/// if successful, or an error message if parsing or generation fails.
///
/// # Examples
///
/// ```
/// use keeper_secrets_manager_core::utils::get_totp_code;
/// let url = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Example";
/// match get_totp_code(url) {
///     Ok(totp_code) => println!("Generated TOTP code: {:?}", totp_code),
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
pub fn get_totp_code(url: &str) -> Result<TotpCode, KSMRError> {
    let comp = Url::parse(url).map_err(|_| KSMRError::TOTPError("Invalid URL".to_string()))?;
    if comp.scheme() != "otpauth" {
        return Err(KSMRError::TOTPError("Not an otpauth URI".to_string()));
    }

    let mut secret = None;
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6;
    let mut period = 30;
    let mut counter = 0;

    // Parse URL query string
    let query_pairs = parse(comp.query().unwrap_or("").as_bytes());
    for (key, value) in query_pairs {
        match key.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "algorithm" => algorithm = value.into_owned().to_uppercase(),
            "digits" => {
                if let Ok(num) = value.parse::<u32>() {
                    if num > 0 && num < 10 {
                        digits = num;
                    } else {
                        return Err(KSMRError::TOTPError(
                            "TOTP Digits may only be 6, 7, or 8".to_string(),
                        ));
                    }
                }
            }
            "period" => {
                if let Ok(num) = value.parse::<u32>() {
                    if num > 0 {
                        period = num;
                    }
                }
            }
            "counter" => {
                if let Ok(num) = value.parse::<u32>() {
                    if num > 0 {
                        counter = num;
                    }
                }
            }
            _ => {}
        }
    }

    // Validate parameters
    let secret = secret
        .ok_or(KSMRError::TOTPError(
            "TOTP secret not found in URI".to_string(),
        ))?
        .to_ascii_uppercase();
    let decoded_key_option = BASE32.decode(secret.as_bytes());
    let key = match decoded_key_option {
        Ok(decoded_key) => decoded_key,
        Err(err) => Err(KSMRError::DecodeError(format!(
            "Invalid TOTP secret: {}",
            err
        )))?,
    };

    let tm_base = if counter > 0 {
        counter
    } else {
        Utc::now().timestamp() as u32
    };
    let tm = tm_base / period;
    let msg = (tm as u64).to_be_bytes();

    let digest: Vec<u8> = match algorithm.as_str() {
        "SHA1" => {
            let mut hmac = Hmac::<Sha1>::new_from_slice(&key)
                .map_err(|_| KSMRError::TOTPError("Failed to create HMAC".to_string()))?;
            hmac.update(&msg);
            hmac.finalize().into_bytes().to_vec()
        }
        "SHA256" => {
            let mut hmac = Hmac::<Sha256>::new_from_slice(&key)
                .map_err(|_| KSMRError::TOTPError("Failed to create HMAC".to_string()))?;
            hmac.update(&msg);
            hmac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut hmac = Hmac::<Sha512>::new_from_slice(&key)
                .map_err(|_| KSMRError::TOTPError("Failed to create HMAC".to_string()))?;
            hmac.update(&msg);
            hmac.finalize().into_bytes().to_vec()
        }
        _ => {
            return Err(KSMRError::TOTPError(format!(
                "Invalid algorithm: {}",
                algorithm
            )))
        }
    };

    let offset = (digest.last().unwrap() & 0x0f) as usize;
    let base = &digest[offset..offset + 4];
    let code_int = ((base[0] & 0x7f) as u32) << 24
        | (base[1] as u32) << 16
        | (base[2] as u32) << 8
        | (base[3] as u32);
    let code = format!(
        "{:0width$}",
        code_int % 10u32.pow(digits),
        width = digits as usize
    );

    let elapsed = tm_base % period; // time elapsed in current period in seconds
    let ttl = period - elapsed; // time to live in seconds

    Ok(TotpCode::new(code, ttl as u64, period as u64))
}

pub fn get_otp_url_from_value_obj(val: serde_json::Value) -> Result<String, KSMRError> {
    let otp_value = match val.is_array() {
        true => val.as_array().unwrap()[0][0].clone(),
        false => {
            return Err(KSMRError::RecordDataError(
                "otpCode or otp field is not an array".to_string(),
            ))
        }
    };

    let url_retrieved = match otp_value.is_string() {
        true => otp_value.as_str().unwrap().to_string(),
        false => {
            return Err(KSMRError::RecordDataError(
                "otpCode or otp field is not a string".to_string(),
            ))
        }
    };

    Ok(url_retrieved)
}
/// Generates a random sample of characters from a given string.
///
/// # Parameters
/// - `sample_length`: The number of characters to sample.
/// - `sample_string`: The string from which to sample characters.
///
/// # Returns
/// A `String` containing the sampled characters.
///
/// # Errors
/// Returns an error if `sample_length` is negative or if `sample_string` is empty.
///
/// # Example
/// ```
/// use keeper_secrets_manager_core::utils::random_sample;
/// let result = random_sample(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").unwrap();
/// println!("Random Sample: {}", result);
/// ```
pub fn random_sample(
    sample_length: usize,
    sample_string: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Validate inputs
    if sample_length == 0 {
        return Ok(String::new());
    }

    if sample_string.is_empty() {
        return Err("sample_string must not be empty".into());
    }

    let mut rng = rand::thread_rng();
    let mut sample = String::new();

    for _ in 0..sample_length {
        let char = sample_string
            .chars()
            .choose(&mut rng)
            .ok_or("Failed to choose a character")?;
        sample.push(char);
    }

    Ok(sample)
}

/// Gets the current Windows user SID and name.
///
/// # Returns
/// A tuple containing the SID and username, or (None, None) if there was an error.
///
/// # Example
/// ```
/// use std::process::{Command, Output};
/// use std::option::Option;
/// use keeper_secrets_manager_core::utils::get_windows_user_sid_and_name;
/// let (sid, username) = get_windows_user_sid_and_name::<fn() -> Output>(None);
/// println!("SID: {:?}, Username: {:?}", sid, username);
/// ```
#[cfg(target_os = "windows")]
pub fn get_windows_user_sid_and_name<F>(command: Option<F>) -> (Option<String>, Option<String>)
where
    F: Fn() -> Output,
{
    let output = match command {
        Some(comm) => comm(),
        None => _default_command(),
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        if let Some(last_line) = lines.last() {
            let parts: Vec<&str> = last_line.split('\\').collect();
            if let Some(username_sid) = parts.last() {
                let username_sid_string = username_sid.to_string();
                let split_parts: Vec<&str> = username_sid_string.split(" ").collect();
                // let mut parts_split  = username_sid.split_ascii_whitespace();
                // let username = parts_split.next().unwrap_or("");
                // let sid = parts_split.next().unwrap_or("");
                let username = split_parts[0].to_string();
                let sid = split_parts[1].to_string();
                return (Some(sid), Some(username));
            }
        }
    } else {
        eprintln!("Failed to execute 'whoami.exe'");
    }

    (None, None)
}

#[cfg(target_os = "windows")]
fn _default_command() -> Output {
    Command::new("whoami.exe")
        .arg("/user")
        .output()
        .expect("Failed to execute whoami.exe")
}

#[cfg(not(target_os = "windows"))]
fn _default_command() -> Output {
    // This can be a dummy output or an error for non-Windows platforms.

    use std::os::unix::process::ExitStatusExt;
    Output {
        status: std::process::ExitStatus::from_raw(1),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

/**
Sets the configuration mode for the specified file, adjusting its permissions
according to the operating system's conventions. On Windows, it uses `icacls`
to set file permissions, while on Linux/MacOS, it sets the permissions to 0600.

# Arguments

* `file` - A string slice that holds the path to the configuration file.

# Returns

This function returns `Ok(())` if the mode is set successfully, or an `io::Error`
if an error occurs.

*/
pub fn set_config_mode(
    file: &str,
) -> Result<(), io::Error> {
    // Check if we should skip setting the mode
    if let Ok(skip_mode) = env::var("KSM_CONFIG_SKIP_MODE") {
        if skip_mode.to_lowercase() == "true" {
            return Ok(());
        }
    }

    // For Windows, use icacls commands
    #[cfg(target_os = "windows")]
    {
        let sid = match get_windows_user_sid_and_name::<fn() -> Output>(None) {
            (Some(sid), _) => sid,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to get user SID",
                ))
            }
        };

        // Commands to set the file permissions
        let commands = vec![
            format!(r#"icacls "{}" /reset"#, file),
            format!(r#"icacls "{}" /inheritance:r"#, file),
            format!(r#"icacls "{}" /remove:g Everyone:F"#, file),
            format!(r#"icacls "{}" /grant:r Administrators:F"#, file),
            format!(r#"icacls "{}" /grant:r "{}:F""#, file, sid),
        ];

        for command in commands {

            let output = Command::new("cmd").args(&["/C", &command]).output()?;

            match output.status.code() {
                Some(2) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Cannot find configuration file {}", file),
                    ))
                }
                Some(5) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Access denied to configuration file {}", file),
                    ))
                }
                Some(1332) => {
                    debug!("{} {}", "Failed to set some ACL permissions: {}", command);
                    continue; // Skip localized group/user names error
                }
                Some(_) if !output.status.success() => {
                    let message = format!(
                        "Could not change the ACL for file '{}'. Set the environmental variable 'KSM_CONFIG_SKIP_MODE' to 'TRUE' to skip setting the ACL mode.",
                        file
                    );
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let full_message = if !stderr.is_empty() {
                        format!("{}: {}", message, stderr.trim())
                    } else {
                        format!("{}.", message)
                    };
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        full_message,
                    ));
                }
                _ => {}
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Linux/MacOS, set file permissions to 0600
        let permissions = fs::metadata(file)?.permissions();
        let mut new_permissions = permissions;
        new_permissions.set_mode(0o600);
        fs::set_permissions(file, new_permissions)?;
    }

    Ok(())
}

//This function runs only on windows and this unit test runs only on windows
/// Retrieves localized account names for known administrative accounts on Windows.
///
/// This function uses the Win32 API to fetch account names for the local system
/// and built-in administrators. It returns a vector of strings containing the
/// localized names.
///
/// # Errors
///
/// This function returns an error if it fails to create a well-known SID,
/// look up the account names, or execute the command to convert the names
/// to the console's code page.
///
/// # Example
///
/// ```ignore
/// fn main() -> Result<(), u32> {
///     match _populate_windows_localized_admin_names_win32api() {
///         Ok(localized_admins) => {
///             for admin in localized_admins {
///                 println!("Localized Admin: {}", admin);
///             }
///         },
///         Err(err) => eprintln!("Error retrieving localized admin names: {}", err),
///     }
///     Ok(())
/// }
/// ```
///
/// # Test
///
/// This test will run if the target operating system is Windows and the
/// function is expected to return a non-empty list of localized admin names.
///
/// ```ignore
/// #[cfg(test)]
/// mod tests {
///     use super::*; // Ensure the test module has access to the function
///
///     #[test]
///     #[cfg(target_os = "windows")] // Only run this test on Windows
///     fn test_populate_windows_localized_admin_names_win32api() {
///         let result = _populate_windows_localized_admin_names_win32api();
///         assert!(result.is_ok(), "Function should return Ok on success");
///         let localized_admins = result.unwrap();
///         assert!(!localized_admins.is_empty(), "Should return at least one localized admin name");
///     }
/// }
/// ```
#[cfg(target_os = "windows")]
fn _populate_windows_localized_admin_names_win32api() -> Result<Vec<String>, u32> {
    use std::ffi::OsString; // Make sure to import OsString
    use std::os::windows::ffi::OsStringExt; // Import the OsStringExt trait
    use std::ptr;
    use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::securitybaseapi::CreateWellKnownSid;
    use winapi::um::winbase::LookupAccountSidW;

    // Define WellKnownSidType manually
    #[allow(non_camel_case_types)]
    #[repr(u32)]
    #[derive(Clone)]
    pub enum WellKnownSidType {
        WinLocalSystemSid = 22,
        WinBuiltinAdministratorsSid = 26,
    }

    // Helper function to convert a wide string (UTF-16) to a Rust String
    fn wide_to_string(wide: &[u16]) -> String {
        let os_string = OsString::from_wide(wide);
        os_string.to_string_lossy().into_owned()
    }

    // Function to get account name for a specific SID type
    fn get_account_name(sid_type: WellKnownSidType) -> Result<(String, String), u32> {
        let mut sid_size = 256;
        let mut sid = vec![0u8; sid_size as usize];

        unsafe {
            // CreateWellKnownSid
            if CreateWellKnownSid(
                sid_type.clone() as u32,
                ptr::null_mut(),
                sid.as_mut_ptr() as *mut _,
                &mut sid_size,
            ) == 0
            {
                let error = GetLastError();
                if error == ERROR_INSUFFICIENT_BUFFER || error == ERROR_INVALID_PARAMETER {
                    sid = vec![0u8; sid_size as usize];
                    if CreateWellKnownSid(
                        sid_type as u32,
                        ptr::null_mut(),
                        sid.as_mut_ptr() as *mut _,
                        &mut sid_size,
                    ) == 0
                    {
                        return Err(GetLastError());
                    }
                } else {
                    return Err(error);
                }
            }

            // LookupAccountSidW to get the size needed for the name and domain
            let mut name_size = 0;
            let mut domain_size = 0;
            let mut sid_name_use = 0;
            LookupAccountSidW(
                ptr::null(),
                sid.as_mut_ptr() as *mut _,
                ptr::null_mut(),
                &mut name_size,
                ptr::null_mut(),
                &mut domain_size,
                &mut sid_name_use,
            );

            let error = GetLastError();
            if error != ERROR_INSUFFICIENT_BUFFER {
                return Err(error);
            }

            // Allocate buffers for the account name and domain name
            let mut name = vec![0u16; name_size as usize];
            let mut domain = vec![0u16; domain_size as usize];

            // LookupAccountSidW to actually get the name and domain
            if LookupAccountSidW(
                ptr::null(),
                sid.as_mut_ptr() as *mut _,
                name.as_mut_ptr(),
                &mut name_size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut sid_name_use,
            ) == 0
            {
                return Err(GetLastError());
            }

            // Convert wide strings to Rust Strings
            let domain_str = wide_to_string(&domain);
            let name_str = wide_to_string(&name);

            Ok((domain_str, name_str))
        }
    }

    let mut localized_admins = Vec::new();
    let mut admins = Vec::new();

    // Retrieve account names for specific well-known SIDs
    if let Ok((_, name)) = get_account_name(WellKnownSidType::WinLocalSystemSid) {
        admins.push(name);
    }

    if let Ok((_, name)) = get_account_name(WellKnownSidType::WinBuiltinAdministratorsSid) {
        admins.push(name);
    }

    // Convert WMI names (admins) to the console's code page using a shell command (like "cmd /c")
    if !admins.is_empty() {
        let mut cmd = String::from("echo.");
        for admin in &admins {
            cmd.push_str(&format!(" & echo {}", admin));
        }

        // Execute the command in the shell
        let output = std::process::Command::new("cmd")
            .args(&["/C", &cmd])
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            let output_lines = output.stdout.split(|&b| b == b'\n');
            for line in output_lines {
                if !line.is_empty() {
                    localized_admins.push(String::from_utf8_lossy(line).trim().to_string());
                }
            }
        }
    }

    Ok(localized_admins)
}

#[derive(Debug)]
pub enum ConfigError {
    PermissionDenied(String),
    FileNotFound(String),
    GeneralError(String),
}

/// This function checks the permissions of a given configuration file.
/// On Windows, it uses the `icacls` command to verify permissions.
/// On Unix-like systems (Linux, macOS), it checks the file mode and ensures that
/// only the owner has access.
///
/// The function will skip permission checking if the `KSM_CONFIG_SKIP_MODE` environment
/// variable is set to `TRUE`.
///
/// On Windows, if access is denied or the file is missing, specific errors are returned.
/// The function also checks for warnings about overly permissive access modes.
///
/// # Errors
///
/// Returns:
/// - `ConfigError::PermissionDenied` if the file is accessible by users other than the owner.
/// - `ConfigError::FileNotFound` if the file does not exist.
/// - `ConfigError::GeneralError` if there are other issues, such as executing the `icacls` command.
///
/// # Example (Unix-like systems)
/// ```ignore
/// use std::fs;
/// #[cfg(unix)]
/// use std::os::unix::fs::PermissionsExt;
/// use keeper_secrets_manager_core::utils::check_config_mode;
/// use keeper_secrets_manager_core::utils::ConfigError;
///
/// // Create a file and set restrictive permissions (only owner can access).
/// let file_path = "client-config.json";
/// fs::File::create(file_path).unwrap();
/// let mut perms = fs::metadata(file_path).unwrap().permissions();
/// perms.set_mode(0o600);  // Owner can read/write
/// fs::set_permissions(file_path, perms).unwrap();
///
/// // Run the function
/// match check_config_mode(file_path) {
///     Ok(true) => println!("Permissions are correctly set."),
///     Ok(false) => println!("Permissions are too open."),
///     Err(ConfigError::PermissionDenied(err)) => eprintln!("Permission denied: {}", err),
///     Err(ConfigError::FileNotFound(err)) => eprintln!("File not found: {}", err),
///     Err(ConfigError::GeneralError(err)) => eprintln!("General error: {}", err),
///     _ => eprintln!("Unknown error."),
/// }
/// ```
///
/// # Example (Windows)
/// ```rust,ignore
/// use keeper_secrets_manager_core::utils::check_config_mode;
/// use keeper_secrets_manager_core::utils::ConfigError;
///
/// let file_path = "client-config.json";
///
/// // Run the function
/// match check_config_mode(file_path) {
///     Ok(true) => println!("Permissions are correctly set."),
///     Ok(false) => println!("Permissions are too open."),
///     Err(ConfigError::PermissionDenied(err)) => eprintln!("Permission denied: {}", err),
///     Err(ConfigError::FileNotFound(err)) => eprintln!("File not found: {}", err),
///     Err(ConfigError::GeneralError(err)) => eprintln!("General error: {}", err),
///     _ => eprintln!("Unknown error."),
/// }
/// ```
pub fn check_config_mode(file: &str) -> Result<bool, ConfigError> {
    let skip_mode_check = env::var("KSM_CONFIG_SKIP_MODE")
        .unwrap_or("FALSE".to_string())
        .eq_ignore_ascii_case("TRUE");

    if skip_mode_check {
        return Ok(true);
    }

    #[cfg(target_os = "windows")]
    return check_windows_permissions(file);

    #[cfg(not(target_os = "windows"))]
    return check_unix_permissions(file);
}

#[cfg(target_os = "windows")]
fn check_windows_permissions(file: &str) -> Result<bool, ConfigError> {
    use std::process::Command;

    // Execute the `icacls` command to check file permissions
    let output = Command::new("icacls")
        .arg(file)
        .output()
        .map_err(|e| ConfigError::GeneralError(format!("Error executing icacls: {}", e)))?;

    if !output.status.success() {
        return match output.status.code() {
            Some(2) => Err(ConfigError::FileNotFound(file.to_string())),
            Some(5) => Err(ConfigError::PermissionDenied(file.to_string())),
            _ => Err(ConfigError::GeneralError(
                "Unknown error in icacls".to_string(),
            )),
        };
    }

    // Additional checks for user permissions
    if !is_file_accessible(file) {
        return Err(ConfigError::PermissionDenied(format!(
            "Access denied to {}",
            file
        )));
    }

    Ok(true)
}

#[cfg(not(target_os = "windows"))]
fn check_unix_permissions(file: &str) -> Result<bool, ConfigError> {
    // Check if the file exists first

    use std::path::Path;
    let file_path = Path::new(file);
    if !file_path.exists() {
        return Err(ConfigError::FileNotFound(file.to_string()));
    }

    // Attempt to open the file to verify access permissions
    let metadata =
        fs::metadata(file_path).map_err(|_| ConfigError::FileNotFound(file.to_string()))?;
    if !is_file_accessible(file) {
        return Err(ConfigError::PermissionDenied(file.to_string()));
    }
    // Retrieve file mode and permissions for validation
    let permissions = metadata.permissions().mode();
    if permissions & 0o077 != 0 {
        eprintln!(
            "Warning: File permissions for {} are too open ({:o}). Consider setting to 0600.",
            file, permissions
        );
        return Err(ConfigError::PermissionDenied(format!(
            "File permissions too open for {}",
            file
        )));
    }

    Ok(true)
}

// Check if file is accessible
fn is_file_accessible(file: &str) -> bool {
    File::open(file).is_ok()
}

#[derive(Debug)]
pub struct PasswordOptions {
    length: usize,
    lowercase: Option<i32>,
    uppercase: Option<i32>,
    digits: Option<i32>,
    special_characters: Option<i32>,
    special_characterset: String,
}

impl PasswordOptions {
    /// Creates a new PasswordOptions with default values.
    pub fn new() -> Self {
        PasswordOptions {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: None,
            uppercase: None,
            digits: None,
            special_characters: None,
            special_characterset: String::from(SPECIAL_CHARACTERS),
        }
    }

    /// Set the password length.
    pub fn length(mut self, length: usize) -> Self {
        if length > 0 {
            self.length = length;
        } else {
            self.length = 32
        }
        self
    }

    /// Set the minimum number of lowercase characters.
    pub fn lowercase(mut self, count: i32) -> Self {
        self.lowercase = Some(count);
        self
    }

    /// Set the minimum number of uppercase characters.
    pub fn uppercase(mut self, count: i32) -> Self {
        self.uppercase = Some(count);
        self
    }

    /// Set the minimum number of digits.
    pub fn digits(mut self, count: i32) -> Self {
        self.digits = Some(count);
        self
    }

    /// Set the minimum number of special characters.
    pub fn special_characters(mut self, count: i32) -> Self {
        self.special_characters = Some(count);
        self
    }

    /// Set the custom set of special characters.
    pub fn special_characterset(mut self, charset: String) -> Self {
        self.special_characterset = charset;
        self
    }
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates a new password based on the specified options.
///
/// The generated password will adhere to the constraints set by the
/// provided `PasswordOptions`. If the specified character counts exceed
/// the total desired password length, an error will be returned.
///
/// # Parameters
///
/// - `options`: An instance of `PasswordOptions` that defines the desired
///   characteristics of the password, such as length and minimum character
///   counts for lowercase, uppercase, digits, and special characters.
///
/// # Returns
///
/// - `Ok(String)`: A randomly generated password that meets the specified
///   criteria.
/// - `Err(String)`: An error message if the specified character counts
///   exceed the total password length or if there are any issues during
///   password generation.
///
/// # Example
///
/// ```rust
/// use keeper_secrets_manager_core::utils::generate_password_with_options;
/// use keeper_secrets_manager_core::utils::PasswordOptions;
///
/// let options = PasswordOptions::new()
///     .length(16)
///     .lowercase(4)
///     .uppercase(4)
///     .digits(4);
///
/// match generate_password_with_options(options) {
///     Ok(password) => println!("Generated Password: {}", password),
///     Err(err) => eprintln!("Error: {}", err),
/// }
/// ```
///
/// # Panics
///
/// This function does not panic, but will return an error if constraints are not met.
///
/// # Errors
///
/// - If the specified lowercase, uppercase, digits, and special characters
///   exceed the total length of the password, an error will be returned.
pub fn generate_password_with_options(options: PasswordOptions) -> Result<String, KSMRError> {
    let mut rng = thread_rng();

    // Collect the counts for each character type
    let lowercase_count = options.lowercase.unwrap_or(0).max(0);
    let uppercase_count = options.uppercase.unwrap_or(0).max(0);
    let digits_count = options.digits.unwrap_or(0).max(0);
    let special_count = options.special_characters.unwrap_or(0).max(0);

    // Calculate the total number of specified characters
    let total_specified = lowercase_count + uppercase_count + digits_count + special_count;

    // Check if specified characters exceed the total length
    if total_specified > options.length as i32 {
        return Err(KSMRError::PasswordCreationError(format!(
            "The specified character counts ({}) exceed the total password length ({})!",
            total_specified, options.length
        )));
    }

    let extra_count = options.length as i32 - total_specified;

    // Build the extra character pool based on available options
    let mut extra_chars = String::new();
    if options.lowercase.is_some() || lowercase_count > 0 {
        extra_chars.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if options.uppercase.is_some() || uppercase_count > 0 {
        extra_chars.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.digits.is_some() || digits_count > 0 {
        extra_chars.push_str("0123456789");
    }
    if options.special_characters.is_some() || special_count > 0 {
        extra_chars.push_str(&options.special_characterset);
    }
    if extra_chars.is_empty() {
        extra_chars.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        extra_chars.push_str(SPECIAL_CHARACTERS);
    }

    // Initialize the category map
    let category_map = vec![
        (lowercase_count as usize, "abcdefghijklmnopqrstuvwxyz"),
        (uppercase_count as usize, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (digits_count as usize, "0123456789"),
        (special_count as usize, &options.special_characterset),
        (extra_count.max(0) as usize, &extra_chars),
    ];

    let mut password_list = Vec::new();
    for (count, chars) in category_map {
        let char_slice: Vec<char> = chars.chars().collect();
        let mut repeated_chars = char_slice.iter().cycle(); // Infinite repetition
        for _ in 0..count {
            if let Some(&sample) = repeated_chars.next() {
                password_list.push(sample);
            }
        }
    }

    let mut remaining_length = options.length - password_list.len();

    while remaining_length > 0 {
        // Randomly select additional characters from the extra characters
        let extra_char_slice: Vec<char> = extra_chars.chars().collect();
        let additional_samples: Vec<char> = extra_char_slice
            .choose_multiple(&mut rng, remaining_length)
            .cloned()
            .collect();

        password_list.extend(additional_samples);
        remaining_length = options.length - password_list.len()
    }
    password_list.shuffle(&mut rng);

    Ok(password_list.into_iter().collect())
}

pub fn generate_password() -> Result<String, KSMRError> {
    let password_options_default = PasswordOptions::new();
    generate_password_with_options(password_options_default)
}
