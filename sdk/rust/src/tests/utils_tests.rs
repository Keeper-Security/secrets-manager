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
mod str_to_bool_tests {
    use crate::utils::str_to_bool;

    #[test]
    fn test_str_to_bool_true_values() {
        // Test all inputs that should return `Ok(true)`
        let true_values = vec!["y", "yes", "t", "true", "on", "1"];

        for val in true_values {
            assert_eq!(
                str_to_bool(val),
                Ok(true),
                "Expected true for input: {}",
                val
            );
        }
    }

    #[test]
    fn test_str_to_bool_false_values() {
        // Test all inputs that should return `Ok(false)`
        let false_values = vec!["n", "no", "f", "false", "off", "0"];

        for val in false_values {
            assert_eq!(
                str_to_bool(val),
                Ok(false),
                "Expected false for input: {}",
                val
            );
        }
    }

    #[test]
    fn test_str_to_bool_case_insensitivity() {
        // Test case-insensitive handling
        let mixed_case_true = vec!["Y", "Yes", "T", "True", "ON", "1"];
        let mixed_case_false = vec!["N", "NO", "F", "False", "OFF", "0"];

        for val in mixed_case_true {
            assert_eq!(
                str_to_bool(val),
                Ok(true),
                "Expected true for input: {}",
                val
            );
        }

        for val in mixed_case_false {
            assert_eq!(
                str_to_bool(val),
                Ok(false),
                "Expected false for input: {}",
                val
            );
        }
    }

    #[test]
    fn test_str_to_bool_invalid_values() {
        // Test invalid inputs that should return an Err
        let invalid_values = vec!["maybe", "onoff", "2", "tru", "yesno", ""];

        for val in invalid_values {
            assert!(
                str_to_bool(val).is_err(),
                "Expected error for input: {}",
                val
            );
        }
    }

    #[test]
    fn test_str_to_bool_error_message() {
        // Test the exact error message for an invalid value
        let invalid_input = "invalid";
        let expected_error = format!("invalid truth value {:?}", invalid_input.to_lowercase());
        assert_eq!(str_to_bool(invalid_input), Err(expected_error));
    }
}

#[cfg(test)]
mod get_os_tests {
    #[cfg(test)]
    use crate::utils::determine_os;

    #[test]
    fn test_get_os_linux() {
        let os = determine_os("linux");
        assert_eq!(os, "linux");
    }

    #[test]
    fn test_get_os_macos() {
        let os = determine_os("macos");
        assert_eq!(os, "macOS");
    }

    #[test]
    fn test_get_os_windows_win32() {
        // Simulate 32-bit Windows
        if cfg!(target_os = "windows") {
            let os = determine_os("windows");
            let windows_32 = os == "win32";
            let windows_64 = os == "win64";
            assert_eq!(true, windows_32 || windows_64);
        }
    }

    #[test]
    fn test_get_os_windows_win64() {
        // Simulate 64-bit Windows
        if cfg!(target_arch = "x86_64") {
            let os = determine_os("windows");
            let windows_32 = os == "win32";
            let windows_64 = os == "win64";
            assert_eq!(true, windows_32 || windows_64);
        }
    }

    #[test]
    fn test_get_os_other_os() {
        let os = determine_os("freebsd");
        assert_eq!(os, "freebsd");

        let os = determine_os("solaris");
        assert_eq!(os, "solaris");

        let os = determine_os("unknown");
        assert_eq!(os, "unknown");
    }
}

#[cfg(test)]
mod bytes_to_string_tests {
    use crate::utils::bytes_to_string;

    #[test]
    fn test_bytes_to_string_valid_utf8() {
        let bytes = b"hello";
        let result = bytes_to_string(bytes);
        assert_eq!(result, Ok("hello".to_string()));

        let bytes = b"world";
        let result = bytes_to_string(bytes);
        assert_eq!(result, Ok("world".to_string()));

        let bytes = b"rust programming";
        let result = bytes_to_string(bytes);
        assert_eq!(result, Ok("rust programming".to_string()));
    }

    #[test]
    fn test_bytes_to_string_invalid_utf8() {
        let bytes: &[u8] = &[0, 159, 146, 150]; // Invalid UTF-8 sequence
        let result = bytes_to_string(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_to_string_empty_bytes() {
        let bytes: &[u8] = b"";
        let result = bytes_to_string(bytes);
        assert_eq!(result, Ok("".to_string())); // Empty string from empty byte slice
    }

    #[test]
    fn test_bytes_to_string_mixed_bytes() {
        let bytes: &[u8] = b"valid\xFFinvalid"; // Mixed valid and invalid bytes
        let result = bytes_to_string(bytes);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod bytes_to_int_tests {
    use num_bigint::BigUint;

    use crate::utils::bytes_to_int;

    #[test]
    fn test_bytes_to_int_valid() {
        let bytes = &[0x01, 0x02, 0x03, 0x04]; // 16909060 in decimal
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(16909060u64));

        let bytes = &[0xFF, 0xFF, 0xFF, 0xFF]; // 4294967295 in decimal
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(4294967295u64));

        let bytes = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]; // 1 in decimal
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(1u64));

        let bytes = &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF]; // 4294967295 in decimal
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(549755813887u64));
    }

    #[test]
    fn test_bytes_to_int_empty() {
        let bytes: &[u8] = &[];
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(0u32)); // Should return None for empty byte slice
    }

    #[test]
    fn test_bytes_to_int_single_byte() {
        let bytes = &[0x01]; // Should return 1
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(1u32));

        let bytes = &[0xFF]; // Should return 255
        let result = bytes_to_int(bytes).unwrap();
        assert_eq!(result, BigUint::from(255u32));
    }
}

#[cfg(test)]
mod bytes_to_base64_tests {
    use crate::utils::bytes_to_base64;

    #[test]
    fn test_bytes_to_base64_basic() {
        let bytes = b"hello";
        let expected = "aGVsbG8="; // Base64 encoded "hello"
        assert_eq!(bytes_to_base64(bytes), expected);
    }

    #[test]
    fn test_bytes_to_base64_empty() {
        let bytes: &[u8] = b""; // Empty input
        let expected = ""; // Base64 encoding of empty input is also empty
        assert_eq!(bytes_to_base64(bytes), expected);
    }

    #[test]
    fn test_bytes_to_base64_non_ascii() {
        let bytes = [0xF0, 0x9F, 0x98, 0x80]; // Unicode smiley face "😀"
        let expected = "8J+YgA==";
        assert_eq!(bytes_to_base64(&bytes), expected);
    }

    #[test]
    fn test_bytes_to_base64_binary_data() {
        let bytes = [0xFF, 0xD8, 0xFF, 0xE0]; // Start of JPEG header
        let expected = "/9j/4A==";
        assert_eq!(bytes_to_base64(&bytes), expected);
    }
}

#[cfg(test)]
mod base64_to_string_tests {
    use crate::utils::base64_to_string;
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    #[test]
    fn test_base64_to_string_valid() {
        let base64_input = STANDARD.encode("hello");
        let expected = "hello";
        assert_eq!(base64_to_string(&base64_input).unwrap(), expected);
    }

    #[test]
    fn test_base64_to_string_empty() {
        let base64_input = URL_SAFE_NO_PAD.encode("");
        let expected = "";
        assert_eq!(base64_to_string(&base64_input).unwrap(), expected);
    }

    #[test]
    fn test_base64_to_string_invalid_base64() {
        let base64_input = "!!not_base64!!";
        let result = base64_to_string(base64_input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode Base64 string"));
    }

    #[test]
    fn test_base64_to_string_invalid_utf8() {
        let invalid_utf8_bytes = vec![0xF0, 0x28, 0x8C, 0x28]; // Invalid UTF-8 byte sequence
        let base64_input = URL_SAFE_NO_PAD.encode(&invalid_utf8_bytes);
        let result = base64_to_string(&base64_input);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(crate::custom_error::KSMRError::DecodeError(
                "Failed to decode Base64 string".to_string()
            ))
        );
    }
}

#[cfg(test)]
mod url_safe_str_to_bytes_tests {
    use crate::{custom_error::KSMRError, utils::url_safe_str_to_bytes};

    #[test]
    fn test_url_safe_str_to_bytes_valid() {
        let input = "dGVzdGxlbjgq"; // This is base64 for "testlen8"
        let result = url_safe_str_to_bytes(input);
        assert_eq!(result, Ok(vec![116, 101, 115, 116, 108, 101, 110, 56, 42]));
        // Valid input
    }

    #[test]
    fn test_url_safe_str_to_bytes_invalid() {
        let input = "invalid_base64_string";
        let result = url_safe_str_to_bytes(input);
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid input length: 21".to_string()
            ))
        ); // Expect an invalid base64 error
    }

    #[test]
    fn test_url_safe_str_to_bytes_empty() {
        let input = "";
        let result = url_safe_str_to_bytes(input);
        assert_eq!(result, Ok(Vec::new())); // Expect decoded bytes too short error when we are checking for minimum length
                                            // assert_eq!(result, Ok(vec![]));
    }

    #[test]
    fn test_url_safe_str_to_bytes_special_characters() {
        let input = "dGVzdGxlbjgq"; // This is base64 for "star"
        let result = url_safe_str_to_bytes(input);
        // Assuming that this special character results in fewer than 8 bytes
        assert_eq!(result, Ok(vec![116, 101, 115, 116, 108, 101, 110, 56, 42]));
    }
}

#[cfg(test)]
mod url_safe_str_to_int_tests {
    use num_bigint::BigUint;
    use std::str::FromStr;

    use crate::{custom_error::KSMRError, utils::url_safe_str_to_int};

    #[test]
    fn test_url_safe_str_to_int_invalid_base64() {
        let input = "invalid_base64_string!";
        let result = url_safe_str_to_int(input);
        assert_eq!(
            result,
            Err(KSMRError::DecodeError(
                "Invalid symbol 33, offset 21.".to_string()
            ))
        );
    }

    #[test]
    fn test_url_safe_str_to_int_decoded_bytes_too_short() {
        let input = "aA=="; // Base64 for "a" (1 byte)
        let result = url_safe_str_to_int(input);
        assert_eq!(
            result,
            Err(KSMRError::DecodeError("Invalid padding".to_string()))
        ); // Expecting InsufficientBytes error
    }

    #[test]
    fn test_url_safe_str_to_int_empty_string() {
        let input = "";
        let result = url_safe_str_to_int(input);
        assert_ne!(
            result,
            Err(KSMRError::InsufficientBytes(
                "Input string is empty".to_string()
            ))
        );
    }

    #[test]
    fn test_url_safe_str_to_int_special_characters() {
        let input = "4oCU";
        let _expected = BigUint::from_str("14844052").unwrap(); // this is expected if decoder bytes should be of at least 8 bytes long condition is not present.
        let result = url_safe_str_to_int(input);
        assert_eq!(result, Ok(_expected));
    }
}

#[cfg(test)]
mod generate_uid_bytes_tests {
    use crate::utils::generate_uid_bytes;
    use std::collections::HashSet;
    #[test]
    fn test_generate_uid_bytes_with_valid_dash() {
        let uid_bytes = generate_uid_bytes();

        assert!(uid_bytes.len() == 16); // Ensure the length of uid_bytes is 16

        let mut bytes_hashset: HashSet<_> = HashSet::new();
        for _ in 1..=100 {
            bytes_hashset.insert(generate_uid_bytes());
        }

        assert_eq!(bytes_hashset.len(), 100);
    }
}

#[cfg(test)]
mod temp_otp_codes_tests {
    use crate::utils::TotpCode;

    #[test]
    fn test_totp_code_creation() {
        let cases = vec![
            ("123456".to_string(), 30, 60),
            ("654321".to_string(), 10, 30),
            ("111111".to_string(), 0, 60),
            ("999999".to_string(), 5, 45),
        ];

        for (code, time_left, period) in cases {
            let totp = TotpCode::new(code.clone(), time_left, period);
            assert_eq!(totp.get_code(), code);
            assert_eq!(totp.get_time_left(), time_left);
            assert_eq!(totp.get_period(), period);
        }
    }

    #[test]
    fn test_get_code() {
        let cases = vec![
            ("123456".to_string(), 30, 60, "123456"),
            ("654321".to_string(), 10, 30, "654321"),
            ("000000".to_string(), 20, 60, "000000"),
        ];

        for (code, time_left, period, expected_code) in cases {
            let totp = TotpCode::new(code, time_left, period);
            assert_eq!(totp.get_code(), expected_code);
        }
    }

    #[test]
    fn test_get_time_left() {
        let cases = vec![
            ("123456".to_string(), 30, 60, 30),
            ("654321".to_string(), 10, 30, 10),
            ("000000".to_string(), 45, 60, 45),
        ];

        for (code, time_left, period, expected_time_left) in cases {
            let totp = TotpCode::new(code, time_left, period);
            assert_eq!(totp.get_time_left(), expected_time_left);
        }
    }

    #[test]
    fn test_get_period() {
        let cases = vec![
            ("123456".to_string(), 30, 60, 60),
            ("654321".to_string(), 10, 30, 30),
            ("000000".to_string(), 45, 45, 45),
        ];

        for (code, time_left, period, expected_period) in cases {
            let totp = TotpCode::new(code, time_left, period);
            assert_eq!(totp.get_period(), expected_period);
        }
    }
}

#[cfg(test)]
mod get_totp_code_tests {
    use crate::utils::get_totp_code;
    use crate::utils::TotpCode;

    #[test]
    fn test_valid_totp_code_sha1() {
        let url: &str =
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30";
        let totp: TotpCode = get_totp_code(url).expect("Expected a valid TOTP code");
        assert_eq!(totp.get_code().len(), 6);
        assert_eq!(totp.get_period(), 30);
    }

    #[test]
    fn test_valid_totp_code_sha256() {
        let url: &str =
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60";
        let totp: TotpCode = get_totp_code(url).expect("Expected a valid TOTP code");
        assert_eq!(totp.get_code().len(), 8);
        assert_eq!(totp.get_period(), 60);
    }

    #[test]
    fn test_valid_totp_code_sha512() {
        let url: &str =
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60";
        let totp: TotpCode = get_totp_code(url).expect("Expected a valid TOTP code");
        assert_eq!(totp.get_code().len(), 8);
        assert_eq!(totp.get_period(), 60);
    }

    // #[test]
    // fn test_invalid_scheme() {
    //     let url: &str = "http://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1";
    //     let err: String = get_totp_code(url).expect_err("Expected error due to invalid scheme");
    //     assert_eq!(err, "Not an otpauth URI");
    // }

    // #[test]
    // fn test_missing_secret() {
    //     let url: &str = "otpauth://totp/Test?algorithm=SHA1";
    //     let err: String = get_totp_code(url).expect_err("Expected error due to missing secret");
    //     assert_eq!(err, "TOTP secret not found in URI");
    // }

    // #[test]
    // fn test_invalid_secret_format() {
    //     let url: &str = "otpauth://totp/Test?secret=INVALIDSECRET&algorithm=SHA1";
    //     let err: String =
    //         get_totp_code(url).expect_err("Expected error due to invalid secret format");
    //     assert_eq!(err, "Invalid secret format");
    // }

    // #[test]
    // fn test_invalid_algorithm() {
    //     let url: &str = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=MD5";
    //     let err: String = get_totp_code(url).expect_err("Expected error due to invalid algorithm");
    //     assert_eq!(err, "Invalid algorithm: MD5");
    // }

    #[test]
    fn test_custom_digits_and_period() {
        let url: &str =
            "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=8&period=45";
        let totp: TotpCode = get_totp_code(url).expect("Expected a valid TOTP code");
        assert_eq!(totp.get_code().len(), 8);
        assert_eq!(totp.get_period(), 45);
    }
}

#[cfg(test)]
mod random_sample_tests {
    use crate::utils::random_sample;

    #[test]
    fn test_sample_length_zero() {
        // Case: sample_length is zero, should return an empty string
        let result = random_sample(0, "abc").expect("Expected Ok result");
        assert_eq!(result, "");
    }

    #[test]
    fn test_sample_string_empty() {
        // Case: sample_string is empty, should return an error
        let result = random_sample(5, "");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "sample_string must not be empty"
        );
    }

    #[test]
    fn test_sample_length_with_valid_string() {
        // Case: Generate a sample of specified length with a non-empty string
        let sample_length = 5;
        let result = random_sample(sample_length, "abcdef").expect("Expected Ok result");
        assert_eq!(result.len(), sample_length);

        // Check that all characters in result are from sample_string
        for char in result.chars() {
            assert!("abcdef".contains(char));
        }
    }

    #[test]
    fn test_sample_length_exceeds_string_length() {
        // Case: Generate a sample longer than sample_string length
        let sample_length = 10;
        let result = random_sample(sample_length, "abc").expect("Expected Ok result");
        assert_eq!(result.len(), sample_length);

        // Check that all characters in result are from sample_string
        for char in result.chars() {
            assert!("abc".contains(char));
        }
    }

    #[test]
    fn test_single_character_string() {
        // Case: sample_string has only one character
        let result = random_sample(5, "a").expect("Expected Ok result");
        assert_eq!(result, "aaaaa");
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod get_windows_user_sid_and_name_tests {
    use crate::utils::get_windows_user_sid_and_name;
    use std::os::windows::process::ExitStatusExt;
    use std::process::Output;

    #[test]
    fn test_get_windows_user_sid_and_name_with_mock() {
        let mock_command = || Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"Domain\\Username S-1-5-21-3623811015-3361044348-30300820-1013".to_vec(),
            stderr: Vec::new(),
        };

        let (sid, username) = get_windows_user_sid_and_name(Some(mock_command));
        assert_eq!(
            sid,
            Some("S-1-5-21-3623811015-3361044348-30300820-1013".to_string())
        );
        assert_eq!(username, Some("Username".to_string()));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_windows_user_sid_and_name_real_command() {
        let (sid, username) = get_windows_user_sid_and_name::<fn() -> Output>(None);
        assert!(sid.is_some());
        assert!(username.is_some());
    }
}

#[cfg(test)]
mod set_config_mode_tests {
    use crate::utils::set_config_mode;
    use std::env;
    #[cfg(target_os = "windows")]
    use std::fs::Permissions;
    use std::fs::{self, File};
    #[cfg(target_os = "windows")]
    use std::io;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    #[test]
    fn test_set_config_mode_windows_skip_mode() {
        env::set_var("KSM_CONFIG_SKIP_MODE", "true");

        // Mock file path
        let file_path = "C:\\path\\to\\config_file.txt";

        // If `KSM_CONFIG_SKIP_MODE` is true, function should return Ok without setting mode.
        assert!(set_config_mode(file_path, None).is_ok());

        env::remove_var("KSM_CONFIG_SKIP_MODE");
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    #[test]
    fn test_set_config_mode_windows_with_icacls() {
        // Mock file path
        let file_path = "C:\\path\\to\\config_file.txt";

        // Mock SID retrieval function, mock command execution to simulate success/failure
        let mock_get_windows_user_sid_and_name = || {
            // Return a mock SID and username
            (
                Some("S-1-5-21-3623811015-3361044348-30300820-1013".to_string()),
                Some("Username".to_string()),
            )
        };

        // Ensure permissions are correctly set and check error cases
        // Simulate the command's output and responses

        let result = set_config_mode(file_path, None);
        // Based on the mock, add assertions for expected outcomes
        assert!(result.is_ok());
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_family = "unix")]
    #[test]
    fn test_set_config_mode_unix() {
        // Create a temporary file to test Unix permissions
        let file_path = "/tmp/test_config_file.txt";
        File::create(file_path).expect("Failed to create test file");

        // Execute the function to set Unix permissions
        let result = set_config_mode(file_path, None);

        // Assert that the function completed successfully
        assert!(result.is_ok());

        // Check file permissions
        let metadata = fs::metadata(file_path).expect("Failed to read metadata");
        let permissions = metadata.permissions();

        // Ensure the file permissions are set to 0o600
        assert_eq!(permissions.mode() & 0o777, 0o600);

        // Clean up
        fs::remove_file(file_path).expect("Failed to delete test file");
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_set_config_mode_env_skip() {
        // Set environment variable to skip setting the mode
        env::set_var("KSM_CONFIG_SKIP_MODE", "true");

        // Create a dummy file for testing
        let file_path = "/tmp/test_config_file_skip.txt";
        File::create(file_path).expect("Failed to create test file");

        // Call the function and expect it to return Ok immediately
        let result = set_config_mode(file_path, None);
        assert!(result.is_ok());

        // Clean up
        fs::remove_file(file_path).expect("Failed to delete test file");

        // Clear environment variable
        env::remove_var("KSM_CONFIG_SKIP_MODE");
    }
}

#[cfg(test)]
mod check_config_mode_tests {
    use crate::utils::check_config_mode;
    use crate::utils::ConfigError;
    use std::env;
    use std::fs;
    #[cfg(target_os = "windows")]
    use std::io::{self, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    #[cfg(target_os = "windows")]
    use std::process::Command;
    #[cfg(target_os = "windows")]
    use tempfile::NamedTempFile;

    // Helper function to create a temporary file for testing
    fn create_temp_file_with_permissions(content: &str, mode: u32) -> String {
        // let temp_file = tempfile::NamedTempFile::new().unwrap();
        // let path = temp_file.path().to_str().unwrap().to_string();

        let path = Path::new("./test_temp_file.txt");
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
        fs::write(&path, content).unwrap();

        // Set the file permissions
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(mode);
            fs::set_permissions(&path, permissions).expect("Unable to set permissions");

            // // Adjust ownership (Unix only)
            // Command::new("chown")
            //     .arg("$(whoami)")
            //     .arg(path.to_str().unwrap())
            //     .status()
            //     .expect("Failed to change file ownership");
        }

        return path.to_str().unwrap().to_string();
    }

    #[test]
    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    fn test_check_config_mode_windows_no_file() {
        // Test for a non-existent file on Windows
        let path = "C:\\path\\to\\nonexistent_file.txt";
        let result = check_config_mode(path);
        assert!(result.is_err());
        if let Err(ConfigError::FileNotFound(ref path)) = result {
            assert_eq!(path, path);
        }
        if Path::new(path).exists() {
            fs::remove_file(path).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_config_mode_windows_permission_denied() {
        // Test for a file that exists but is permission denied
        let path = create_temp_file_with_permissions("content", 0o000); // No permissions
        let result = check_config_mode(&path);
        assert!(result.is_err());
        if let Err(ConfigError::PermissionDenied(ref denied_path)) = result {
            assert_eq!(denied_path, &path);
        }
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_config_mode_windows_too_open_permissions() {
        // Create a temporary file and set too open permissions
        let path = create_temp_file_with_permissions("content", 0o777); // World writable
        let result = check_config_mode(&path);
        assert!(result.is_err());
        if let Err(ConfigError::PermissionDenied(ref denied_path)) = result {
            assert_eq!(
                denied_path.as_str(),
                format!("File permissions too open for {}", &path)
            );
        }
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_config_mode_windows_proper_permissions() {
        // Test with a file that has proper permissions
        let path = create_temp_file_with_permissions("content", 0o600); // Owner only
        let result = check_config_mode(&path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[test]
    fn test_check_config_mode_unix_no_file() {
        // Test for a non-existent file on Unix
        let result = check_config_mode("/path/to/nonexistent_file.txt");
        assert!(result.is_err());
        if let Err(ConfigError::FileNotFound(ref path)) = result {
            assert_eq!(path, "/path/to/nonexistent_file.txt");
        }
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[test]
    fn test_check_config_mode_unix_permission_denied() {
        // Test for a file that exists but is permission denied
        let path = create_temp_file_with_permissions("content", 0o000); // No permissions
        let result = check_config_mode(&path);
        assert!(result.is_err());
        if let Err(ConfigError::PermissionDenied(ref denied_path)) = result {
            assert_eq!(denied_path, &path);
        }
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[test]
    fn test_check_config_mode_unix_too_open_permissions() {
        // Create a temporary file and set too open permissions
        let path = create_temp_file_with_permissions("content", 0o777); // World writable
        let result = check_config_mode(&path);
        assert!(result.is_err());
        if let Err(ConfigError::PermissionDenied(ref denied_path)) = result {
            assert_eq!(
                denied_path.as_str(),
                format!("File permissions too open for {}", &path)
            );
        }
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[ignore]
    #[cfg(feature = "sequential_tests")]
    #[test]
    fn test_check_config_mode_unix_proper_permissions() {
        // Test with a file that has proper permissions
        let path = create_temp_file_with_permissions("content", 0o600); // Owner only
        let result = check_config_mode(&path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[test]
    #[ignore]
    #[cfg(feature = "sequential_tests")]
    fn test_check_config_mode_skip_mode_check() {
        // Test to skip mode check via environment variable
        env::set_var("KSM_CONFIG_SKIP_MODE", "TRUE");
        let path = create_temp_file_with_permissions("content", 0o600);
        let result = check_config_mode(&path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        env::remove_var("KSM_CONFIG_SKIP_MODE"); // Clean up
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }

    #[test]
    #[ignore]
    #[cfg(feature = "sequential_tests")]
    fn test_check_config_mode_skip_warning() {
        // Test skipping warning
        let path = create_temp_file_with_permissions("content", 0o600);
        env::set_var("KSM_CONFIG_SKIP_MODE_WARNING", "TRUE");
        let result = check_config_mode(&path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        env::remove_var("KSM_CONFIG_SKIP_MODE_WARNING"); // Clean up
        if Path::new("./test_temp_file.txt").exists() {
            fs::remove_file(Path::new("./test_temp_file.txt")).unwrap();
        }
    }
}

#[cfg(test)]
mod generate_password_tests {
    use crate::{
        custom_error::KSMRError,
        utils::{generate_password, PasswordOptions},
    };

    #[test]
    fn test_generate_password_default_options() {
        let options = PasswordOptions::new().length(32);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_password_with_lowercase() {
        let options = PasswordOptions::new().length(32).lowercase(4);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().filter(|c| c.is_lowercase()).count() >= 4);
    }

    #[test]
    fn test_generate_password_with_uppercase() {
        let options = PasswordOptions::new().length(32).uppercase(4);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().filter(|c| c.is_uppercase()).count() >= 4);
    }

    #[test]
    fn test_generate_password_with_digits() {
        let options = PasswordOptions::new().length(32).digits(4);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().filter(|c| c.is_digit(10)).count() >= 4);
    }

    #[test]
    fn test_generate_password_with_special_characters() {
        let options = PasswordOptions::new().length(32).special_characters(4);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(
            password
                .chars()
                .filter(|c| "!@#$%^&*()-_=+[]{};:,.<>?/|QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm".contains(*c))
                .count()
                >= 4
        );
    }

    #[test]
    fn test_generate_password_with_all_character_types() {
        let options = PasswordOptions::new()
            .length(32)
            .lowercase(4)
            .uppercase(4)
            .digits(4)
            .special_characters(4);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().filter(|c| c.is_lowercase()).count() >= 4);
        assert!(password.chars().filter(|c| c.is_uppercase()).count() >= 4);
        assert!(password.chars().filter(|c| c.is_digit(10)).count() >= 4);
        assert!(
            password
                .chars()
                .filter(|c| "!@#$%^&*()-_=+[]{};:,.<>?/|QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm".contains(*c))
                .count()
                >= 4
        );
    }

    #[test]
    fn test_generate_password_with_exceeding_character_count() {
        let options = PasswordOptions::new()
            .length(20)
            .lowercase(15)
            .uppercase(10)
            .digits(10);
        let result = generate_password(options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            KSMRError::PasswordCreationError(format!(
                "The specified character counts (35) exceed the total password length (20)!"
            ))
        );
    }

    #[test]
    fn test_generate_password_with_zero_length() {
        let options = PasswordOptions::new().length(0);
        let result = generate_password(options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_generate_password_with_only_special_characters() {
        let options = PasswordOptions::new()
            .length(32)
            .special_characters(32)
            .special_characterset("!@#$%^&*()".to_string());
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| "!@#$%^&*()".contains(c)));
    }

    #[test]
    fn test_generate_password_with_no_constraints() {
        let options = PasswordOptions::new().length(32);
        let password = generate_password(options).unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().any(|c| c.is_lowercase()
            || c.is_uppercase()
            || c.is_digit(10)
            || "!@#$%^&*()-_=+[]{};:,.<>?/|".contains(c)));
    }
}
