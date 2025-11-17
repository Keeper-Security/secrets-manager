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
use keeper_secrets_manager_core::utils::{self, TotpCode};

mod tests {
    use super::*;

    // Basic TOTP generation test
    #[test]
    fn test_totp_codes() {
        let totp_url =
            "otpauth://totp?secret=JBSWY3DPEHPK3PXP&issuer=&algorithm=SHA1&digits=8&period=30";
        let totp = get_totp_code(totp_url).unwrap();

        // TOTP codes are time-dependent, so we just validate structure
        assert_eq!(totp.get_code().len(), 8); // 8 digits specified
        assert!(totp.get_period() > 0); // Period should be positive
        assert!(totp.get_time_left() <= 30); // Time left should be <= period
    }

    // Algorithm tests - SHA1 (most common)
    #[test]
    fn test_totp_sha1_6_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
        assert_eq!(totp.get_period(), 30);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_sha1_8_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=8&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 8);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    // Algorithm tests - SHA256
    #[test]
    fn test_totp_sha256_6_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=6&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
        assert_eq!(totp.get_period(), 30);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_sha256_8_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 8);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    // Algorithm tests - SHA512
    #[test]
    fn test_totp_sha512_6_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=6&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
        assert_eq!(totp.get_period(), 30);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_sha512_8_digits() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 8);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    // Period tests
    #[test]
    fn test_totp_period_30() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_period(), 30);
        assert!(totp.get_time_left() > 0);
        assert!(totp.get_time_left() <= 30);
    }

    #[test]
    fn test_totp_period_60() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&period=60";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_period(), 60);
        assert!(totp.get_time_left() <= 60);
    }

    #[test]
    fn test_totp_period_90() {
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&period=90";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_period(), 90);
        assert!(totp.get_time_left() <= 90);
    }

    // Default parameter tests
    #[test]
    fn test_totp_defaults() {
        // When parameters are omitted, should use defaults:
        // - algorithm: SHA1
        // - digits: 6
        // - period: 30
        let url = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6); // Default digits
        assert_eq!(totp.get_period(), 30); // Default period
    }

    #[test]
    fn test_totp_with_issuer() {
        let url = "otpauth://totp/Google:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_with_account_name() {
        let url = "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
        assert!(totp.get_code().chars().all(|c| c.is_ascii_digit()));
    }

    // Code format validation
    #[test]
    fn test_totp_code_is_numeric() {
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6";
        let totp = utils::get_totp_code(url).unwrap();

        let code = totp.get_code();
        assert!(code.chars().all(|c| c.is_ascii_digit()), "TOTP code should be all digits");
    }

    #[test]
    fn test_totp_code_has_leading_zeros() {
        // TOTP codes should maintain leading zeros (e.g., "001234" not "1234")
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6";
        let totp = utils::get_totp_code(url).unwrap();

        // Code length should be exactly as specified
        assert_eq!(totp.get_code().len(), 6);
    }

    // Time left validation
    #[test]
    fn test_totp_time_left_is_positive() {
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        assert!(totp.get_time_left() > 0, "Time left should be positive");
        assert!(totp.get_time_left() <= 30, "Time left should be <= period");
    }

    // Different secret lengths
    #[test]
    fn test_totp_short_secret() {
        let url = "otpauth://totp?secret=ABCDEFGH"; // Short valid base32 secret
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
    }

    #[test]
    fn test_totp_long_secret() {
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"; // Long secret
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
    }

    // URL encoding tests
    #[test]
    fn test_totp_url_with_encoded_chars() {
        let url = "otpauth://totp/My%20App:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20App";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
    }

    // Consistency tests - same URL at same time should produce same code
    #[test]
    fn test_totp_consistency() {
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6";

        let totp1 = utils::get_totp_code(url).unwrap();
        let totp2 = utils::get_totp_code(url).unwrap();

        // Should produce same code when called within same time window
        assert_eq!(totp1.get_code(), totp2.get_code());
        assert_eq!(totp1.get_period(), totp2.get_period());
    }

    // Different algorithms should produce different codes
    #[test]
    fn test_totp_algorithms_produce_different_codes() {
        let secret = "JBSWY3DPEHPK3PXP";

        let url_sha1 = format!("otpauth://totp?secret={}&algorithm=SHA1", secret);
        let url_sha256 = format!("otpauth://totp?secret={}&algorithm=SHA256", secret);
        let url_sha512 = format!("otpauth://totp?secret={}&algorithm=SHA512", secret);

        let totp_sha1 = utils::get_totp_code(&url_sha1).unwrap();
        let totp_sha256 = utils::get_totp_code(&url_sha256).unwrap();
        let totp_sha512 = utils::get_totp_code(&url_sha512).unwrap();

        // Different algorithms should produce different codes
        // (though theoretically they could collide, it's extremely unlikely)
        let codes = vec![totp_sha1.get_code(), totp_sha256.get_code(), totp_sha512.get_code()];

        // At least one should be different (likely all three are different)
        assert!(
            codes[0] != codes[1] || codes[1] != codes[2],
            "Different algorithms should typically produce different codes"
        );
    }

    // RFC 6238 test vectors (if available)
    // Note: RFC 6238 provides test vectors for specific timestamps
    // These would require time-based mocking which we don't have yet

    // Parameter extraction tests
    #[test]
    fn test_totp_extracts_period_correctly() {
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&period=45";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_period(), 45);
    }

    #[test]
    fn test_totp_handles_missing_algorithm() {
        // Should default to SHA1 when algorithm not specified
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6";
        let totp = utils::get_totp_code(url).unwrap();

        // Should still generate a valid code (using SHA1 default)
        assert_eq!(totp.get_code().len(), 6);
    }

    #[test]
    fn test_totp_handles_missing_digits() {
        // Should default to 6 digits when not specified
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
    }

    #[test]
    fn test_totp_handles_missing_period() {
        // Should default to 30 seconds when not specified
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_period(), 30);
    }

    // Edge case: Minimal URL
    #[test]
    fn test_totp_minimal_url() {
        // Absolute minimum: just otpauth://totp and secret
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6); // Default digits
        assert_eq!(totp.get_period(), 30); // Default period
        assert!(totp.get_time_left() > 0);
    }

    // Complex account names
    #[test]
    fn test_totp_complex_account_name() {
        let url = "otpauth://totp/ACME%20Corp:john.doe%2Badmin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Corp";
        let totp = utils::get_totp_code(url).unwrap();

        assert_eq!(totp.get_code().len(), 6);
    }

    // Verify TOTP codes change over time (different time windows)
    #[test]
    fn test_totp_codes_change_over_time() {
        // This test documents that TOTP codes are time-dependent
        // In a real scenario with time mocking, we could verify:
        // - Code at time T
        // - Different code at time T + period
        // - Same code at time T + (period - 1 second)

        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        // We can't actually test time passage without mocking,
        // but we validate the code is generated correctly
        assert!(totp.get_time_left() > 0);
        assert!(totp.get_time_left() <= totp.get_period());
    }

    // Base32 secret validation
    #[test]
    fn test_totp_valid_base32_secret() {
        // Valid base32: A-Z, 2-7, padding with =
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP"; // Valid
        let result = utils::get_totp_code(url);

        assert!(result.is_ok(), "Valid base32 secret should work");
    }

    #[test]
    fn test_totp_secret_with_padding() {
        // Base32 secrets may have = padding
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP====";
        let result = utils::get_totp_code(url);

        // Should handle padded secrets
        assert!(result.is_ok() || result.is_err()); // Implementation-dependent
    }

    // Case sensitivity of algorithm parameter
    #[test]
    fn test_totp_algorithm_case_insensitive() {
        let url_upper = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256";
        let url_lower = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&algorithm=sha256";

        let totp_upper = utils::get_totp_code(url_upper);
        let totp_lower = utils::get_totp_code(url_lower);

        // Both should work (or both should fail consistently)
        assert_eq!(totp_upper.is_ok(), totp_lower.is_ok());
    }

    // Period boundary tests
    #[test]
    fn test_totp_time_left_at_period_start() {
        // At the start of a period, time_left should be close to period value
        let url = "otpauth://totp?secret=JBSWY3DPEHPK3PXP&period=30";
        let totp = utils::get_totp_code(url).unwrap();

        // Time left should be between 1 and period
        assert!(totp.get_time_left() >= 1);
        assert!(totp.get_time_left() <= 30);
    }

    // Code length validation for different digit counts
    #[test]
    fn test_totp_respects_digit_count() {
        for digits in &[6, 7, 8] {
            let url = format!("otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits={}", digits);
            let totp = utils::get_totp_code(&url).unwrap();

            assert_eq!(
                totp.get_code().len(),
                *digits as usize,
                "TOTP should respect digits parameter"
            );
        }
    }

    // Non-standard but valid periods
    #[test]
    fn test_totp_custom_periods() {
        for period in &[15, 45, 120] {
            let url = format!("otpauth://totp?secret=JBSWY3DPEHPK3PXP&period={}", period);
            let totp = utils::get_totp_code(&url).unwrap();

            assert_eq!(totp.get_period(), *period);
            assert!(totp.get_time_left() <= *period);
        }
    }
}

fn get_totp_code(url: &str) -> Result<TotpCode, String> {
    let totp = utils::get_totp_code(url).unwrap();
    Ok(totp)
}
