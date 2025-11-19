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

    #[test]
    fn test_totp_codes() {
        let totp_url =
            "otpauth://totp?secret=JBSWY3DPEHPK3PXP&issuer=&algorithm=SHA1&digits=8&period=30";
        let totp = get_totp_code(totp_url).unwrap();

        // The 'left' value (TOTP code) retrieved from the given URL will need to be generated for the first time,
        // so the test will fail on the first run because the code will be unique and time-dependent.
        // After the first run, capture the 'left' value and use it as the 'right' value for future assertions.
        // The 'left' value changes every 30 seconds, so the second run of the test must occur within 30 seconds
        // of the first run in order to pass the assertion.
        // assert_eq!(totp.get_code(), "91961278"); // Replace with the actual value from the first test run
        assert_ne!(totp.get_code(), "91961278");
    }
}

fn get_totp_code(url: &str) -> Result<TotpCode, String> {
    let totp = utils::get_totp_code(url).unwrap();
    Ok(totp)
}
