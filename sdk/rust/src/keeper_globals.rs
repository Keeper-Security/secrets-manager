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

use lazy_static::lazy_static;
// use log::error;  // Not needed for now as we are just hard coding it
// use std::process::Command;  // Not needed for now as we are just hard coding it

// const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");  // Not needed for now as we are just hard coding it
const RUST_VERSION_PREFIX: &str = "mr";

pub fn get_client_version(_hardcode: bool) -> String {
    // Hardcoded to version 17.0.0 as requested
    "17.0.0".to_string()

    // Original dynamic version logic - commented out
    /*
    let mut version = SDK_VERSION.to_string();

    if !hardcode {
        // Attempt to get the version from the Cargo.toml metadata
        let output = Command::new("cargo")
            .arg("metadata")
            .arg("--no-deps")
            .output();

        match output {
            Ok(output) => {
                if let Ok(metadata) = String::from_utf8(output.stdout) {
                    if let Some(ksm_version) = metadata
                        .lines()
                        .find(|line| line.contains("keeper-secrets-manager-core"))
                    {
                        let version_part = ksm_version
                            .split('=')
                            .nth(1)
                            .unwrap_or("")
                            .trim_matches('"')
                            .trim();
                        let version_parts: Vec<&str> = version_part.split('.').collect();

                        if version_parts.len() >= 3 {
                            let version_minor = version_parts[1];
                            let version_revision = version_parts[2]
                                .chars()
                                .take_while(|c| c.is_ascii_digit())
                                .collect::<String>();
                            version = format!("{}.{}", version_minor, version_revision);
                        }
                    }
                }
            }
            Err(_) => {
                error!("Cargo needs to be installed for running this sdk")
            }
        }
    }

    version
    */
}

lazy_static! {
    static ref CLIENT_VERSION: String = get_client_version(false);
    pub static ref KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID: String =
        format!("{}{}", RUST_VERSION_PREFIX, CLIENT_VERSION.clone());
}
