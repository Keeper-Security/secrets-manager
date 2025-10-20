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

const RUST_VERSION_PREFIX: &str = "mr";

pub fn get_client_version(_hardcode: bool) -> String {
    // Get version from Cargo.toml at compile time (env! macro)
    // This aligns with Python, JavaScript, and .NET SDKs which use dynamic versioning
    env!("CARGO_PKG_VERSION").to_string()
}

lazy_static! {
    static ref CLIENT_VERSION: String = get_client_version(false);
    pub static ref KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID: String =
        format!("{}{}", RUST_VERSION_PREFIX, CLIENT_VERSION.clone());
}
