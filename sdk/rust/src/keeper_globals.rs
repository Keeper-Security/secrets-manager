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

use std::sync::LazyLock;

const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
const RUST_VERSION_PREFIX: &str = "mr";

pub fn get_client_version(_hardcode: bool) -> String {
    SDK_VERSION.to_string()
}

static CLIENT_VERSION: LazyLock<String> = LazyLock::new(|| get_client_version(false));
pub static KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID: LazyLock<String> =
    LazyLock::new(|| format!("{}{}", RUST_VERSION_PREFIX, CLIENT_VERSION.clone()));

// Throttle retry (KSM-876 / KSM-882). The backend throttles HTTP 403 {"error":"throttled"}
// per clientId+endpoint (100 requests / 10s window; memcached TTL 10s that resets on every
// request, so the counter only clears after 10s of silence).
pub const MAX_THROTTLE_RETRIES: u32 = 5;
pub const BASE_THROTTLE_DELAY_SEC: u64 = 11; // 1s safety margin over the backend's 10s memcached TTL
