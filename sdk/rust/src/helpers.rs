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

use std::env;

use log::debug;
use url::Url;

use crate::{
    config_keys::ConfigKeys, constants::get_keeper_servers, custom_error::KSMRError,
    enums::KvStoreType, storage::KeyValueStorage,
};

pub fn get_servers(code: String, config_store: KvStoreType) -> Result<String, KSMRError> {
    let env_server = match env::var("KSM_HOSTNAME").is_ok() {
        true => env::var("KSM_HOSTNAME").unwrap(),
        false => "".to_string(),
    };
    let keeper_servers = get_keeper_servers();
    let mut server_to_use = match (
        !env_server.is_empty(),
        config_store.get(ConfigKeys::KeyHostname),
    ) {
        (true, _) => env_server, // If `env_server` is not empty, use it.
        (false, Ok(Some(hostname_data))) if !hostname_data.is_empty() => hostname_data, // Valid hostname in config.
        (false, Ok(Some(_))) if code.is_empty() => keeper_servers.get("US").unwrap().to_string(), // No hostname and no code.
        (false, Ok(Some(_))) => code, // No hostname, use `code`.
        _ => keeper_servers.get("US").unwrap().to_string(), // Default to "US" server.
    };
    let server_to_return = match keeper_servers.get(server_to_use.as_str()) {
        Some(server) => server.to_string(),
        None => {
            if !server_to_use.contains("http") {
                server_to_use = format!("https://{}", server_to_use);
            }

            Url::parse(&server_to_use)
                .ok()
                .and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| server_to_use.clone())
        }
    };
    debug!("keeper hostname resolved to: {}", server_to_return);
    Ok(server_to_return)
}
