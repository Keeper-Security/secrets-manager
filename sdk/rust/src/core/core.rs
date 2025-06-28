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
use std::str::FromStr;

use crate::cache::{self, KSMCache};
use crate::dto::dtos::{KeeperFileUpload, KeeperFolder, RecordCreate};
use crate::dto::payload::FileUploadFunctionResult;
use crate::enums::{KvStoreType, StandardFieldTypeEnum};
use crate::storage::InMemoryKeyValueStorage;
use crate::storage::KeyValueStorage;

use crate::config_keys::ConfigKeys;
use crate::constants::{get_keeper_public_keys, get_keeper_servers};
use crate::crypto::{unpad_data, CryptoUtils};
use crate::utils::{
    self, bytes_to_string, dict_to_json, generate_random_bytes, generate_uid, generate_uid_bytes,
    url_safe_str_to_bytes,
};
use hmac::{Hmac, Mac};
use log::Level;
use reqwest::blocking::{multipart, Client};
use reqwest::header::HeaderName;
use sha2::Sha512;

use std::collections::HashMap;

use crate::custom_error::KSMRError;
use crate::dto::{
    validate_payload, AppData, CreateFolderPayload, CreateOptions, CreatePayload,
    DeleteFolderPayload, DeletePayload, EncryptedPayload, FileUploadPayload, Folder, GetPayload,
    KsmHttpResponse, Payload, QueryOptions, Record, SecretsManagerResponse, TransmissionKey,
    UpdateFolderPayload, UpdatePayload, UpdateTransactionType,
};
use crate::helpers::{get_folder_key, get_servers};
use crate::keeper_globals::KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID;
use crate::utils::{base64_to_bytes, bytes_to_base64, json_to_dict, string_to_bytes};
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::header;
use serde_json::Value;

use crate::enums::{LogLevel, SecretsManagerLogger};

pub struct ClientOptions {
    pub token: String,
    pub insecure_skip_verify: Option<bool>,
    pub config: KvStoreType,
    pub log_level: Level,
    pub hostname: Option<String>,
    cache: KSMCache,
}

impl ClientOptions {
    pub fn new(
        token: String,
        config: KvStoreType,
        log_level: Level,
        hostname: Option<String>,
        insecure_skip_verify: Option<bool>,
        cache: KSMCache,
    ) -> Self {
        Self {
            token,
            config,
            log_level,
            hostname,
            insecure_skip_verify,
            cache,
        }
    }

    pub fn new_client_options(token: String, config: KvStoreType) -> Self {
        Self::new(
            token,
            config,
            Level::Info,
            None,
            None,
            cache::KSMCache::None,
        )
    }

    pub fn set_cache(&mut self, cache: KSMCache) {
        self.cache = cache;
    }
}
const DEFAULT_KEY_ID: &str = "10";
const NOTATION_PREFIX: &str = "keeper";

pub struct SecretsManager {
    pub token: String,
    pub hostname: String,
    pub verify_ssl_certs: bool,
    pub config: KvStoreType,
    pub log_level: Level,
    pub cache: KSMCache,
    pub logger: SecretsManagerLogger,
}

impl Clone for SecretsManager {
    fn clone(&self) -> Self {
        SecretsManager {
            // Clone each field of the struct
            token: self.token.clone(),
            hostname: self.hostname.clone(),
            verify_ssl_certs: self.verify_ssl_certs,
            config: self.config.clone(),
            log_level: self.log_level,
            cache: self.cache.clone(),
            logger: self.logger.clone(),
        }
    }
}

impl SecretsManager {
    pub fn new(client_options: ClientOptions) -> Result<Self, KSMRError> {
        let mut secrets_manager = SecretsManager {
            token: String::new(),
            hostname: String::new(),
            verify_ssl_certs: false,
            config: KvStoreType::None,
            log_level: Level::Info, // Default to Info if not provided
            cache: KSMCache::None,  // Default is no cache
            logger: SecretsManagerLogger::default(), // Default logger
        };

        let init_logger_result = Self::init_logger(Some(client_options.log_level));
        match init_logger_result {
            Ok(_) => {
                secrets_manager.logger = init_logger_result.unwrap();
            }
            Err(e) => {
                return Err(e);
            }
        }

        let mut config = client_options.config;
        if matches!(config, KvStoreType::None) {
            if env::var("KSM_CONFIG").is_ok() {
                // Create a new InMemoryKeyValueStorage instance
                let config_str = env::var("KSM_CONFIG").unwrap();
                let in_memory_storage =
                    InMemoryKeyValueStorage::new(Some(config_str)).map_err(|e| {
                        KSMRError::SecretManagerCreationError(
                            format!("Error creating InMemoryKeyValueStorage: {}", e).to_owned(),
                        )
                    })?;
                config = KvStoreType::InMemory(in_memory_storage);
                secrets_manager.config = config.clone();
            }
        } else if !client_options.token.is_empty() {
            let token_parts: Vec<&str> = client_options.token.trim().split(":").collect();
            if token_parts.len() == 1 {
                if client_options.hostname.is_none()
                    || client_options
                        .hostname
                        .as_ref()
                        .map_or(true, String::is_empty)
                {
                    return Err(KSMRError::SecretManagerCreationError(
                        "The hostname must be present in the token or provided as a parameter"
                            .to_owned(),
                    ));
                }
                secrets_manager.token = client_options.token.clone();
                secrets_manager.hostname = client_options
                    .hostname
                    .ok_or_else(|| {
                        KSMRError::SecretManagerCreationError("Hostname is required".to_owned())
                    })?
                    .clone();
            } else {
                let token_host_key = token_parts[0].to_uppercase();
                let keeper_servers = get_keeper_servers();
                let token_host = keeper_servers.get(token_host_key.as_str());
                if token_host.is_none() {
                    secrets_manager.hostname = token_parts[0].to_string().to_owned();
                } else {
                    secrets_manager.hostname = token_host.as_ref().unwrap().to_string();
                }
                secrets_manager.token = token_parts[1].to_string();
            }
            if secrets_manager.token.is_empty() {
                secrets_manager.token = client_options.token.clone();
            }
        }

        if !client_options.cache.is_none() {
            secrets_manager.cache = client_options.cache;
        }

        secrets_manager.verify_ssl_certs = client_options.insecure_skip_verify.unwrap_or(false);
        if env::var("KSM_SKIP_VERIFY").is_ok() {
            let env_skip_verify = env::var("KSM_SKIP_VERIFY").unwrap().parse::<bool>();
            match env_skip_verify {
                Ok(skip_verify) => secrets_manager.verify_ssl_certs = !skip_verify,
                Err(e) => {
                    return Err(KSMRError::SecretManagerCreationError(format!(
                        "Error parsing KSM_SKIP_VERIFY to a boolean value: {}",
                        e
                    )));
                }
            }
        }

        if matches!(config, KvStoreType::None) {
            config = KvStoreType::File(crate::storage::FileKeyValueStorage::new(None)?);
        }

        if !secrets_manager.token.is_empty() {
            config
                .set(ConfigKeys::KeyClientKey, secrets_manager.token.clone())
                .unwrap();
        }
        if !secrets_manager.hostname.is_empty() {
            config
                .set(ConfigKeys::KeyHostname, secrets_manager.hostname.clone())
                .unwrap();
        }

        secrets_manager
            .logger
            .log_info("Initializing SecretsManager and values are set");

        if config.get(ConfigKeys::KeyServerPublicKeyId).is_ok() {
            let server_public_key_id: Option<String> =
                config.get(ConfigKeys::KeyServerPublicKeyId).unwrap();
            let keeper_public_keys = get_keeper_public_keys();
            if server_public_key_id.is_none() {
                secrets_manager.logger.log_debug(&format!(
                    "Setting public key id to the default: {}",
                    DEFAULT_KEY_ID
                ));
                config
                    .set(ConfigKeys::KeyServerPublicKeyId, DEFAULT_KEY_ID.to_string())
                    .unwrap();
            } else if server_public_key_id.is_some()
                && !keeper_public_keys.contains_key(server_public_key_id.unwrap().as_str())
            {
                secrets_manager.logger.log_debug(&format!(
                    "Public key id {} does not exists, set to default : {}",
                    config
                        .get(ConfigKeys::KeyServerPublicKeyId)
                        .unwrap()
                        .unwrap(),
                    DEFAULT_KEY_ID
                ));
                config
                    .set(ConfigKeys::KeyServerPublicKeyId, DEFAULT_KEY_ID.to_string())
                    .unwrap();
            }
        } else {
            return Err(KSMRError::SecretManagerCreationError(
                "Failed to retrieve the server public key id from config".to_owned(),
            ));
        }
        secrets_manager.config = config.clone();

        match secrets_manager._init() {
            Ok(secrets_manager) => Ok(secrets_manager),
            Err(e) => Err(e),
        }
    }

    fn init_logger(log_level: Option<Level>) -> Result<SecretsManagerLogger, KSMRError> {
        let log_level = match log_level {
            Some(Level::Error) => LogLevel::ERROR,
            Some(Level::Warn) => LogLevel::WARNING,
            Some(Level::Info) => LogLevel::INFO,
            Some(Level::Debug) => LogLevel::DEBUG,
            Some(Level::Trace) => LogLevel::INFO,
            None if env::var("RUST_LOG").is_ok() => {
                let log_level = env::var("RUST_LOG").unwrap();
                match log_level.as_str() {
                    "ERROR" => LogLevel::ERROR,
                    "WARNING" => LogLevel::WARNING,
                    "INFO" => LogLevel::INFO,
                    "DEBUG" => LogLevel::DEBUG,
                    "TRACE" => LogLevel::INFO,
                    _ => {
                        return Err(KSMRError::InvalidLogLevel(
                            "Unknown log level provided".to_string(),
                        ))
                    }
                }
            }
            _ => LogLevel::INFO,
        };

        let logger = SecretsManagerLogger::new(log_level);
        Ok(logger)
    }

    fn _init(&mut self) -> Result<Self, KSMRError> {
        if !self.verify_ssl_certs {
            self.logger.log_debug("WARNING: Running without SSL cert verification. Execute 'SecretsManager(..., verify_ssl_certs=True)' or 'KSM_SKIP_VERIFY=FALSE' to enable verification.");
        }

        let client_id = self.config.get(ConfigKeys::KeyClientId).map_err(|e| {
            KSMRError::SecretManagerCreationError(format!(
                "Error getting client key from config: {}",
                e
            ))
        })?;

        let client_id_copy = client_id.clone();
        let client_id_empty_state = match client_id_copy {
            Some(client_id) => client_id.is_empty(),
            None => true,
        };
        let mut unbound_token = false;
        if !self.token.is_empty() {
            unbound_token = true;
            if !client_id_empty_state {
                let client_key = self.token.clone();
                let client_key_bytes = url_safe_str_to_bytes(&client_key).map_err(|e| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error parsing client key to bytes: {}",
                        e
                    ))
                })?;

                let client_key_hash = Hmac::<Sha512>::new_from_slice(client_key_bytes.as_slice())
                    .map_err(|e| {
                        KSMRError::SecretManagerCreationError(format!("Error creating HMAC: {}", e))
                    })?
                    .chain_update(b"KEEPER_SECRETS_MANAGER_CLIENT_ID")
                    .finalize()
                    .into_bytes()
                    .to_vec();

                let token_client_id: String = bytes_to_base64(&client_key_hash);
                match client_id {
                    Some(client_id) => {
                        if token_client_id == client_id {
                            let app_key = self.config.get(ConfigKeys::KeyAppKey).unwrap();
                            if app_key.is_some() {
                                unbound_token = false;
                                self.logger.log_warn(
                                    "the storage is already initiated with the same token",
                                );
                            } else {
                                self.logger
                                    .log_warn("the storage is already initiated but not bound");
                            }
                        } else {
                            return Err(KSMRError::SecretManagerCreationError(format!("The provided token does not match the client id and is initiated with a different token - client ID: {}", client_id)));
                        }
                    }
                    None => {
                        self.logger
                            .log_warn("the storage is already initiated but not bound");
                    }
                }
            }
        }

        if !(client_id_empty_state || unbound_token) {
            self.logger.log_debug("Already bound to the token");

            if self.config.get(ConfigKeys::KeyClientKey).unwrap().is_none() {
                let _ = self.config.delete(ConfigKeys::KeyClientKey).map_err(|er| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error deleting client key: {}",
                        er
                    ))
                });
            }
            return Ok(self.clone());
        } else {
            let existing_secret_key = self
                .load_secret_key()
                .map_err(|err| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error loading secret key: {}",
                        err
                    ))
                })?
                .clone();

            if existing_secret_key.is_empty() {
                return Err(KSMRError::SecretManagerCreationError(
                    "Failed to load existing secret key and cannot locate One time password"
                        .to_string(),
                ));
            }

            let existing_secret_key_bytes = url_safe_str_to_bytes(&existing_secret_key)
                .map_err(|err| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error parsing existing secret key to bytes: {}",
                        err
                    ))
                })?
                .clone();

            let existing_secret_key_hash_bytes =
                Hmac::<Sha512>::new_from_slice(existing_secret_key_bytes.as_slice())
                    .map_err(|e| {
                        KSMRError::SecretManagerCreationError(format!("Error creating HMAC: {}", e))
                    })?
                    .chain_update(b"KEEPER_SECRETS_MANAGER_CLIENT_ID")
                    .finalize()
                    .into_bytes()
                    .to_vec();

            let existing_secret_key_hash = bytes_to_base64(&existing_secret_key_hash_bytes);

            let _ = self.config.delete(ConfigKeys::KeyClientId).map_err(|err| {
                KSMRError::SecretManagerCreationError(format!("Error deleting client id: {}", err))
            })?;
            let _ = self
                .config
                .delete(ConfigKeys::KeyPrivateKey)
                .map_err(|err| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error deleting private key: {}",
                        err
                    ))
                })?;

            if self.config.get(ConfigKeys::KeyClientId).unwrap().is_none() {
                self.config.delete(ConfigKeys::KeyAppKey).map_err(|err| {
                    KSMRError::SecretManagerCreationError(format!(
                        "Error deleting app key: {}",
                        err
                    ))
                })?;
            };

            self.config
                .set(ConfigKeys::KeyClientId, existing_secret_key_hash.clone())
                .unwrap();

            let private_key = self.config.get(ConfigKeys::KeyPrivateKey).map_err(|err| {
                KSMRError::SecretManagerCreationError(format!(
                    "Error getting private key from config: {}",
                    err
                ))
            })?;

            let private_key_value = match private_key {
                Some(value) => value.clone(),
                None => "".to_string(),
            };

            if private_key_value.is_empty() {
                let private_key_der = CryptoUtils::generate_private_key_der()?;
                let _y = private_key_der.to_vec();
                let private_key_set_result = self
                    .config
                    .set(ConfigKeys::KeyPrivateKey, bytes_to_base64(&private_key_der));
                let _ = match private_key_set_result {
                    Ok(_) => Ok(self.clone()),
                    Err(err) => Err(KSMRError::SecretManagerCreationError(format!(
                        "Error setting private key: {}",
                        err
                    ))),
                };
            }
        }

        Ok(self.clone())
    }

    pub fn load_secret_key(&self) -> Result<String, KSMRError> {
        let mut current_secret_key = "".to_string();
        // implementation of load_secret_key method
        let env_secret_key = env::var("KSM_TOKEN")
            .ok()
            .filter(|val| !val.is_empty())
            .unwrap_or("".to_string());

        if !env_secret_key.is_empty() {
            current_secret_key = env_secret_key;
            self.logger
                .log_info("Secret key found in environment variable");
        }

        if current_secret_key.is_empty() && !self.token.is_empty() {
            current_secret_key = self.token.clone();
            self.logger.log_info("Secret key found in config");
        }

        if current_secret_key.is_empty() {
            let config_secret_key = self.config.get(ConfigKeys::KeyClientKey)?;
            current_secret_key = config_secret_key.unwrap().clone();
            self.logger
                .log_info("Secret key found in configuration file");
        }

        Ok(current_secret_key)
    }

    pub fn generate_transmission_key(key_id: &str) -> Result<TransmissionKey, KSMRError> {
        let transmission_key = generate_random_bytes(32);
        let keeper_public_keys = get_keeper_public_keys();
        if !keeper_public_keys.contains_key(key_id) {
            return Err(KSMRError::SecretManagerCreationError(format!(
                "Public key not found for key id: {}",
                key_id
            )));
        }

        let server_public_key = keeper_public_keys.get(key_id).unwrap();
        let server_public_key_raw_key_bytes = url_safe_str_to_bytes(server_public_key).unwrap();
        let encrypted_key =
            CryptoUtils::public_encrypt(&transmission_key, &server_public_key_raw_key_bytes, None)?;

        Ok(TransmissionKey::new(
            key_id.to_owned(),
            transmission_key,
            encrypted_key,
        ))
    }

    fn prepare_get_payload(
        self,
        storage: KvStoreType,
        query_options: Option<QueryOptions>,
    ) -> Result<GetPayload, KSMRError> {
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = storage
            .get(crate::config_keys::ConfigKeys::KeyClientId)
            .map_err(|_| KSMRError::StorageError("Client ID not found".to_string()))?
            .ok_or_else(|| KSMRError::StorageError("Client ID not found".to_string()))?;

        let app_key_str_option = storage.get(ConfigKeys::KeyAppKey)?;
        let app_key_str = match app_key_str_option {
            Some(key_str) => key_str.to_owned(),
            None => "".to_string(),
        };
        let mut public_key_bytes = Vec::new();
        if app_key_str.is_empty() {
            let private_key: String = match storage.get(ConfigKeys::KeyPrivateKey)? {
                Some(private_key) => private_key,
                None => "".to_string(),
            };
            if private_key.is_empty() {
                return Err(KSMRError::StorageError(
                    "Could not find private key when retrieving error".to_string(),
                ));
            }
            public_key_bytes = CryptoUtils::extract_public_key_bytes(&private_key)?;
        };

        let base_64_public_key = match public_key_bytes.len() {
            0 => None,
            _ => Some(bytes_to_base64(&public_key_bytes)),
        };

        let mut get_payload =
            GetPayload::new(client_version, client_id, base_64_public_key, None, None);
        if query_options.is_some() {
            let query_options_data = query_options.unwrap();
            get_payload
                .set_optional_field("records_filter", query_options_data.get_records_filter());
            get_payload
                .set_optional_field("folders_filter", query_options_data.get_folders_filter());
        }
        Ok(get_payload)
    }

    pub fn post_function(
        self,
        url: String,
        transmission_key: TransmissionKey,
        encrypted_payload_and_signature: EncryptedPayload,
        verify_ssl_certificates: bool,
    ) -> Result<KsmHttpResponse, KSMRError> {
        let authorization_signature_string = format!(
            "Signature {}",
            bytes_to_base64(encrypted_payload_and_signature.signature.as_bytes())
        );

        let auth_string = authorization_signature_string.to_string();
        let gzip_deflate = "gzip, deflate".to_string();
        let transmission_key_for_header = bytes_to_base64(&transmission_key.encrypted_key);
        let transmission_key_header_name =
            HeaderName::from_str("TransmissionKey").map_err(|err| {
                KSMRError::SecretManagerCreationError(format!(
                    "error creating header name: {}",
                    err
                ))
            })?;
        let public_key_header_name = HeaderName::from_str("PublicKeyId").map_err(|err| {
            KSMRError::SecretManagerCreationError(format!("error creating header name: {}", err))
        })?;
        let gzip_header_name = HeaderName::from_str("Accept-Encoding").map_err(|err| {
            KSMRError::SecretManagerCreationError(format!("error creating header name: {}", err))
        })?;
        let public_key_for_header = transmission_key.public_key_id.to_string();

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(verify_ssl_certificates)
            .build()
            .map_err(|err| {
                KSMRError::SecretManagerCreationError(format!("error creating builder: {}", err))
            })?;

        let request_builder = client
            .post(url)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_LENGTH,
                encrypted_payload_and_signature.encrypted_payload.len(),
            )
            .header(header::AUTHORIZATION, auth_string)
            .header(transmission_key_header_name, transmission_key_for_header)
            .header(public_key_header_name, public_key_for_header)
            .header(gzip_header_name, gzip_deflate)
            .body(encrypted_payload_and_signature.encrypted_payload);

        let response = request_builder
            .send()
            .map_err(|err| KSMRError::HTTPError(err.to_string()))?;

        let response_status = response.status().as_u16();
        let response_bytes = response
            .bytes()
            .map_err(|err| KSMRError::HTTPError(err.to_string()))?;

        let ksm = KsmHttpResponse::new(
            response_status,
            response_bytes.to_vec(),
            String::from_utf8_lossy(&response_bytes).to_string(),
        );

        Ok(ksm)
    }

    fn encrypt_and_sign_payload(
        storage: KvStoreType,
        transmission_key: TransmissionKey,
        payload: &dyn Payload,
    ) -> Result<EncryptedPayload, KSMRError> {
        validate_payload(payload)?;

        let payload_json_str = payload
            .to_json()
            .map_err(|err| KSMRError::SerializationError(err.to_string()))?;
        let payload_bytes = string_to_bytes(&payload_json_str);

        let encrypted_payload =
            CryptoUtils::encrypt_aes_gcm(&payload_bytes, &transmission_key.key, None)
                .map_err(|err| KSMRError::CryptoError(err.to_string()))?;

        let encrypted_key = transmission_key.encrypted_key.clone();
        let encrypted_payload_clone = encrypted_payload.clone();
        let signature_base = encrypted_key
            .clone()
            .into_iter()
            .chain(encrypted_payload_clone.iter().cloned())
            .collect::<Vec<u8>>();

        let der_private_key = storage
            .get(ConfigKeys::KeyPrivateKey)
            .map_err(|_| KSMRError::StorageError("Private key not found".to_string()))?
            .ok_or_else(|| KSMRError::StorageError("Private key not found".to_string()))?;

        let private_key = CryptoUtils::der_base64_private_key_to_private_key(&der_private_key)
            .map_err(|err| KSMRError::CryptoError(err.to_string()))?;

        let signature = CryptoUtils::sign_data(&signature_base, private_key)
            .map_err(|err| KSMRError::CryptoError(err.to_string()))?;

        let private_key_for_verification =
            CryptoUtils::der_base64_private_key_to_private_key(&der_private_key)
                .map_err(|err| KSMRError::CryptoError(err.to_string()))?;

        //validate sign here
        let signature_validity = CryptoUtils::validate_signature(
            &signature_base,
            signature.as_bytes(),
            &private_key_for_verification.public_key().to_sec1_bytes(),
        )?;

        if signature_validity {
            info!("signature has been verified");
        }

        Ok(EncryptedPayload::new(encrypted_payload, signature))
    }

    fn handle_http_error(
        mut self,
        status_code: u16,
        response: Option<String>,
    ) -> Result<bool, KSMRError> {
        // Attempt to read the response body
        let body = match response {
            Some(response) => response,
            None => "".to_string(),
        };
        let mut _retry = false;
        let log_message = format!(
            "Error: {}  (http error code: {}, raw: {})",
            "status", status_code, body
        );

        // Check for key rotation
        let key_rotation_regex = Regex::new(r#""key_id"\s*:\s*\d+\s*(?:,|\})"#).unwrap();
        let key_invalid_regex =
            Regex::new(r#""error"\s*:\s*"key"|"message"\s*:\s*"invalid key id""#).unwrap();
        let key_rotation = key_rotation_regex.is_match(&body) && key_invalid_regex.is_match(&body);

        if key_rotation {
            warn!("{}", log_message);
        } else {
            error!("{}", log_message);
        }

        let val: Value = match serde_json::from_str(&body) {
            Ok(json) => json,
            Err(_) => {
                return Err(KSMRError::DeserializationError(format!(
                    "Invalid JSON response: {}",
                    body
                )));
            }
        };
        let response_dict = match val.as_object() {
            Some(obj_data) => obj_data
                .into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, Value>>(),
            None => HashMap::new(),
        };

        // Process `result_code` or `error`
        let rc = response_dict
            .get("result_code")
            .or_else(|| response_dict.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut msg = String::new();
        if rc == "invalid_client_version" {
            let client_id = self
                .config
                .get(ConfigKeys::KeyClientId)
                .unwrap_or(Some(String::from("unknown")))
                .unwrap();
            error!(
                "Client version {} was not registered in the backend",
                client_id.to_string()
            );
            if let Some(additional_info) = response_dict.get("additional_info") {
                if let Some(info) = additional_info.as_str() {
                    msg = info.to_string();
                }
            }
        } else if rc == "key" {
            if let Some(key_id) = response_dict.get("key_id").and_then(|v| v.as_str()) {
                info!("Server has requested we use public key {}", key_id);
                let keeper_public_keys = get_keeper_public_keys();
                if key_id.is_empty() {
                    msg = "The public key is blank from the server".to_string();
                } else if keeper_public_keys.contains_key(key_id) {
                    let _ = self
                        .config
                        .set(ConfigKeys::KeyServerPublicKeyId, key_id.to_string())
                        .map_err(|err| KSMRError::StorageError(err.to_string()))?;
                    info!("Server has requested we use public key {}", key_id);
                    _retry = true;
                    return Ok(_retry);
                } else {
                    msg = format!("The public key at {} does not exist in the SDK", key_id);
                }
            }
        } else {
            let response_msg = response_dict
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A");
            msg = format!("Error: {}, message={}", rc, response_msg);
        }

        if !msg.is_empty() {
            Err(KSMRError::HTTPError(msg))
        } else if !body.is_empty() {
            Err(KSMRError::HTTPError(body))
        } else {
            Err(KSMRError::HTTPError(format!(
                "Unhandled error with status code: {}",
                status_code
            )))
        }
    }

    fn process_post_request(
        &mut self,
        url: String,
        transmission_key: &mut TransmissionKey,
        encrypted_payload: EncryptedPayload,
        verify: bool,
    ) -> Result<KsmHttpResponse, KSMRError> {
        let keeper_response = self
            .clone()
            .post_function(
                url.clone(),
                transmission_key.clone(),
                encrypted_payload,
                verify,
            )
            .map_err(|e| KSMRError::SecretManagerCreationError(e.to_string()));
        if !url.contains("get_secret") {
            return keeper_response;
        }
        if self.cache.is_none() {
            return keeper_response;
        }
        let ksp = match keeper_response {
            Ok(resp) => {
                let response = resp.clone();
                let response_data = response.data;
                let actual_data: Vec<u8> = transmission_key
                    .key
                    .iter()
                    .cloned()
                    .chain(response_data.iter().cloned())
                    .collect();
                self.cache
                    .save_cached_value(&actual_data)
                    .map_err(|e| KSMRError::SecretManagerCreationError(e.to_string()))?;
                resp
            }
            Err(e) => {
                if e.to_string().contains("Error sending or receiving data from keeper servers. Exact message includes : error sending request for url ("){
                    // add error handling which is pulling data from cache and giving as ksm response
                    let cached_data = self.cache.get_cached_value().map_err(|e| KSMRError::SecretManagerCreationError(e.to_string()))?;
                    let cached_data_data_part = cached_data[32..].to_vec();
                    let cached_data_transmission_key = cached_data[0..32].to_vec();
                    transmission_key.key = cached_data_transmission_key;
                    let ksp = KsmHttpResponse{
                        data: cached_data_data_part,
                        status_code: 200,
                        http_response: None
                    };
                    return Ok(ksp);
                }else{
                    return Err(e);
                }
            }
        };
        Ok(ksp)
    }

    fn post_query(&mut self, path: String, payload: &dyn Payload) -> Result<Vec<u8>, KSMRError> {
        let keeper_server = get_servers(self.hostname.clone(), self.config.clone())
            .map_err(|e| KSMRError::StorageError(e.to_string()))?;

        let url = format!("https://{}/api/rest/sm/v1/{}", keeper_server, path);
        let mut keeper_response: KsmHttpResponse;
        let mut transmission_key: TransmissionKey;
        let mut retry = true;
        while retry {
            let transmission_key_id = self
                .config
                .get(ConfigKeys::KeyServerPublicKeyId)
                .map_err(|e| KSMRError::StorageError(e.to_string()))?
                .ok_or(KSMRError::StorageError(
                    "Error finding public key id in storage".to_string(),
                ))?;

            transmission_key =
                SecretsManager::generate_transmission_key(transmission_key_id.as_str())
                    .map_err(|e| KSMRError::SecretManagerCreationError(e.to_string()))?;

            let encrypted_payload_and_signature = Self::encrypt_and_sign_payload(
                self.config.clone(),
                transmission_key.clone(),
                payload,
            )
            .map_err(|e| KSMRError::SecretManagerCreationError(e.to_string()))?;

            keeper_response = self.process_post_request(
                url.clone(),
                &mut transmission_key,
                encrypted_payload_and_signature.clone(),
                true,
            )?;

            if keeper_response.status_code == 200 {
                info!("Successfully Made API call to {}", path);
                // let keeper_result;
                let keeper_result = if keeper_response.data.is_empty() {
                    keeper_response.data
                } else {
                    CryptoUtils::decrypt_aes(&keeper_response.data, &transmission_key.key)?
                };
                return Ok(keeper_result);
            }

            // Handle the error. Handling will throw an exception if it doesn't want us to retry.
            let handle_error_result: bool = self
                .clone()
                .handle_http_error(keeper_response.status_code, keeper_response.http_response)?;
            retry = handle_error_result
        }
        Err(KSMRError::SecretManagerCreationError(
            "Error in post_query".to_string(),
        ))
    }

    fn fetch_and_decrypt_secrets(
        &mut self,
        query_options: QueryOptions,
    ) -> Result<SecretsManagerResponse, KSMRError> {
        let payload = self
            .clone()
            .prepare_get_payload(self.config.clone(), Some(query_options))?;
        let decrypted_response_bytes = self.post_query("get_secret".to_string(), &payload)?;
        let decrypted_response_string = bytes_to_string(&decrypted_response_bytes)?;

        let decrypted_response_dict =
            json_to_dict(decrypted_response_string.as_str()).unwrap_or_default();
        let mut records: Vec<Record> = Vec::new();
        let mut shared_folders: Vec<Folder> = Vec::new();

        let mut just_bound = false;
        let mut _secret_key = Vec::new();
        if decrypted_response_dict.contains_key("encryptedAppKey")
            && decrypted_response_dict
                .get("encryptedAppKey")
                .unwrap()
                .as_str()
                .is_some()
        {
            just_bound = true;

            _secret_key = self.set_app_key_if_absent(decrypted_response_dict.clone())?;
        } else {
            let app_key_base64 = self
                .config
                .get(ConfigKeys::KeyAppKey)
                .map_err(|e| e.to_string())
                .unwrap()
                .unwrap_or("".to_string());
            _secret_key = base64_to_bytes(app_key_base64.as_str())?;
        }

        let empty_vec_for_record = Vec::new();
        let empty_vec_for_folder = Vec::new();
        let records_resp = decrypted_response_dict
            .get("records")
            .unwrap()
            .as_array()
            .unwrap_or(&empty_vec_for_record);
        let folders_resp = decrypted_response_dict
            .get("folders")
            .unwrap()
            .as_array()
            .unwrap_or(&empty_vec_for_folder);

        match decrypted_response_dict.contains_key("warnings"){
            true => {
                let warnings_option = decrypted_response_dict.get("warnings");
                match warnings_option {
                    Some(warnings) => {
                        match warnings{
                            Value::Array(warnings_array) => {
                                for warning in warnings_array {
                                    warn!("Warning shown while fetching secrets: `{}`", warning.as_str().unwrap().to_string());
                                }
                            },
                           _ =>{info!("No warnings found when pulling secrets");},
                        }
                    },
                    None => {info!("No warnings found when pulling secrets");},
                }
            },
            false => {
                info!("No warnings found when pulling secrets");
            },
        }
            // let warnings = decrypted_response_dict.get("warnings").

        let mut secrets_manager_response = SecretsManagerResponse::new();
        let mut records_count = 0;
        let mut shared_folders_count = 0;
        if !records_resp.is_empty() {
            let records_array = records_resp;
            for record in records_array {
                let new_map = serde_json::Map::new();
                let record_hashmap = record.as_object().unwrap_or(&new_map);
                let record_hashmap_parsed = record_hashmap
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Value>>();
                let record_result =
                    Record::new_from_json(record_hashmap_parsed, &_secret_key, None);
                if record_result.is_err() {
                    log::error!("Error parsing record: {}", record);
                } else {
                    let unwrapped_record = record_result.unwrap();
                    records_count += 1;
                    records.push(unwrapped_record);
                }
            }
        }

        if !folders_resp.is_empty() {
            let folders_array = folders_resp;
            for folder in folders_array {
                let new_map = serde_json::Map::new();
                let folder_hashmap = folder.as_object().unwrap_or(&new_map);
                let folder_hashmap_parsed = folder_hashmap
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Value>>();
                let folder_result: Option<Folder> =
                    Folder::new_from_json(folder_hashmap_parsed, &_secret_key);
                if folder_result.is_none() {
                    log::error!("Error parsing folder: {}", folder);
                } else {
                    let unwrapped_folder = folder_result.unwrap();
                    shared_folders_count += 1;
                    records_count += unwrapped_folder.records()?.len();
                    records.extend(unwrapped_folder.records()?);
                    shared_folders.push(unwrapped_folder);
                }
            }
        }

        self.logger
            .log_debug(format!("Individual records: {}", records_count).as_str());
        self.logger
            .log_debug(format!("Shared folders: {}", shared_folders_count).as_str());
        self.logger
            .log_debug(format!("total count: {}", records_count + shared_folders_count).as_str());

        if decrypted_response_dict.contains_key("appData") {
            let app_data_str = CryptoUtils::url_safe_str_to_bytes(
                decrypted_response_dict
                    .get("appData")
                    .unwrap()
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let app_data_key_string = self
                .config
                .get(ConfigKeys::KeyAppKey)
                .map_err(|e| e.to_string())
                .unwrap()
                .unwrap_or("".to_string());

            let app_data_key_bytes = base64_to_bytes(app_data_key_string.as_str())?;

            let app_data_json = CryptoUtils::decrypt_aes(&app_data_str, &app_data_key_bytes)?;

            let app_data_dict = serde_json::from_slice::<AppData>(&app_data_json)
                .map_err(|e| KSMRError::DeserializationError(e.to_string()));
            match app_data_dict {
                Ok(app_data) => {
                    secrets_manager_response.app_data = app_data;
                }
                Err(err) => error!("Error parsing app data: {}", err),
            }
        }

        if decrypted_response_dict.contains_key("expiresOn") {
            secrets_manager_response.expires_on = decrypted_response_dict
                .get("expiresOn")
                .unwrap()
                .as_i64()
                .unwrap();
        }

        if decrypted_response_dict.contains_key("warnings") {
            let warnings_array = decrypted_response_dict.get("warnings").unwrap().as_str();
            match warnings_array {
                Some(warnings) => {
                    secrets_manager_response.warnings = Some(warnings.to_string());
                }
                None => info!("No warnings"),
            };
        }

        secrets_manager_response.records = records;
        secrets_manager_response.folders = shared_folders;
        secrets_manager_response.just_bound = just_bound;
        Ok(secrets_manager_response)
    }

    fn fetch_and_decrypt_folders(mut self) -> Result<Vec<KeeperFolder>, KSMRError> {
        let payload = self
            .clone()
            .prepare_get_payload(self.config.clone(), None)?;
        let decrypted_response_bytes = self.post_query("get_folders".to_string(), &payload)?;
        let decrypted_response_string = bytes_to_string(&decrypted_response_bytes)?;

        let decrypted_response_dict =
            json_to_dict(decrypted_response_string.as_str()).unwrap_or_default();

        let app_key_base64 = match self.config.get(ConfigKeys::KeyAppKey)? {
            Some(app_key) => app_key,
            None => {
                let _ = self.set_app_key_if_absent(decrypted_response_dict.clone())?;

                match self.config.get(ConfigKeys::KeyAppKey)? {
                    Some(app_key) => app_key,
                    None => "".to_string(),
                }
            }
        };
        let app_key = base64_to_bytes(app_key_base64.as_str())?;

        let empty_vec_for_folder = Vec::new();
        let folders_resp = decrypted_response_dict
            .get("folders")
            .unwrap()
            .as_array()
            .unwrap_or(&empty_vec_for_folder);

        if folders_resp.is_empty() {
            return Ok(Vec::new());
        }

        let mut folders: Vec<KeeperFolder> = Vec::new();
        for folder in folders_resp {
            let folder_obj = folder
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<HashMap<String, Value>>();
            let folder_key_string = match folder_obj.get("folderKey") {
                Some(folder_key_value) => folder_key_value.as_str().unwrap().to_string(),
                None => "".to_string(),
            };

            let folder_parent = match folder_obj.get("parent") {
                Some(folder_parent_value) => match folder_parent_value.as_str() {
                    Some(folder_parent_val) => folder_parent_val.to_string(),
                    None => "".to_string(),
                },
                None => "".to_string(),
            };
            let mut _folder_key = Vec::new();
            if folder_parent.is_empty() {
                let folder_key_bytes = utils::base64_to_bytes(&folder_key_string)?;
                _folder_key = CryptoUtils::decrypt_aes(&folder_key_bytes, &app_key)?;
            } else {
                let shared_folder_key = self
                    .clone()
                    .get_shared_folder_key(
                        folders.clone(),
                        folders_resp.to_vec(),
                        folder_parent.clone(),
                    )
                    .unwrap_or_default();
                let folder_key_bytes = utils::base64_to_bytes(&folder_key_string)?;
                _folder_key = CryptoUtils::decrypt_aes_cbc(&folder_key_bytes, &shared_folder_key)?;
            }

            let mut _folder_name = "".to_string();
            let folder_data = match folder_obj.get("data") {
                Some(folder_data_value) => match folder_data_value.as_str() {
                    Some(folder_data_val) => folder_data_val.to_string(),
                    None => "".to_string(),
                },
                None => "".to_string(),
            };

            if !folder_data.is_empty() {
                let folder_data_bytes = utils::base64_to_bytes(&folder_data)?;
                _folder_key = match _folder_key.len() {
                    32 => _folder_key,
                    _ => unpad_data(&_folder_key)?,
                };

                let folder_data_json_bytes_decrypted =
                    CryptoUtils::decrypt_aes_cbc(&folder_data_bytes, &_folder_key)?;
                let folder_data_string =
                    utils::bytes_to_string_unpad(&folder_data_json_bytes_decrypted)?;
                let folder_data_dict: serde_json::Value =
                    serde_json::from_str(&folder_data_string)?;
                _folder_name = folder_data_dict
                    .as_object()
                    .unwrap()
                    .get("name")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
            }

            let folder_ = KeeperFolder::new(&folder_obj, _folder_key)?;
            folders.push(folder_);
        }
        Ok(folders)
    }

    fn get_shared_folder_key(
        self,
        folders: Vec<KeeperFolder>,
        response_folders: Vec<Value>,
        parent: String,
    ) -> Option<Vec<u8>> {
        let mut parent_copy = parent.clone();
        loop {
            let parent_folder = response_folders
                .clone()
                .into_iter()
                .filter(|folder_value| {
                    let folder = match folder_value.as_object() {
                        Some(folder) => folder,
                        None => return false,
                    };

                    let folder_uid = folder.get("folderUid").unwrap();
                    let folder_uid_str = folder_uid.as_str().unwrap();
                    folder_uid_str == parent_copy
                })
                .collect::<Vec<serde_json::Value>>();
            if parent_folder.is_empty() {
                return None;
            }

            let parent_folder = parent_folder.first().unwrap().as_object().unwrap();
            let parents_parent = match parent_folder.get("parent") {
                Some(uid_val) => match uid_val.as_str() {
                    Some(uid) => uid.to_string(),
                    None => "".to_string(),
                },
                None => "".to_string(),
            };
            if !parents_parent.is_empty() {
                parent_copy = parents_parent;
            } else {
                let shared_folder = folders
                    .iter()
                    .filter(|folder| folder.folder_uid == parent_copy)
                    .cloned()
                    .collect::<Vec<KeeperFolder>>();

                if shared_folder.is_empty() {
                    return None;
                } else {
                    return Some(shared_folder.first().unwrap().folder_key.clone());
                }
            }
        }
    }

    pub fn get_folders(self) -> Result<Vec<KeeperFolder>, KSMRError> {
        let folders = self.fetch_and_decrypt_folders()?;
        Ok(folders)
    }

    fn get_secrets_full_response_with_options(
        &mut self,
        query_options: QueryOptions,
    ) -> Result<SecretsManagerResponse, KSMRError> {
        let query_options_clone = query_options.clone();
        let mut secrets_manager_response =
            self.fetch_and_decrypt_secrets(query_options_clone.clone())?;

        if secrets_manager_response.just_bound {
            secrets_manager_response = self.fetch_and_decrypt_secrets(query_options_clone)?;
        }

        if secrets_manager_response.warnings.is_some() {
            warn!("{}", secrets_manager_response.warnings.as_ref().unwrap());
        }

        Ok(secrets_manager_response)
    }

    pub fn get_secrets_with_options(
        &mut self,
        query_options: QueryOptions,
    ) -> Result<Vec<Record>, KSMRError> {
        let secrets_manager_response =
            self.get_secrets_full_response_with_options(query_options)?;

        let records = secrets_manager_response.records;
        Ok(records)
    }

    pub fn get_secrets_full_response(
        &mut self,
        uid_array: Vec<String>,
    ) -> Result<SecretsManagerResponse, KSMRError> {
        let query_options = QueryOptions::new(uid_array, Vec::new());
        let secrets_manager_response =
            self.get_secrets_full_response_with_options(query_options)?;
        Ok(secrets_manager_response)
    }

    pub fn get_secrets(&mut self, uid_array: Vec<String>) -> Result<Vec<Record>, KSMRError> {
        let secrets_manager_response = self.get_secrets_full_response(uid_array)?;
        Ok(secrets_manager_response.records)
    }

    pub fn delete_secret(&mut self, record_uid: Vec<String>) -> Result<String, KSMRError> {
        let config_clone = self.config.clone();
        let delete_payload = Self::delete_payload(config_clone, record_uid)?;
        let response = self.post_query("delete_secret".to_string(), &delete_payload)?;
        let response_str = utils::bytes_to_string(&response)?;

        let response_dict = json_to_dict(&response_str).ok_or_else(|| {
            KSMRError::DeserializationError("Failed to parse response".to_string())
        })?;

        let records = response_dict
            .get("records")
            .ok_or_else(|| {
                KSMRError::DeserializationError("Missing 'records' in response".to_string())
            })
            .and_then(|records| {
                serde_json::from_value::<Vec<HashMap<String, Value>>>(records.clone()).map_err(
                    |e| KSMRError::DeserializationError(format!("Failed to parse response: {}", e)),
                )
            })?;

        let simplified_records = records
            .into_iter()
            .map(|record| {
                record
                    .into_iter()
                    .map(|(k, v)| (k, v.to_string()))
                    .collect::<HashMap<String, String>>()
            })
            .collect();

        self.clone()
            .calculate_successful_deletes(simplified_records)
    }

    pub fn calculate_successful_deletes(
        self,
        dict: Vec<HashMap<String, String>>,
    ) -> Result<String, KSMRError> {
        let deleted_secrets: Vec<String> = dict
            .into_iter()
            .filter_map(|dict_value| {
                if dict_value.get("responseCode") == Some(&"\"ok\"".to_string()) {
                    dict_value.get("recordUid").cloned()
                } else {
                    if let Some(record_uid) = dict_value.get("recordUid") {
                        error!("Failed to delete secret: {}", record_uid);
                    }
                    None
                }
            })
            .collect();

        Ok(deleted_secrets.join(", "))
    }
    fn prepare_delete_folder_payload(
        storage: KvStoreType,
        folder_uids: Vec<String>,
        force_deletion: bool,
    ) -> Result<DeleteFolderPayload, KSMRError> {
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match storage.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => "".to_string(),
        };
        let payload =
            DeleteFolderPayload::new(client_version, client_id, folder_uids, force_deletion);
        Ok(payload)
    }

    pub fn delete_folder(
        &mut self,
        folder_uids: Vec<String>,
        force_delete: bool,
    ) -> Result<Vec<HashMap<String, Value>>, KSMRError> {
        let payload = SecretsManager::prepare_delete_folder_payload(
            self.config.clone(),
            folder_uids,
            force_delete,
        )?;
        let response = self.post_query("delete_folder".to_string(), &payload)?;
        let response_str = utils::bytes_to_string(&response)?;

        let response_dict = json_to_dict(&response_str).ok_or_else(|| {
            KSMRError::DeserializationError("Failed to parse response".to_string())
        })?;

        let folders = response_dict
            .get("folders")
            .ok_or_else(|| {
                KSMRError::DeserializationError("Missing 'folders' in response".to_string())
            })
            .and_then(|records| {
                serde_json::from_value::<Vec<HashMap<String, Value>>>(records.clone()).map_err(
                    |e| KSMRError::DeserializationError(format!("Failed to parse response: {}", e)),
                )
            })?;
        Ok(folders)
    }

    fn set_app_key_if_absent(
        &mut self,
        decrypted_response_dict: HashMap<String, Value>,
    ) -> Result<Vec<u8>, KSMRError> {
        let encrypted_key_value = decrypted_response_dict.get("encryptedAppKey");
        let encrypted_master_key_value = match encrypted_key_value {
            Some(value) => match value.as_str() {
                Some(val) => val.to_string(),
                None => "".to_string(),
            },
            None => "".to_string(),
        };
        let encrypted_master_key =
            CryptoUtils::url_safe_str_to_bytes(encrypted_master_key_value.as_str()).unwrap();
        let client_key = CryptoUtils::url_safe_str_to_bytes(
            self.config
                .get(ConfigKeys::KeyClientKey)
                .unwrap()
                .unwrap()
                .as_str(),
        )
        .unwrap();

        let secret_key = CryptoUtils::decrypt_aes(&encrypted_master_key, &client_key)?;
        let secret_key_bytes = bytes_to_base64(&secret_key);
        self.config.set(ConfigKeys::KeyAppKey, secret_key_bytes)?;
        let _ = self.config.delete(ConfigKeys::KeyClientKey)?;

        if decrypted_response_dict.contains_key("appOwnerPublicKey") {
            let app_public_key = decrypted_response_dict
                .get("appOwnerPublicKey")
                .unwrap()
                .as_str()
                .unwrap();
            let app_owner_public_key_bytes =
                match CryptoUtils::url_safe_str_to_bytes(app_public_key) {
                    Ok(val) => val,
                    Err(e) => {
                        if e.to_string().contains("Invalid padding") {
                            CryptoUtils::url_safe_str_to_bytes_trim_padding(app_public_key)?
                        } else {
                            return Err(KSMRError::CryptoError(e.to_string()));
                        }
                    }
                };
            let app_owner_public_key_string = bytes_to_base64(&app_owner_public_key_bytes);
            self.config
                .set(ConfigKeys::KeyOwnerPublicKey, app_owner_public_key_string)?;
        }
        Ok(secret_key)
    }

    fn prepare_update_payload(
        &mut self,
        folder_uid: String,
        folder_name: String,
        folder_key: Vec<u8>,
    ) -> Result<UpdateFolderPayload, KSMRError> {
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match self.config.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => Err(KSMRError::StorageError("Client ID not found".to_string()))?,
        };

        let mut keeper_folder: HashMap<_, _> = HashMap::new();
        keeper_folder.insert("name".to_string(), Value::String(folder_name));
        let folder_data_json = dict_to_json(&keeper_folder)?;
        let folder_data_bytes = utils::string_to_bytes(&folder_data_json);

        let encrypted_folder_data =
            CryptoUtils::encrypt_aes_cbc(&folder_data_bytes, &folder_key, None)?;
        let payload_data = CryptoUtils::bytes_to_url_safe_str(&encrypted_folder_data);

        let update_payload =
            UpdateFolderPayload::new(client_version, client_id, folder_uid, payload_data);
        Ok(update_payload)
    }

    pub fn update_folder(
        &mut self,
        folder_uid: String,
        folder_name: String,
        folders: Vec<KeeperFolder>,
    ) -> Result<String, KSMRError> {
        let folders_copy = match folders.is_empty() {
            true => self.clone().get_folders()?,
            false => folders,
        };

        let mut folder_key = Vec::new();
        for folder in folders_copy {
            if folder.folder_uid == folder_uid {
                folder_key = folder.folder_key;
                break;
            }
        }

        if folder_key.is_empty() {
            return Err(KSMRError::RecordDataError(format!(
                "unable to update folder-  folder key for {} not found",
                folder_uid
            )));
        };

        let update_payload = self.prepare_update_payload(
            folder_uid.clone(),
            folder_name.clone(),
            folder_key.clone(),
        )?;

        let _resp = self.post_query("update_folder".to_string(), &update_payload)?;
        Ok("updated folder".to_string())
    }

    fn prepare_create_folder_payload(
        &mut self,
        create_options: CreateOptions,
        folder_name: String,
        shared_folder_key: Vec<u8>,
    ) -> Result<CreateFolderPayload, KSMRError> {
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match self.config.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => Err(KSMRError::StorageError("Client ID not found".to_string()))?,
        };
        let shared_folder_uid = create_options.folder_uid.clone();
        let parent_uid = create_options.sub_folder_uid.clone();
        let folder_uid = generate_uid();

        let folder_key = CryptoUtils::generate_random_bytes(32);

        let encrypted_folder_key_bytes =
            CryptoUtils::encrypt_aes_cbc(&folder_key, &shared_folder_key, None)?;
        let encrypted_folder_key = CryptoUtils::bytes_to_url_safe_str(&encrypted_folder_key_bytes);

        let mut keeper_folder_name_map = HashMap::new();
        keeper_folder_name_map.insert("name".to_string(), Value::String(folder_name.clone()));
        let folder_name_json = dict_to_json(&keeper_folder_name_map)?;
        let folder_name_bytes = utils::string_to_bytes(&folder_name_json);
        let encrypted_folder_name_bytes =
            CryptoUtils::encrypt_aes_cbc(&folder_name_bytes, &folder_key, None)?;
        let encrypted_folder_name_string =
            CryptoUtils::bytes_to_url_safe_str(&encrypted_folder_name_bytes);

        let created_payload = CreateFolderPayload::new(
            client_version,
            client_id,
            folder_uid,
            shared_folder_uid,
            encrypted_folder_key,
            encrypted_folder_name_string,
            parent_uid,
        );
        Ok(created_payload)
    }

    pub fn create_folder(
        &mut self,
        create_options: CreateOptions,
        folder_name: String,
        folders: Vec<KeeperFolder>,
    ) -> Result<String, KSMRError> {
        let folders_copy = match folders.is_empty() {
            true => self.clone().get_folders()?,
            false => folders,
        };

        let shared_folder_data = folders_copy
            .into_iter()
            .find(|folder| folder.folder_uid == create_options.folder_uid);

        let shared_folder = match shared_folder_data {
            Some(shared) => shared,
            None => {
                return Err(KSMRError::RecordDataError(format!(
                    "unable to create folder-  folder key for {} not found",
                    create_options.folder_uid
                )));
            }
        };

        if shared_folder.folder_key.is_empty() || shared_folder.folder_uid.is_empty() {
            return Err(KSMRError::RecordDataError(format!(
                "unable to create folder-  folder key for {} not found",
                create_options.folder_uid
            )));
        };
        let payload = self.prepare_create_folder_payload(
            create_options,
            folder_name,
            shared_folder.folder_key.clone(),
        )?;
        let _resp = self.post_query("create_folder".to_string(), &payload)?;
        Ok(format!("created folder :{}", payload.folder_uid))
    }

    pub fn get_secret_by_title(&mut self, title: &str) -> Result<Option<Vec<Record>>, KSMRError> {
        let retrieved_secrets = self.get_secrets(Vec::new())?;
        let mut filtered_secrets = Vec::new();
        for secret in retrieved_secrets {
            if secret.title == title {
                filtered_secrets.push(secret);
            }
        }
        match filtered_secrets.len() {
            0 => {
                println!("No secrets found with title: {}", title);
                Ok(None)
            }
            _ => {
                println!(
                    "Secrets found with title {} are {} in number",
                    title,
                    filtered_secrets.len()
                );
                Ok(Some(filtered_secrets))
            }
        }
    }

    fn delete_payload(
        storage: KvStoreType,
        record_uid: Vec<String>,
    ) -> Result<DeletePayload, KSMRError> {
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match storage.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => "".to_string(),
        };

        let payload = DeletePayload::new(client_version, client_id, record_uid);
        Ok(payload)
    }

    fn prepare_update_secret_payload(
        storage: KvStoreType,
        record: Record,
        transaction_type: Option<UpdateTransactionType>,
    ) -> Result<UpdatePayload, KSMRError> {
        let record_uid = record.uid.clone();
        let revision = record.revision.unwrap_or_default();
        let client_id = match storage.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => {
                return Err(KSMRError::CustomError(
                    "client id not found in config".to_string(),
                ))
            }
        };

        let raw_json_bytes = utils::string_to_bytes(&record.raw_json);
        let encrypted_raw_json_bytes =
            CryptoUtils::encrypt_aes_gcm(&raw_json_bytes, &record.record_key_bytes, None)?;
        let stringified_encrypted_data =
            CryptoUtils::bytes_to_url_safe_str(&encrypted_raw_json_bytes);

        let mut payload = UpdatePayload::new(
            KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string(),
            client_id,
            record_uid,
            revision,
            stringified_encrypted_data,
        );

        if transaction_type.is_some()
            || (transaction_type.is_some()
                && (transaction_type.clone().unwrap() != UpdateTransactionType::None))
        {
            payload.set_transaction_type(transaction_type.unwrap());
        }

        Ok(payload)
    }

    pub fn save(
        &mut self,
        record: Record,
        transaction_type: Option<UpdateTransactionType>,
    ) -> Result<(), KSMRError> {
        info!("updating record: {}", record.title);
        let payload = Self::prepare_update_secret_payload(
            self.config.clone(),
            record,
            transaction_type.clone(),
        )?;

        let _result = self.post_query("update_secret".to_string(), &payload)?;
        Ok(())
    }

    pub fn upload_file(
        &mut self,
        owner_record: Record,
        file: KeeperFileUpload,
    ) -> Result<String, KSMRError> {
        self.logger.log_info(
            format!(
                "uploading file: {} to record with UID: {}",
                file.name, owner_record.uid
            )
            .as_str(),
        );
        self.logger.log_debug(
            format!(
                "preparing upload payload. owner_record.uid=[{}], fine name: {}, file_size: {}",
                owner_record.uid,
                file.name,
                file.data.len()
            )
            .as_str(),
        );

        let upload_payload =
            Self::prepare_file_upload_payload(self.config.clone(), owner_record, file)?;
        let payload = upload_payload.get_payload();
        let encrypted_file_data = upload_payload.get_encrypted_data();

        self.logger.log_debug("posting prepare data");

        let response_data = self.post_query("add_file".to_string(), &payload)?;

        let response_json_str = bytes_to_string(&response_data)?;
        let response_dict = json_to_dict(&response_json_str).ok_or_else(|| {
            KSMRError::DeserializationError("Failed to parse response".to_string())
        })?;
        let upload_url = match response_dict.get("url") {
            Some(url) => match url.as_str() {
                Some(url_val) => url_val.to_string(),
                None => {
                    return Err(KSMRError::CustomError(
                        "upload url not found in response".to_string(),
                    ))
                }
            },
            None => {
                return Err(KSMRError::CustomError(
                    "upload url not found in response".to_string(),
                ))
            }
        };

        let parameters_json_str = match response_dict.get("parameters") {
            Some(parameters) => match parameters.as_str() {
                Some(parameters_val) => parameters_val.to_string(),
                None => {
                    return Err(KSMRError::CustomError(
                        "parameters not found in response".to_string(),
                    ))
                }
            },
            None => {
                return Err(KSMRError::CustomError(
                    "parameters not found in response".to_string(),
                ))
            }
        };

        let parameters_dict = json_to_dict(&parameters_json_str).ok_or_else(|| {
            KSMRError::DeserializationError("Failed to parse response".to_string())
        })?;
        debug!("uploading file to url: {}", upload_url);
        let update_functionality_response =
            self.upload_file_function(&upload_url, parameters_dict, encrypted_file_data)?;
        let status = update_functionality_response
            .get("isOk")
            .ok_or_else(|| {
                KSMRError::DeserializationError(
                    "Failed to parse response from upload file functionality".to_string(),
                )
            })?
            .as_bool()
            .ok_or_else(|| {
                KSMRError::DeserializationError(
                    "Failed to parse response from upload file functionality".to_string(),
                )
            })?;

        if status {
            Ok(payload.file_record_uid.clone())
        } else {
            Err(KSMRError::CustomError("Failed to upload file".to_string()))
        }
    }

    fn upload_file_function(
        &mut self,
        url: &str,
        upload_parameters: HashMap<String, Value>,
        encrypted_file_data: Vec<u8>,
    ) -> Result<HashMap<String, Value>, KSMRError> {
        // Build the multipart form with the encrypted file
        let mut form = multipart::Form::new();

        // Add upload parameters to the form
        for (key, value) in upload_parameters.clone() {
            form = form.text(key, value.as_str().unwrap().to_string());
        }

        // Add the file field
        form = form.part("file", multipart::Part::bytes(encrypted_file_data));

        // Send the POST request with the multipart form
        let client = Client::new();
        let response = client
            .post(url)
            .multipart(form)
            .send()
            .map_err(|err| KSMRError::HTTPError(err.to_string()))?;

        // Extract response data
        let status_code = response.status().as_u16();
        let is_ok = response.status().is_success();
        let text = response.text().map_err(|err| {
            KSMRError::CustomError(format!(
                "Error extracting text from upload file response : {}",
                err
            ))
        })?;

        // Build the result
        let mut result = HashMap::new();
        result.insert("isOk".to_string(), Value::Bool(is_ok));
        result.insert("statusCode".to_string(), Value::Number(status_code.into()));
        result.insert("data".to_string(), Value::String(text));

        Ok(result)
    }

    fn prepare_file_upload_payload(
        storage: KvStoreType,
        mut owner_record: Record,
        file: KeeperFileUpload,
    ) -> Result<FileUploadFunctionResult, KSMRError> {
        let owner_public_key = match storage.get(ConfigKeys::KeyOwnerPublicKey)?{
            Some(public_key) => public_key,
            None => return Err(KSMRError::CustomError("Unable to upload file - owner key is missing. Looks like application was created using out date client (Web Vault or Commander)".to_string())),
        };

        let owner_public_key_bytes =
            match CryptoUtils::url_safe_str_to_bytes(owner_public_key.as_str()) {
                Ok(val) => val,
                Err(e) => {
                    if e.to_string().contains("Invalid padding") {
                        CryptoUtils::url_safe_str_to_bytes_trim_padding(owner_public_key.as_str())?
                    } else {
                        return Err(KSMRError::CryptoError(e.to_string()));
                    }
                }
            };

        let mut file_record_dict = HashMap::new();
        file_record_dict.insert("name".to_string(), Value::String(file.name.clone()));
        file_record_dict.insert("size".to_string(), Value::Number(file.data.len().into()));
        file_record_dict.insert(
            "type".to_string(),
            Value::String(file.mime_type.to_string()),
        );
        file_record_dict.insert("title".to_string(), Value::String(file.title));
        let _last_modified = chrono::Utc::now().timestamp_millis();

        let file_record_json_str = dict_to_json(&file_record_dict)?;

        let file_record_json_bytes = utils::string_to_bytes(&file_record_json_str);

        let file_record_key = generate_random_bytes(32);
        let file_record_uid = generate_random_bytes(16);
        let file_record_uid_string = CryptoUtils::bytes_to_url_safe_str(&file_record_uid);

        let encrypted_file_record_bytes =
            CryptoUtils::encrypt_aes_gcm(&file_record_json_bytes, &file_record_key, None)?;
        let encrypted_file_record_key =
            CryptoUtils::public_encrypt(&file_record_key, &owner_public_key_bytes, None)?;
        let encrypted_link_key_bytes =
            CryptoUtils::encrypt_aes_gcm(&file_record_key, &owner_record.record_key_bytes, None)?;

        let encrypted_file_data = CryptoUtils::encrypt_aes_gcm(&file.data, &file_record_key, None)?;

        //fileRef related code
        let _rec_dict = &owner_record.record_dict;

        let file_ref_field_existence =
            owner_record.field_exists("fields", StandardFieldTypeEnum::FILEREF.get_type());
        if !file_ref_field_existence {
            let mut file_ref_obj = HashMap::new();
            file_ref_obj.insert(
                "type".to_string(),
                Value::String(StandardFieldTypeEnum::FILEREF.get_type().to_string()),
            );
            let record_uid_value_str = Value::String(file_record_uid_string.clone());
            let record_uid_value_str_arr = vec![record_uid_value_str];
            file_ref_obj.insert("value".to_string(), Value::Array(record_uid_value_str_arr));
            owner_record.insert_field("fields", file_ref_obj)?;
        } else {
            let existing_file_refs = owner_record
                .get_standard_field_value(StandardFieldTypeEnum::FILEREF.get_type(), false)?;
            let mut existing_file_refs_array = existing_file_refs.as_array().unwrap()[0]
                .as_array()
                .unwrap()
                .clone();
            existing_file_refs_array.push(Value::String(file_record_uid_string.clone()));
            owner_record.set_standard_field_value_mut(
                StandardFieldTypeEnum::FILEREF.get_type(),
                serde_json::Value::Array(existing_file_refs_array),
            )?;
        }

        let owner_record_raw_json = utils::dict_to_json(&owner_record.record_dict.clone())?;
        let owner_record_raw_json_bytes = string_to_bytes(&owner_record_raw_json);

        let encrypted_owner_record_bytes = CryptoUtils::encrypt_aes_gcm(
            &owner_record_raw_json_bytes,
            &owner_record.record_key_bytes,
            None,
        )?;
        let encrypted_owner_record_str =
            CryptoUtils::bytes_to_url_safe_str(&encrypted_owner_record_bytes);

        // Now we have all data required.
        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match storage.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => return Err(KSMRError::CustomError("Unable to upload file - client id is missing. Looks like application was created using out date client (Web Vault or Commander)".to_string())),
        };
        let file_record_data = CryptoUtils::bytes_to_url_safe_str(&encrypted_file_record_bytes);
        let file_record_key = bytes_to_base64(&encrypted_file_record_key);
        let link_key = bytes_to_base64(&encrypted_link_key_bytes);

        let payload = FileUploadPayload::new(
            client_version,
            client_id,
            file_record_uid_string,
            file_record_key,
            file_record_data,
            owner_record.uid,
            encrypted_owner_record_str,
            link_key,
            encrypted_file_data.len().try_into().unwrap(),
        );

        let result = FileUploadFunctionResult::new(payload, encrypted_file_data);

        Ok(result)
    }

    pub fn create_secret(
        &mut self,
        parent_folder_uid: String,
        record_create_object: RecordCreate,
    ) -> Result<String, KSMRError> {
        let record_json_str = record_create_object.to_json()?;
        let records_and_folders_response = self.get_secrets_full_response(Vec::new())?;

        let found_folder = match get_folder_key(parent_folder_uid.clone(), records_and_folders_response){
            Some(found_folder) => found_folder,
            None => return Err(KSMRError::SecretManagerCreationError(format!("Folder uid= '{}' was not retrieved. If you are creating a record to a folder folder that you know exists, make sure that at least one record is present in the prior to adding a record to the folder.",parent_folder_uid))),
        };
        let create_options = CreateOptions::new(parent_folder_uid.clone(), None);

        let payload = self.prepare_create_secret_payload(
            self.config.clone(),
            create_options,
            record_json_str,
            found_folder,
        )?;

        self.post_query("create_secret".to_string(), &payload)?;
        Ok(payload.record_uid.clone())
    }

    fn prepare_create_secret_payload(
        &mut self,
        storage: KvStoreType,
        create_options: CreateOptions,
        record_data_json_str: String,
        folder_key: Vec<u8>,
    ) -> Result<CreatePayload, KSMRError> {
        let owner_public_key = match storage.get(ConfigKeys::KeyOwnerPublicKey)? {
            Some(public_key) => public_key,
            None => {
                return Err(KSMRError::StorageError(
                    "Unable to create secret - owner public key is missing.".to_string(),
                ))
            }
        };
        let owner_public_key_bytes =
            match CryptoUtils::url_safe_str_to_bytes(owner_public_key.as_str()) {
                Ok(val) => val,
                Err(e) => {
                    if e.to_string().contains("Invalid padding") {
                        CryptoUtils::url_safe_str_to_bytes_trim_padding(owner_public_key.as_str())?
                    } else {
                        return Err(KSMRError::CryptoError(e.to_string()));
                    }
                }
            };

        if folder_key.is_empty() {
            return Err(KSMRError::StorageError(
                "Unable to create secret - folder key is missing.".to_string(),
            ));
        }

        let record_key = utils::generate_random_bytes(32);
        let record_uid = generate_uid_bytes();

        let record_data_bytes = utils::string_to_bytes(&record_data_json_str);
        let record_data_encrypted =
            CryptoUtils::encrypt_aes_gcm(&record_data_bytes, &record_key, None)?;
        let record_key_encrypted =
            CryptoUtils::public_encrypt(&record_key, &owner_public_key_bytes, None)?;
        let folder_key_encrypted = CryptoUtils::encrypt_aes_gcm(&record_key, &folder_key, None)?;

        let client_version = KEEPER_SECRETS_MANAGER_SDK_CLIENT_ID.to_string();
        let client_id = match storage.get(ConfigKeys::KeyClientId)? {
            Some(client_id) => client_id,
            None => return Err(KSMRError::CustomError("Unable to create secret - client id is missing. Looks like application was created using out date client (Web Vault or Commander)".to_string())),
        };
        let record_uid_str = CryptoUtils::bytes_to_url_safe_str(&record_uid);
        let record_key_encrypted_str = utils::bytes_to_base64(&record_key_encrypted);
        let folder_key_encoded = bytes_to_base64(&folder_key_encrypted);
        let encoded_data = bytes_to_base64(&record_data_encrypted);
        let sub_folder_uid = create_options.sub_folder_uid.clone();

        let create_payload = CreatePayload::new(
            client_version,
            client_id,
            record_uid_str,
            record_key_encrypted_str,
            create_options.folder_uid,
            folder_key_encoded,
            encoded_data,
            sub_folder_uid,
        );

        Ok(create_payload)
    }

    pub fn try_get_notation_results(&mut self, notation: &str) -> Result<Vec<String>, KSMRError> {
        let tried_results = self.get_notation_result(notation.to_string());
        let results = match tried_results {
            Ok(results) => results,
            Err(err) => {
                error!("{}", err);
                Vec::new()
            }
        };
        Ok(results)
    }

    pub fn get_notation(&mut self, url: String) -> Result<String, KSMRError> {
        let mut parsed_notation = SecretsManager::parse_notation(&url, true)?;
        if parsed_notation.len() < 3 {
            return Err(KSMRError::NotationError(format!(
                "Invalid Notation -{}",
                url
            )));
        };

        if parsed_notation[1].text.is_none() {
            return Err(KSMRError::NotationError(format!(
                "Invalid notation '{}' - UID/Title is missing in the keeper url.",
                url
            )));
        }
        let record_token = parsed_notation[1].text.clone().unwrap().0.clone();
        if parsed_notation[2].text.is_none() {
            return Err(KSMRError::NotationError(format!(
                "Keeper notation is invalid : {}",
                url
            )));
        }
        let selector = parsed_notation[2].text.clone().unwrap().0.clone();

        // legacy mode compatibility code
        let val1 = parsed_notation[2].index1.clone().is_some();
        let val3 = match val1 {
            true => parsed_notation[2].index1.clone().unwrap().1 != "[]",
            false => false,
        };
        let val2 = parsed_notation[2].index2.clone().is_some();
        let val4 = match val2 {
            true => parsed_notation[2].index2.clone().unwrap().1 != "[]",
            false => false,
        };
        if val1 && val2 && val3 && val4 {
            parsed_notation[2].index1 = Some(("0".to_string(), "[0]".to_string()))
        };

        let index1_clone = parsed_notation[2].index1.clone();
        let index2_clone = parsed_notation[2].index2.clone();
        let index1 = match index1_clone {
            Some(val) => Some(val.0.clone()),
            None => None,
        };
        let index2 = match index2_clone {
            Some(val) => Some(val.0.clone()),
            None => None,
        };
        let parameter = match parsed_notation[2].parameter.clone() {
            Some(parameter) => Some(parameter.0.clone()),
            None => None,
        };

        let selectors_with_params = ["file", "field", "custom_field"];
        let selector_status = selectors_with_params.contains(&selector.as_str());
        if parameter.is_none() && selector_status {
            return Err(KSMRError::NotationError(format!(
                "Invalid notation '{url}' - field key/parameter is missing in the keeper url."
            )));
        }
        if parameter.is_some() && !selector_status {
            return Err(KSMRError::NotationError(format!(
                "Invalid notation '{url}' - field key/parameter is required only for fields/file."
            )));
        }

        let mut return_single = true;
        let mut index = 0;
        let mut dict_key = None;

        if parameter.is_some() {
            let index1_value = match index1.clone() {
                Some(val) => val,
                None => "".to_string(),
            };
            let is_digit = index1_value.parse::<i32>().is_ok();
            if is_digit {
                index = index1_value.parse::<i32>().unwrap();
            } else if index1.is_some() && index1_value.is_empty() {
                dict_key = index1.clone();
            } else {
                return_single = false;
            }

            if index2.is_some() {
                if !return_single {
                    return Err(KSMRError::NotationError("If the second [] is a dictionary key, the first [] needs to have any index.".to_string()));
                };
                let index2_value = index2.unwrap();
                let index_2_is_digit = index2_value.parse::<i32>().is_ok();
                if index_2_is_digit {
                    return Err(KSMRError::NotationError("The second [] can only by a key for the dictionary. It cannot be an index.".to_string()));
                } else if !index2_value.clone().is_empty() {
                    dict_key = Some(index2_value);
                } else {
                    return Err(KSMRError::NotationError(
                        "The second [] must have key for the dictionary. Cannot be blank."
                            .to_string(),
                    ));
                }
            }
        }

        let mut records = Vec::new();
        let re = Regex::new(r"^[A-Za-z0-9_-]{22}$").unwrap();
        if re.is_match(&record_token) {
            let re_array = vec![record_token.clone()];
            records = self.get_secrets(re_array)?;
            if records.len() > 1 {
                return Err(KSMRError::NotationError(format!(
                    "found more than one record with same uid/title: {}",
                    record_token
                )));
            }
        };

        if records.is_empty() {
            let secrets = self.get_secrets(vec![])?;
            if !secrets.is_empty() {
                records = secrets
                    .iter()
                    .filter(|secret| secret.title == record_token)
                    .cloned()
                    .collect()
            }
        }

        if records.len() > 1 {
            return Err(KSMRError::NotationError(format!(
                "Notation error -  multiple records matched {}",
                record_token
            )));
        }
        if records.is_empty() {
            return Err(KSMRError::NotationError(format!(
                "Notation error -  No records matched {}",
                record_token
            )));
        }
        let record = records[0].clone();

        if selector.to_lowercase().clone() == "type" {
            if !record.record_type.is_empty() {
                return Ok(record.record_type);
            }
        } else if selector.to_lowercase().clone() == "title" {
            if !record.title.is_empty() {
                return Ok(record.title);
            }
        } else if selector.to_lowercase().clone() == "notes" {
            let record_notes = record.record_dict.get("notes");
            if let Some(note) = record_notes {
                return Ok(note.as_str().unwrap().to_string());
            }
        } else if selector.to_lowercase().clone() == "file" {
            if parameter.is_none() {
                return Err(KSMRError::NotationError(format!("Notation error - Missing required parameter: filename or file UID for files in record '{record_token}'")));
            }
            if record.files.is_empty() {
                return Err(KSMRError::NotationError(format!(
                    "Notation error - Record {record_token} has no file attachments."
                )));
            }
            let files_array: Vec<crate::dto::KeeperFile> = record.files.clone();
            let mut files: Vec<crate::dto::KeeperFile> = files_array
                .iter()
                .filter(|file| {
                    let parameter_value = parameter.clone().unwrap_or("".to_string());
                    (file.name == parameter_value)
                        || (file.title == parameter_value)
                        || (file.uid == parameter_value)
                })
                .cloned()
                .collect();
            let parameter_value = parameter.clone().unwrap_or("".to_string());
            if files.len() > 1 {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has multiple files matching the search criteria '{parameter_value}'")));
            }
            if files.is_empty() {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has no files matching the search criteria '{parameter_value}'")));
            }
            let contents = match files[0].get_file_data() {
                Ok(val) => val.unwrap(),
                Err(_) => {
                    return Err(KSMRError::NotationError(format!(
                        "Notation error - Record {record_token} has corrupted KeeperFile data."
                    )))
                }
            };
            let text = CryptoUtils::bytes_to_url_safe_str(&contents);
            return Ok(text);
        } else if ["field".to_string(), "custom_field".to_string()]
            .contains(&selector.to_lowercase())
        {
            let field_kind = match selector.to_lowercase() == *"field" {
                true => "standard_field".to_string(),
                false => "custom_field".to_string(),
            };
            let parameter_value = parameter.unwrap();
            let fields = match field_kind == *"standard_field" {
                true => record.get_standard_field(&parameter_value)?,
                false => record.get_custom_field(&parameter_value)?,
            };
            let mut arrayed_values: Vec<Vec<Value>> = Vec::new();
            for field in fields {
                let arrayed_val = field.as_array().cloned().unwrap();
                arrayed_values.push(arrayed_val);
            }
            if arrayed_values.is_empty() || arrayed_values[0].is_empty() {
                return Err(KSMRError::RecordDataError(format!(
                    "No standard field with field type: {} exists on record: {}",
                    parameter_value, record.title
                )));
            }

            let field_type = parameter_value.clone();
            let mut ret: HashMap<String, String> = HashMap::new();
            let inflated_field_types = Self::inflate_ref_types();
            let field_type_presence_in_inflated_types =
                inflated_field_types.contains_key(&field_type);
            if field_type_presence_in_inflated_types {
                let values_parsed = arrayed_values
                    .iter()
                    .map(|value| value[0].as_str().unwrap().to_string())
                    .collect();
                let replaced_field_types = inflated_field_types.get(&field_type).unwrap().clone();
                let value2 = self.inflate_field_value(values_parsed, replaced_field_types)?;
                ret = value2[0].clone();
            } else {
                let values_parsed: Vec<String> = arrayed_values
                    .iter()
                    .map(|value| value[0].as_str().unwrap().to_string())
                    .collect();
                let joined_string = values_parsed.join(" , ");
                if values_parsed.is_empty() {
                    ret.insert(field_type, "".to_string());
                } else {
                    ret.insert(field_type, joined_string);
                }
            }
            if return_single {
                if arrayed_values.is_empty() {
                    return Ok("".to_string());
                }
                match arrayed_values.get(index as usize) {
                    Some(_val) => {
                        if ["cardRef", "addressRef", "fileRef"].contains(&parameter_value.as_str())
                        {
                            return Ok(serde_json::to_string(&ret).unwrap());
                        } else {
                            if dict_key.is_some() && !dict_key.clone().unwrap().is_empty() {
                                let dict_key_ref = dict_key.clone().unwrap();
                                if !ret.contains_key(&dict_key_ref) {
                                    return Err(KSMRError::NotationError(format!("Cannot find the dictionary key {dict_key_ref} in the value.")));
                                }
                            }
                            if !index.is_negative() {
                                let ret_val = ret.get(&parameter_value.clone()).unwrap().clone();
                                let ret_val_array: Vec<String> =
                                    ret_val.split(" , ").map(|s| s.to_string()).collect();
                                if ret_val_array.len() > index as usize {
                                    return Ok(ret_val_array[index as usize].clone());
                                } else {
                                    return Err(KSMRError::NotationError(format!(
                                        "Notation error -  cannot find the index {} in the value.",
                                        index
                                    )));
                                }
                            }
                            return Ok(ret.get(&parameter_value.clone()).unwrap().clone());
                        }
                    }
                    None => {
                        return Err(KSMRError::NotationError(format!(
                            "Notation error -  cannot find the index {} in the value.",
                            index
                        )))
                    }
                }
            } else if ret.contains_key(&parameter_value.clone()) {
                return Ok(ret.get(&parameter_value.clone()).unwrap().clone());
            } else {
                return Ok(serde_json::to_string(&ret).unwrap());
            }
        } else {
            return Err(KSMRError::NotationError(format!(
                "Invalid Notation {url} - Bad selector '{selector}'."
            )));
        }

        Ok("".to_string())
    }

    pub fn parse_subsection(
        text: &str,
        mut pos: usize,
        delimiters: &str,
        escaped: bool,
    ) -> Result<Option<(String, String)>, KSMRError> {
        let escape_char = '\\';
        let escape_chars = "/[]\\"; // Characters that can be escaped
        let mut token = String::new();
        let mut raw = String::new();

        // Validate input
        if text.is_empty() || pos >= text.len() {
            return Ok(None);
        }
        if delimiters.is_empty() || delimiters.len() > 2 {
            return Err(KSMRError::NotationError(format!(
                "Notation parser: Internal error - Incorrect delimiters count. Delimiters: '{}'",
                delimiters
            )));
        }

        let delimiters: Vec<char> = delimiters.chars().collect(); // Convert delimiters to Vec<char>
        let chars: Vec<char> = text.chars().collect(); // Convert text to Vec<char>

        while pos < chars.len() {
            let current_char = chars[pos];
            if escaped && current_char == escape_char {
                // Handle escape sequences
                if pos + 1 >= chars.len() || !escape_chars.contains(chars[pos + 1]) {
                    return Err(KSMRError::NotationError(format!(
                        "Notation parser: Incorrect escape sequence at position {}",
                        pos
                    )));
                }

                // Add escaped character to token and raw
                token.push(chars[pos + 1]);
                raw.push(current_char);
                raw.push(chars[pos + 1]);
                pos += 2;
            } else {
                // Add current character to raw text
                raw.push(current_char);

                if delimiters.len() == 1 {
                    // Single delimiter case
                    if current_char == delimiters[0] {
                        break; // End of section
                    } else {
                        token.push(current_char);
                    }
                } else {
                    // Two delimiters case
                    let start_delim = delimiters[0];
                    let end_delim = delimiters[1];

                    // Ensure section starts correctly with the opening delimiter
                    if raw.len() == 1 && current_char != start_delim {
                        return Err(KSMRError::NotationError(
                            "Notation parser error: Index sections must start with '['".to_string(),
                        ));
                    }
                    // Disallow extra opening delimiters inside the section
                    if raw.len() > 1 && current_char == start_delim {
                        return Err(KSMRError::NotationError(
                            "Notation parser error: Index sections do not allow extra '[' inside."
                                .to_string(),
                        ));
                    }
                    // End section if the closing delimiter is found
                    if current_char == end_delim {
                        break;
                    }
                    // Add valid characters to token
                    if current_char != start_delim {
                        token.push(current_char);
                    }
                }
                pos += 1;
            }
        }

        // Validate enclosing delimiters for two-delimiter case
        if delimiters.len() == 2 {
            let start_delim = delimiters[0];
            let end_delim = delimiters[1];

            if raw.len() < 2
                || !raw.starts_with(start_delim)
                || !raw.ends_with(end_delim)
                || (escaped && raw.chars().nth_back(1) == Some(escape_char))
            {
                return Err(KSMRError::NotationError(
                    "Notation parser error: Index sections must be enclosed in '[' and ']'"
                        .to_string(),
                ));
            }
        }

        Ok(Some((token, raw)))
    }

    pub fn parse_section(
        notation: &str,
        section: &str,
        pos: isize,
    ) -> Result<NotationSection, KSMRError> {
        if notation.is_empty() {
            return Err(KSMRError::NotationError(
                "Keeper notation parsing error - missing notation URI".to_string(),
            ));
        }

        let section_name = section.to_lowercase();
        let sections = ["prefix", "record", "selector", "footer"];
        if !sections.contains(&section_name.as_str()) {
            return Err(KSMRError::NotationError(
                format!(
                    "Keeper notation parsing error - unknown section: {}",
                    section_name
                )
                .to_string(),
            ));
        }

        let mut result = NotationSection::new(section);
        result.start_pos = pos;
        result.index1 = None;
        result.index2 = None;

        match section_name.as_str() {
            "prefix" => {
                let uri_prefix = format!("{}://", NOTATION_PREFIX);
                if notation
                    .to_lowercase()
                    .starts_with(&uri_prefix.to_lowercase())
                {
                    result.is_present = true;
                    result.start_pos = 0;
                    result.end_pos = (uri_prefix.len() - 1).try_into().unwrap();
                    result.text = Some((
                        notation[..uri_prefix.len()].to_string(),
                        notation[..uri_prefix.len()].to_string(),
                    ));
                }
            }
            "footer" => {
                result.is_present = pos < notation.len().try_into().unwrap();
                if result.is_present {
                    result.start_pos = pos;
                    result.end_pos = (notation.len() - 1).try_into().unwrap();
                    result.text = Some((
                        notation[pos.try_into().unwrap()..].to_string(),
                        notation[pos.try_into().unwrap()..].to_string(),
                    ));
                }
            }
            "record" => {
                result.is_present = pos < notation.len().try_into().unwrap();
                if result.is_present {
                    if let Some(parsed) =
                        Self::parse_subsection(notation, pos.try_into().unwrap(), "/", true)?
                    {
                        result.start_pos = pos;
                        result.end_pos = pos + parsed.1.len() as isize - 1;
                        result.text = Some(parsed.clone());
                    }
                }
            }
            "selector" => {
                result.is_present = pos < notation.len().try_into().unwrap();
                if result.is_present {
                    if let Some(parsed) =
                        Self::parse_subsection(notation, pos.try_into().unwrap(), "/", false)?
                    {
                        result.start_pos = pos;
                        result.end_pos = pos + parsed.1.len() as isize - 1;
                        result.text = Some(parsed.clone());

                        // Handle selector-specific logic
                        let long_selectors = ["field", "custom_field", "file"];
                        if long_selectors.contains(&parsed.0.to_lowercase().as_str()) {
                            if let Some(param) = Self::parse_subsection(
                                notation,
                                result.end_pos as usize + 1,
                                "[",
                                true,
                            )? {
                                result.parameter = Some(param.clone());

                                // Adjust end_pos for parameter length
                                let plen_adjustment =
                                    if param.1.ends_with('[') && !param.1.ends_with("\\[") {
                                        1
                                    } else {
                                        0
                                    };
                                result.end_pos += param.1.len() as isize - plen_adjustment;
                                // Parse index1
                                if let Some(index1) = Self::parse_subsection(
                                    notation,
                                    result.end_pos as usize + 1,
                                    "[]",
                                    true,
                                )? {
                                    result.index1 = Some(index1.clone());
                                    result.end_pos += index1.1.len() as isize;

                                    // Parse index2
                                    if let Some(index2) = Self::parse_subsection(
                                        notation,
                                        result.end_pos as usize + 1,
                                        "[]",
                                        true,
                                    )? {
                                        result.index2 = Some(index2.clone());
                                        result.end_pos += index2.1.len() as isize;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                return Err(KSMRError::NotationError(format!(
                    "Keeper notation parsing error - unknown section '{}'",
                    section_name
                )));
            }
        }
        Ok(result)
    }

    pub fn parse_notation(
        notation: &str,
        legacy_mode: bool,
    ) -> Result<Vec<NotationSection>, KSMRError> {
        if notation.is_empty() {
            return Err(KSMRError::NotationError(
                "Keeper notation is missing or invalid.".to_string(),
            ));
        }

        // Check for URL-safe base64 encoding
        let mut notation = notation.to_string();
        if !notation.contains('/') {
            let decoded = utils::base64_to_bytes(&notation).map_err(|_| {
                KSMRError::NotationError(
                    "Invalid format of Keeper notation - plaintext URI or URL-safe base64 string expected."
                        .to_string(),
                )
            })?;
            notation = utils::bytes_to_string(&decoded).map_err(|_| {
                KSMRError::NotationError(
                    "Invalid Keeper notation - decoded base64 is not valid UTF-8.".to_string(),
                )
            })?;
        }

        // Parse sections
        let prefix = SecretsManager::parse_section(&notation, "prefix", 0)?;
        let pos = if prefix.is_present {
            prefix.end_pos + 1
        } else {
            0
        };

        let record = SecretsManager::parse_section(&notation, "record", pos)?;
        let pos = if record.is_present {
            record.end_pos + 1
        } else {
            notation.len() as isize
        };

        let mut selector = SecretsManager::parse_section(&notation, "selector", pos)?;
        let pos = if selector.is_present {
            selector.end_pos + 1
        } else {
            notation.len() as isize
        };
        let footer = SecretsManager::parse_section(&notation, "footer", pos)?;

        // Verify parsed query
        let short_selectors = ["type", "title", "notes"];
        let full_selectors = ["field", "custom_field", "file"];
        let selectors = [&short_selectors[..], &full_selectors[..]].concat();

        if !record.is_present || !selector.is_present {
            return Err(KSMRError::NotationError(
                "Keeper notation URI missing information about the UID, file, field type, or field key."
                    .to_string(),
            ));
        }

        if footer.is_present {
            return Err(KSMRError::NotationError(
                "Keeper notation is invalid - extra characters after the last section.".to_string(),
            ));
        }

        if let Some(ref sel_text) = selector.text {
            if !selectors.contains(&sel_text.0.to_lowercase().as_str()) {
                return Err(KSMRError::NotationError(
                    "Keeper notation is invalid - bad selector, must be one of (type, title, notes, field, custom_field, file)."
                        .to_string(),
                ));
            }

            if short_selectors.contains(&sel_text.0.to_lowercase().as_str())
                && selector.parameter.is_some()
            {
                return Err(KSMRError::NotationError(
                    "Keeper notation is invalid - selectors (type, title, notes) do not have parameters."
                        .to_string(),
                ));
            }

            if full_selectors.contains(&sel_text.0.to_lowercase().as_str()) {
                if selector.parameter.is_none() {
                    return Err(KSMRError::NotationError(
                        "Keeper notation is invalid - selectors (field, custom_field, file) require parameters."
                            .to_string(),
                    ));
                }

                if sel_text.0.to_lowercase() == "file"
                    && !(selector.index1.is_none() && selector.index2.is_none())
                {
                    return Err(KSMRError::NotationError(
                        "Keeper notation is invalid - file selectors don't accept indexes."
                            .to_string(),
                    ));
                }

                if sel_text.0.to_lowercase() != "file"
                    && selector.index1.is_none()
                    && selector.index2.is_some()
                {
                    return Err(KSMRError::NotationError(
                        "Keeper notation is invalid - two indexes required.".to_string(),
                    ));
                }

                if selector.index1.is_some() {
                    let sector_match_status = regex::Regex::new(r"^\[\d*\]$")
                        .unwrap()
                        .is_match(&selector.index1.clone().unwrap().1);
                    if !sector_match_status {
                        if !legacy_mode {
                            return Err(KSMRError::NotationError(
                                "Keeper notation is invalid - first index must be numeric: [n] or [].".to_string(),
                            ));
                        }

                        if selector.index2.is_none() {
                            let index_clone = Some((
                                selector.index1.clone().unwrap().0.clone(),
                                selector.index1.clone().unwrap().1.clone(),
                            ));
                            selector.index2 = index_clone;
                            selector.index1 = Some(("".to_string(), "[]".to_string()));
                        }
                    }
                }
            }
        }

        Ok(vec![prefix, record, selector, footer])
    }

    pub fn get_notation_result(&mut self, notation: String) -> Result<Vec<String>, KSMRError> {
        let mut result = Vec::new();
        let parsed = SecretsManager::parse_notation(&notation, false)
            .map_err(|e| KSMRError::NotationError(e.to_string()))?;

        if parsed.len() < 3 {
            return Err(KSMRError::NotationError(format!(
                "Invalid Notation -{}",
                notation
            )));
        };

        if parsed[2].text.is_none() {
            return Err(KSMRError::NotationError(format!(
                "Keeper notation is invalid : {}",
                notation
            )));
        }
        let selector = parsed[2].text.clone().unwrap().0.clone();
        if parsed[1].text.is_none() {
            return Err(KSMRError::NotationError(format!(
                "Keeper notation is invalid - missing UID/title {}.",
                notation
            )));
        }
        let record_token = parsed[1].text.clone().unwrap().0.clone();
        let mut records = Vec::new();
        let re = Regex::new(r"^[A-Za-z0-9_-]{22}$").unwrap();
        if re.is_match(&record_token) {
            let re_array = vec![record_token.clone()];
            records = self.get_secrets(re_array)?;
            if records.len() > 1 {
                return Err(KSMRError::NotationError(format!(
                    "found more than one record with same uid/title: {}",
                    record_token
                )));
            }
        };

        if records.is_empty() {
            let secrets = self.get_secrets(vec![])?;
            if !secrets.is_empty() {
                records = secrets
                    .iter()
                    .filter(|secret| secret.title == record_token)
                    .cloned()
                    .collect()
            }
        }
        if records.len() > 1 {
            return Err(KSMRError::NotationError(format!(
                "Notation error -  multiple records matched {}",
                record_token
            )));
        }

        if records.is_empty() {
            return Err(KSMRError::NotationError(format!(
                "Notation error -  No records matched {}",
                record_token
            )));
        }

        let record = records[0].clone();
        let parameter: Option<String> = parsed[2].parameter.clone().map(|par| par.clone().0);
        let index1: Option<String> = parsed[2].index1.clone().map(|ind| ind.clone().0);
        let _index2: Option<String> = parsed[2].index2.clone().map(|ind| ind.clone().0);

        if selector.to_lowercase().clone() == "type" {
            if !record.record_type.is_empty() {
                result.push(record.record_type);
            }
        } else if selector.to_lowercase().clone() == "title" {
            if !record.title.is_empty() {
                result.push(record.title);
            }
        } else if selector.to_lowercase().clone() == "notes" {
            let record_notes = record.record_dict.get("notes");
            if let Some(note) = record_notes {
                result.push(note.as_str().unwrap().to_string())
            }
        } else if selector.to_lowercase().clone() == "file" {
            if parameter.is_none() {
                return Err(KSMRError::NotationError(format!("Notation error - Missing required parameter: filename or file UID for files in record '{record_token}'")));
            }
            if record.files.is_empty() {
                return Err(KSMRError::NotationError(format!(
                    "Notation error - Record {record_token} has no file attachments."
                )));
            }
            let files_array: Vec<crate::dto::KeeperFile> = record.files.clone();
            let mut files: Vec<crate::dto::KeeperFile> = files_array
                .iter()
                .filter(|file| {
                    let parameter_value = parameter.clone().unwrap_or("".to_string());
                    (file.name == parameter_value)
                        || (file.title == parameter_value)
                        || (file.uid == parameter_value)
                })
                .cloned()
                .collect();
            let parameter_value = parameter.clone().unwrap_or("".to_string());
            if files.len() > 1 {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has multiple files matching the search criteria '{parameter_value}'")));
            }
            if files.is_empty() {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has no files matching the search criteria '{parameter_value}'")));
            }
            let contents = match files[0].get_file_data() {
                Ok(val) => val.unwrap(),
                Err(_) => {
                    return Err(KSMRError::NotationError(format!(
                        "Notation error - Record {record_token} has corrupted KeeperFile data."
                    )))
                }
            };
            let text = CryptoUtils::bytes_to_url_safe_str(&contents);
            result.push(text);
        } else if ["field".to_string(), "custom_field".to_string()]
            .iter()
            .any(|s| s.eq_ignore_ascii_case(selector.to_lowercase().as_str()))
        {
            if parameter.is_none() {
                return Err(KSMRError::NotationError("Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel.".to_string()));
            }
            let parameter_value = parameter.clone().unwrap();

            let fields_option = record.record_dict.get("fields");
            let fields = match fields_option {
                Some(val) => match val.is_array() {
                    true => val.as_array().unwrap(),
                    false => &Vec::new(),
                },
                None => &Vec::new(),
            };

            let fields_filtered: Vec<serde_json::Value> = fields
                .iter()
                .filter(|field| match field.is_object() {
                    true => {
                        let field_obj = field.as_object().unwrap();
                        let type_value = match field_obj.get("type") {
                            Some(val) => match val.is_string() {
                                true => val.as_str().unwrap().to_string(),
                                false => "some_non_existing_value".to_string(),
                            },
                            None => "some_non_existing_type".to_string(),
                        };
                        let label_value = match field_obj.get("label") {
                            Some(val) => match val.is_string() {
                                true => val.as_str().unwrap().to_string(),
                                false => "some_non_existing_value".to_string(),
                            },
                            None => "some_non_existing_label".to_string(),
                        };
                        parameter_value == type_value || parameter_value == label_value
                    }
                    false => false,
                })
                .cloned()
                .collect();

            if fields_filtered.len() > 1 {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has multiple fields matching the search criteria '{parameter_value}'")));
            }
            if fields_filtered.is_empty() {
                return Err(KSMRError::NotationError(format!("Notation error - Record {record_token} has no fields matching the search criteria '{parameter_value}'")));
            }

            let field = fields_filtered[0].clone();
            let _field_type = match field.get("type") {
                Some(val) => match val.is_string() {
                    true => val.as_str().unwrap().to_string(),
                    false => "".to_string(),
                },
                None => "".to_string(),
            };

            let idx = match index1 {
                Some(val) => match val.parse::<isize>() {
                    Ok(num) => num,
                    Err(_) => {
                        // Handle the error, for example:
                        return Err(KSMRError::NotationError(format!(
                            "Invalid index value: {}",
                            val
                        )));
                    }
                },
                None => -1,
            };

            let mut _values = Vec::new();
            _values = field.get("value").unwrap().as_array().unwrap().clone();
            if idx >= _values.len() as isize {
                return Err(KSMRError::NotationError(format!(
                    "idx out of range: {} for field {}",
                    idx, parameter_value
                )));
            }
            if idx >= 0 {
                let val = _values[idx as usize].clone();
                match val.is_array() {
                    true => _values[idx as usize].clone().as_array().unwrap(),
                    false => todo!(),
                };
            }

            let val1 = parsed[2].index2.clone().is_none();
            let val2 = parsed[2].index2.clone().unwrap().1.clone() == "\"\"";
            let val3 = parsed[2].index2.clone().unwrap().1.clone() == "\"[]\"";
            let full_obj_val = val1 || val2 || val3;

            let index_2_value = parsed[2].index2.clone();
            let obj_property_name = match index_2_value {
                Some(val) => val.0.clone(),
                None => "".to_string(),
            };

            let mut res: Vec<String> = Vec::new();

            for field_value in _values.clone() {
                if field.is_null() {
                    error!("Notation error - Empty field value for field '{parameter_value}'");
                }
                if full_obj_val {
                    let v = match field_value.is_string() {
                        true => field_value.as_str().unwrap().to_string(),
                        false => serde_json::to_string(&field_value.as_str().unwrap().to_string())
                            .unwrap(),
                    };
                    res.push(v);
                } else if field_value.is_object() {
                    let field_val_obj = field_value.as_object().unwrap();
                    let key_presence = field_val_obj.contains_key(&obj_property_name);
                    if key_presence {
                        let property_option = field_val_obj.get(&obj_property_name);
                        let property = match property_option {
                            Some(prop) => prop,
                            None => &Value::Null,
                        };
                        let v = match property.is_string() {
                            true => property.as_str().unwrap().to_string(),
                            false => serde_json::to_string(&property.as_str().unwrap().to_string())
                                .unwrap(),
                        };
                        res.push(v);
                    } else {
                        error!("Notation error - Object property '{obj_property_name}'");
                    }
                } else {
                    error!("Notation error - Cannot extract property '{obj_property_name}' from null value.");
                }
            }

            if res.len() == _values.len() {
                error!("Notation error - Cannot extract property '{obj_property_name}' from null value.");
            }
            if !res.is_empty() {
                result.extend_from_slice(&res);
            }
        } else {
            return Err(KSMRError::NotationError(format!(
                "Notation error - Invalid notation: {}",
                notation
            )));
        }
        Ok(result)
    }

    pub fn inflate_field_value(
        &mut self,
        uids: Vec<String>,
        replace_fields: Vec<String>,
    ) -> Result<Vec<HashMap<String, String>>, KSMRError> {
        let mut value: Vec<HashMap<String, String>> = Vec::new();
        // Retrieve and organize records by UID
        let records = self.get_secrets(uids.clone())?;
        let _record_type = match records.is_empty(){
            true => return Err(KSMRError::RecordDataError(format!("No records found with the details for field given with uids : {uids:?} in given folder/application scope."))),
            false => records[0].record_type.clone(),
        };
        let lookup: HashMap<String, Record> =
            records.into_iter().map(|r| (r.uid.clone(), r)).collect();
        if lookup.is_empty() {
            return Err(KSMRError::RecordDataError(format!("No records found with the details for field given with uids : {uids:?} in given folder/application scope.")));
        }
        for uid in &uids {
            if let Some(record) = lookup.get(uid) {
                // let new_value: Option<HashMap<String, String>> = None;
                let mut final_data_object = HashMap::new();
                for replacement_key in &replace_fields {
                    let real_field = match record.get_standard_field(replacement_key) {
                        Ok(field) => field,
                        Err(err) => {
                            error!("Failed to get standard field {}: {}", replacement_key, err);
                            continue;
                        }
                    };
                    let real_field_value =
                        &record.standard_fields_searched_map(replacement_key)?[0];
                    let real_field_value_type = real_field_value
                        .get("type")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string();
                    let real_field_value_label = match real_field_value.get("label") {
                        Some(val) => val.as_str().unwrap().to_string(),
                        None => "".to_string(),
                    };

                    let real_value;
                    match real_field.is_empty() {
                        // we should not have empty field array
                        true => continue,
                        false => {
                            // we select the first field that matches our filter
                            let real_field_first = real_field[0].clone();
                            match real_field_first.is_array() {
                                // value is always array, so checking for corruption of data
                                false => continue,
                                true => {
                                    let real_first_value_array =
                                        real_field_first.as_array().unwrap();
                                    // returning the first value of data which is object
                                    real_value = match real_first_value_array.is_empty() {
                                        true => continue,
                                        false => real_first_value_array[0].clone(),
                                    };
                                }
                            }
                        }
                    };

                    let _real_value_hashmap: HashMap<String, String> = match real_value.is_object(){
                        true => {
                            let hashmap: HashMap<String, String> = real_value.as_object().unwrap().clone().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
                            hashmap.iter().for_each(|(k, v)| {
                                final_data_object.insert(k.clone(), v.clone());
                            });
                            hashmap
                        },
                        false => match real_value.is_string(){
                            true => {
                                let hashmap = HashMap::new();
                                let val = real_value.as_str().unwrap().to_string();
                                if replacement_key=="addressRef"{
                                    let return_value = self.inflate_field_value(vec![val], vec!["address".to_string()])?;
                                    final_data_object.extend(return_value[0].clone());
                                    hashmap
                                }else{
                                    if !real_field_value_label.is_empty(){
                                        final_data_object.insert(real_field_value_label, val);
                                    }else{
                                        final_data_object.insert(real_field_value_type, val);
                                    }
                                    hashmap
                                }
                            },
                            false => return Err(KSMRError::NotationError(format!("Notation error - Cannot extract property '{replacement_key}' from null value."))),
                        },
                    };
                }
                value = vec![final_data_object];
            }
        }

        Ok(value)
    }

    fn inflate_ref_types() -> HashMap<String, Vec<String>> {
        let mut map = HashMap::new();
        map.insert("addressRef".to_string(), vec!["address".to_string()]);
        map.insert(
            "cardRef".to_string(),
            vec![
                "paymentCard".to_string(),
                "text".to_string(),
                "pinCode".to_string(),
                "addressRef".to_string(),
            ],
        );
        map
    }
}

#[derive(Debug, Default)]
pub struct NotationSection {
    pub section: String,                     // section name - ex. prefix
    pub is_present: bool,                    // presence flag
    pub start_pos: isize,                    // section start pos in URI
    pub end_pos: isize,                      // section end pos in URI
    pub text: Option<(String, String)>,      // [unescaped, raw] text
    pub parameter: Option<(String, String)>, // <field type>|<field label>|<file name>
    pub index1: Option<(String, String)>,    // numeric index [N] or []
    pub index2: Option<(String, String)>,    // property index - ex. field/name[0][middle]
}

impl NotationSection {
    pub fn new(section: &str) -> Self {
        NotationSection {
            section: section.to_string(),
            is_present: false,
            start_pos: -1,
            end_pos: -1,
            text: None,
            parameter: None,
            index1: None,
            index2: None,
        }
    }
}
