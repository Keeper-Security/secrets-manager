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

use crate::custom_error::KSMRError;
use log::debug;
use serde::{Deserialize, Serialize};
use std::any::Any;

fn custom_pretty_json<T: Serialize>(
    value: &T,
    indent_size: usize,
) -> Result<String, serde_json::Error> {
    let raw_json = serde_json::to_value(value)?;
    let mut result = String::new();
    format_json(&raw_json, &mut result, 0, indent_size);
    Ok(result)
}

fn format_json(value: &serde_json::Value, result: &mut String, level: usize, indent_size: usize) {
    let indent = " ".repeat(level * indent_size);
    let next_indent = " ".repeat((level + 1) * indent_size);

    match value {
        serde_json::Value::Object(map) => {
            result.push_str("{\n");
            for (i, (key, val)) in map.iter().enumerate() {
                result.push_str(&next_indent);
                result.push('"');
                result.push_str(key);
                result.push_str("\": ");
                format_json(val, result, level + 1, indent_size);
                if i < map.len() - 1 {
                    result.push(',');
                }
                result.push('\n');
            }
            result.push_str(&indent);
            result.push('}');
        }
        serde_json::Value::Array(array) => {
            result.push_str("[\n");
            for (i, val) in array.iter().enumerate() {
                result.push_str(&next_indent);
                format_json(val, result, level + 1, indent_size);
                if i < array.len() - 1 {
                    result.push(',');
                }
                result.push('\n');
            }
            result.push_str(&indent);
            result.push(']');
        }
        serde_json::Value::String(s) => {
            result.push('"');
            result.push_str(s);
            result.push('"');
        }
        serde_json::Value::Number(num) => {
            result.push_str(&num.to_string());
        }
        serde_json::Value::Bool(b) => {
            result.push_str(&b.to_string());
        }
        serde_json::Value::Null => {
            result.push_str("null");
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    transmission_key: TransmissionKey,
    client_id: String,
    client_key: String,
}

impl Context {
    pub fn new(transmission_key: TransmissionKey, client_id: String, client_key: String) -> Self {
        Context {
            transmission_key,
            client_id,
            client_key,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransmissionKey {
    pub public_key_id: String,
    pub key: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

impl TransmissionKey {
    pub fn new(public_key_id: String, key: Vec<u8>, encrypted_key: Vec<u8>) -> Self {
        TransmissionKey {
            public_key_id,
            key,
            encrypted_key,
        }
    }
}

impl Clone for TransmissionKey {
    fn clone(&self) -> Self {
        TransmissionKey {
            // Clone each field of the struct
            public_key_id: self.public_key_id.clone(),
            key: self.key.clone(),
            encrypted_key: self.encrypted_key.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayload {
    client_version: String,
    client_id: String,
    public_key: Option<String>,
    requested_records: Option<Vec<String>>,
    requested_folders: Option<Vec<String>>,
    pub request_links: Option<bool>, // Request linked records (v16.7.0+)
}

impl GetPayload {
    pub fn new(
        client_version: String,
        client_id: String,
        public_key: Option<String>,
        requested_records: Option<Vec<String>>,
        requested_folders: Option<Vec<String>>,
    ) -> GetPayload {
        GetPayload {
            client_version,
            client_id,
            public_key,
            requested_records,
            requested_folders,
            request_links: None,
        }
    }

    pub fn with_request_links(
        client_version: String,
        client_id: String,
        public_key: Option<String>,
        requested_records: Option<Vec<String>>,
        requested_folders: Option<Vec<String>>,
        request_links: Option<bool>,
    ) -> GetPayload {
        GetPayload {
            client_version,
            client_id,
            public_key,
            requested_records,
            requested_folders,
            request_links,
        }
    }

    pub fn set_optional_field<T>(&mut self, field: &str, value: T)
    where
        T: Into<Option<Vec<String>>>,
    {
        match field {
            "records_filter" => self.requested_records = value.into(),
            "folders_filter" => self.requested_folders = value.into(),
            _ => (),
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(custom_pretty_json(&self, 4).unwrap())
    }

    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|e| {
            log::error!("Error deserializing GetPayload from JSON: {}", e);
            KSMRError::DeserializationError(format!(
                "Error deserializing GetPayload from JSON: {}",
                e
            ))
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateTransactionType {
    #[default]
    #[serde(rename = "")]
    None,
    General,
    Rotation,
}

// impl Default for UpdateTransactionType {
//     fn default() -> Self {
//         UpdateTransactionType::None
//     }
// }

impl UpdateTransactionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateTransactionType::None => "",
            UpdateTransactionType::General => "general",
            UpdateTransactionType::Rotation => "rotation",
        }
    }
}

impl std::str::FromStr for UpdateTransactionType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(UpdateTransactionType::None),
            "general" => Ok(UpdateTransactionType::General),
            "rotation" => Ok(UpdateTransactionType::Rotation),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePayload {
    pub client_version: String,
    pub client_id: String,
    pub record_uid: String,
    pub revision: i64,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<UpdateTransactionType>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "links2Remove")]
    pub links2_remove: Option<Vec<String>>, // Links to remove (file UIDs, record UIDs) - v16.7.0+
}

impl UpdatePayload {
    pub fn new(
        client_version: String,
        client_id: String,
        record_uid: String,
        revision: i64,
        data: String,
    ) -> Self {
        UpdatePayload {
            client_version,
            client_id,
            record_uid,
            revision,
            data,
            transaction_type: None,
            links2_remove: None,
        }
    }

    pub fn set_transaction_type(&mut self, transaction_type: UpdateTransactionType) {
        if transaction_type != UpdateTransactionType::None {
            self.transaction_type = Some(transaction_type);
        } else {
            self.transaction_type = None;
        }
    }

    /// Converts `UpdatePayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing UpdatePayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `UpdatePayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing UpdatePayload from JSON: {}",
                err
            ))
        })
    }

    pub fn set_links_to_remove(&mut self, links: Vec<String>) {
        debug!(
            "set_links_to_remove called with {} links: {:?}",
            links.len(),
            links
        );
        self.links2_remove = if links.is_empty() { None } else { Some(links) };
        debug!("  -> links2_remove is now: {:?}", self.links2_remove);
    }
}

/// Options for updating secrets with advanced features
///
/// # Fields
/// * `transaction_type` - Type of transaction (General or Rotation)
/// * `links_to_remove` - Array of link UIDs to remove (file links, record links)
///
/// # Example
/// ```rust
/// use keeper_secrets_manager_core::dto::payload::{UpdateOptions, UpdateTransactionType};
///
/// let options = UpdateOptions::new(UpdateTransactionType::Rotation, vec!["file-uid-123".to_string()]);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateOptions {
    pub transaction_type: UpdateTransactionType,
    pub links_to_remove: Vec<String>,
}

impl UpdateOptions {
    pub fn new(transaction_type: UpdateTransactionType, links_to_remove: Vec<String>) -> Self {
        UpdateOptions {
            transaction_type,
            links_to_remove,
        }
    }

    pub fn with_transaction_type(transaction_type: UpdateTransactionType) -> Self {
        UpdateOptions {
            transaction_type,
            links_to_remove: vec![],
        }
    }

    pub fn with_links_removal(links_to_remove: Vec<String>) -> Self {
        UpdateOptions {
            transaction_type: UpdateTransactionType::General,
            links_to_remove,
        }
    }
}

impl Default for UpdateOptions {
    fn default() -> Self {
        UpdateOptions {
            transaction_type: UpdateTransactionType::General,
            links_to_remove: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CompleteTransactionPayload {
    pub client_version: String,
    pub client_id: String,
    pub record_uid: String,
}

impl CompleteTransactionPayload {
    pub fn new(client_version: String, client_id: String, record_uid: String) -> Self {
        CompleteTransactionPayload {
            client_version,
            client_id,
            record_uid,
        }
    }

    /// Converts `CompleteTransactionPayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing CompleteTransactionPayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `CompleteTransactionPayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing CompleteTransactionPayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreatePayload {
    pub client_version: String,
    pub client_id: String,
    pub record_uid: String,
    pub record_key: String,
    pub folder_uid: String,
    pub folder_key: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_folder_uid: Option<String>,
}

impl CreatePayload {
    /// Constructor for `CreatePayload`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_version: String,
        client_id: String,
        record_uid: String,
        record_key: String,
        folder_uid: String,
        folder_key: String,
        data: String,
        sub_folder_uid: Option<String>,
    ) -> Self {
        Self {
            client_version,
            client_id,
            record_uid,
            record_key,
            folder_uid,
            folder_key,
            data,
            sub_folder_uid,
        }
    }

    /// Converts `CreatePayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing CreatePayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `CreatePayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing CreatePayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeletePayload {
    pub client_version: String,
    pub client_id: String,
    pub record_uids: Vec<String>,
}

impl DeletePayload {
    /// Constructor for `DeletePayload`
    pub fn new(client_version: String, client_id: String, record_uids: Vec<String>) -> Self {
        Self {
            client_version,
            client_id,
            record_uids,
        }
    }

    /// Converts `DeletePayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing DeletePayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `DeletePayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing DeletePayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateFolderPayload {
    pub client_version: String,
    pub client_id: String,
    pub folder_uid: String,
    pub shared_folder_uid: String,
    pub shared_folder_key: String,
    pub data: String,
    pub parent_uid: String,
}

impl CreateFolderPayload {
    pub fn new(
        client_version: String,
        client_id: String,
        folder_uid: String,
        shared_folder_uid: String,
        shared_folder_key: String,
        data: String,
        parent_uid: Option<String>,
    ) -> Self {
        match parent_uid {
            Some(uid) => Self {
                client_version,
                client_id,
                folder_uid,
                shared_folder_uid,
                shared_folder_key,
                data,
                parent_uid: uid,
            },
            None => Self {
                client_version,
                client_id,
                folder_uid,
                shared_folder_uid,
                shared_folder_key,
                data,
                parent_uid: "".to_string(),
            },
        }
    }

    /// Converts `CreateFolderPayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(custom_pretty_json(&self, 4).unwrap())
    }

    /// Populates `CreateFolderPayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing CreateFolderPayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFolderPayload {
    pub client_version: String,
    pub client_id: String,
    pub folder_uid: String,
    pub data: String,
}

impl UpdateFolderPayload {
    /// Constructor for `UpdateFolderPayload`
    pub fn new(
        client_version: String,
        client_id: String,
        folder_uid: String,
        data: String,
    ) -> Self {
        Self {
            client_version,
            client_id,
            folder_uid,
            data,
        }
    }

    /// Converts `UpdateFolderPayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing UpdateFolderPayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `UpdateFolderPayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing UpdateFolderPayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFolderPayload {
    pub client_version: String,
    pub client_id: String,
    pub folder_uids: Vec<String>,
    pub force_deletion: bool,
}

impl DeleteFolderPayload {
    /// Constructor for `DeleteFolderPayload`
    pub fn new(
        client_version: String,
        client_id: String,
        folder_uids: Vec<String>,
        force_deletion: bool,
    ) -> Self {
        Self {
            client_version,
            client_id,
            folder_uids,
            force_deletion,
        }
    }

    /// Converts `DeleteFolderPayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing DeleteFolderPayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `DeleteFolderPayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing DeleteFolderPayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadPayload {
    pub client_version: String,
    pub client_id: String,
    pub file_record_uid: String,
    pub file_record_key: String,
    pub file_record_data: String,
    pub owner_record_uid: String,
    pub owner_record_data: String,
    pub link_key: String,
    pub file_size: i32,
}

impl FileUploadPayload {
    /// Constructor for `FileUploadPayload`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_version: String,
        client_id: String,
        file_record_uid: String,
        file_record_key: String,
        file_record_data: String,
        owner_record_uid: String,
        owner_record_data: String,
        link_key: String,
        file_size: i32,
    ) -> Self {
        Self {
            client_version,
            client_id,
            file_record_uid,
            file_record_key,
            file_record_data,
            owner_record_uid,
            owner_record_data,
            link_key,
            file_size,
        }
    }

    /// Converts `FileUploadPayload` to a JSON string.
    pub fn to_json(&self) -> Result<String, KSMRError> {
        serde_json::to_string(self).map_err(|err| {
            KSMRError::SerializationError(format!(
                "Error serializing FileUploadPayload to JSON: {}",
                err
            ))
        })
    }

    /// Populates `FileUploadPayload` fields from a JSON string.
    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        serde_json::from_str(json_data).map_err(|err| {
            KSMRError::DeserializationError(format!(
                "Error deserializing FileUploadPayload from JSON: {}",
                err
            ))
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub encrypted_payload: Vec<u8>,
    pub signature: ecdsa::der::Signature<p256::NistP256>,
}

impl EncryptedPayload {
    /// Constructor for `EncryptedPayload`
    pub fn new(
        encrypted_payload: Vec<u8>,
        signature: ecdsa::der::Signature<p256::NistP256>,
    ) -> Self {
        EncryptedPayload {
            encrypted_payload,
            signature,
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Err(KSMRError::NotImplemented(
            "serialization has not been implemented for private keys".to_string(),
        ))
    }

    pub fn from_json(json_data: &str) -> Result<Self, KSMRError> {
        let _ = json_data;
        Err(KSMRError::NotImplemented(
            "de-serialization has not been implemented for private keys".to_string(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct KsmHttpResponse {
    pub status_code: u16,
    pub data: Vec<u8>,
    pub http_response: Option<String>,
}

impl KsmHttpResponse {
    /// Constructor for `KsmHttpResponse`
    pub fn new(status_code: u16, data: Vec<u8>, http_response: String) -> Self {
        KsmHttpResponse {
            status_code,
            data,
            http_response: Some(http_response),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub records_filter: Vec<String>,
    pub folders_filter: Vec<String>,
    pub request_links: Option<bool>, // Request linked records (GraphSync) - v16.7.0+
}

impl QueryOptions {
    pub fn new(records_filter: Vec<String>, folders_filter: Vec<String>) -> Self {
        QueryOptions {
            records_filter,
            folders_filter,
            request_links: None,
        }
    }

    pub fn with_links(
        records_filter: Vec<String>,
        folders_filter: Vec<String>,
        request_links: bool,
    ) -> Self {
        QueryOptions {
            records_filter,
            folders_filter,
            request_links: Some(request_links),
        }
    }

    pub fn get_records_filter(&self) -> Option<Vec<String>> {
        match self.records_filter.len() {
            0 => None,
            _ => Some(self.records_filter.clone()),
        }
    }

    pub fn get_folders_filter(&self) -> Option<Vec<String>> {
        match self.folders_filter.len() {
            0 => None,
            _ => Some(self.folders_filter.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub folder_uid: String,
    pub sub_folder_uid: Option<String>,
}

impl CreateOptions {
    pub fn new(folder_uid: String, sub_folder_uid: Option<String>) -> Self {
        CreateOptions {
            folder_uid,
            sub_folder_uid,
        }
    }
}

pub trait Payload: Any {
    fn as_any(&self) -> &dyn Any;
    fn to_json(&self) -> Result<String, KSMRError>;
}

macro_rules! impl_payload {
    ($($type:ty),*) => {
        $(
            impl Payload for $type {
                fn as_any(&self) -> &dyn Any {
                    self
                }

                fn to_json(&self) -> Result<String, KSMRError> {
                    self.to_json()
                }
            }
        )*
    };
}

impl_payload!(
    GetPayload,
    UpdatePayload,
    CreatePayload,
    FileUploadPayload,
    CompleteTransactionPayload,
    DeletePayload,
    CreateFolderPayload,
    UpdateFolderPayload,
    DeleteFolderPayload
);

// Helper function to check if a payload is of an expected type
fn is_instance_of<T: Any>(payload: &dyn Payload) -> bool {
    payload.as_any().is::<T>()
}

// Validate the payload type
pub fn validate_payload(payload: &dyn Payload) -> Result<(), KSMRError> {
    if is_instance_of::<GetPayload>(payload)
        || is_instance_of::<UpdatePayload>(payload)
        || is_instance_of::<CreatePayload>(payload)
        || is_instance_of::<FileUploadPayload>(payload)
        || is_instance_of::<CompleteTransactionPayload>(payload)
        || is_instance_of::<DeletePayload>(payload)
        || is_instance_of::<CreateFolderPayload>(payload)
        || is_instance_of::<UpdateFolderPayload>(payload)
        || is_instance_of::<DeleteFolderPayload>(payload)
    {
        Ok(())
    } else {
        Err(KSMRError::InvalidPayloadError(format!(
            "Unknown payload type: {:?}",
            payload.as_any().type_id()
        )))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadFunctionResult {
    payload: FileUploadPayload,
    encrypted_file_data: Vec<u8>,
}

impl FileUploadFunctionResult {
    pub fn new(payload: FileUploadPayload, encrypted_file_data: Vec<u8>) -> Self {
        FileUploadFunctionResult {
            payload,
            encrypted_file_data,
        }
    }

    pub fn get_encrypted_data(&self) -> Vec<u8> {
        self.encrypted_file_data.clone()
    }

    pub fn get_payload(&self) -> FileUploadPayload {
        self.payload.clone()
    }
}
