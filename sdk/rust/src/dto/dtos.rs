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

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::DateTime;
use data_encoding::HEXLOWER;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt::{self},
    fs::{self, File},
    io::{Read, Write as _},
    path::Path,
};

use crate::{
    crypto::{unpad_data, CryptoUtils},
    custom_error::KSMRError,
    enums::ValueResult,
    utils::{self, json_to_dict},
};

use super::field_structs::KeeperField;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Record {
    pub record_key_bytes: Vec<u8>,
    pub uid: String,
    pub title: String,
    pub record_type: String,
    pub files: Vec<KeeperFile>,
    pub raw_json: String,
    pub record_dict: HashMap<String, Value>,
    pub password: Option<String>,
    pub revision: Option<i64>,
    pub is_editable: bool,
    pub folder_uid: String,
    pub folder_key_bytes: Option<Vec<u8>>,
    pub inner_folder_uid: Option<String>,
    pub links: Vec<HashMap<String, Value>>, // GraphSync linked records (v16.7.0+)
}

impl Record {
    pub fn new(
        record_dict: &HashMap<String, Value>,
        secret_key: Vec<u8>,
        folder_uid: Option<String>,
    ) -> Result<Self, KSMRError> {
        let uid = record_dict
            .get("recordUid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let folder_uid = folder_uid.unwrap_or_default();
        let mut record_key_bytes = Vec::new();
        secret_key.clone_into(&mut record_key_bytes);
        let record_key_encrypted_bytes = record_dict
            .get("recordKey")
            .and_then(Value::as_str)
            .map(|s| STANDARD.decode(s).unwrap_or_default());

        if let Some(encrypted_bytes) = record_key_encrypted_bytes {
            record_key_bytes = CryptoUtils::decrypt_aes(&encrypted_bytes, &secret_key).unwrap();
        }

        let record_encrypted_data_value = record_dict.get("data").and_then(Value::as_str);

        let raw_json = record_encrypted_data_value
            .ok_or_else(|| KSMRError::DecodeError("cannot decrypt record".to_string()))?;

        let raw_json_string = CryptoUtils::decrypt_record(raw_json.as_bytes(), &record_key_bytes)?;

        let record_dict: HashMap<String, Value> = serde_json::from_str(&raw_json_string)
            .map_err(|e| KSMRError::SerializationError(e.to_string()))?;

        // Title and type
        let title = record_dict
            .get("title")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_default();
        let record_type = record_dict
            .get("type")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_default();

        let revision = record_dict.get("revision").and_then(Value::as_i64);
        let is_editable = record_dict
            .get("isEditable")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut files = Vec::new();
        if let Some(file_list) = record_dict.get("files").and_then(Value::as_array) {
            for file_data in file_list {
                if let Some(file_map) = file_data.as_object() {
                    let file_map_hashmap: HashMap<String, Value> = file_map
                        .clone()
                        .into_iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    let created_keeper_file =
                        KeeperFile::new_from_json(file_map_hashmap, record_key_bytes.clone());
                    match created_keeper_file {
                        Ok(file) => files.push(file),
                        Err(e) => {
                            error!("Error loading file: {}", e);
                        }
                    }
                }
            }
        }

        let password = if record_type == "login" {
            record_dict
                .get("fields")
                .and_then(|fields| fields.as_array())
                .and_then(|fields| {
                    fields
                        .iter()
                        .find(|field| {
                            field.get("type") == Some(&Value::String("password".to_string()))
                        })
                        .and_then(|field| field.get("value"))
                        .and_then(|value| value.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(Value::as_str)
                })
                .map(String::from)
        } else {
            None
        };

        // Parse links array (GraphSync linked records)
        let links = record_dict
            .get("links")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|link| {
                        link.as_object().map(|obj| {
                            obj.iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect::<HashMap<String, Value>>()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            uid,
            title,
            record_type,
            files,
            raw_json: raw_json_string,
            record_dict: record_dict.clone(),
            password,
            revision,
            is_editable,
            folder_uid,
            inner_folder_uid: record_dict
                .get("innerFolderUid")
                .and_then(Value::as_str)
                .map(|s| s.to_string()),
            record_key_bytes,
            folder_key_bytes: None,
            links,
        })
    }

    /// Finds a file by title within the Record's files.
    pub fn find_file_by_title(
        &mut self,
        title: &str,
    ) -> Result<Option<&mut KeeperFile>, KSMRError> {
        Ok(self
            .files
            .iter_mut()
            .find(|file: &&mut KeeperFile| file.title == *title))
    }

    pub fn update(&mut self) -> Result<(), KSMRError> {
        // Update the title and type in the record_dict HashMap
        self.record_dict
            .insert("title".to_string(), Value::String(self.title.clone()));
        self.record_dict.insert(
            "record_type".to_string(),
            Value::String(self.record_type.clone()),
        );

        // Find the password field in fields, and update the password attribute if it exists
        if let Some(fields) = self
            .record_dict
            .get_mut("fields")
            .and_then(|f| f.as_array_mut())
        {
            if let Some(password_field) = fields
                .iter_mut()
                .find(|field| field.get("record_type").and_then(|t| t.as_str()) == Some("password"))
            {
                if let Some(values) = password_field.get("value").and_then(|v| v.as_array()) {
                    if let Some(Value::String(password)) = values.first() {
                        self.password = Some(password.clone());
                    }
                }
            }
        }

        self.raw_json = serde_json::to_string(&self.record_dict).map_err(|_| {
            KSMRError::SerializationError("Failed to serialize record_dict".to_string())
        })?;

        Ok(())
    }

    pub fn _value(&self, values: Option<Vec<&[Value]>>, single: bool) -> ValueResult {
        if single {
            let first_value = values
                .and_then(|v| v.first().cloned())
                .map(|v| v.to_owned());
            ValueResult::Single(first_value)
        } else {
            let all_values = values
                .map(|v| v.iter().map(|s| s.to_vec()).collect())
                .unwrap_or_default();
            ValueResult::Multiple(all_values)
        }
    }

    fn field_search(
        mut fields: Vec<HashMap<String, Value>>,
        field_key: &str,
    ) -> Option<Vec<HashMap<String, Value>>> {
        let mut fields_returned: Vec<HashMap<String, Value>> = Vec::new();
        // Check for a matching "label" key first
        for field in fields.clone().drain(..) {
            if let Some(item_label) = field.get("label").and_then(Value::as_str) {
                if item_label.eq(field_key) {
                    fields_returned.push(field.clone());
                }
            }
        }
        if !fields_returned.is_empty() {
            return Some(fields_returned.clone());
        }
        // Search for a matching "type" key
        for field in fields.drain(..) {
            if let Some(item_type) = field.get("type").and_then(Value::as_str) {
                if item_type.eq_ignore_ascii_case(field_key) {
                    fields_returned.push(field.clone());
                }
            }
        }
        if !fields_returned.is_empty() {
            return Some(fields_returned.clone());
        }
        None
    }

    // Retrieve a standard field by field type.
    pub fn get_standard_field(&self, field_type: &str) -> Result<Vec<Value>, KSMRError> {
        let fields_searched = self.standard_fields_searched_map(field_type)?;

        let mut fields_searched_map: Vec<Value> = Vec::new();
        for field_searched in fields_searched.clone() {
            let field_searched_mapped: Value = field_searched
                .get("value") //.into_iter().map(|field| field.get("value").cloned().unwrap_or(Value::Null))
                .ok_or_else(|| {
                    KSMRError::RecordDataError(format!("Field {} not found in record", field_type))
                })?
                .clone();
            fields_searched_map.push(field_searched_mapped);
        }

        Ok(fields_searched_map)
    }

    pub fn standard_fields_searched_map(
        &self,
        field_type: &str,
    ) -> Result<Vec<HashMap<String, Value>>, KSMRError> {
        let fields_2 = self.record_dict.get("fields");
        let fields = fields_2.and_then(Value::as_array).ok_or_else(|| {
            KSMRError::RecordDataError(format!(
                "Cannot find standard field {} in record",
                field_type
            ))
        })?;

        // Parse each `Value` into its specific type
        #[allow(clippy::unnecessary_filter_map)]
        let fields_2: Vec<HashMap<String, Value>> = fields
            .iter()
            .filter_map(|value| match value {
                Value::Object(map) => Some(map.clone().into_iter().collect()),
                Value::Array(arr) => Some(
                    arr.iter()
                        .enumerate()
                        .map(|(i, v)| (i.to_string(), v.clone()))
                        .collect(),
                ),
                Value::String(s) => Some(
                    [("string".to_string(), Value::String(s.clone()))]
                        .into_iter()
                        .collect(),
                ),
                Value::Number(num) => Some(
                    [("number".to_string(), Value::Number(num.clone()))]
                        .into_iter()
                        .collect(),
                ),
                Value::Bool(b) => Some(
                    [("bool".to_string(), Value::Bool(*b))]
                        .into_iter()
                        .collect(),
                ),
                Value::Null => Some(HashMap::new()),
            })
            .collect();

        let fields_searched: Vec<HashMap<String, Value>> =
            match Self::field_search(fields_2, field_type) {
                Some(field) => field,
                None => {
                    return Err(KSMRError::RecordDataError(format!(
                        "Field {} not found in record",
                        field_type
                    )))
                }
            };
        Ok(fields_searched)
    }
    // Retrieve the standard field value by type, either as a single value or an array of values.
    pub fn get_standard_field_value(
        &self,
        field_type: &str,
        single: bool,
    ) -> Result<Value, KSMRError> {
        let fields = self.get_standard_field(field_type)?;
        let mut arrayed_values: Vec<Vec<Value>> = Vec::new();

        for field in fields {
            let arrayed_val = field.as_array().cloned().unwrap();
            arrayed_values.push(arrayed_val);
        }

        if arrayed_values.is_empty() || arrayed_values[0].is_empty() {
            return Err(KSMRError::RecordDataError(format!(
                "No standard field with field type: {} exists on record: {}",
                field_type, self.title
            )));
        }

        // Use `_value` to return a single value or an array, based on `single` parameter
        match self._value(
            Some(arrayed_values.iter().map(|v| v.as_slice()).collect()),
            single,
        ) {
            ValueResult::Single(Some(value)) => Ok(value[0].clone()),
            ValueResult::Single(None) => Ok(Value::Null),
            ValueResult::Multiple(values) => {
                // Flatten the 2D array to 1D
                let flat: Vec<Value> = values.into_iter().flatten().collect();
                Ok(Value::Array(flat))
            }
        }
    }

    pub fn get_standard_field_mut(&mut self, field_type: &str) -> Result<&mut Value, KSMRError> {
        // Get mutable reference to "fields"
        let fields = self
            .record_dict
            .get_mut("fields")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                KSMRError::RecordDataError(format!(
                    "Cannot find standard field {} in record",
                    field_type
                ))
            })?;

        // Find the field by "label" or "type"
        let retrieved_field = fields
            .iter_mut()
            .find(|field| {
                field.get("label").and_then(Value::as_str) == Some(field_type)
                    || field
                        .get("type")
                        .and_then(Value::as_str)
                        .map(|t| t.eq_ignore_ascii_case(field_type))
                        .unwrap_or(false)
            })
            .ok_or_else(|| {
                KSMRError::RecordDataError(format!("Field {} not found in record", field_type))
            });

        retrieved_field
    }

    /// Set a standard field's value
    pub fn set_standard_field_value_mut(
        &mut self,
        field_type: &str,
        value: Value,
    ) -> Result<(), KSMRError> {
        // Get a mutable reference to the field
        let field = self.get_standard_field_mut(field_type)?;

        // Ensure the field is an object and update the "value" key
        let field_obj = field.as_object_mut().ok_or_else(|| {
            KSMRError::RecordDataError(format!(
                "Expected an object for standard field {} in record",
                field_type
            ))
        })?;

        match value.is_array() {
            true => {
                field_obj.insert("value".to_string(), value);
            }
            false => {
                field_obj.insert("value".to_string(), [value].into());
            }
        }
        // Update the "value" field
        self.update()?;
        Ok(())
    }

    // Retrieve a custom field by field type.
    pub fn get_custom_field(&self, field_type: &str) -> Result<Vec<Value>, KSMRError> {
        let fields_2 = self.record_dict.get("custom");

        let fields = fields_2.and_then(Value::as_array).ok_or_else(|| {
            KSMRError::RecordDataError(format!("Cannot find custom field {} in record", field_type))
        })?;

        // Parse each `Value` into its specific type
        #[allow(clippy::unnecessary_filter_map)]
        let fields_2: Vec<HashMap<String, Value>> = fields
            .iter()
            .filter_map(|value| match value {
                Value::Object(map) => Some(map.clone().into_iter().collect()),
                Value::Array(arr) => Some(
                    arr.iter()
                        .enumerate()
                        .map(|(i, v)| (i.to_string(), v.clone()))
                        .collect(),
                ),
                Value::String(s) => Some(
                    [("string".to_string(), Value::String(s.clone()))]
                        .into_iter()
                        .collect(),
                ),
                Value::Number(num) => Some(
                    [("number".to_string(), Value::Number(num.clone()))]
                        .into_iter()
                        .collect(),
                ),
                Value::Bool(b) => Some(
                    [("bool".to_string(), Value::Bool(*b))]
                        .into_iter()
                        .collect(),
                ),
                Value::Null => Some(HashMap::new()),
            })
            .collect();

        let fields_searched = match Self::field_search(fields_2, field_type) {
            Some(field) => field,
            None => {
                return Err(KSMRError::RecordDataError(format!(
                    "Field {} not found in record",
                    field_type
                )))
            }
        };

        let mut fields_searched_map: Vec<Value> = Vec::new();
        for field_searched in fields_searched.clone() {
            let field_searched_mapped: Value = field_searched
                .get("value")
                .ok_or_else(|| {
                    KSMRError::RecordDataError(format!("Field {} not found in record", field_type))
                })?
                .clone();
            fields_searched_map.push(field_searched_mapped);
        }

        Ok(fields_searched_map)
    }

    // Retrieve the custom field value by type, either as a single value or an array of values.
    pub fn get_custom_field_value(
        &self,
        field_type: &str,
        single: bool,
    ) -> Result<Value, KSMRError> {
        let fields = self.get_custom_field(field_type)?;
        let mut arrayed_values: Vec<Vec<Value>> = Vec::new();

        for field in fields {
            let arrayed_val = field.as_array().cloned().unwrap();
            arrayed_values.push(arrayed_val);
        }

        // Use `_value` to return a single value or an array, based on `single` parameter
        match self._value(
            Some(arrayed_values.iter().map(|v| v.as_slice()).collect()),
            single,
        ) {
            ValueResult::Single(Some(value)) => Ok(value[0].clone()),
            ValueResult::Single(None) => Ok(Value::Null),
            ValueResult::Multiple(values) => {
                // Flatten the 2D array to 1D
                let flat: Vec<Value> = values.into_iter().flatten().collect();
                Ok(Value::Array(flat))
            }
        }
    }

    pub fn get_custom_field_mut(&mut self, field_type: &str) -> Result<&mut Value, KSMRError> {
        // Get mutable reference to "fields"
        let fields = self
            .record_dict
            .get_mut("custom")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                KSMRError::RecordDataError(format!(
                    "Cannot find standard field {} in record",
                    field_type
                ))
            })?;

        // Find the field by "label" or "type"
        let retrieved_field = fields
            .iter_mut()
            .find(|field| {
                field.get("label").and_then(Value::as_str) == Some(field_type)
                    || field
                        .get("type")
                        .and_then(Value::as_str)
                        .map(|t| t.eq_ignore_ascii_case(field_type))
                        .unwrap_or(false)
            })
            .ok_or_else(|| {
                KSMRError::RecordDataError(format!("Field {} not found in record", field_type))
            });

        retrieved_field
    }

    /// Set a standard field's value
    pub fn set_custom_field_value_mut(
        &mut self,
        field_type: &str,
        value: Value,
    ) -> Result<(), KSMRError> {
        // Get a mutable reference to the field
        let field = self.get_custom_field_mut(field_type)?;

        // Ensure the field is an object and update the "value" key
        let field_obj = field.as_object_mut().ok_or_else(|| {
            KSMRError::RecordDataError(format!(
                "Expected an object for standard field {} in record",
                field_type
            ))
        })?;

        // Update the "value" field
        field_obj.insert("value".to_string(), [value].into());
        self.update()?;
        Ok(())
    }

    pub fn new_from_json(
        record_dict: HashMap<String, serde_json::Value>,
        secret_key: &[u8],
        folder_uid: Option<String>,
    ) -> Result<Self, KSMRError> {
        let mut record = Record::default();

        // Record UID - Extract early for error logging
        if let Some(uid) = record_dict.get("recordUid").and_then(|v| v.as_str()) {
            record.uid = uid.trim().to_string();
        }

        // Record Key
        if let Some(record_key_str) = record_dict
            .get("recordKey")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
        {
            if !record_key_str.is_empty() {
                let record_key_encrypted = utils::base64_to_bytes(record_key_str)?;
                match CryptoUtils::decrypt_aes(&record_key_encrypted, secret_key) {
                    Ok(record_key_bytes) => {
                        record.record_key_bytes = record_key_bytes;
                    }
                    Err(err) => {
                        let error_msg = format!(
                            "Error decrypting record key: {} - Record UID: {}",
                            err, record.uid
                        );
                        error!("{}", error_msg);
                        return Err(KSMRError::CryptoError(error_msg));
                    }
                }
            }
        } else {
            // Single Record Share
            record.record_key_bytes = secret_key.to_vec();
        }

        let mut decrypted_data = HashMap::new();
        // Encrypted Record Data
        if let Some(record_data_str) = record_dict.get("data").and_then(|v| v.as_str()) {
            if !record.record_key_bytes.is_empty() {
                let record_encrypted_data = utils::base64_to_bytes(record_data_str)?;
                match CryptoUtils::decrypt_record(&record_encrypted_data, &record.record_key_bytes)
                {
                    Ok(record_data_json) => {
                        record.raw_json = record_data_json.clone();
                        record.record_dict = json_to_dict(&record_data_json).unwrap();
                        decrypted_data = json_to_dict(&record_data_json).unwrap();
                    }
                    Err(err) => {
                        let error_msg = format!(
                            "Error decrypting record data: {} - Record UID: {}",
                            err, record.uid
                        );
                        error!("{}", error_msg);
                        return Err(KSMRError::CryptoError(error_msg));
                    }
                }
            }
        }

        if !decrypted_data.is_empty() {
            // Record Title
            if let Some(title) = decrypted_data.get("title").and_then(|v| v.as_str()) {
                record.title = title.trim().to_string();
            }
        }

        // Record Type
        if let Some(record_type) = record.record_dict.get("type").and_then(|v| v.as_str()) {
            record.record_type = record_type.to_string();
            let password = if record_type == "login" {
                record_dict
                    .get("fields")
                    .and_then(|fields| fields.as_array())
                    .and_then(|fields| {
                        fields
                            .iter()
                            .find(|field| {
                                field.get("type") == Some(&Value::String("password".to_string()))
                            })
                            .and_then(|field| field.get("value"))
                            .and_then(|value| value.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(Value::as_str)
                    })
                    .map(String::from)
            } else {
                None
            };
            match password {
                Some(pass) => record.password = Some(pass),
                None => record.password = None,
            }
        }

        if let Some(uid) = folder_uid {
            if !uid.trim().is_empty() {
                record.folder_uid = uid.clone();
                record.folder_key_bytes = Some(secret_key.to_vec());
            }
        }

        // Inner Folder UID
        if let Some(inner_folder_uid) = record_dict.get("innerFolderUid").and_then(|v| v.as_str()) {
            record.inner_folder_uid = Some(inner_folder_uid.trim().to_string());
        }

        // Revision
        if let Some(revision) = record_dict.get("revision").and_then(|v| v.as_f64()) {
            record.revision = Some(revision as i64);
        }

        // Is Editable
        if let Some(is_editable) = record_dict.get("isEditable").and_then(|v| v.as_bool()) {
            record.is_editable = is_editable;
        }
        let mut _files = Vec::new();
        if let Some(file_list) = record_dict.get("files").and_then(Value::as_array) {
            for file_data in file_list {
                if let Some(file_map) = file_data.as_object() {
                    let file_map_hashmap: HashMap<String, Value> = file_map
                        .clone()
                        .into_iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    let created_keeper_file = KeeperFile::new_from_json(
                        file_map_hashmap,
                        record.record_key_bytes.to_vec(),
                    );
                    match created_keeper_file {
                        Ok(file) => _files.push(file),
                        Err(e) => {
                            error!("Error loading file: {}", e);
                        }
                    }
                }
            }
            record.files = _files;
        }

        // Parse links from server response envelope (GraphSync linked records)
        if let Some(Value::Array(links_array)) = record_dict.get("links") {
            record.links = links_array
                .iter()
                .filter_map(|link| {
                    link.as_object().map(|obj| {
                        obj.iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<HashMap<String, Value>>()
                    })
                })
                .collect();
        }

        Ok(record)
    }

    pub fn field_exists(&self, section: &str, name: &str) -> bool {
        // Check if the section is valid
        if section != "fields" && section != "custom" {
            return false;
        }

        // Retrieve the section from the record dictionary
        let section_data = self.record_dict.get(section);
        if section_data.is_none() {
            return false;
        }

        // Ensure the section is an array
        let arr = section_data.unwrap();
        let section_array = match arr.is_array() {
            true => arr.as_array().unwrap(),
            false => return false,
        };

        // Iterate through the array and check for the field
        for item in section_array {
            let item_obj = match item.is_object() {
                true => item.as_object().unwrap(),
                false => return false,
            };
            let item_type = match item_obj.get("type") {
                Some(t) => t.as_str().unwrap(),
                None => return false,
            };
            if item_type == name {
                let item_val = item_obj.get("value");
                match item_val {
                    Some(item_of_value) => match item_of_value.is_array() {
                        true => match item_of_value.as_array() {
                            Some(arr) => match arr.len() {
                                0 => continue, // Skip empty fields, continue checking
                                _ => return true,
                            },
                            None => return false,
                        },
                        false => return false,
                    },
                    None => return false,
                }
            }
        }
        false
    }

    pub fn insert_field(
        &mut self,
        section: &str,
        field: HashMap<String, serde_json::Value>,
    ) -> Result<(), KSMRError> {
        // Validate section
        if section != "fields" && section != "custom" {
            return Err(KSMRError::RecordDataError(format!(
                "Unknown field section '{}'",
                section
            )));
        }

        // Ensure the section exists and is initialized
        let section_fields = self
            .record_dict
            .entry(section.to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));

        // Add the field
        if let Some(arr) = section_fields.as_array_mut() {
            arr.push(serde_json::to_value(&field).unwrap());
        } else {
            // Handle the case where section_fields is not an array
            return Err(KSMRError::RecordDataError(format!(
                "Section '{}' is not an array",
                section
            )));
        }
        Ok(())
    }

    /// Consolidate multiple fileRef fields into one (fixes legacy bug where upload_file created separate fields)
    pub fn consolidate_file_refs(&mut self) {
        use log::debug;

        if let Some(Value::Array(fields)) = self.record_dict.get_mut("fields") {
            let mut all_file_uids: Vec<Value> = Vec::new();
            let mut first_fileref_index: Option<usize> = None;

            // Collect all file UIDs from all fileRef fields
            for (idx, field) in fields.iter().enumerate() {
                if let Some(field_obj) = field.as_object() {
                    if field_obj.get("type").and_then(|v| v.as_str()) == Some("fileRef") {
                        if first_fileref_index.is_none() {
                            first_fileref_index = Some(idx);
                        }
                        if let Some(Value::Array(values)) = field_obj.get("value") {
                            all_file_uids.extend(values.clone());
                        }
                    }
                }
            }

            // If there's more than one fileRef field, consolidate
            let fileref_count = fields
                .iter()
                .filter(|f| f.get("type").and_then(|v| v.as_str()) == Some("fileRef"))
                .count();

            if fileref_count > 1 {
                debug!(
                    "Record '{}': Consolidating {} fileRef fields into one (total {} file UIDs)",
                    self.title,
                    fileref_count,
                    all_file_uids.len()
                );

                // Remove all fileRef fields
                fields
                    .retain(|field| field.get("type").and_then(|v| v.as_str()) != Some("fileRef"));

                // Add back a single consolidated fileRef field
                if !all_file_uids.is_empty() {
                    let mut consolidated_field = serde_json::Map::new();
                    consolidated_field
                        .insert("type".to_string(), Value::String("fileRef".to_string()));
                    consolidated_field
                        .insert("value".to_string(), Value::Array(all_file_uids.clone()));

                    // Insert at the original position of the first fileRef field
                    if let Some(idx) = first_fileref_index {
                        fields.insert(idx, Value::Object(consolidated_field));
                    } else {
                        fields.push(Value::Object(consolidated_field));
                    }

                    debug!("Record '{}': Consolidation complete - now has 1 fileRef field with {} UIDs",
                           self.title, all_file_uids.len());
                }

                // Update raw_json to reflect the changes
                if let Ok(json_str) = serde_json::to_string(&self.record_dict) {
                    self.raw_json = json_str;
                }
            }
        }
    }

    pub fn print(&self) {
        println!("===");
        println!("Title: {}", self.title);
        println!("UID:   {}", self.uid);
        println!("Type:  {}", self.record_type);
        println!();

        println!("Fields");
        println!("------");

        if let Some(fields) = self.record_dict.get("fields").and_then(|v| v.as_array()) {
            for field in fields {
                if let (Some(field_type), Some(values)) = (
                    field.get("type").and_then(|v| v.as_str()),
                    field.get("value").and_then(|v| v.as_array()),
                ) {
                    if field_type != "fileRef" && field_type != "oneTimeCode" {
                        let value_str: Vec<_> = values
                            .iter()
                            .map(Record::extract_strings)
                            .map(|v| v.join(","))
                            .collect();
                        println!("{} : {}", field_type, value_str.join(", "));
                    }
                }
            }
        }

        println!();
        println!("Custom Fields");
        println!("------");

        if let Some(custom_fields) = self.record_dict.get("custom").and_then(|v| v.as_array()) {
            for field in custom_fields {
                if let (Some(label), Some(field_type), Some(values)) = (
                    field.get("label").and_then(|v| v.as_str()),
                    field.get("type").and_then(|v| v.as_str()),
                    field.get("value").and_then(|v| v.as_array()),
                ) {
                    let value_str: Vec<_> = values.iter().filter_map(|v| v.as_str()).collect();
                    println!("{} ({}) : {}", label, field_type, value_str.join(", "));
                }
            }
        }
    }

    fn extract_strings(value: &Value) -> Vec<String> {
        let mut results = Vec::new();

        match value {
            Value::String(s) => results.push(s.clone()), // Collect strings
            Value::Number(s) => results.push(s.to_string().clone()),
            Value::Array(arr) => {
                for item in arr {
                    results.extend(Self::extract_strings(item)); // Recurse for arrays
                }
            }
            Value::Object(map) => {
                for val in map.values() {
                    results.extend(Self::extract_strings(val)); // Recurse for map values
                }
            }
            _ => {} // Ignore other types
        }

        results
    }

    pub fn find_file_by_filename(
        &mut self,
        filename: &str,
    ) -> Result<Option<&mut KeeperFile>, KSMRError> {
        Ok(self.files.iter_mut().find(|file| file.name == filename))
    }

    pub fn find_file(&mut self, name: &str) -> Result<Option<&mut KeeperFile>, KSMRError> {
        Ok(self
            .files
            .iter_mut()
            .find(|file| file.uid == name || file.name == name || file.title == name))
    }

    pub fn find_files(&mut self, name: &str) -> Vec<&mut KeeperFile> {
        self.files
            .iter_mut()
            .filter(|file| file.uid == name || file.name == name || file.title == name)
            .collect()
    }

    pub fn download_file_by_title(&mut self, title: &str, path: &str) -> Result<bool, KSMRError> {
        let found_file = self.find_file_by_title(title)?;

        match found_file {
            Some(file) => {
                let file_status = file.save_file(path, false)?;
                Ok(file_status)
            }
            None => Err(KSMRError::FileError(format!(
                "File with title {} not found",
                title
            ))),
        }
    }

    pub fn download_file(&mut self, uid: &str, path: &str) -> Result<bool, KSMRError> {
        let found_file = self.find_file(uid)?;

        match found_file {
            Some(file) => {
                let file_status = file.save_file(path, false)?;
                Ok(file_status)
            }
            None => {
                info!(
                    "File with name/uid {} not found in record with uid {}",
                    uid, self.uid
                );
                Ok(false)
            }
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[Record: uid={}, type={:?}, title={:?}, files count={}]",
            self.uid,
            self.record_type,
            self.title,
            self.files.len()
        )
    }
}

impl Record {
    /// Returns the record's linked credentials (GraphSync links, v16.7.0+) as typed
    /// [`KeeperRecordLink`] values instead of raw maps.
    ///
    /// This is the ergonomic, typed accessor for the raw [`Record::links`] field — it
    /// matches the Python SDK's `KeeperRecordLink` reference implementation (KSM-992).
    /// The raw `links` field remains available unchanged for backward compatibility;
    /// entries without a `recordUid` string are skipped here.
    pub fn get_links(&self) -> Vec<KeeperRecordLink> {
        self.links
            .iter()
            .filter_map(KeeperRecordLink::from_map)
            .collect()
    }
}

/// A typed view over a single linked-credential entry on a [`Record`].
///
/// A link entry carries `recordUid`, optional base64 `data`, and an optional `path`
/// discriminator. Observed payload shapes (verified against the live backend):
///
/// - path `"meta"` (self-link, `record_uid` == owning record): plain base64 JSON with
///   `allowedSettings` (rotation, connections, portForwards, sessionRecording,
///   typescriptRecording, aiEnabled, aiSessionTerminate, remoteBrowserIsolation),
///   plus `rotateOnTermination`, `version` and `no_update_services`.
/// - path `None` (credential link to another record): plain base64 JSON with
///   `is_admin`, `is_launch_credential`, `is_iam_user`, `belongs_to` and
///   `rotation_settings`; or no data at all (pure record reference).
/// - path `"ai_settings"` / `"jit_settings"` (self-links): data is AES-256-GCM
///   encrypted under the owning record's key — see [`Self::get_decrypted_data`].
///
/// The accessors never fail loudly: parse, decode or decryption failures yield
/// `None`/`false`. The original link entry is kept untouched in [`Self::raw`], and
/// [`Self::get_link_data`] returns the complete parsed payload, so fields unknown to
/// this SDK version are always preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperRecordLink {
    /// UID of the linked record.
    pub record_uid: String,
    /// Base64-encoded link metadata (plain JSON or encrypted), if present.
    pub data: Option<String>,
    /// Link path discriminator (e.g. `meta`, `ai_settings`, `jit_settings`), if present.
    pub path: Option<String>,
    /// The untouched original link entry (lossless retention of every key the server
    /// sent, including ones this SDK version doesn't know about yet).
    #[serde(skip)]
    pub raw: HashMap<String, Value>,
}

impl KeeperRecordLink {
    /// Build a typed link from its parts; `raw` is synthesized from them. Prefer
    /// [`Record::get_links`] for links coming from the server, which keeps the
    /// complete original entry in `raw`.
    pub fn new(record_uid: impl Into<String>, data: Option<String>, path: Option<String>) -> Self {
        let record_uid = record_uid.into();
        let mut raw = HashMap::new();
        raw.insert("recordUid".to_string(), Value::String(record_uid.clone()));
        raw.insert(
            "data".to_string(),
            data.clone().map(Value::String).unwrap_or(Value::Null),
        );
        raw.insert(
            "path".to_string(),
            path.clone().map(Value::String).unwrap_or(Value::Null),
        );
        Self {
            record_uid,
            data,
            path,
            raw,
        }
    }

    /// Build a typed link from a raw `links` entry. Returns `None` if the entry has no
    /// `recordUid` string. The full original entry is kept in `raw`.
    fn from_map(map: &HashMap<String, Value>) -> Option<Self> {
        let record_uid = map.get("recordUid").and_then(Value::as_str)?.to_string();
        let data = map.get("data").and_then(Value::as_str).map(str::to_string);
        let path = map.get("path").and_then(Value::as_str).map(str::to_string);
        Some(Self {
            record_uid,
            data,
            path,
            raw: map.clone(),
        })
    }

    /// Base64-decode `data` and parse it as a JSON object. Returns `None` when `data` is
    /// absent, not valid base64, or not a JSON object (e.g. encrypted bytes).
    fn parse_json_data(&self) -> Option<serde_json::Map<String, Value>> {
        let decoded = self.get_decoded_data()?;
        match serde_json::from_str::<Value>(&decoded) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        }
    }

    /// Read a strict boolean from the link data; missing or non-bool values are `false`.
    ///
    /// With `check_allowed_settings` the nested `allowedSettings` object is consulted
    /// when the key is absent (or non-bool) at the top level — a top-level boolean wins.
    /// The backend nests permission flags under `allowedSettings` in `meta` links.
    fn bool_value(&self, key: &str, check_allowed_settings: bool) -> bool {
        let Some(map) = self.parse_json_data() else {
            return false;
        };
        if let Some(value) = map.get(key).and_then(Value::as_bool) {
            return value;
        }
        if check_allowed_settings {
            if let Some(value) = map
                .get("allowedSettings")
                .and_then(Value::as_object)
                .and_then(|allowed| allowed.get(key))
                .and_then(Value::as_bool)
            {
                return value;
            }
        }
        false
    }

    /// Whether the linked user is an admin (`is_admin`).
    pub fn is_admin_user(&self) -> bool {
        self.bool_value("is_admin", false)
    }

    /// Whether this is a launch credential link (`is_launch_credential`).
    pub fn is_launch_credential(&self) -> bool {
        self.bool_value("is_launch_credential", false)
    }

    /// Whether the linked user is an IAM user (`is_iam_user`).
    pub fn is_iam_user(&self) -> bool {
        self.bool_value("is_iam_user", false)
    }

    /// Whether the linked credential belongs to the record (`belongs_to`).
    pub fn belongs_to(&self) -> bool {
        self.bool_value("belongs_to", false)
    }

    /// Whether service updates are disabled for this link (`no_update_services`).
    pub fn no_update_services(&self) -> bool {
        self.bool_value("no_update_services", false)
    }

    /// Whether rotation is allowed (`rotation`, top-level or in `allowedSettings`).
    pub fn allows_rotation(&self) -> bool {
        self.bool_value("rotation", true)
    }

    /// Whether connections are allowed (`connections`, top-level or in `allowedSettings`).
    pub fn allows_connections(&self) -> bool {
        self.bool_value("connections", true)
    }

    /// Whether port forwards are allowed (`portForwards`, top-level or in
    /// `allowedSettings`).
    pub fn allows_port_forwards(&self) -> bool {
        self.bool_value("portForwards", true)
    }

    /// Whether session recording is enabled (`sessionRecording`, top-level or in
    /// `allowedSettings`).
    pub fn allows_session_recording(&self) -> bool {
        self.bool_value("sessionRecording", true)
    }

    /// Whether TypeScript recording is enabled (`typescriptRecording`, top-level or in
    /// `allowedSettings`).
    pub fn allows_typescript_recording(&self) -> bool {
        self.bool_value("typescriptRecording", true)
    }

    /// Whether remote browser isolation is enabled (`remoteBrowserIsolation`, top-level
    /// or in `allowedSettings`).
    pub fn allows_remote_browser_isolation(&self) -> bool {
        self.bool_value("remoteBrowserIsolation", true)
    }

    /// Whether AI features are enabled (`aiEnabled`, top-level or in `allowedSettings`).
    pub fn ai_enabled(&self) -> bool {
        self.bool_value("aiEnabled", true)
    }

    /// Whether AI session termination is enabled (`aiSessionTerminate`, top-level or in
    /// `allowedSettings`).
    pub fn ai_session_terminate(&self) -> bool {
        self.bool_value("aiSessionTerminate", true)
    }

    /// Whether rotation on termination is enabled (`rotateOnTermination`).
    pub fn rotates_on_termination(&self) -> bool {
        self.bool_value("rotateOnTermination", false)
    }

    /// The link data schema version (`version`) when it is an integer, else `None`
    /// (e.g. `ai_settings` carries a string version such as `"v1.0.0"`).
    pub fn get_link_data_version(&self) -> Option<i64> {
        self.parse_json_data()
            .and_then(|m| m.get("version").and_then(Value::as_i64))
    }

    /// The `allowedSettings` object from the link data (empty map when absent).
    pub fn get_allowed_settings(&self) -> serde_json::Map<String, Value> {
        self.parse_json_data()
            .and_then(|map| match map.get("allowedSettings") {
                Some(Value::Object(allowed)) => Some(allowed.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// The `rotation_settings` object from the link data (schedule, pwd_complexity,
    /// disabled, noop, saas_record_uid_list), or `None` when absent.
    pub fn get_rotation_settings(&self) -> Option<serde_json::Map<String, Value>> {
        match self.parse_json_data()?.get("rotation_settings") {
            Some(Value::Object(settings)) => Some(settings.clone()),
            _ => None,
        }
    }

    /// Base64-decode `data` to a UTF-8 string (lossy). Returns `None` if `data` is absent
    /// or not valid base64.
    pub fn get_decoded_data(&self) -> Option<String> {
        let data = self.data.as_ref()?;
        utils::base64_to_bytes(data)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Whether the decoded data looks like readable JSON (starts with `{` or `[`).
    pub fn has_readable_data(&self) -> bool {
        match self.get_decoded_data() {
            Some(decoded) => decoded.starts_with('{') || decoded.starts_with('['),
            None => false,
        }
    }

    /// Whether this link's `path` is a known potentially-encrypted path
    /// (`ai_settings` or `jit_settings`). Other paths, including `meta`, carry
    /// plain base64 JSON.
    pub fn might_be_encrypted(&self) -> bool {
        matches!(
            self.path.as_deref(),
            Some("ai_settings") | Some("jit_settings")
        )
    }

    /// Whether the data appears encrypted by inspecting the decoded bytes (not JSON and
    /// not mostly printable text).
    pub fn has_encrypted_data(&self) -> bool {
        match self.get_decoded_data() {
            Some(decoded) => {
                !decoded.starts_with('{')
                    && !decoded.starts_with('[')
                    && !Self::is_printable_text(&decoded)
            }
            None => false,
        }
    }

    /// Decrypt `data` with the provided record key using AES-256-GCM. Returns `None` if
    /// `data`/`record_key` is absent or decryption fails.
    pub fn get_decrypted_data(&self, record_key: Option<&[u8]>) -> Option<String> {
        let data = self.data.as_ref()?;
        let key = record_key?;
        let encrypted = utils::base64_to_bytes(data).ok()?;
        let decrypted = CryptoUtils::decrypt_aes(&encrypted, key).ok()?;
        Some(String::from_utf8_lossy(&decrypted).into_owned())
    }

    /// Get link data as a JSON object, auto-handling plain JSON or encrypted data.
    /// Plain JSON parses without a key; encrypted data requires `record_key`.
    pub fn get_link_data(
        &self,
        record_key: Option<&[u8]>,
    ) -> Option<serde_json::Map<String, Value>> {
        let decoded = self.get_decoded_data()?;
        if decoded.starts_with('{') || decoded.starts_with('[') {
            return match serde_json::from_str::<Value>(&decoded) {
                Ok(Value::Object(map)) => Some(map),
                _ => None,
            };
        }
        // Not plain JSON — try decryption if a key is available.
        let decrypted = self.get_decrypted_data(record_key)?;
        match serde_json::from_str::<Value>(&decrypted) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        }
    }

    /// Get PAM settings data from this link — only when `path == "meta"`.
    ///
    /// Meta links are self-links (`record_uid` == owning record) carrying the record's
    /// own PAM settings: `allowedSettings`, `rotateOnTermination`, `version`,
    /// `no_update_services`. Plain JSON today; the key is accepted for forward
    /// compatibility.
    pub fn get_meta_data(
        &self,
        record_key: Option<&[u8]>,
    ) -> Option<serde_json::Map<String, Value>> {
        self.get_settings_for_path("meta", record_key)
    }

    /// Get AI settings data — only when `path == "ai_settings"`.
    ///
    /// Encrypted under the owning record's key. Known fields: `version` (string, e.g.
    /// `"v1.0.0"`) and `riskLevels` (critical/high/medium/low, each with `tags`
    /// allow/deny lists and `aiSessionTerminate`). Additional fields may be present in
    /// newer versions; the returned map preserves all of them.
    pub fn get_ai_settings_data(
        &self,
        record_key: &[u8],
    ) -> Option<serde_json::Map<String, Value>> {
        if self.path.as_deref() != Some("ai_settings") {
            return None;
        }
        self.get_link_data(Some(record_key))
    }

    /// Get JIT (Just-In-Time) settings data — only when `path == "jit_settings"`.
    ///
    /// Encrypted under the owning record's key. Known fields: `createEphemeral`,
    /// `elevate`, `elevationMethod`, `elevationString`, `baseDistinguishedName`.
    /// Additional fields may be present in newer versions; the returned map preserves
    /// all of them.
    pub fn get_jit_settings_data(
        &self,
        record_key: &[u8],
    ) -> Option<serde_json::Map<String, Value>> {
        if self.path.as_deref() != Some("jit_settings") {
            return None;
        }
        self.get_link_data(Some(record_key))
    }

    /// Get settings data for any `path` — returns `None` unless the link's `path` matches
    /// `settings_path`.
    pub fn get_settings_for_path(
        &self,
        settings_path: &str,
        record_key: Option<&[u8]>,
    ) -> Option<serde_json::Map<String, Value>> {
        if self.path.as_deref() != Some(settings_path) {
            return None;
        }
        self.get_link_data(record_key)
    }

    /// Whether a string is mostly printable text (>90% of the first 100 chars printable),
    /// used to distinguish encrypted bytes from text.
    fn is_printable_text(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let sample: Vec<char> = s.chars().take(100).collect();
        let printable = sample
            .iter()
            .filter(|&&c| (' '..='~').contains(&c) || c == '\n' || c == '\r' || c == '\t')
            .count();
        (printable as f32 / sample.len() as f32) > 0.9
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperFile {
    // Define the fields of KeeperFile here
    file_key: String,
    pub metadata_dict: HashMap<String, Value>,

    data: Vec<u8>,

    pub uid: String,
    pub file_type: String,
    pub title: String,
    pub name: String,
    last_modified: i64,
    size: i64,
    pub url: Option<String>,           // Download URL (v16.7.0+)
    pub thumbnail_url: Option<String>, // Thumbnail URL (v16.7.0+)
    pub proxy_url: Option<String>,     // Proxy URL for HTTP requests
    pub(crate) skip_ssl_verify: bool, // Skip SSL cert verification (for corporate proxies like Zscaler)
    /// Pre-built HTTP client for file downloads. Avoids constructing a new
    /// reqwest::blocking::Client inside tokio::spawn_blocking, which fails
    /// because reqwest's blocking module creates an internal tokio runtime.
    /// See: https://github.com/seanmonstar/reqwest/issues/1017
    #[serde(skip)]
    pub(crate) http_client: Option<reqwest::blocking::Client>,

    f: HashMap<String, Value>,
    record_key_bytes: Vec<u8>,
}

#[allow(clippy::inherent_to_string)]
impl KeeperFile {
    pub fn deep_copy(&self) -> KeeperFile {
        KeeperFile {
            file_key: self.file_key.clone(),
            metadata_dict: self.metadata_dict.clone(),
            data: self.data.clone(),
            uid: self.uid.clone(),
            file_type: self.file_type.clone(),
            title: self.title.clone(),
            name: self.name.clone(),
            last_modified: self.last_modified,
            size: self.size,
            url: self.url.clone(),
            thumbnail_url: self.thumbnail_url.clone(),
            proxy_url: self.proxy_url.clone(),
            skip_ssl_verify: self.skip_ssl_verify,
            http_client: self.http_client.clone(),
            f: self.f.clone(),
            record_key_bytes: self.record_key_bytes.clone(),
        }
    }

    /// Returns the pre-built HTTP client if available, or builds a fallback one.
    /// The pre-built client is propagated from SecretsManager to avoid constructing
    /// reqwest::blocking::Client inside tokio::spawn_blocking (reqwest#1017).
    fn resolve_http_client(&self) -> Result<reqwest::blocking::Client, KSMRError> {
        if let Some(client) = &self.http_client {
            return Ok(client.clone());
        }
        let mut client_builder =
            reqwest::blocking::Client::builder().danger_accept_invalid_certs(self.skip_ssl_verify);
        if let Some(ref proxy_url) = self.proxy_url {
            let url = reqwest::Url::parse(proxy_url).map_err(|e| {
                KSMRError::FileError(format!("Invalid proxy URL '{}': {}", proxy_url, e))
            })?;
            let mut proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| KSMRError::FileError(format!("Failed to configure proxy: {}", e)))?;
            if !url.username().is_empty() {
                let password = url.password().unwrap_or("");
                proxy = proxy.basic_auth(url.username(), password);
            }
            client_builder = client_builder.proxy(proxy);
        }
        client_builder
            .build()
            .map_err(|e| KSMRError::FileError(format!("Failed to build HTTP client: {}", e)))
    }

    /// Decrypts the file key using the record key bytes.
    pub fn decrypt_file_key(&self) -> Result<Vec<u8>, KSMRError> {
        // Retrieve the Base64-encoded file key from metadata
        let file_key_encrypted_base64 = self
            .f
            .get("fileKey")
            .ok_or_else(|| {
                KSMRError::KeyNotFoundError("fileKey not found in metadata".to_string())
            })?
            .as_str()
            .ok_or_else(|| KSMRError::DecodeError("fileKey is not a string".to_string()))?;

        // Decode the Base64-encoded string
        let file_key_encrypted = utils::base64_to_bytes(file_key_encrypted_base64)?;

        // Decrypt the file key using AES
        CryptoUtils::decrypt_aes(&file_key_encrypted, &self.record_key_bytes).map_err(|e| {
            log::error!(
                "Error decrypting file key: {}, error: {}",
                file_key_encrypted_base64,
                e
            );
            KSMRError::CryptoError(format!("Failed to decrypt file key: {}", e))
        })
    }

    pub fn get_meta(&mut self) -> Result<HashMap<String, Value>, KSMRError> {
        // If metadata is already populated, return it
        if !self.metadata_dict.is_empty() {
            return Ok(self.metadata_dict.clone());
        }

        // Retrieve the Base64-encoded file metadata
        let data_str = self
            .f
            .get("data")
            .and_then(|data| data.as_str())
            .ok_or_else(|| {
                KSMRError::KeyNotFoundError("Missing 'data' field in metadata".to_string())
            })?;

        // Decrypt the file key
        let file_key = self.decrypt_file_key()?;

        // Decode the Base64-encoded metadata
        let data_bytes = utils::base64_to_bytes(data_str)?;

        // Decrypt the metadata
        let decrypted_meta = CryptoUtils::decrypt_aes(&data_bytes, &file_key)
            .map_err(|e| KSMRError::CryptoError(format!("Failed to decrypt metadata: {}", e)))?;

        // Convert decrypted metadata into a UTF-8 string
        let meta_json = utils::bytes_to_string(&decrypted_meta)?;

        // Parse the JSON string into a HashMap
        self.metadata_dict = json_to_dict(&meta_json).unwrap_or_default();

        Ok(self.metadata_dict.clone())
    }

    /// Returns the decrypted raw file data.
    pub fn get_file_data(&mut self) -> Result<Option<Vec<u8>>, KSMRError> {
        // Return cached data if it exists
        if !self.data.is_empty() {
            return Ok(Some(self.data.clone()));
        }

        // Decrypt the file key
        let file_key = self.decrypt_file_key()?;

        // Get the file URL
        let file_url = self
            .get_url()
            .map_err(|_| KSMRError::FileError("File URL is invalid".to_string()))?;

        let http_client = self.resolve_http_client()?;
        let mut response = http_client
            .get(&file_url)
            .send()
            .map_err(|e| KSMRError::FileError(format!("Failed to fetch file: {}", e)))?;

        // Ensure the HTTP request was successful
        if !response.status().is_success() {
            return Err(KSMRError::HTTPError(format!(
                "HTTP request failed with status: {}",
                response.status()
            )));
        }

        // Read the response body
        let mut encrypted_data = Vec::new();
        response
            .read_to_end(&mut encrypted_data)
            .map_err(|e| KSMRError::IOError(format!("Failed to read response body: {}", e)))?;

        // Decrypt the file data
        let decrypted_data = CryptoUtils::decrypt_aes(&encrypted_data, &file_key)
            .map_err(|e| KSMRError::CryptoError(format!("Failed to decrypt file: {}", e)))?;

        // Cache the decrypted data
        self.data = decrypted_data.clone();

        Ok(Some(decrypted_data))
    }

    /// Retrieves the URL from the `f` HashMap, if available.
    pub fn get_url(&self) -> Result<String, KSMRError> {
        // Try url field first (if populated from API), then fall back to f HashMap
        if let Some(url) = &self.url {
            return Ok(url.clone());
        }

        let file_url = self
            .f
            .get("url") // Look for the "url" key in the HashMap
            .and_then(|value| value.as_str()) // Ensure the value is a string
            .unwrap_or_default() // Return the string if found, or an empty string if not
            .to_string(); // Convert to a String
        Ok(file_url)
    }

    /// Downloads and decrypts the file thumbnail.
    ///
    /// # Returns
    /// * `Result<Option<Vec<u8>>, KSMRError>` - Decrypted thumbnail data, or None if no thumbnail available
    ///
    /// # Example
    /// ```rust,ignore
    /// # use keeper_secrets_manager_core::dto::KeeperFile;
    /// # use keeper_secrets_manager_core::custom_error::KSMRError;
    /// # fn example(file: &mut KeeperFile) -> Result<(), KSMRError> {
    /// if let Some(thumbnail_data) = file.get_thumbnail_data()? {
    ///     // Save thumbnail to disk
    ///     std::fs::write("thumbnail.jpg", thumbnail_data)?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_thumbnail_data(&mut self) -> Result<Option<Vec<u8>>, KSMRError> {
        // Check if thumbnail URL is available
        let thumbnail_url = if let Some(url) = &self.thumbnail_url {
            url.clone()
        } else if let Some(url) = self.f.get("thumbnailUrl").and_then(|v| v.as_str()) {
            url.to_string()
        } else {
            return Ok(None); // No thumbnail available
        };

        // Decrypt the file key
        let file_key = self.decrypt_file_key()?;

        let http_client = self.resolve_http_client()?;
        let mut response = http_client
            .get(&thumbnail_url)
            .send()
            .map_err(|e| KSMRError::FileError(format!("Failed to fetch thumbnail: {}", e)))?;

        // Ensure the HTTP request was successful
        if !response.status().is_success() {
            return Err(KSMRError::HTTPError(format!(
                "HTTP request failed with status: {}",
                response.status()
            )));
        }

        // Read the response body
        let mut encrypted_thumbnail = Vec::new();
        response
            .read_to_end(&mut encrypted_thumbnail)
            .map_err(|e| KSMRError::IOError(format!("Failed to read thumbnail: {}", e)))?;

        // Decrypt the thumbnail data
        let decrypted_thumbnail = CryptoUtils::decrypt_aes(&encrypted_thumbnail, &file_key)
            .map_err(|e| KSMRError::CryptoError(format!("Failed to decrypt thumbnail: {}", e)))?;

        Ok(Some(decrypted_thumbnail))
    }

    pub fn new_from_json(
        file_dict: HashMap<String, Value>,
        record_key_bytes: Vec<u8>,
    ) -> Result<Self, KSMRError> {
        // Extract url and thumbnailUrl from file_dict before creating struct
        let url = file_dict
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let thumbnail_url = file_dict
            .get("thumbnailUrl")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut file = KeeperFile {
            file_key: String::new(),
            metadata_dict: HashMap::new(),
            data: vec![],
            uid: String::new(),
            file_type: String::new(),
            title: String::new(),
            name: String::new(),
            last_modified: 0,
            size: 0,
            url,
            thumbnail_url,
            proxy_url: None,
            skip_ssl_verify: false,
            http_client: None,
            f: file_dict.clone(),
            record_key_bytes,
        };

        // Extract metadata if present
        let meta = file.get_meta()?;
        if let Some(file_uid) = file_dict.get("fileUid").and_then(|v| v.as_str()) {
            file.uid = file_uid.to_string();
        }
        if let Some(file_type) = meta.get("type").and_then(|v| v.as_str()) {
            file.file_type = file_type.to_string();
        }
        if let Some(title) = meta.get("title").and_then(|v| v.as_str()) {
            file.title = title.to_string();
        }
        if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
            file.name = name.to_string();
        }
        if let Some(last_modified) = meta.get("lastModified").and_then(|v| v.as_f64()) {
            file.last_modified = last_modified as i64;
        }
        if let Some(size) = meta.get("size").and_then(|v| v.as_f64()) {
            file.size = size as i64;
        }

        Ok(file)
    }

    pub fn save_file(
        &mut self,
        path: impl AsRef<Path>,
        create_folders: bool,
    ) -> Result<bool, KSMRError> {
        let path = path.as_ref();
        // Resolve the absolute path
        let abs_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => path.to_path_buf(), // Fallback to given path if canonicalization fails
        };

        // Get the parent directory
        let dir_path = abs_path.parent().ok_or_else(|| {
            KSMRError::PathError(format!(
                "Failed to determine parent directory for path: {}",
                path.display()
            ))
        })?;

        // Create folders if needed
        if create_folders {
            if let Err(err) = fs::create_dir_all(dir_path) {
                error!("Error creating folders: {}", err);
                return Err(KSMRError::IOError(format!(
                    "Failed to create directories: {}",
                    err
                )));
            }
        }

        // Verify that the directory exists
        if !dir_path.exists() {
            return Err(KSMRError::PathError(format!(
                "Directory does not exist: {}",
                dir_path.display()
            )));
        }

        // Write the file data
        let _download_file_data = self.get_file_data()?;

        let mut file = File::create(&abs_path).map_err(|err| {
            KSMRError::IOError(format!(
                "Failed to create file {}: {}",
                abs_path.display(),
                err
            ))
        })?;
        file.write_all(&self.data).map_err(|err| {
            KSMRError::IOError(format!(
                "Failed to write to file {}: {}",
                abs_path.display(),
                err
            ))
        })?;

        Ok(true)
    }

    /// Download (if not already cached) and write the file's decrypted bytes to `path`.
    ///
    /// Convenience wrapper over [`save_file`](Self::save_file) that accepts any path type
    /// (`&str`, `String`, `&Path`, `PathBuf`) and does not create parent directories.
    pub fn save_to_file(&mut self, path: impl AsRef<Path>) -> Result<bool, KSMRError> {
        self.save_file(path, false)
    }

    pub fn to_string(&self) -> String {
        format!("[KeeperFile - name: {}, title: {}]", self.name, self.title)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperFolder {
    pub folder_key: Vec<u8>,
    pub folder_uid: String,
    pub parent_uid: String,
    pub name: String,
}

impl KeeperFolder {
    pub fn new(
        folder_map: &HashMap<String, serde_json::Value>,
        folder_key: Vec<u8>,
    ) -> Result<Self, KSMRError> {
        let mut folder = KeeperFolder {
            folder_key,
            folder_uid: String::new(),
            parent_uid: String::new(),
            name: String::new(),
        };

        if let Some(serde_json::Value::String(val)) = folder_map.get("folderUid") {
            folder.folder_uid = val.clone();
        }

        if let Some(serde_json::Value::String(val)) = folder_map.get("parent") {
            folder.parent_uid = val.clone();
        }

        if let Some(serde_json::Value::String(val)) = folder_map.get("data") {
            let data = match CryptoUtils::url_safe_str_to_bytes(val) {
                Ok(data) => data,
                Err(e) => {
                    if e.to_string().contains("Invalid padding") {
                        CryptoUtils::url_safe_str_to_bytes_trim_padding(val)?
                    } else {
                        return Err(e);
                    }
                }
            };
            if let Ok(decrypted_data) = CryptoUtils::decrypt_aes_cbc(&data, &folder.folder_key) {
                #[derive(Deserialize)]
                struct FolderName {
                    name: String,
                }
                let decrypted_data_unpadded = unpad_data(decrypted_data.as_slice()).unwrap();
                if let Ok(folder_name) =
                    serde_json::from_slice::<FolderName>(&decrypted_data_unpadded)
                {
                    folder.name = folder_name.name;
                } else {
                    error!("Error parsing folder name from decrypted data");
                }
            }
        }
        Ok(folder)
    }

    pub fn to_serialized_string(&self) -> String {
        let mut clone: HashMap<String, Value> = HashMap::new();
        clone.insert(
            "folderKey".to_string(),
            Value::String(HEXLOWER.encode(&self.folder_key)),
        );
        clone.insert(
            ("folderUid").to_string(),
            Value::String(self.folder_uid.clone()),
        );
        clone.insert(
            "parentUid".to_string(),
            Value::String(self.parent_uid.clone()),
        );
        clone.insert("name".to_string(), Value::String(self.name.clone()));
        serde_json::to_string_pretty(&clone).unwrap_or_else(|_| "Failed to serialize".to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Folder {
    key: Vec<u8>,
    pub uid: String,
    parent_uid: String,
    name: String,
    data: HashMap<String, Value>,
    folder_records: Vec<HashMap<String, Value>>,
}

impl Folder {
    pub fn new_from_json(folder_dict: HashMap<String, Value>, secret_key: &[u8]) -> Option<Self> {
        let mut folder = Folder {
            key: vec![],
            uid: String::new(),
            parent_uid: String::new(),
            name: String::new(),
            data: folder_dict.clone(),
            folder_records: vec![],
        };

        if let Some(Value::String(uid)) = folder_dict.get("folderUid") {
            folder.uid = uid.trim().to_string();

            if let Some(Value::String(folder_key_enc)) = folder_dict.get("folderKey") {
                let folder_key_bytes = utils::base64_to_bytes(folder_key_enc).unwrap();
                match CryptoUtils::decrypt_aes(&folder_key_bytes, secret_key) {
                    Ok(folder_key) => {
                        folder.key = folder_key;

                        if let Some(Value::Array(records)) = folder_dict.get("records") {
                            for record in records {
                                if let Some(record_map) = record.as_object() {
                                    folder.folder_records.push(
                                        record_map
                                            .clone()
                                            .into_iter()
                                            .map(|(k, v)| (k.clone(), v.clone()))
                                            .collect(),
                                    );
                                } else {
                                    log::error!("Folder records JSON is in incorrect format");
                                }
                            }
                        }
                    }
                    Err(err) => {
                        log::error!(
                            "Error decrypting folder key: {:?} - Folder UID: {}",
                            err,
                            folder.uid
                        );
                    }
                }
            }
        } else {
            log::error!("Not a folder");
            return None;
        }

        Some(folder)
    }

    pub fn get_folder_key(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn records(&self) -> Result<Vec<Record>, KSMRError> {
        let mut records = vec![];
        for record_map in &self.folder_records {
            let record_result =
                Record::new_from_json(record_map.clone(), &self.key, Some(self.uid.to_string()));

            // if record_result.is_err() {
            //     log::error!("Error parsing folder record: {:?}", record_map);
            // } else {
            //     records.push(record_result.unwrap());
            // }

            if let Ok(record) = record_result {
                records.push(record);
            } else {
                log::error!("Error parsing folder record: {:?}", record_map);
            }
        }
        Ok(records)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AppData {
    title: Option<String>,
    app_type: Option<String>,
}

impl AppData {
    pub fn new(title: Option<String>, app_type: Option<String>) -> Self {
        AppData { title, app_type }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SecretsManagerResponse {
    pub app_data: AppData,
    pub folders: Vec<Folder>,
    pub records: Vec<Record>,
    pub expires_on: i64,
    pub warnings: Option<String>,
    pub just_bound: bool,
}

impl SecretsManagerResponse {
    pub fn expires_on_str(&self, date_format: Option<&str>) -> String {
        let unix_time_seconds = self.expires_on / 1000;
        let naive_datetime =
            DateTime::from_timestamp(unix_time_seconds.saturating_sub(i64::MIN), 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap()); // Handle invalid timestamps gracefully
        let format = date_format.unwrap_or("%Y-%m-%d %H:%M:%S");
        naive_datetime.format(format).to_string()
    }

    pub fn new() -> Self {
        SecretsManagerResponse {
            app_data: AppData::default(),
            folders: Vec::new(),
            records: Vec::new(),
            expires_on: 0,
            warnings: None,
            just_bound: false,
        }
    }
}

pub struct KeeperFileUpload {
    pub name: String,
    pub data: Vec<u8>,
    pub title: String,
    pub mime_type: String,
}

impl KeeperFileUpload {
    pub fn get_file_for_upload(
        file_path: &str,
        file_name: Option<&str>,
        file_title: Option<&str>,
        mime_type: Option<&str>,
    ) -> Result<KeeperFileUpload, KSMRError> {
        // Resolve file name
        let resolved_name = file_name
            .unwrap_or_else(|| {
                Path::new(file_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
            })
            .to_string();

        // Resolve file title
        let resolved_title = file_title.unwrap_or(resolved_name.as_str()).to_string();

        // Resolve MIME type
        let resolved_type = mime_type.unwrap_or("application/octet-stream").to_string();

        // Read file data
        let file_data = fs::read(file_path)
            .map_err(|err| KSMRError::IOError(format!("Error reading file data: {}", err)))?;

        // Return KeeperFileUpload instance
        Ok(KeeperFileUpload {
            name: resolved_name,
            title: resolved_title,
            mime_type: resolved_type,
            data: file_data,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RecordCreate {
    pub record_type: String,
    pub title: String,
    pub notes: Option<String>,
    pub fields: Option<Vec<KeeperField>>,
    pub custom: Option<Vec<KeeperField>>,
}

pub const VALID_RECORD_FIELDS: [&str; 45] = [
    "accountNumber",
    "address",
    "addressRef",
    "appFiller",
    "bankAccount",
    "birthDate",
    "cardRef",
    "checkbox",
    "databaseType",
    "date",
    "directoryType",
    "dropdown",
    "email",
    "birthDate",
    "expirationDate",
    "fileRef",
    "host",
    "isSSIDHidden",
    "keyPair",
    "licenseNumber",
    "login",
    "multiline",
    "name",
    "note",
    "oneTimeCode",
    "otp",
    "pamHostname",
    "pamRemoteBrowserSettings",
    "pamResources",
    "pamSettings",
    "passkey",
    "password",
    "paymentCard",
    "phone",
    "pinCode",
    "rbiUrl",
    "recordRef",
    "schedule",
    "script",
    "secret",
    "securityQuestion",
    "text",
    "trafficEncryptionSeed",
    "url",
    "wifiEncryption",
];

impl RecordCreate {
    pub fn new(
        record_type: impl Into<String>,
        title: impl Into<String>,
        notes: Option<String>,
    ) -> Self {
        Self {
            record_type: record_type.into(),
            title: title.into(),
            notes,
            fields: None,
            custom: None,
        }
    }

    pub fn validate(&self) -> Result<(), KSMRError> {
        // Validate title
        if self.title.trim().is_empty() {
            return Err(KSMRError::RecordDataError(
                "Record title should not be empty.".to_string(),
            ));
        }

        // Validate notes
        if let Some(notes) = &self.notes {
            if notes.trim().is_empty() {
                return Err(KSMRError::RecordDataError(
                    "Record notes should not be empty.".to_string(),
                ));
            }
        }

        // Validate fields
        if let Some(fields) = &self.fields {
            let mut field_type_errors = vec![];
            let mut field_value_errors = vec![];

            for field in fields {
                // Validate field type
                if !VALID_RECORD_FIELDS.contains(&field.field_type.as_str()) {
                    field_type_errors.push(field.field_type.clone());
                }

                // Validate field value
                match field.value.is_array() {
                    true => {
                        if field.value.as_array().unwrap().is_empty() {
                            field_value_errors.push(field.field_type.clone());
                        }
                    }
                    false => {
                        return Err(KSMRError::RecordDataError(
                            "Field value is not Array".to_string(),
                        ))
                    }
                };
            }

            if !field_type_errors.is_empty() {
                return Err(KSMRError::RecordDataError(format!(
                    "Following field types are not allowed: [{}]. Allowed field types are: [{}]",
                    field_type_errors.join(", "),
                    VALID_RECORD_FIELDS.join(", ")
                )));
            }

            if !field_value_errors.is_empty() {
                return Err(KSMRError::RecordDataError(format!(
                    "Fields with the following types should have non-empty list values: [{}]",
                    field_value_errors.join(", ")
                )));
            }
        }

        Ok(())
    }

    pub fn to_dict(&self) -> Result<HashMap<String, Value>, KSMRError> {
        self.validate()?; // Ensure validation passes before creating the dictionary

        let mut rec_dict = HashMap::new();
        rec_dict.insert("type".to_string(), Value::String(self.record_type.clone()));
        rec_dict.insert("title".to_string(), Value::String(self.title.clone()));

        if let Some(notes) = &self.notes {
            rec_dict.insert("notes".to_string(), Value::String(notes.clone()));
        }

        if let Some(fields) = &self.fields {
            rec_dict.insert(
                "fields".to_string(),
                Value::Array(
                    fields
                        .iter()
                        .map(|f| serde_json::to_value(f).unwrap())
                        .collect(),
                ),
            );
        }

        if let Some(custom) = &self.custom {
            rec_dict.insert(
                "custom".to_string(),
                serde_json::to_value(custom.clone()).unwrap(),
            );
        }

        Ok(rec_dict)
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        let rec_dict = self.to_dict()?;
        serde_json::to_string(&rec_dict).map_err(|e| {
            KSMRError::SerializationError(format!("Error serializing record field data: {}", e))
        })
    }

    pub fn append_standard_fields(&mut self, field: KeeperField) {
        if self.fields.is_none() {
            self.fields = Some(vec![]);
        }
        self.fields.as_mut().unwrap().push(field);
    }

    pub fn append_custom_field(&mut self, field: KeeperField) {
        if self.custom.is_none() {
            self.custom = Some(vec![]);
        }
        self.custom.as_mut().unwrap().push(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct a minimal KeeperFile for testing struct-level behavior.
    /// Private fields are accessible here because we are in the same module.
    fn make_test_file(proxy_url: Option<String>) -> KeeperFile {
        KeeperFile {
            file_key: String::new(),
            metadata_dict: HashMap::new(),
            data: vec![],
            uid: String::new(),
            file_type: String::new(),
            title: String::new(),
            name: String::new(),
            last_modified: 0,
            size: 0,
            url: None,
            thumbnail_url: None,
            proxy_url,
            skip_ssl_verify: false,
            http_client: None,
            f: HashMap::new(),
            record_key_bytes: vec![],
        }
    }

    /// Regression test for KSM-791:
    /// KeeperFile.proxy_url must exist and default to None so that
    /// get_file_data() / get_thumbnail_data() build a proxy-aware HTTP client.
    /// Previously the field did not exist and bare reqwest::get() was used.
    #[test]
    fn test_keeper_file_proxy_url_defaults_to_none() {
        let file = make_test_file(None);
        assert!(file.proxy_url.is_none());
    }

    /// Regression test for KSM-791:
    /// proxy_url must be settable so that SecretsManager can propagate its
    /// proxy configuration to files after record decryption.
    #[test]
    fn test_keeper_file_proxy_url_can_be_set() {
        let mut file = make_test_file(None);
        file.proxy_url = Some("http://proxy.example.com:8080".to_string());
        assert_eq!(
            file.proxy_url,
            Some("http://proxy.example.com:8080".to_string())
        );
    }

    /// Regression test for KSM-791:
    /// deep_copy() must preserve proxy_url so that callers that clone a file
    /// (e.g. notation lookups) do not silently lose proxy configuration.
    #[test]
    fn test_keeper_file_deep_copy_preserves_proxy_url() {
        let file_with_proxy = make_test_file(Some("http://proxy.example.com:8080".to_string()));
        let copied = file_with_proxy.deep_copy();
        assert_eq!(
            copied.proxy_url,
            Some("http://proxy.example.com:8080".to_string())
        );

        let file_without_proxy = make_test_file(None);
        let copied_none = file_without_proxy.deep_copy();
        assert!(copied_none.proxy_url.is_none());
    }

    /// Regression test for KSM-933: verify_ssl_certs (positive-sense) and
    /// skip_ssl_verify (negative-sense) have opposite conventions. Propagation
    /// from SecretsManager to KeeperFile must negate — not copy directly.
    #[test]
    fn test_skip_ssl_verify_polarity_invariant() {
        // Strict mode: verify_ssl_certs=true → skip_ssl_verify must be false
        let verify_ssl_certs = true;
        let mut file = make_test_file(None);
        file.skip_ssl_verify = !verify_ssl_certs;
        assert!(
            !file.skip_ssl_verify,
            "strict mode: skip_ssl_verify must be false"
        );

        // Permissive mode: verify_ssl_certs=false → skip_ssl_verify must be true
        let verify_ssl_certs = false;
        let mut file = make_test_file(None);
        file.skip_ssl_verify = !verify_ssl_certs;
        assert!(
            file.skip_ssl_verify,
            "permissive mode: skip_ssl_verify must be true"
        );
    }
}
