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
use log::{error, info};
use reqwest::blocking::get;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt::{self},
    fs::{self, File},
    io::{Read, Write as _},
    path::{Path, PathBuf},
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
                            let msg = format!("Error loading file: {}", e);
                            eprintln!("{}", msg);
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
                            let msg = format!("Error loading file: {}", e);
                            eprintln!("{}", msg);
                        }
                    }
                }
            }
            record.files = _files;
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
                let file_status = file.save_file(path.to_string(), false)?;
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
                let file_status = file.save_file(path.to_string(), false)?;
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
            f: self.f.clone(),
            record_key_bytes: self.record_key_bytes.clone(),
        }
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

        // Fetch the file data from the URL
        let mut response = get(&file_url)
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

        // Fetch the thumbnail data from the URL
        let mut response = get(&thumbnail_url)
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

    pub fn save_file(&mut self, path: String, create_folders: bool) -> Result<bool, KSMRError> {
        // Resolve the absolute path
        let abs_path = match fs::canonicalize(&path) {
            Ok(p) => p,
            Err(_) => PathBuf::from(&path), // Fallback to given path if canonicalization fails
        };

        // Get the parent directory
        let dir_path = abs_path.parent().ok_or_else(|| {
            KSMRError::PathError(format!(
                "Failed to determine parent directory for path: {}",
                path
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
            Value::String(hex::encode(self.folder_key.clone())),
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
    pub fn new(record_type: String, title: String, notes: Option<String>) -> Self {
        Self {
            record_type,
            title,
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
