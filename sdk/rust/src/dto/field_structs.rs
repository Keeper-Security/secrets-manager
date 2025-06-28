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

use std::{collections::HashMap, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Error;
use serde_json::Value;

use crate::{
    custom_error::KSMRError,
    enums::Country,
    enums::StandardFieldTypeEnum,
    utils::{self, PasswordOptions},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeeperField {
    #[serde(rename(serialize = "type", deserialize = "field_type"))]
    pub field_type: String,
    #[serde(default = "default_empty_string")]
    pub label: String,
    #[serde(default = "default_value")]
    pub value: Value,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default = "default_boolean")]
    pub privacy_screen: bool,
}

impl KeeperField {
    pub fn new(field_type: String, label: Option<String>) -> Self {
        KeeperField {
            field_type,
            label: label.unwrap_or("".to_string()),
            value: Value::Null,
            required: false,
            privacy_screen: false,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        match key {
            "field_type" => Some(&self.field_type),
            "label" => Some(&self.label),
            _ => None,
        }
    }
}

fn default_boolean() -> bool {
    false
}

pub fn default_value() -> Value {
    Value::Null
}

fn default_empty_vector<T>() -> Vec<T> {
    vec![]
}

fn default_empty_string() -> String {
    "".to_string()
}

fn default_empty_number() -> u8 {
    0
}

fn default_empty_number_i32() -> i32 {
    0
}

fn default_empty_number_i64() -> i64 {
    0
}

fn default_empty_vector_value() -> Value {
    Value::Array(vec![])
}

pub fn default_empty_option_string() -> Option<String> {
    Some("".to_string())
}

pub fn string_to_value_array(val: String) -> Value {
    Value::Array(vec![Value::String(val)])
}

pub fn number_value_to_value_array(val: Value) -> Value {
    Value::Array(vec![val])
}

pub fn string_to_value(val: String) -> Value {
    Value::String(val)
}

pub fn value_to_value_array(val: Value) -> Value {
    Value::Array(vec![val])
}

fn _extract_to_option_value(opt: ValueType) -> Option<Vec<Value>> {
    match opt {
        ValueType::VecValue(vec) => vec,
        ValueType::StringValue(str) => Some(vec![serde_json::Value::String(str)]),
    }
}

pub enum ValueType {
    VecValue(Option<Vec<Value>>),
    StringValue(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Login {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let login_field_entry = field_structs::Login::new("dummy_Email@email.com".to_string(),Some("dummy_login_label".to_string()),None,None);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(login_field_entry);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_empty_vector_value")]
    value: Value,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
}

impl Login {
    pub fn new_login(value: String) -> KeeperField {
        let value_parsed = value;
        Login::new(value_parsed, None, None, None)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: Option<bool>,
        privacy_screen: Option<bool>,
    ) -> KeeperField {
        let login_value = Value::Array(vec![Value::String(value)]);
        KeeperField {
            field_type: StandardFieldTypeEnum::LOGIN.get_type().to_string(),
            label: label.unwrap_or(StandardFieldTypeEnum::LOGIN.get_type().to_string()),
            value: login_value,
            required: required.unwrap_or(false),
            privacy_screen: privacy_screen.unwrap_or(false),
        }
    }

    pub fn as_keeper_field(&self) -> KeeperField {
        self.keeper_fields.clone()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordComplexity {
    #[serde(default = "default_empty_number")]
    pub length: u8,
    #[serde(default = "default_empty_number")]
    pub caps: u8,
    #[serde(default = "default_empty_number")]
    pub lower: u8,
    #[serde(default = "default_empty_number")]
    pub digits: u8,
    #[serde(default = "default_empty_number")]
    pub special: u8,
}

impl PasswordComplexity {
    pub fn new(
        length: Option<u8>,
        caps: Option<u8>,
        lower: Option<u8>,
        digits: Option<u8>,
        special: Option<u8>,
    ) -> Self {
        PasswordComplexity {
            length: length.unwrap_or(32),
            caps: caps.unwrap_or(0),
            lower: lower.unwrap_or(0),
            digits: digits.unwrap_or(0),
            special: special.unwrap_or(0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let password_field_entry = field_structs::Password::new("".to_string(),Some("dummy_password_label".to_string()),None,Some(true),None,None)?;
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(password_field_entry);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_empty_vector_value")]
    value: Value,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    enforce_generation: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    complexity: Option<PasswordComplexity>,
}

impl Password {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: Option<bool>,
        enforce_generation: Option<bool>,
        privacy_screen: Option<bool>,
        password_complexity: Option<PasswordComplexity>,
    ) -> Result<KeeperField, KSMRError> {
        let password_value;
        if value.is_empty() {
            let enforce_generation_value = enforce_generation.unwrap_or_default();
            if enforce_generation_value {
                let pass_complexity = match password_complexity {
                    Some(password_complexity) => password_complexity,
                    None => PasswordComplexity::new(None, None, None, None, None),
                };
                let password_options = PasswordOptions::new()
                    .digits(pass_complexity.digits.into())
                    .length(pass_complexity.length.into())
                    .lowercase(pass_complexity.lower.into())
                    .uppercase(pass_complexity.caps.into())
                    .special_characters(pass_complexity.special.into());
                let generated_password_value = utils::generate_password(password_options)?;
                password_value = Value::Array(vec![Value::String(generated_password_value)]);
            } else {
                return Err(KSMRError::RecordDataError("Password value is empty and enforce generation is false, please make one or other a true value".to_string()));
            }
        } else {
            password_value = Value::Array(vec![Value::String(value)]);
        }

        let mut keeper_field = KeeperField::new("password".to_string(), label);
        keeper_field.value = password_value;
        keeper_field.required = required.unwrap_or(false);
        keeper_field.privacy_screen = privacy_screen.unwrap_or(false);

        Ok(keeper_field)
    }

    pub fn new_password(value: String) -> Result<KeeperField, KSMRError> {
        Password::new(value, None, None, None, None, None)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct URL {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let url_field =  field_structs::URL::new("dummy_url.com".to_string(), None, None, None);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(url_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_empty_vector_value")]
    value: Value,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
}

impl URL {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: Option<bool>,
        privacy_screen: Option<bool>,
    ) -> KeeperField {
        let url_value = string_to_value_array(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::URL.get_type().to_string(), label);
        keeper_field.value = url_value;
        keeper_field.required = required.unwrap_or(false);
        keeper_field.privacy_screen = privacy_screen.unwrap_or(false);

        keeper_field
    }

    pub fn new_url(value: String) -> KeeperField {
        URL::new(value, None, None, None)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileRef {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let file_ref_field = field_structs::FileRef::new("file::/files.file.co".to_string(), None, None);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(file_ref_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_empty_vector")]
    pub value: Vec<Value>,
    #[serde(default = "default_boolean")]
    required: bool,
}

impl FileRef {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(value: String, label: Option<String>, required: Option<bool>) -> KeeperField {
        let file_ref_value = string_to_value_array(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::FILEREF.get_type().to_string(), label);
        keeper_field.value = file_ref_value;
        keeper_field.required = required.unwrap_or(false);

        keeper_field
    }

    pub fn new_file_ref(value: String) -> KeeperField {
        FileRef::new(value, None, None)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OneTimePassword {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    #[serde(default = "default_empty_vector")]
    value: Vec<Value>,
}

impl OneTimePassword {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: Option<bool>,
        privacy_screen: Option<bool>,
    ) -> KeeperField {
        let otp_value = string_to_value_array(value);
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::ONETIMECODE.get_type().to_string(),
            label,
        );
        keeper_field.value = otp_value;
        keeper_field.required = required.unwrap_or(false);
        keeper_field.privacy_screen = privacy_screen.unwrap_or(true);
        keeper_field
    }

    pub fn new_otp(value: String) -> KeeperField {
        OneTimePassword::new(value, None, None, None)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    middle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last: Option<String>,
}

impl Name {
    pub fn new(first: Option<String>, middle: Option<String>, last: Option<String>) -> Self {
        Name {
            first,
            middle,
            last,
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Names {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<Name>,
}

impl Names {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let name: Name =field_structs::Name::new(Some("Sample".to_string()), None, Some("User".to_string()));
    ///     let names: Vec<Name> = vec![name];
    ///     let names_field: KeeperField = field_structs::Names::new(names, None, false, false);
    ///     login_new.append_standard_fields(names_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<Name>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::NAMES.get_type().to_string(), label);
        keeper_field.value = Names::vec_name_to_names_string(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    fn vec_name_to_names_string(mut value: Vec<Name>) -> Value {
        let names_string: Vec<Value> = value
            .iter_mut()
            .map(|name: &mut Name| name.to_json().unwrap())
            .map(|name: String| {
                Value::from_str(name.as_str())
                    .map_err(|err: Error| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        let names_string_value_array: Value = Value::Array(names_string);
        names_string_value_array
    }

    pub fn new_names(value: Vec<Name>) -> KeeperField {
        Names::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Date {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<i64>,
}

impl Date {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value_in_date_milliseconds: u128,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let date_value = number_value_to_value_array(Value::Number(
            serde_json::Number::from_u128(value_in_date_milliseconds).unwrap(),
        ));

        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::NAMES.get_type().to_string(), label);
        keeper_field.value = date_value;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_date(value: u128) -> KeeperField {
        Date::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BirthDate {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<i64>,
}

impl BirthDate {
    ///```ignore
    ///     let mut birth_certificate = RecordCreate::new(DefaultRecordType::birthCertificate.get_type().to_string(), "birth_certificate".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let name = field_structs::Name::new(Some("first_name".to_string()), None, Some("last name".to_string()));
    ///     let names = vec![name];
    ///     let names_field = field_structs::Names::new(names, Some("some_label".to_string()), false, false);
    ///     let now = SystemTime::now();
    /// // Calculate milliseconds since UNIX epoch
    ///     let millis = now
    ///         .duration_since(UNIX_EPOCH)
    ///         .expect("Time went backwards")
    ///         .as_millis();
    ///     let date_field = field_structs::BirthDate::new_birth_date(millis);
    ///     birth_certificate.append_standard_fields(date_field);
    ///     birth_certificate.append_standard_fields(names_field);
    ///     let created_record: Result<String, KSMRError> = secrets_manager.create_secret("0fLf6oIA9KY8V4BIbWz0kA".to_string(), birth_certificate);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: u128,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field_date = Date::new(value, label, required, privacy_screen);
        keeper_field_date.field_type = StandardFieldTypeEnum::BIRTHDATE.get_type().to_string();
        keeper_field_date
    }

    pub fn new_birth_date(value: u128) -> KeeperField {
        BirthDate::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExpirationDate {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<u128>,
}

impl ExpirationDate {
    ///```ignore
    ///     let mut birth_certificate = RecordCreate::new(DefaultRecordType::birthCertificate.get_type().to_string(), "birth_certificate".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let name = field_structs::Name::new(Some("first_name".to_string()), None, Some("last name".to_string()));
    ///     let names = vec![name];
    ///     let names_field = field_structs::Names::new(names, Some("some_label".to_string()), false, false);
    ///     let now = SystemTime::now();
    /// // Calculate milliseconds since UNIX epoch
    ///     let millis = now
    ///         .duration_since(UNIX_EPOCH)
    ///         .expect("Time went backwards")
    ///         .as_millis();
    ///     let date_field = field_structs::ExpirationDate::new_birth_date(millis);
    ///     birth_certificate.append_standard_fields(date_field);
    ///     birth_certificate.append_standard_fields(names_field);
    ///     let created_record: Result<String, KSMRError> = secrets_manager.create_secret("0fLf6oIA9KY8V4BIbWz0kA".to_string(), birth_certificate);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: u128,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = Date::new(value, label, required, privacy_screen);
        keeper_field.field_type = StandardFieldTypeEnum::EXPIRATIONDATE.get_type().to_string();
        keeper_field
    }

    pub fn new_expiration_date(value: u128) -> KeeperField {
        ExpirationDate::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Text {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl Text {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let text_field =  field_structs::Text::new("dummy_text".to_string(), None, false, false);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(text_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let text_value = string_to_value_array(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::TEXT.get_type().to_string(), label);
        keeper_field.value = text_value;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;

        keeper_field
    }

    pub fn new_text(value: String) -> KeeperField {
        Text::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityQuestion {
    question: String,
    answer: String,
}

impl SecurityQuestion {
    pub fn new(question: String, answer: String) -> Self {
        SecurityQuestion { question, answer }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityQuestions {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<SecurityQuestion>,
}

impl SecurityQuestions {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<SecurityQuestion>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::SECURITYQUESTIONS
                .get_type()
                .to_string(),
            label,
        );
        keeper_field.value =
            SecurityQuestions::vec_security_question_to_security_questions_string(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    fn vec_security_question_to_security_questions_string(
        mut value: Vec<SecurityQuestion>,
    ) -> Value {
        let security_questios_string: Vec<Value> = value
            .iter_mut()
            .map(|security_question| security_question.to_json().unwrap())
            .map(|security_question| {
                Value::from_str(security_question.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(security_questios_string)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Multiline {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl Multiline {
    /// ```ignore
    ///     let mut new_record = RecordCreate::new(DefaultRecordType::Login.get_type().to_string(), "sample record".to_string(), None);
    ///     let multiline_field = field_structs::Multiline::new("Hello\nWorld".to_string(), None, true, false);
    ///     new_record.append_custom_field(multiline_field);
    ///     let created_record: Result<String, KSMRError> = secrets_manager.create_secret("Yi_OxwTV2tdBWi-_Aegs_w".to_string(), new_record);
    ///
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::MULTILINE.get_type().to_string(),
            label,
        );
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field.value = string_to_value_array(value);
        keeper_field
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Email {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl Email {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let text_field =  field_structs::Text::new("dummy_text".to_string(), None, false, false);
    ///     let email_field = field_structs::Email::new("sample_email@metron.com".to_string(), None, false, false);
    ///     login_new.append_standard_fields(email_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::EMAIL.get_type().to_string(), label);
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_email(value: String) -> KeeperField {
        Email::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CardRef {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl CardRef {
    pub fn new(value: String, label: Option<String>, required: bool, privacy_screen: bool) -> Self {
        CardRef {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::CARDREF.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
            privacy_screen,
        }
    }

    pub fn new_card_ref(value: String) -> Self {
        CardRef::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressRef {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl AddressRef {
    /// ```ignore
    /// let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    /// let mut address_new = RecordCreate::new("address".to_string(), "sampleaddress1".to_string(), Some("dummy_notes_changed".to_string()));
    /// let address1 = field_structs::Address::new(Some("street1".to_string()), Some("street2".to_string()), Some("city".to_string()), Some("state".to_string()), "IN".to_string(), None)?;
    /// let addresses= field_structs::Addresses::new_addresses(address1);
    /// address_new.append_standard_fields(addresses);
    /// let created_address = secrets_manager.create_secret("0fLf6oIA9KY8V4BIbWz0kA".to_string(), address_new)?;
    /// let address_ref_field = field_structs::AddressRef::new_address_ref(created_address);
    /// login_new.append_custom_field(address_ref_field);
    /// let created_record: Result<String, KSMRError> = secrets_manager.create_secret("parent_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let address_ref_value = string_to_value_array(value);
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::ADDRESSREF.get_type().to_string(),
            label,
        );
        keeper_field.value = address_ref_value;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;

        keeper_field
    }

    pub fn new_address_ref(value: String) -> KeeperField {
        AddressRef::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PinCode {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl PinCode {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let pincode_field = field_structs::PinCode::new("233556".to_string(), Some("PINCODE_DUMMY_LABEL".to_string()), false, false);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(pincode_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let pincode_value = string_to_value_array(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::PINCODE.get_type().to_string(), label);
        keeper_field.value = pincode_value;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_pin_code(value: String) -> KeeperField {
        PinCode::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PhoneTypeOption {
    Mobile,
    Home,
    Work,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Phone {
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>, // Region code, e.g., US
    number: String, // Phone number, e.g., 510-222-5555
    #[serde(skip_serializing_if = "Option::is_none")]
    ext: Option<String>, // Extension number, e.g., 9987
    #[serde(rename(serialize = "type", deserialize = "field_type"))]
    phone_type: Option<PhoneTypeOption>, // Phone type, e.g., Mobile
}

impl Phone {
    pub fn new(
        number: String,
        region: Option<String>,
        ext: Option<String>,
        phone_type: Option<PhoneTypeOption>,
    ) -> Self {
        let phone_type_parsed = match phone_type {
            Some(PhoneTypeOption::Mobile) => Some(PhoneTypeOption::Mobile),
            Some(PhoneTypeOption::Home) => Some(PhoneTypeOption::Home),
            Some(PhoneTypeOption::Work) => Some(PhoneTypeOption::Work),
            None => Some(PhoneTypeOption::Home),
        };
        Phone {
            region,
            number,
            ext,
            phone_type: phone_type_parsed,
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Phones {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<Phone>,
}

impl Phones {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let phone1 = field_structs::Phone::new("1234567890".to_string(), None, None, None);
    ///     let phone2 = field_structs::Phone::new("1234567891".to_string(), Some("US".to_string()), None, None);
    ///     let phone3 = field_structs::Phone::new("1234567892".to_string(), None, Some("1".to_string()), None);
    ///     let phones = vec![phone1, phone2, phone3];
    ///     let phones_field = field_structs::Phones::new_phones(phones);
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     login_new.append_standard_fields(phones_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<Phone>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let phones_field = Phones::vec_phone_to_phones_string(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::PHONES.get_type().to_string(), label);
        keeper_field.value = phones_field;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    fn vec_phone_to_phones_string(mut value: Vec<Phone>) -> Value {
        let phones_string = value
            .iter_mut()
            .map(|phone| phone.to_json().unwrap())
            .map(|phone| {
                Value::from_str(phone.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(phones_string)
    }

    pub fn new_phones(value: Vec<Phone>) -> KeeperField {
        Phones::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Secret {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl Secret {
    ///```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let secret = field_structs::Secret::new("Dummy secret".to_string(), Some("secret".to_string()), true, false);
    ///     login_new.append_custom_field(secret);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::SECRET.get_type().to_string(), label);
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_secret(value: String) -> KeeperField {
        Secret::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecureNote {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl SecureNote {
    /// ```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let mut login_new = RecordCreate::new("login".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let secret_note = field_structs::SecureNote::new("This is a sample note".to_string(), None, true, false);
    ///     login_new.append_standard_fields(secret_note);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::SECURENOTE.get_type().to_string(),
            label,
        );
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_secure_note(value: String) -> KeeperField {
        SecureNote::new(value, None, false, false)
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Note {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl Note {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(value: String, required: bool, privacy_screen: bool) -> KeeperField {
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::NOTE.get_type().to_string(), None);
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountNumber {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    value: String,
}

impl AccountNumber {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(value: String) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::ACCOUNTNUMBER.get_type().to_string(),
            None,
        );
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = true;
        keeper_field.privacy_screen = false;
        keeper_field
    }

    pub fn new_account_number(value: String) -> KeeperField {
        AccountNumber::new(value)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCard {
    #[serde(skip_serializing_if = "Option::is_none")]
    card_number: Option<String>, // Card number
    #[serde(skip_serializing_if = "Option::is_none")]
    card_expiration_date: Option<String>, // Expiration date
    #[serde(skip_serializing_if = "Option::is_none")]
    card_security_code: Option<String>, // Security code
}

impl PaymentCard {
    /// card_expiration_date should be in format of MM/YYYY else it wont reflect correctly in your record.
    pub fn new(
        card_number: Option<String>,
        card_expiration_date: Option<String>,
        card_security_code: Option<String>,
    ) -> Self {
        PaymentCard {
            card_number,
            card_expiration_date,
            card_security_code,
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PaymentCards {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<PaymentCard>,
}

impl PaymentCards {
    /// Note that only one address can be given for a record of address type and if you want more than one address, then you have to give it as addressRef field
    /// ```ignore
    ///     let mut bank_card_record = RecordCreate::new(DefaultRecordType::BankCard.get_type().to_string(), "samplebankcard1".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let payment_card = field_structs::PaymentCard::new(Some("8878881234211432".to_string()), Some("".to_string()), Some("1244".to_string()));
    ///     let payment_cards = field_structs::PaymentCards::new_payment_cards(payment_card);
    ///     bank_card_record.append_standard_fields(payment_cards);
    ///     let created_record = secrets_manager.create_secret("<some_folder_uid>".to_string(), bank_card_record);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: PaymentCard,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let value_string = Value::from_str(value.to_json().unwrap().as_str()).unwrap();
        let cards_field = value_to_value_array(value_string);
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::PAYMENTCARDS.get_type().to_string(),
            label,
        );
        keeper_field.value = cards_field;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    pub fn new_payment_cards(value: PaymentCard) -> KeeperField {
        PaymentCards::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum AccountType {
    Savings,
    Checking,
    Other,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BankAccount {
    account_type: AccountType,  // Account type (e.g., Checking, Savings)
    routing_number: String,     // Routing number
    account_number: String,     // Account number
    other_type: Option<String>, // Other account type
}

impl BankAccount {
    ///let bank_account_field = field_structs::BankAccount::new(AccountType::Savings, "1122334455".to_string(), "33445566778".to_string(), None, Some("Account Field Label".to_string()));
    /// let mut bank_account_record = RecordCreate::new(DefaultRecordType::BankAccounts.get_type().to_string(), "Bank Account Reference".to_string(), Some("sum notes".to_string()));
    /// bank_account_record.append_standard_fields(bank_account_field);
    /// let created_record = secrets_manager.create_secret("folder_uid".to_string(), bank_account_record);
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        account_type: AccountType,
        routing_number: String,
        account_number: String,
        other_type: Option<String>,
        label: Option<String>,
    ) -> KeeperField {
        let oth_type = match account_type == AccountType::Other {
            true => Some(
                other_type
                    .unwrap_or_else(|| "Other".to_string())
                    .to_string(),
            ),
            false => None,
        };
        let bank_account = BankAccount {
            account_type,
            routing_number,
            account_number,
            other_type: oth_type,
        };

        // Serialize the BankAccount into a JSON string
        let account_json = Value::from_str(bank_account.to_json().unwrap().as_str()).unwrap();

        // Convert the JSON string into a value array (assumes implementation of `string_to_value_array`)
        let account_value = value_to_value_array(account_json);
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::BANKACCOUNT.get_type().to_string(),
            label,
        );
        keeper_field.value = account_value;
        keeper_field.required = false;
        keeper_field.privacy_screen = false;
        keeper_field
    }

    fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BankAccounts {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<BankAccount>,
}

impl BankAccounts {
    pub fn new(
        value: BankAccount,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> Self {
        BankAccounts {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::BANKACCOUNT.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
            privacy_screen,
        }
    }

    pub fn new_bank_accounts(value: BankAccount) -> Self {
        BankAccounts::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    public_key: Option<String>,  // Public key
    private_key: Option<String>, // Private key
}

impl KeyPair {
    pub fn new(public_key: Option<String>, private_key: Option<String>) -> Self {
        KeyPair {
            public_key,
            private_key,
        }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPairs {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<KeyPair>,
}

impl KeyPairs {
    ///```ignore
    ///     let mut new_record = RecordCreate::new(DefaultRecordType::SSHKeys.get_type().to_string(), "sample ssh key 1".to_string(), None);
    ///     let key_pair = field_structs::KeyPair::new(Some("jkaghdsjabd354afzdc".to_string()), Some("jgFdjavbf34f6f".to_string()));
    ///     let key_pair_array = vec![key_pair];
    ///     let key_pairs_field = field_structs::KeyPairs::new(key_pair_array, None, true, false);
    ///     new_record.append_standard_fields(key_pairs_field);
    ///     let created_record: Result<String, KSMRError> = secrets_manager.create_secret("Yi_OxwTV2tdBWi-_Aegs_w".to_string(), new_record);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<KeyPair>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::KEYPAIRS.get_type().to_string(),
            label,
        );
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field.value = KeyPairs::vec_key_pair_to_key_pairs_string(value);
        keeper_field
    }

    fn vec_key_pair_to_key_pairs_string(mut value: Vec<KeyPair>) -> Value {
        let key_pairs_string: Vec<Value> = value
            .iter_mut()
            .map(|key_pair| key_pair.to_json().unwrap())
            .map(|key_pair| {
                Value::from_str(key_pair.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(key_pairs_string)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    host_name: Option<String>, // Hostname
    port: Option<String>,      // Port number
}

impl Host {
    pub fn new(host_name: Option<String>, port: Option<String>) -> Self {
        Host { host_name, port }
    }

    pub fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hosts {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<Host>,
}

impl Hosts {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(value: Vec<Host>) -> KeeperField {
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::HOSTS.get_type().to_string(), None);
        keeper_field.value = Hosts::vec_host_to_hosts_string(value);
        keeper_field
    }

    fn vec_host_to_hosts_string(mut value: Vec<Host>) -> Value {
        let hosts_string: Vec<Value> = value
            .iter_mut()
            .map(|host| host.to_json().unwrap())
            .map(|host| {
                Value::from_str(host.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(hosts_string)
    }

    pub fn new_hosts(value: Vec<Host>) -> KeeperField {
        Hosts::new(value)
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Address {
    #[serde(default = "default_empty_option_string")]
    street1: Option<String>, // Street 1
    #[serde(default = "default_empty_option_string")]
    street2: Option<String>, // Street 2
    #[serde(default = "default_empty_option_string")]
    city: Option<String>, // City
    #[serde(default = "default_empty_option_string")]
    state: Option<String>, // State
    country: String, // Country
    #[serde(default = "default_empty_option_string")]
    zip: Option<String>, // Zip code
}

impl Address {
    pub fn new(
        street1: Option<String>,
        street2: Option<String>,
        city: Option<String>,
        state: Option<String>,
        country: String,
        zip: Option<String>,
    ) -> Result<Self, KSMRError> {
        let country_parsed: Country =
            match Country::from_string(&country) {
                Some(country) => country,
                None => return Err(KSMRError::RecordDataError(
                    "Country is a mandatory field for address dn country has to be a valid field"
                        .to_string(),
                )),
            };
        Ok(Address {
            street1,
            street2,
            city,
            state,
            country: country_parsed.to_string(),
            zip,
        })
    }

    fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Addresses {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Value,
}

impl Addresses {
    ///```ignore
    ///     use keeper_secrets_manager_core::dto::field_structs;
    ///     let mut login_new = RecordCreate::new("address".to_string(), "custom_login_new_login_create".to_string(), Some("dummy_notes_changed".to_string()));
    ///     let address: Address = field_structs::Address::new(Some("ABC".to_string()), Some("PQR".to_string()), Some("Pune".to_string()), Some("Maharashtra".to_string()), Some("baHrAin".to_string()), Some("411018".to_string()));
    ///     let addresses: Vec<Address> = vec![address];
    ///     let address_field: KeeperField = field_structs::Addresses::new(addresses, None, false, false);
    ///     login_new.append_custom_field(address_field);
    ///     let created_record :Result<String, KSMRError> = secrets_manager.create_secret("some_folder_uid".to_string(), login_new);
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<Address>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let addresses_value = Addresses::vec_address_to_addresses_string(value);
        let mut keeper_field =
            KeeperField::new(StandardFieldTypeEnum::ADDRESS.get_type().to_string(), label);
        keeper_field.value = addresses_value;
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }

    fn vec_address_to_addresses_string(mut value: Vec<Address>) -> Value {
        let addresses_string: Vec<Value> = value
            .iter_mut()
            .map(|address| address.to_json().unwrap())
            .map(|address| {
                Value::from_str(address.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(addresses_string)
    }

    pub fn new_addresses(value: Vec<Address>) -> KeeperField {
        Addresses::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LicenseNumber {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<String>,
}

impl LicenseNumber {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: String,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::LICENSENUMBER.get_type().to_string(),
            label,
        );
        keeper_field.value = string_to_value_array(value);
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RecordRef {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<String>,
}

impl RecordRef {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        RecordRef {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::RECORDREF.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
        }
    }

    pub fn new_record_ref(value: String) -> Self {
        RecordRef::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Schedule {
    #[serde(default = "default_empty_string")]
    schedule_type: String,
    #[serde(default = "default_empty_string")]
    cron: String,
    #[serde(default = "default_empty_string")]
    time: String,
    #[serde(default = "default_empty_string")]
    tz: String,
    #[serde(default = "default_empty_string")]
    weekday: String,
    #[serde(default = "default_empty_number_i32")]
    interval_count: i32,
}

impl Schedule {
    pub fn new(
        schedule_type: String,
        cron: String,
        time: String,
        tz: String,
        weekday: String,
        interval_count: i32,
    ) -> Self {
        Schedule {
            schedule_type,
            cron,
            time,
            tz,
            weekday,
            interval_count,
        }
    }

    pub fn new_schedule(schedule_type: String) -> Self {
        Schedule::new(
            schedule_type,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            0,
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Schedules {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<Schedule>,
}

impl Schedules {
    pub fn new(value: Schedule, label: Option<String>, required: bool) -> Self {
        Schedules {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::SCHEDULES.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
        }
    }

    pub fn new_schedules(value: Schedule) -> Self {
        Schedules::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryType {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<String>,
}

impl DirectoryType {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        DirectoryType {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::DIRECTORYTYPE.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
        }
    }

    pub fn new_directory_type(value: String) -> Self {
        DirectoryType::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseType {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<String>,
}

impl DatabaseType {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        DatabaseType {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::DATABASETYPE.get_type().to_string(),
                label,
            ),
            value: vec![value],
            required,
        }
    }

    pub fn new_database_type(value: String) -> Self {
        DatabaseType::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamHostname {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<Host>,
}

impl PamHostname {
    pub fn new(value: Host, label: Option<String>, required: bool, privacy_screen: bool) -> Self {
        PamHostname {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::PAMHOSTNAME.get_type().to_string(),
                label,
            ),
            required,
            privacy_screen,
            value: vec![value],
        }
    }

    pub fn new_pam_hostname(value: Host) -> Self {
        PamHostname::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AllowedSettings {
    #[serde(default = "default_boolean")]
    connections: bool,
    #[serde(default = "default_boolean")]
    port_forwards: bool,
    #[serde(default = "default_boolean")]
    rotation: bool,
    #[serde(default = "default_boolean")]
    session_recording: bool,
    #[serde(default = "default_boolean")]
    typescript_recording: bool,
}

impl AllowedSettings {
    pub fn new(
        connections: bool,
        port_forwards: bool,
        rotation: bool,
        session_recording: bool,
        typescript_recording: bool,
    ) -> Self {
        AllowedSettings {
            connections,
            port_forwards,
            rotation,
            session_recording,
            typescript_recording,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamResource {
    #[serde(default = "default_empty_string")]
    controller_uid: String,
    #[serde(default = "default_empty_string")]
    folder_uid: String,
    resource_ref: Vec<String>,
    allowed_settings: AllowedSettings,
}

impl PamResource {
    pub fn new(
        controller_uid: String,
        folder_uid: String,
        resource_ref: Vec<String>,
        allowed_settings: AllowedSettings,
    ) -> Self {
        PamResource {
            controller_uid,
            folder_uid,
            resource_ref,
            allowed_settings,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamResources {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<PamResource>,
}

impl PamResources {
    pub fn new(value: PamResource, label: Option<String>, required: bool) -> Self {
        PamResources {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::PAMRESOURCES.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_pam_resources(value: PamResource) -> Self {
        PamResources::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Checkbox {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<bool>,
}

impl Checkbox {
    pub fn new(value: bool, label: Option<String>, required: bool) -> Self {
        Checkbox {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::CHECKBOX.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_checkbox(value: bool) -> Self {
        Checkbox::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Script {
    #[serde(default = "default_empty_string")]
    file_ref: String,
    #[serde(default = "default_empty_string")]
    command: String,
    record_ref: Vec<String>,
}

impl Script {
    pub fn new(file_ref: String, command: String, record_ref: Vec<String>) -> Self {
        Script {
            file_ref,
            command,
            record_ref,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Scripts {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    #[serde(default = "default_boolean")]
    privacy_screen: bool,
    value: Vec<Script>,
}

impl Scripts {
    pub fn new(value: Script, label: Option<String>, required: bool, privacy_screen: bool) -> Self {
        Scripts {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::SCRIPTS.get_type().to_string(),
                label,
            ),
            required,
            privacy_screen,
            value: vec![value],
        }
    }

    pub fn new_scripts(value: Script) -> Self {
        Scripts::new(value, None, false, false)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PasskeyPrivateKey {
    #[serde(default = "default_empty_string")]
    crv: String,
    #[serde(default = "default_empty_string")]
    d: String,
    #[serde(default = "default_boolean")]
    ext: bool,
    #[serde(default)]
    key_ops: Vec<String>,
    #[serde(default = "default_empty_string")]
    kty: String,
    #[serde(default = "default_empty_string")]
    x: String,
    #[serde(default = "default_empty_number_i64")]
    y: i64,
}

impl PasskeyPrivateKey {
    pub fn new(
        crv: String,
        d: String,
        ext: bool,
        key_ops: Vec<String>,
        kty: String,
        x: String,
        y: i64,
    ) -> Self {
        PasskeyPrivateKey {
            crv,
            d,
            ext,
            key_ops,
            kty,
            x,
            y,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Passkey {
    #[serde(default)]
    private_key: PasskeyPrivateKey,
    #[serde(default = "default_empty_string")]
    credential_id: String,
    #[serde(default = "default_empty_number_i64")]
    sign_count: i64,
    #[serde(default = "default_empty_string")]
    user_id: String,
    #[serde(default = "default_empty_string")]
    relying_party: String,
    #[serde(default = "default_empty_string")]
    username: String,
    #[serde(default = "default_empty_number_i64")]
    created_date: i64,
}

impl Passkey {
    pub fn new(
        private_key: PasskeyPrivateKey,
        credential_id: String,
        sign_count: i64,
        user_id: String,
        relying_party: String,
        username: String,
        created_date: i64,
    ) -> Self {
        Passkey {
            private_key,
            credential_id,
            sign_count,
            user_id,
            relying_party,
            username,
            created_date,
        }
    }
}

// impl Default for PasskeyPrivateKey {
//     fn default() -> Self {
//         PasskeyPrivateKey {
//             crv: String::new(),
//             d: String::new(),
//             ext: false,
//             key_ops: Vec::new(),
//             kty: String::new(),
//             x: String::new(),
//             y: 0,
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct Passkeys {
    #[serde(flatten)]
    keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    required: bool,
    value: Vec<Passkey>,
}

impl Passkeys {
    pub fn new(value: Passkey, label: Option<String>, required: bool) -> Self {
        Passkeys {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::PASSKEYS.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_passkeys(value: Passkey) -> Self {
        Passkeys::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IsSsidHidden {
    #[serde(flatten)]
    pub keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default)]
    pub value: Vec<bool>,
}

impl IsSsidHidden {
    pub fn new(value: bool, label: Option<String>, required: bool) -> Self {
        IsSsidHidden {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::ISSSIDHIDDEN.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_is_ssid_hidden(value: bool) -> Self {
        IsSsidHidden::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WifiEncryption {
    #[serde(flatten)]
    pub keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default)]
    pub value: Vec<String>,
}

impl WifiEncryption {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        WifiEncryption {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::WIFIENCRYPTION.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_wifi_encryption(value: String) -> Self {
        WifiEncryption::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dropdown {
    #[serde(flatten)]
    pub keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default = "default_empty_vector")]
    pub value: Vec<String>,
}

impl Dropdown {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        Dropdown {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::DROPDOWN.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_dropdown(value: String) -> Self {
        Dropdown::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RbiUrl {
    #[serde(flatten)]
    pub keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default = "default_empty_vector")]
    pub value: Vec<String>,
}

impl RbiUrl {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        RbiUrl {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::RBIURL.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_rbi_url(value: String) -> Self {
        RbiUrl::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppFiller {
    #[serde(default = "default_empty_option_string")]
    pub application_title: Option<String>,
    #[serde(default = "default_empty_option_string")]
    pub content_filter: Option<String>,
    #[serde(default = "default_empty_option_string")]
    pub macro_sequence: Option<String>,
}

impl AppFiller {
    pub fn new(
        application_title: Option<String>,
        content_filter: Option<String>,
        macro_sequence: Option<String>,
    ) -> Self {
        AppFiller {
            application_title,
            content_filter,
            macro_sequence,
        }
    }

    fn to_json(&self) -> Result<String, KSMRError> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppFillers {
    #[serde(flatten)]
    pub keeper_fields: KeeperField,
    #[serde(default = "default_boolean")]
    pub required: bool,
    #[serde(default = "default_boolean")]
    pub privacy_screen: bool,
    #[serde(default = "default_empty_vector")]
    pub value: Vec<AppFiller>,
}

impl AppFillers {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        value: Vec<AppFiller>,
        label: Option<String>,
        required: bool,
        privacy_screen: bool,
    ) -> KeeperField {
        let mut keeper_field = KeeperField::new(
            StandardFieldTypeEnum::APPFILLERS.get_type().to_string(),
            label,
        );
        keeper_field.required = required;
        keeper_field.privacy_screen = privacy_screen;
        keeper_field.value = AppFillers::vec_app_filler_to_app_fillers_string(value);
        keeper_field
    }

    fn vec_app_filler_to_app_fillers_string(mut value: Vec<AppFiller>) -> Value {
        let app_fillers_string: Vec<Value> = value
            .iter_mut()
            .map(|app_filler| app_filler.to_json().unwrap())
            .map(|app_filler| {
                Value::from_str(app_filler.as_str())
                    .map_err(|err| KSMRError::DeserializationError(err.to_string()))
                    .unwrap()
            })
            .collect::<Vec<Value>>();
        Value::Array(app_fillers_string)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamRbiConnection {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub user_records: Vec<String>,
    #[serde(default)]
    pub allow_url_manipulation: bool,
    #[serde(default)]
    pub allowed_url_patterns: Option<String>,
    #[serde(default)]
    pub allowed_resource_url_patterns: Option<String>,
    #[serde(default)]
    pub http_credentials_uid: Option<String>,
    #[serde(default)]
    pub autofill_configuration: Option<String>,
}

impl PamRbiConnection {
    pub fn new(
        protocol: Option<String>,
        user_records: Vec<String>,
        allow_url_manipulation: bool,
        allowed_url_patterns: Option<String>,
        allowed_resource_url_patterns: Option<String>,
        http_credentials_uid: Option<String>,
        autofill_configuration: Option<String>,
    ) -> Self {
        PamRbiConnection {
            protocol,
            user_records,
            allow_url_manipulation,
            allowed_url_patterns,
            allowed_resource_url_patterns,
            http_credentials_uid,
            autofill_configuration,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamRemoteBrowserSetting {
    #[serde(default)]
    pub connection: Option<PamRbiConnection>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamRemoteBrowserSettings {
    pub keeper_fields: KeeperField,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub value: Vec<PamRemoteBrowserSetting>,
}

impl PamRemoteBrowserSettings {
    pub fn new(value: PamRemoteBrowserSetting, label: Option<String>, required: bool) -> Self {
        PamRemoteBrowserSettings {
            keeper_fields: KeeperField::new(
                StandardFieldTypeEnum::PAMREMOTEBROWSERSETTINGS
                    .get_type()
                    .to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_pam_remote_browser_settings(value: PamRemoteBrowserSetting) -> Self {
        PamRemoteBrowserSettings::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamSettingsPortForward {
    #[serde(default = "default_boolean")]
    pub reuse_port: bool,
    #[serde(default = "default_empty_string")]
    pub port: String,
}

impl PamSettingsPortForward {
    pub fn new(port: String, reuse_port: bool) -> Self {
        PamSettingsPortForward { reuse_port, port }
    }

    pub fn new_pam_settings_port_forward(port: String) -> Self {
        PamSettingsPortForward::new(port, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamSettingsConnection {
    #[serde(default = "default_empty_option_string")]
    pub protocol: Option<String>,
    #[serde(default = "default_empty_vector")]
    pub user_records: Vec<String>,
    #[serde(default = "default_empty_option_string")]
    pub security: Option<String>,
    #[serde(default = "default_boolean")]
    pub ignore_cert: bool,
    #[serde(default = "default_empty_option_string")]
    pub resize_method: Option<String>,
    #[serde(default = "default_empty_option_string")]
    pub color_scheme: Option<String>,
}

impl PamSettingsConnection {
    pub fn new(
        protocol: Option<String>,
        user_records: Vec<String>,
        security: Option<String>,
        ignore_cert: bool,
        resize_method: Option<String>,
        color_scheme: Option<String>,
    ) -> Self {
        PamSettingsConnection {
            protocol,
            user_records,
            security,
            ignore_cert,
            resize_method,
            color_scheme,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamSetting {
    pub port_forward: Vec<PamSettingsPortForward>,
    pub connection: Vec<PamSettingsConnection>,
}

impl PamSetting {
    pub fn new(
        port_forward: Vec<PamSettingsPortForward>,
        connection: Vec<PamSettingsConnection>,
    ) -> Self {
        PamSetting {
            port_forward,
            connection,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamSettings {
    #[serde(flatten)]
    pub keeper_field: KeeperField,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub value: Vec<PamSetting>,
}

impl PamSettings {
    pub fn new(value: PamSetting, label: Option<String>, required: bool) -> Self {
        PamSettings {
            keeper_field: KeeperField::new(
                StandardFieldTypeEnum::PAMSETTINGS.get_type().to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }

    pub fn new_pam_settings(value: PamSetting) -> Self {
        PamSettings::new(value, None, false)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrafficEncryptionSeed {
    #[serde(flatten)]
    pub keeper_field: KeeperField,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub value: Vec<String>,
}

impl TrafficEncryptionSeed {
    pub fn new(value: String, label: Option<String>, required: bool) -> Self {
        TrafficEncryptionSeed {
            keeper_field: KeeperField::new(
                StandardFieldTypeEnum::TRAFFICENCRYPTIONSEED
                    .get_type()
                    .to_string(),
                label,
            ),
            required,
            value: vec![value],
        }
    }
}

pub fn struct_to_map<T>(data: &T) -> Result<HashMap<String, Value>, KSMRError>
where
    T: Serialize,
{
    // Try to serialize the struct into a serde_json::Value
    let value =
        serde_json::to_value(data).map_err(|e| KSMRError::SerializationError(e.to_string()))?;

    // Try to convert the Value into a HashMap
    match value.as_object() {
        Some(obj) => {
            // Clone the object into a HashMap and return
            Ok(obj.clone().into_iter().collect())
        }
        None => Err(KSMRError::DataConversionError(
            "Expected an object but found something else".to_string(),
        )),
    }
}
