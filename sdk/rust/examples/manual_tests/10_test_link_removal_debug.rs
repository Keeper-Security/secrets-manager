// Debug version of link removal test

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::{UpdateOptions, UpdateTransactionType},
    storage::InMemoryKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    env_logger::init();

    let config_base64 =
        std::fs::read_to_string("plans/config.base64").expect("Failed to read plans/config.base64");

    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_base64))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let secret_with_files = secrets.iter().find(|s| !s.files.is_empty()).unwrap();

    println!("Record: {}", secret_with_files.title);

    // Show fileRef before
    if let Some(fields) = secret_with_files.record_dict.get("fields") {
        if let Some(fields_array) = fields.as_array() {
            for field in fields_array {
                if field.get("type").and_then(|v| v.as_str()) == Some("fileRef") {
                    println!("FileRef BEFORE: {}", field.get("value").unwrap());
                }
            }
        }
    }

    let record_uid = secret_with_files.uid.clone();
    let secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let record = secrets.into_iter().next().unwrap();

    let file_uid = record.files.first().unwrap().uid.clone();
    println!("\nRemoving file UID: {}", file_uid);

    let update_options = UpdateOptions::new(UpdateTransactionType::General, vec![file_uid.clone()]);

    secrets_manager.update_secret_with_options(record, update_options)?;
    println!("✅ Update succeeded");

    // Check fileRef after
    let updated_secrets = secrets_manager.get_secrets(vec![record_uid])?;
    let updated_record = updated_secrets.into_iter().next().unwrap();

    println!("\nFiles after: {}", updated_record.files.len());

    if let Some(fields) = updated_record.record_dict.get("fields") {
        if let Some(fields_array) = fields.as_array() {
            for field in fields_array {
                if field.get("type").and_then(|v| v.as_str()) == Some("fileRef") {
                    println!("FileRef AFTER: {}", field.get("value").unwrap());
                }
            }
        }
    }

    Ok(())
}
