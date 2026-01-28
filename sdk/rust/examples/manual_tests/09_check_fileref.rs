// Check if record has fileRef field and what's in it

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::InMemoryKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    let config_base64 =
        std::fs::read_to_string("plans/config.base64").expect("Failed to read plans/config.base64");

    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_base64))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let secret_with_files = secrets
        .iter()
        .find(|s| !s.files.is_empty())
        .expect("No secrets with files");

    println!(
        "Record: {} (UID: {})",
        secret_with_files.title, secret_with_files.uid
    );
    println!("Files: {}", secret_with_files.files.len());

    // Check record_dict for fileRef field
    if let Some(fields) = secret_with_files.record_dict.get("fields") {
        println!("\nFields in record_dict:");
        if let Some(fields_array) = fields.as_array() {
            for field in fields_array {
                if let Some(field_type) = field.get("type").and_then(|v| v.as_str()) {
                    println!("  - Type: {}", field_type);
                    if field_type == "fileRef" {
                        println!("    Found fileRef field!");
                        if let Some(value) = field.get("value") {
                            println!("    Value: {}", value);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
