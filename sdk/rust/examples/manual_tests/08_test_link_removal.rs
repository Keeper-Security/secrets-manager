// Manual Integration Test 08: Update with Options - Link Removal
//
// This test validates update_secret_with_options and link removal

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::{UpdateOptions, UpdateTransactionType},
    storage::InMemoryKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 08: Update with Options (Link Removal) ===\n");

    // Load base64 config
    let config_base64 =
        std::fs::read_to_string("plans/config.base64").expect("Failed to read plans/config.base64");

    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_base64))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    println!("Finding secret with file attachments...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    let secret_with_files = secrets
        .iter()
        .find(|s| !s.files.is_empty() && s.is_editable)
        .expect("No editable secrets with files");

    println!(
        "Found: {} (UID: {})",
        secret_with_files.title, secret_with_files.uid
    );
    println!("Files before: {}", secret_with_files.files.len());
    for (i, file) in secret_with_files.files.iter().enumerate() {
        println!("  {}. {} (UID: {})", i + 1, file.name, file.uid);
    }

    // Get fresh copy
    let record_uid = secret_with_files.uid.clone();
    let secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let record = secrets.into_iter().next().unwrap();

    let file_to_remove = record.files.first().unwrap();
    let file_uid = file_to_remove.uid.clone();
    let file_name = file_to_remove.name.clone();

    println!("\nRemoving file: {} (UID: {})", file_name, file_uid);

    // Test update_with_options for link removal
    let update_options = UpdateOptions::new(UpdateTransactionType::None, vec![file_uid.clone()]);

    println!("Calling update_secret_with_options...");
    match secrets_manager.update_secret_with_options(record, update_options) {
        Ok(_) => {
            println!("✅ update_secret_with_options SUCCEEDED!");

            // Verify removal
            println!("\nVerifying file removal...");
            let updated_secrets = secrets_manager.get_secrets(vec![record_uid])?;
            let updated_record = updated_secrets.into_iter().next().unwrap();

            println!("Files after: {}", updated_record.files.len());
            for (i, file) in updated_record.files.iter().enumerate() {
                println!("  {}. {} (UID: {})", i + 1, file.name, file.uid);
            }

            let still_exists = updated_record.files.iter().any(|f| f.uid == file_uid);
            if !still_exists {
                println!("\n✅ FILE REMOVED SUCCESSFULLY!");
            } else {
                println!("\n⚠️ File still exists (link removal may not have worked)");
            }
        }
        Err(e) => {
            println!("❌ update_secret_with_options failed: {}", e);
        }
    }

    Ok(())
}
