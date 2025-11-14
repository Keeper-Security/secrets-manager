// Manual Integration Test 5: Update with Options (Link Removal)
//
// This test validates:
// - update_secret_with_options()
// - UpdateOptions struct
// - Link removal (links_to_remove)
// - UpdatePayload.links2_remove field
//
// Run with: cargo run --example 05_update_with_options
//
// Prerequisites:
// - Run 01_initialize_and_get_secrets first
// - Have a secret with file attachments

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::{UpdateOptions, UpdateTransactionType},
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 5: Update with Options ===\n");

    let config = FileKeyValueStorage::new_config_storage("test_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Find a secret with files
    println!("Finding secret with file attachments...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    let secret_with_files = secrets
        .iter()
        .find(|s| !s.files.is_empty() && s.is_editable)
        .expect("No editable secrets with file attachments found");

    println!("Found secret: {}", secret_with_files.title);
    println!("Files before: {}", secret_with_files.files.len());

    for (i, file) in secret_with_files.files.iter().enumerate() {
        println!("  {}. {} (UID: {})", i + 1, file.name, file.uid);
    }

    // Get fresh copy for update
    let record_uid = secret_with_files.uid.clone();
    let mut secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let record = secrets.into_iter().next().unwrap();

    if record.files.is_empty() {
        println!("\n⚠️ No files to remove. Skipping link removal test.");
        println!("Testing update_secret_with_options() with empty links_to_remove...");

        let update_options = UpdateOptions::new(UpdateTransactionType::General, vec![]);
        secrets_manager.update_secret_with_options(record, update_options)?;

        println!("✅ update_secret_with_options() works with empty links_to_remove");
        return Ok(());
    }

    // Collect file UIDs to remove (we'll remove the first file as a test)
    let file_to_remove = record.files.first().unwrap();
    let file_uid_to_remove = file_to_remove.uid.clone();
    let file_name_to_remove = file_to_remove.name.clone();

    println!(
        "\nRemoving file: {} (UID: {})",
        file_name_to_remove, file_uid_to_remove
    );

    // Create update options with link removal
    let update_options = UpdateOptions::new(
        UpdateTransactionType::General,
        vec![file_uid_to_remove.clone()],
    );

    println!("Updating with link removal...");
    secrets_manager.update_secret_with_options(record, update_options)?;

    println!("✅ Update with link removal successful");

    // Verify the file was removed
    println!("\nVerifying file removal...");
    let mut updated_secrets = secrets_manager.get_secrets(vec![record_uid])?;
    let updated_record = updated_secrets.into_iter().next().unwrap();

    println!("Files after: {}", updated_record.files.len());

    let file_still_exists = updated_record
        .files
        .iter()
        .any(|f| f.uid == file_uid_to_remove);

    if !file_still_exists {
        println!("✅ File successfully removed from record");
    } else {
        println!("⚠️ File still exists (link removal may not have worked)");
    }

    Ok(())
}
