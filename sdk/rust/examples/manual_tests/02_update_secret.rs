// Manual Integration Test 2: Update Secret
//
// This test validates:
// - update_secret() method
// - Field modification
// - Record encryption and transmission
//
// Run with: cargo run --example 02_update_secret
//
// Prerequisites:
// - Run 01_initialize_and_get_secrets first to create config
// - Have at least one editable secret in your vault

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    enums::StandardFieldTypeEnum,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 2: Update Secret ===\n");

    // Use existing config
    let config = FileKeyValueStorage::new_config_storage("test_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Get all secrets
    println!("Retrieving secrets...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    // Find an editable secret
    let editable_secret = secrets
        .into_iter()
        .find(|s| s.is_editable)
        .expect("No editable secrets found. Please ensure you have edit permissions.");

    println!("Found editable secret: {}", editable_secret.title);
    println!("UID: {}", editable_secret.uid);

    // Get the record again (fresh copy for update)
    let mut secrets = secrets_manager.get_secrets(vec![editable_secret.uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    // Show current password (if login record)
    if let Ok(current_password) = record.get_standard_field_value("password", true) {
        println!("Current password: {}", current_password);
    }

    // Generate a new test password
    let new_password = format!("TestPassword_{}", chrono::Utc::now().timestamp());
    println!("New password: {}", new_password);

    // Modify the password field
    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        new_password.clone().into(),
    )?;

    println!("\nUpdating secret...");
    secrets_manager.update_secret(record)?;

    println!("✅ SUCCESS: Secret updated");

    // Verify the update by fetching again
    println!("\nVerifying update...");
    let mut updated_secrets = secrets_manager.get_secrets(vec![editable_secret.uid.clone()])?;
    let updated_record = updated_secrets.into_iter().next().unwrap();

    if let Ok(updated_password) = updated_record.get_standard_field_value("password", true) {
        println!("Updated password: {}", updated_password);

        if updated_password == new_password {
            println!("✅ Password verified - update successful!");
        } else {
            println!("⚠️ Password mismatch - verification failed");
        }
    }

    Ok(())
}
