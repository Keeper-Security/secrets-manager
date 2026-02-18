// Example 03: Updating Secrets
//
// This example demonstrates how to update secret fields
// Prerequisites: Run 01_quick_start.rs first to create keeper_config.json
//
// Run with: cargo run --manifest-path examples/rust/Cargo.toml --bin 03_update_secrets

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    enums::StandardFieldTypeEnum,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Example 03: Updating Secrets ===\n");

    // Load saved configuration
    let config = FileKeyValueStorage::new_config_storage("keeper_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Find an editable secret
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let editable_secret = secrets
        .iter()
        .find(|s| s.is_editable)
        .expect("No editable secrets found");

    println!("Updating secret: {}", editable_secret.title);
    println!("UID: {}\n", editable_secret.uid);

    // Get a fresh copy of the secret for updating
    let mut secrets = secrets_manager.get_secrets(vec![editable_secret.uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    // Show current password
    if let Ok(current_password) = record.get_standard_field_value("password", true) {
        println!("Current password: {}", current_password);
    }

    // Update the password field
    let new_password = format!("UpdatedPassword_{}", chrono::Utc::now().timestamp());
    println!("New password: {}", new_password);

    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        new_password.clone().into(),
    )?;

    // Save the changes
    println!("\nSaving updated secret...");
    secrets_manager.update_secret(record)?;

    println!("✅ Secret updated successfully!");

    // Verify the update
    println!("\nVerifying update...");
    let updated_secrets = secrets_manager.get_secrets(vec![editable_secret.uid.clone()])?;
    let updated_record = updated_secrets.into_iter().next().unwrap();

    if let Ok(verified_password) = updated_record.get_standard_field_value("password", true) {
        println!("Verified password: {}", verified_password);
        if verified_password == new_password {
            println!("✅ Password update confirmed!");
        }
    }

    println!("\n💡 Tip: You can update any standard field using set_standard_field_value_mut()");
    println!("   Available fields: login, password, url, email, phone, etc.");

    Ok(())
}
