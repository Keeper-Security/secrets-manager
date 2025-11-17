// Manual Integration Test 07: Test Rotation with Base64 Config
//
// This test validates transaction types work with the serialization fix
//
// Run with: cargo run --example 07_test_rotation_base64

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::UpdateTransactionType,
    enums::StandardFieldTypeEnum,
    storage::InMemoryKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 07: Rotation with Base64 Config ===\n");

    // Load base64 config
    let config_base64 =
        std::fs::read_to_string("plans/config.base64").expect("Failed to read plans/config.base64");

    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_base64))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    println!("Retrieving secrets...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    // Find editable secret
    let editable = secrets
        .iter()
        .find(|s| s.is_editable)
        .expect("No editable secrets found");

    println!("Found editable: {} (UID: {})", editable.title, editable.uid);

    // Get fresh copy
    let record_uid = editable.uid.clone();
    let secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    // Show current password
    if let Ok(current_password) = record.get_standard_field_value("password", true) {
        println!("Current password: {}", current_password);
    }

    // Generate test password
    let test_password = format!("RotationTest_{}", chrono::Utc::now().timestamp());
    println!("New password: {}", test_password);

    // Update password
    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        test_password.clone().into(),
    )?;

    // Test 1: Try Rotation transaction type
    println!("\n--- Test 1: Rotation Transaction Type ---");
    match secrets_manager
        .update_secret_with_transaction(record.clone(), UpdateTransactionType::Rotation)
    {
        Ok(_) => {
            println!("✅ Rotation transaction SUCCEEDED!");

            // Try to complete the transaction
            println!("\nCompleting (commit) rotation transaction...");
            match secrets_manager.complete_transaction(record_uid.clone(), false) {
                Ok(_) => println!("✅ Transaction commit SUCCEEDED!"),
                Err(e) => println!("❌ Transaction commit failed: {}", e),
            }
        }
        Err(e) => println!("❌ Rotation transaction failed: {}", e),
    }

    // Get fresh copy for second test
    let secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    let test_password2 = format!("GeneralTest_{}", chrono::Utc::now().timestamp());
    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        test_password2.clone().into(),
    )?;

    // Test 2: Try General transaction type
    println!("\n--- Test 2: General Transaction Type ---");
    match secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::General) {
        Ok(_) => println!("✅ General transaction SUCCEEDED!"),
        Err(e) => println!("❌ General transaction failed: {}", e),
    }

    Ok(())
}
