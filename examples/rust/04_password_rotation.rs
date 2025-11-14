// Example 04: Password Rotation with Transactions
//
// This example shows how to safely rotate passwords using transactions
// Prerequisites: Run 01_quick_start.rs first to create keeper_config.json
//
// Run with: cargo run --manifest-path examples/rust/Cargo.toml --bin 04_password_rotation

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::UpdateTransactionType,
    enums::StandardFieldTypeEnum,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Example 04: Password Rotation with Transactions ===\n");

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

    println!("Rotating password for: {}", editable_secret.title);
    let record_uid = editable_secret.uid.clone();

    // STEP 1: Get the secret and update the password
    let mut secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    if let Ok(current_password) = record.get_standard_field_value("password", true) {
        println!("Current password: {}", current_password);
    }

    let new_password = format!("Rotated_{}", chrono::Utc::now().timestamp());
    println!("New password: {}", new_password);

    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        new_password.clone().into(),
    )?;

    // STEP 2: Start rotation transaction
    println!("\n📝 Starting rotation transaction...");
    secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::Rotation)?;
    println!("✅ Rotation transaction started");

    // STEP 3: Test the new password (simulation)
    println!("\n🔄 In production, you would test the new password on your system here...");
    println!("   Example: Test database connection, SSH login, API call, etc.");

    // Simulate successful test
    let test_passed = true;

    // STEP 4: Commit or rollback based on test results
    if test_passed {
        println!("\n✅ Password test passed - committing transaction...");
        secrets_manager.complete_transaction(record_uid.clone(), false)?;
        println!("✅ Transaction committed - new password is active!");
    } else {
        println!("\n❌ Password test failed - rolling back transaction...");
        secrets_manager.complete_transaction(record_uid.clone(), true)?;
        println!("✅ Transaction rolled back - old password restored");
    }

    // Verify final state
    println!("\nVerifying final password...");
    let final_secrets = secrets_manager.get_secrets(vec![record_uid])?;
    let final_record = final_secrets.into_iter().next().unwrap();

    if let Ok(final_password) = final_record.get_standard_field_value("password", true) {
        println!("Final password: {}", final_password);
    }

    println!("\n🎉 Password rotation complete!");
    println!();
    println!("💡 Transaction workflow:");
    println!("   1. update_secret_with_transaction(record, Rotation)");
    println!("   2. Test new password on target system");
    println!("   3. complete_transaction(uid, false) to commit");
    println!("      OR complete_transaction(uid, true) to rollback");

    Ok(())
}
