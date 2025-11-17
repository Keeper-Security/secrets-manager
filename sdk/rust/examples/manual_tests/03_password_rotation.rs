// Manual Integration Test 3: Password Rotation with Transactions
//
// This test validates:
// - update_secret_with_transaction()
// - complete_transaction() commit
// - complete_transaction() rollback
// - UpdateTransactionType::Rotation
//
// Run with: cargo run --example 03_password_rotation
//
// Prerequisites:
// - Run 01_initialize_and_get_secrets first
// - Have at least one editable secret

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::payload::UpdateTransactionType,
    enums::StandardFieldTypeEnum,
    storage::FileKeyValueStorage,
};
use std::io::{self, Write};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 3: Password Rotation ===\n");

    let config = FileKeyValueStorage::new_config_storage("test_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Get editable secret
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let editable_secret = secrets
        .into_iter()
        .find(|s| s.is_editable)
        .expect("No editable secrets found");

    println!("Using secret: {}", editable_secret.title);
    let record_uid = editable_secret.uid.clone();

    // Get fresh copy
    let secrets = secrets_manager.get_secrets(vec![record_uid.clone()])?;
    let mut record = secrets.into_iter().next().unwrap();

    // Show current password
    if let Ok(current_password) = record.get_standard_field_value("password", true) {
        println!("Current password: {}", current_password);
    }

    // Generate new rotated password
    let rotated_password = format!("Rotated_{}", chrono::Utc::now().timestamp());
    println!("New rotated password: {}", rotated_password);

    // Update password
    record.set_standard_field_value_mut(
        StandardFieldTypeEnum::PASSWORD.get_type(),
        rotated_password.clone().into(),
    )?;

    println!("\nStarting rotation transaction...");
    secrets_manager.update_secret_with_transaction(record, UpdateTransactionType::Rotation)?;

    println!("✅ Rotation transaction started");
    println!("\n--- Simulation: Test new password in your application ---");
    println!("In production, you would test the new password here.");

    // Ask user to commit or rollback
    print!("\nCommit transaction? (y/n): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let should_commit = input.trim().eq_ignore_ascii_case("y");

    if should_commit {
        println!("\nCommitting transaction...");
        secrets_manager.complete_transaction(record_uid.clone(), false)?;
        println!("✅ Transaction COMMITTED - new password is active");
    } else {
        println!("\nRolling back transaction...");
        secrets_manager.complete_transaction(record_uid.clone(), true)?;
        println!("✅ Transaction ROLLED BACK - old password restored");
    }

    // Verify final state
    println!("\nVerifying final state...");
    let final_secrets = secrets_manager.get_secrets(vec![record_uid])?;
    let final_record = final_secrets.into_iter().next().unwrap();

    if let Ok(final_password) = final_record.get_standard_field_value("password", true) {
        println!("Final password: {}", final_password);

        if should_commit {
            if final_password == rotated_password {
                println!("✅ Commit verified - password matches rotated value");
            } else {
                println!("⚠️ Commit failed - password does not match");
            }
        } else {
            if final_password != rotated_password {
                println!("✅ Rollback verified - password reverted");
            } else {
                println!("⚠️ Rollback failed - password still shows rotated value");
            }
        }
    }

    Ok(())
}
