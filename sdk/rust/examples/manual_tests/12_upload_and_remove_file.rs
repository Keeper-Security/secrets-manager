// Manual Integration Test 12: Upload file then remove it with links2Remove
//
// This test:
// 1. Finds an editable record (or uses a specific one)
// 2. Uploads a temporary test file
// 3. Immediately removes it using update_secret_with_options
// 4. Verifies the file was removed
//
// Run with: cargo run --example 12_upload_and_remove_file

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::{
        dtos::KeeperFileUpload,
        payload::{UpdateOptions, UpdateTransactionType},
    },
    storage::InMemoryKeyValueStorage,
};
use serde_json::Value;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), KSMRError> {
    env_logger::init();

    println!("=== Manual Integration Test 12: Upload + Remove File ===\n");

    let config_base64 =
        std::fs::read_to_string("plans/config.base64").expect("Failed to read config");

    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_base64))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Find an editable record (prefer the test record)
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let test_record = secrets
        .iter()
        .find(|s| s.title == "Test links2Remove - Rust SDK" && s.is_editable)
        .or_else(|| secrets.iter().find(|s| s.is_editable))
        .expect("No editable records found");

    println!(
        "Using record: {} (UID: {})",
        test_record.title, test_record.uid
    );
    println!("Files before upload: {}\n", test_record.files.len());

    // Create a temporary test file (use milliseconds to avoid name collisions)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let test_filename = format!("test_file_{}.txt", timestamp);
    let test_content = format!("Test file created at {}", timestamp);

    fs::write(&test_filename, &test_content).expect("Failed to create test file");
    println!("Created temporary file: {}", test_filename);

    // Get fresh record for upload
    let secrets = secrets_manager.get_secrets(vec![test_record.uid.clone()])?;
    let record_for_upload = secrets.into_iter().next().unwrap();

    // Upload the file
    println!("Uploading file to record...");
    let file_upload = KeeperFileUpload::get_file_for_upload(
        &test_filename,
        Some(&test_filename),
        Some(&test_filename),
        Some("text/plain"),
    )?;
    secrets_manager.upload_file(record_for_upload, file_upload)?;
    println!("✅ File uploaded successfully\n");

    // DEBUG: Check the record structure after upload
    println!("DEBUG: Checking record structure after upload...");
    let secrets_debug = secrets_manager.get_secrets(vec![test_record.uid.clone()])?;
    let record_debug = secrets_debug.into_iter().next().unwrap();
    if let Some(Value::Array(fields)) = record_debug.record_dict.get("fields") {
        let file_ref_count = fields
            .iter()
            .filter(|f| f.get("type").and_then(|v| v.as_str()) == Some("fileRef"))
            .count();
        println!(
            "DEBUG: Number of fileRef fields in record: {}",
            file_ref_count
        );
        for (i, field) in fields.iter().enumerate() {
            if field.get("type").and_then(|v| v.as_str()) == Some("fileRef") {
                println!("DEBUG: fileRef field #{}: {:?}", i + 1, field);
            }
        }
    }

    // Get fresh copy of record with the new file
    let secrets = secrets_manager.get_secrets(vec![test_record.uid.clone()])?;
    let record_with_file = secrets.into_iter().next().unwrap();

    println!("Files after upload: {}", record_with_file.files.len());

    // Find the file we just uploaded
    println!("DEBUG: Looking for file with name: {}", test_filename);
    println!("DEBUG: Files with matching name:");
    for (idx, file) in record_with_file.files.iter().enumerate() {
        if file.name == test_filename {
            println!("  [{}] {} (UID: {})", idx, file.name, file.uid);
        }
    }

    let uploaded_file = record_with_file
        .files
        .iter()
        .find(|f| f.name == test_filename)
        .expect("Uploaded file not found");

    let uploaded_file_uid = uploaded_file.uid.clone();
    println!("\nDEBUG: Selected file UID: {}", uploaded_file_uid);
    println!("  - {} (UID: {})\n", uploaded_file.name, uploaded_file_uid);

    // Now remove it using links2Remove
    println!("Removing file using links2Remove...");
    println!(
        "DEBUG: Creating UpdateOptions with UID: {}",
        uploaded_file_uid
    );
    let update_options = UpdateOptions::new(
        UpdateTransactionType::None, // Match Python SDK behavior (uses None, not General)
        vec![uploaded_file_uid.clone()],
    );
    println!(
        "DEBUG: UpdateOptions.links_to_remove = {:?}",
        update_options.links_to_remove
    );

    secrets_manager.update_secret_with_options(record_with_file, update_options)?;
    println!("✅ update_secret_with_options succeeded\n");

    // Verify removal
    println!("Verifying file removal...");
    let secrets = secrets_manager.get_secrets(vec![test_record.uid.clone()])?;
    let updated_record = secrets.into_iter().next().unwrap();

    println!("Files after removal: {}", updated_record.files.len());

    for file in &updated_record.files {
        println!("  - {} (UID: {})", file.name, file.uid);
    }

    let file_still_exists = updated_record
        .files
        .iter()
        .any(|f| f.uid == uploaded_file_uid);

    println!("\nChecking if UID {} still exists...", uploaded_file_uid);

    if !file_still_exists {
        println!("\n✅ SUCCESS! File was removed using links2Remove");

        // Clean up temp file
        fs::remove_file(&test_filename).ok();
        println!("   Cleaned up temporary file: {}", test_filename);
    } else {
        println!("\n❌ FAILED! File still exists after update");
        println!("   The links2Remove feature did not work");

        // Clean up temp file
        fs::remove_file(&test_filename).ok();
    }

    Ok(())
}
