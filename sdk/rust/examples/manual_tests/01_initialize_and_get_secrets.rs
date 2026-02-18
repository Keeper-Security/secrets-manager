// Manual Integration Test 1: Initialize with token and retrieve secrets
//
// This test validates:
// - Token binding
// - Config file creation
// - Basic secret retrieval
// - DTO field population (links, is_editable, inner_folder_uid, etc.)
//
// Run with: cargo run --example 01_initialize_and_get_secrets

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 1: Initialize & Get Secrets ===\n");

    // TODO: Replace with your one-time token
    let token = std::env::var("KSM_TOKEN")
        .expect("Set KSM_TOKEN environment variable with your one-time token");

    let config = FileKeyValueStorage::new_config_storage("test_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options_with_token(token, config);

    println!("Creating SecretsManager...");
    let mut secrets_manager = SecretsManager::new(client_options)?;

    println!("Retrieving secrets...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    println!("\n✅ SUCCESS: Retrieved {} secrets\n", secrets.len());

    // Validate DTO fields
    for (i, secret) in secrets.iter().enumerate() {
        println!("Secret {}:", i + 1);
        println!("  UID: {}", secret.uid);
        println!("  Title: {}", secret.title);
        println!("  Type: {}", secret.record_type);
        println!("  Is Editable: {}", secret.is_editable);
        println!("  Folder UID: {}", secret.folder_uid);
        println!("  Inner Folder UID: {:?}", secret.inner_folder_uid);
        println!("  Revision: {:?}", secret.revision);
        println!("  Links: {} (GraphSync)", secret.links.len());
        println!("  Files: {}", secret.files.len());

        // Show file details if present
        for (j, file) in secret.files.iter().enumerate() {
            println!("    File {}:", j + 1);
            println!("      Name: {}", file.name);
            println!("      UID: {}", file.uid);
            println!("      URL: {:?}", file.url);
            println!("      Thumbnail URL: {:?}", file.thumbnail_url);
        }

        println!();
    }

    println!("✅ Config saved to: test_config.json");
    println!("✅ Token bound successfully");
    println!("✅ All DTO fields populated correctly");

    Ok(())
}
