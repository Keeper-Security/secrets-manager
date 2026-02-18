// Manual Integration Test 4: Search Secrets by Title
//
// This test validates:
// - get_secrets_by_title() (all matches)
// - get_secret_by_title() (first match)
// - Case-sensitive exact matching
//
// Run with: cargo run --example 04_search_by_title
//
// Prerequisites:
// - Run 01_initialize_and_get_secrets first

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Manual Integration Test 4: Search by Title ===\n");

    let config = FileKeyValueStorage::new_config_storage("test_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Get all secrets to show available titles
    println!("Available secrets:");
    let all_secrets = secrets_manager.get_secrets(Vec::new())?;
    for secret in &all_secrets {
        println!("  - \"{}\" (UID: {})", secret.title, secret.uid);
    }

    // Test get_secret_by_title (singular - first match)
    if let Some(first_secret) = all_secrets.first() {
        let search_title = &first_secret.title;
        println!("\n--- Testing get_secret_by_title() ---");
        println!("Searching for title: \"{}\"", search_title);

        if let Some(found) = secrets_manager.get_secret_by_title(search_title)? {
            println!("✅ Found secret: {} (UID: {})", found.title, found.uid);
        } else {
            println!("❌ No secret found");
        }
    }

    // Test get_secrets_by_title (plural - all matches)
    if let Some(first_secret) = all_secrets.first() {
        let search_title = &first_secret.title;
        println!("\n--- Testing get_secrets_by_title() ---");
        println!("Searching for all secrets with title: \"{}\"", search_title);

        let matching = secrets_manager.get_secrets_by_title(search_title)?;
        println!("✅ Found {} matching secret(s)", matching.len());

        for (i, secret) in matching.iter().enumerate() {
            println!("  {}. {} (UID: {})", i + 1, secret.title, secret.uid);
        }
    }

    // Test case sensitivity
    println!("\n--- Testing Case Sensitivity ---");
    if let Some(first_secret) = all_secrets.first() {
        let lowercase_title = first_secret.title.to_lowercase();
        println!("Searching for lowercase: \"{}\"", lowercase_title);

        let matching = secrets_manager.get_secrets_by_title(&lowercase_title)?;
        if matching.is_empty() {
            println!("✅ Case sensitivity verified - no matches for different case");
        } else {
            println!("⚠️ Found matches (unexpected if original was not lowercase)");
        }
    }

    // Test non-existent title
    println!("\n--- Testing Non-Existent Title ---");
    let fake_title = "This Title Does Not Exist 12345";
    println!("Searching for: \"{}\"", fake_title);

    let matching = secrets_manager.get_secrets_by_title(fake_title)?;
    if matching.is_empty() {
        println!("✅ Correctly returned empty Vec for non-existent title");
    }

    if secrets_manager.get_secret_by_title(fake_title)?.is_none() {
        println!("✅ Correctly returned None for non-existent title");
    }

    Ok(())
}
