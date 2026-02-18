// Example 02: Retrieving Secrets
//
// This example shows different ways to retrieve and filter secrets
// Prerequisites: Run 01_quick_start.rs first to create keeper_config.json
//
// Run with: cargo run --manifest-path examples/rust/Cargo.toml --bin 02_retrieve_secrets

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Example 02: Retrieving Secrets ===\n");

    // Load saved configuration
    let config = FileKeyValueStorage::new_config_storage("keeper_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Method 1: Get all secrets
    println!("Method 1: Get All Secrets");
    println!("-------------------------");
    let all_secrets = secrets_manager.get_secrets(Vec::new())?;
    println!("Retrieved {} secrets\n", all_secrets.len());

    // Method 2: Get specific secret by UID
    println!("Method 2: Get Specific Secret by UID");
    println!("-------------------------------------");
    if let Some(first_secret) = all_secrets.first() {
        let uid = first_secret.uid.clone();
        let filtered = secrets_manager.get_secrets(vec![uid.clone()])?;

        if let Some(secret) = filtered.first() {
            println!("Retrieved secret: {}", secret.title);
            println!("  UID: {}", secret.uid);
            println!("  Type: {}", secret.record_type);
            println!("  Revision: {:?}", secret.revision);
        }
    }
    println!();

    // Method 3: Get secret by title (exact match, case-sensitive)
    println!("Method 3: Get Secret by Title");
    println!("------------------------------");
    if let Some(secret) = secrets_manager.get_secret_by_title("Production Database")? {
        println!("Found secret: {}", secret.title);
        println!("  UID: {}", secret.uid);

        // Access password field
        if let Ok(password) = secret.get_standard_field_value("password", true) {
            println!("  Password: {}", password);
        }

        // Access login field
        if let Ok(login) = secret.get_standard_field_value("login", true) {
            println!("  Login: {}", login);
        }
    } else {
        println!("Secret 'Production Database' not found");
    }
    println!();

    // Method 4: Get all secrets with a specific title
    println!("Method 4: Get All Secrets with Title");
    println!("-------------------------------------");
    let matching_secrets = secrets_manager.get_secrets_by_title("Production Database")?;
    println!("Found {} secret(s) with title 'Production Database'", matching_secrets.len());
    println!();

    // Method 5: Using Keeper Notation for precise field access
    println!("Method 5: Using Keeper Notation");
    println!("--------------------------------");
    if let Some(secret) = all_secrets.first() {
        let notation_uri = format!("{}/field/password", secret.uid);
        match secrets_manager.get_notation(notation_uri.clone()) {
            Ok(value) => {
                println!("Notation: {}", notation_uri);
                println!("Value: {}", value);
            }
            Err(e) => println!("Notation query failed: {}", e),
        }
    }
    println!();

    // Method 6: Inspect secret metadata
    println!("Method 6: Secret Metadata");
    println!("-------------------------");
    for secret in all_secrets.iter().take(3) {
        println!("{}", secret.title);
        println!("  Editable: {}", secret.is_editable);
        println!("  Folder: {}", secret.folder_uid);
        if let Some(inner) = &secret.inner_folder_uid {
            println!("  Inner Folder: {}", inner);
        }
        println!("  Links: {} (GraphSync)", secret.links.len());
        println!();
    }

    println!("✅ All retrieval methods demonstrated!");

    Ok(())
}
