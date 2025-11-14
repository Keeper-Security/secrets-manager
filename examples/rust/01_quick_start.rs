// Quick Start Example - Getting started with Keeper Secrets Manager
//
// STEP 1: Run this with a one-time token to create keeper_config.json
// STEP 2: All other examples will use the saved keeper_config.json
//
// Get your token from: https://app.keeper-security.com/secrets-manager
// Run with: KSM_TOKEN='US:YOUR_TOKEN' cargo run --manifest-path examples/rust/Cargo.toml --bin 01_quick_start

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Keeper Secrets Manager - Quick Start ===\n");

    // Get token from environment variable
    let token = match std::env::var("KSM_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("❌ ERROR: KSM_TOKEN environment variable not set\n");
            eprintln!("Please set your one-time token:");
            eprintln!("  export KSM_TOKEN='US:YOUR_ONE_TIME_TOKEN'\n");
            eprintln!("Get your token from:");
            eprintln!("  https://app.keeper-security.com/secrets-manager\n");
            std::process::exit(1);
        }
    };

    println!("🔑 Initializing with one-time token...");

    // Initialize SDK with token and file storage
    // This will create keeper_config.json on first successful connection
    let config = FileKeyValueStorage::new_config_storage("keeper_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options_with_token(token, config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    println!("📡 Connecting to Keeper and binding token...");

    // Get all secrets (this binds the token and saves config)
    let secrets = secrets_manager.get_secrets(Vec::new())?;

    println!("\n✅ SUCCESS! Retrieved {} secrets:", secrets.len());
    println!();

    for (i, secret) in secrets.iter().enumerate() {
        println!("{}. {} ({})", i + 1, secret.title, secret.record_type);
        println!("   UID: {}", secret.uid);
        println!("   Editable: {}", secret.is_editable);
        println!("   Files: {}", secret.files.len());
        if let Some(inner_folder) = &secret.inner_folder_uid {
            println!("   Subfolder: {}", inner_folder);
        }
        println!();
    }

    println!("📝 Configuration saved to keeper_config.json");
    println!("🎉 You can now run the other examples using the saved config!");
    println!();
    println!("Next steps:");
    println!("  cargo run --manifest-path examples/rust/Cargo.toml --bin 02_retrieve_secrets");
    println!("  cargo run --manifest-path examples/rust/Cargo.toml --bin 03_update_secrets");
    println!("  ... and more!");

    Ok(())
}
