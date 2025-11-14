// Example 05: File Operations
//
// This example demonstrates working with file attachments
// Prerequisites: Run 01_quick_start.rs first to create keeper_config.json
//
// Run with: cargo run --manifest-path examples/rust/Cargo.toml --bin 05_files

use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Example 05: File Operations ===\n");

    // Load saved configuration
    let config = FileKeyValueStorage::new_config_storage("keeper_config.json".to_string())?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // Find a secret with file attachments
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    let secret_with_files = secrets
        .iter()
        .find(|s| !s.files.is_empty())
        .expect("No secrets with file attachments found");

    println!("Secret: {}", secret_with_files.title);
    println!("Files: {}\n", secret_with_files.files.len());

    // List all files
    println!("File attachments:");
    for (i, file) in secret_with_files.files.iter().enumerate() {
        println!("{}. {}", i + 1, file.name);
        println!("   UID: {}", file.uid);
        println!("   Type: {}", file.file_type);
        println!("   URL: {:?}", file.url.as_ref().map(|u| &u[..50]));  // Show first 50 chars
        println!("   Thumbnail: {}", file.thumbnail_url.is_some());
        println!();
    }

    // Download a file (if available)
    if let Some(file_info) = secret_with_files.files.first() {
        println!("Downloading file: {}", file_info.name);

        // Get the full secret with files
        let mut secrets = secrets_manager.get_secrets(vec![secret_with_files.uid.clone()])?;
        let mut secret = secrets.into_iter().next().unwrap();

        // Download first file
        if let Some(mut file) = secret.files.into_iter().next() {
            match file.get_file_data() {
                Ok(Some(data)) => {
                    println!("✅ Downloaded {} bytes", data.len());

                    // Save to disk
                    let filename = format!("downloaded_{}", file.name);
                    std::fs::write(&filename, data)
                        .map_err(|e| KSMRError::IOError(e.to_string()))?;
                    println!("✅ Saved to: {}", filename);
                }
                Ok(None) => println!("⚠️ No file data available"),
                Err(e) => println!("❌ Download failed: {}", e),
            }
        }
    }

    println!();

    // Check for thumbnail availability
    println!("Checking for thumbnails...");
    let mut thumbnail_count = 0;
    for secret in &secrets {
        for file in &secret.files {
            if file.thumbnail_url.is_some() {
                thumbnail_count += 1;
                println!("  - {} has thumbnail", file.name);
            }
        }
    }
    if thumbnail_count == 0 {
        println!("  No thumbnails available in current secrets");
    } else {
        println!("\n  Found {} file(s) with thumbnails", thumbnail_count);
    }

    println!("\n✅ File operations demonstrated!");
    println!();
    println!("💡 File operations:");
    println!("   - file.get_file_data() - Download and decrypt");
    println!("   - file.get_thumbnail_data() - Download thumbnail");
    println!("   - file.url - Direct download URL");
    println!("   - file.thumbnail_url - Thumbnail URL");

    Ok(())
}
