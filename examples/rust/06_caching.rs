// Example 06: Disaster Recovery Caching
//
// This example shows how to use caching for offline access
// Prerequisites: Run 01_quick_start.rs first to create keeper_config.json
//
// Run with: cargo run --manifest-path examples/rust/Cargo.toml --bin 06_caching

use keeper_secrets_manager_core::{
    caching, core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    storage::FileKeyValueStorage,
};

fn main() -> Result<(), KSMRError> {
    println!("=== Example 06: Disaster Recovery Caching ===\n");

    // Clear any existing cache to start fresh
    println!("Clearing existing cache...");
    caching::clear_cache().ok();
    println!("Cache cleared\n");

    // Load saved configuration
    let config = FileKeyValueStorage::new_config_storage("keeper_config.json".to_string())?;
    let mut client_options = ClientOptions::new_client_options(config);

    // Enable disaster recovery caching
    println!("Enabling disaster recovery caching...");
    client_options.set_custom_post_function(caching::caching_post_function);

    let mut secrets_manager = SecretsManager::new(client_options)?;

    // First API call - saves to cache automatically
    println!("First API call (will save to cache)...");
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    println!("✅ Retrieved {} secrets", secrets.len());

    // Check cache was created
    let cache_path = caching::get_cache_file_path();
    println!("\nCache information:");
    println!("  Location: {:?}", cache_path);
    println!("  Exists: {}", caching::cache_exists());

    if caching::cache_exists() {
        if let Some(cached_data) = caching::get_cached_data() {
            println!("  Size: {} bytes", cached_data.len());
            println!("  Structure: 32-byte transmission key + encrypted response");
        }
    }

    // Demonstrate cache configuration
    println!("\n💡 Cache configuration:");
    println!("  Default location: ./ksm_cache.bin");
    println!("  Custom location: Set KSM_CACHE_DIR environment variable");
    println!("  Example: export KSM_CACHE_DIR=/var/cache/ksm");

    // Show cache management functions
    println!("\n📚 Cache management:");
    println!("  caching::cache_exists() - Check if cache file exists");
    println!("  caching::get_cached_data() - Load cached data");
    println!("  caching::clear_cache() - Remove cache file");
    println!("  caching::get_cache_file_path() - Get cache location");

    // Network failure behavior
    println!("\n🌐 Network failure behavior:");
    println!("  On success: Saves response to cache");
    println!("  On failure: Falls back to cached data (if available)");
    println!("  No cache: Returns network error");

    println!("\n✅ Caching configured and working!");
    println!();
    println!("💡 To test fallback:");
    println!("   1. Run this example once (creates cache)");
    println!("   2. Disconnect from network");
    println!("   3. Run again - will use cached data");

    // Clean up cache for this demo
    println!("\nCleaning up cache...");
    caching::clear_cache()?;
    println!("✅ Cache cleared");

    Ok(())
}
