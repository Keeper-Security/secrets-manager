#!/usr/bin/env ruby

# Authentication Example - Different ways to authenticate
# Shows how to initialize the SDK and save credentials for reuse

require 'keeper_secrets_manager'

puts "=== Authentication Methods ==="

# Method 1: One-time token (first time setup)
puts "\n1. Using One-Time Token:"
begin
  # Get token from Keeper Secrets Manager UI
  token = ENV['KSM_TOKEN'] || 'US:YOUR_ONE_TIME_TOKEN'
  
  # Option A: Direct use (credentials not saved)
  sm = KeeperSecretsManager.from_token(token)
  puts "✓ Connected with token"
  
  # Option B: Save credentials for reuse
  storage = KeeperSecretsManager::Storage::InMemoryStorage.new
  sm = KeeperSecretsManager.new(token: token, config: storage)
  
  # Get the configuration as base64 for future use
  config_base64 = storage.to_base64
  puts "✓ Configuration saved. Use this for future connections:"
  puts "  export KSM_CONFIG='#{config_base64}'"
  
rescue => e
  puts "✗ Error: #{e.message}"
end

# Method 2: Base64 configuration (subsequent connections)
puts "\n2. Using Base64 Configuration:"
begin
  # Use saved configuration from environment or file
  config_base64 = ENV['KSM_CONFIG'] || 'YOUR_SAVED_BASE64_CONFIG'
  
  # Initialize with configuration
  sm = KeeperSecretsManager.from_config(config_base64)
  
  # Test connection
  secrets = sm.get_secrets
  puts "✓ Connected with saved config, found #{secrets.length} secrets"
  
rescue => e
  puts "✗ Error: #{e.message}"
end

# Method 3: Using configuration file
puts "\n3. Using Configuration File:"
begin
  # Save configuration to a file
  config_file = 'keeper-config.json'
  
  # Initialize with file storage
  sm = KeeperSecretsManager.from_file(config_file)
  
  puts "✓ Connected using config file: #{config_file}"
  
rescue => e
  puts "✗ Error: #{e.message}"
end

# Method 4: Using environment variables
puts "\n4. Using Environment Variables:"
begin
  # Set these environment variables:
  # export KSM_HOSTNAME=keepersecurity.com
  # export KSM_CLIENT_ID=your-client-id
  # export KSM_PRIVATE_KEY=your-private-key
  # export KSM_APP_KEY=your-app-key
  
  storage = KeeperSecretsManager::Storage::EnvironmentStorage.new('KSM_')
  sm = KeeperSecretsManager.new(config: storage)
  
  puts "✓ Connected using environment variables"
  
rescue => e
  puts "✗ Error: #{e.message}"
  puts "  Make sure KSM_* environment variables are set"
end