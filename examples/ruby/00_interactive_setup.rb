#!/usr/bin/env ruby
# frozen_string_literal: true

# Interactive Setup - First-time user onboarding
# This example guides you through setting up Keeper Secrets Manager step-by-step

require 'keeper_secrets_manager'
require 'io/console'

puts "=" * 80
puts "Keeper Secrets Manager - Interactive Setup"
puts "=" * 80
puts

# Check if already configured
if ENV['KSM_CONFIG']
  puts "✓ Found existing KSM_CONFIG environment variable"
  puts "\nWould you like to use it? (y/n)"
  use_existing = STDIN.gets.chomp.downcase

  if use_existing == 'y'
    begin
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(ENV['KSM_CONFIG'])
      sm = KeeperSecretsManager.new(config: storage)
      secrets = sm.get_secrets

      puts "\n✓ Connected successfully!"
      puts "Found #{secrets.length} secrets in your vault"
      secrets.each { |s| puts "  - #{s.title}" }
      exit 0
    rescue => e
      puts "\n✗ Error with existing config: #{e.message}"
      puts "Let's set up a new configuration..."
    end
  end
end

# Step 1: Get one-time token
puts "\n" + "=" * 80
puts "Step 1: One-Time Token"
puts "=" * 80
puts
puts "Get your one-time token from:"
puts "  https://app.keeper-security.com/secrets-manager"
puts
puts "The token format is: REGION:TOKEN_STRING"
puts "Example: US:ABCD1234..."
puts

print "Enter your one-time token: "
token = STDIN.gets.chomp

if token.empty? || token == 'US:YOUR_ONE_TIME_TOKEN'
  puts "\n✗ Invalid token. Please run the script again with a real token."
  exit 1
end

# Parse region from token
region = token.split(':').first.upcase
puts "\n✓ Token received (Region: #{region})"

# Step 2: Choose storage method
puts "\n" + "=" * 80
puts "Step 2: Configuration Storage"
puts "=" * 80
puts
puts "How would you like to store your configuration?"
puts "  1) File (keeper_config.json) - Recommended for servers"
puts "  2) Environment variable (KSM_CONFIG) - Recommended for containers"
puts "  3) Display as base64 (for manual storage)"
puts

print "Enter choice (1-3): "
storage_choice = STDIN.gets.chomp

case storage_choice
when '1'
  # File storage
  print "\nEnter filename (default: keeper_config.json): "
  filename = STDIN.gets.chomp
  filename = 'keeper_config.json' if filename.empty?

  puts "\n" + "=" * 80
  puts "Step 3: Binding Token"
  puts "=" * 80
  puts
  puts "Initializing SDK with one-time token..."
  puts "(This will generate keys and save configuration)"
  puts

  begin
    storage = KeeperSecretsManager::Storage::FileStorage.new(filename)
    sm = KeeperSecretsManager.new(token: token, config: storage)

    puts "\n✓ Token bound successfully!"
    puts "✓ Configuration saved to: #{filename}"
    puts
    puts "Keep this file secure - it contains your private key!"

    # Test connection
    secrets = sm.get_secrets
    puts "\n✓ Connected to vault"
    puts "Found #{secrets.length} secrets:"
    secrets.each { |s| puts "  - #{s.title}" }

    puts "\n" + "=" * 80
    puts "Next Steps:"
    puts "=" * 80
    puts "1. Try running other examples: ruby 03_retrieve_secrets.rb"
    puts "2. Use this in your code:"
    puts "   storage = KeeperSecretsManager::Storage::FileStorage.new('#{filename}')"
    puts "   sm = KeeperSecretsManager.new(config: storage)"
    puts "   secrets = sm.get_secrets"
  rescue => e
    puts "\n✗ Error: #{e.message}"
    puts "\nTroubleshooting:"
    puts "  - Verify your token is valid and not expired"
    puts "  - Check your internet connection"
    puts "  - Ensure you have write permissions for #{filename}"
    exit 1
  end

when '2'
  # Environment variable
  puts "\n" + "=" * 80
  puts "Step 3: Binding Token"
  puts "=" * 80
  puts
  puts "Initializing SDK with one-time token..."
  puts

  begin
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new
    sm = KeeperSecretsManager.new(token: token, config: storage)

    puts "\n✓ Token bound successfully!"

    # Get config as base64
    config_base64 = storage.to_base64

    # Test connection
    secrets = sm.get_secrets
    puts "✓ Connected to vault"
    puts "Found #{secrets.length} secrets:"
    secrets.each { |s| puts "  - #{s.title}" }

    puts "\n" + "=" * 80
    puts "Environment Variable Setup:"
    puts "=" * 80
    puts
    puts "Add this to your environment (.bashrc, .zshrc, or container config):"
    puts
    puts "export KSM_CONFIG='#{config_base64}'"
    puts
    puts "Then use in your code:"
    puts "  storage = KeeperSecretsManager::Storage::InMemoryStorage.new(ENV['KSM_CONFIG'])"
    puts "  sm = KeeperSecretsManager.new(config: storage)"
  rescue => e
    puts "\n✗ Error: #{e.message}"
    exit 1
  end

when '3'
  # Display base64
  puts "\n" + "=" * 80
  puts "Step 3: Binding Token"
  puts "=" * 80
  puts
  puts "Initializing SDK with one-time token..."
  puts

  begin
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new
    sm = KeeperSecretsManager.new(token: token, config: storage)

    puts "\n✓ Token bound successfully!"

    # Get config as base64
    config_base64 = storage.to_base64

    # Test connection
    secrets = sm.get_secrets
    puts "✓ Connected to vault"
    puts "Found #{secrets.length} secrets"

    puts "\n" + "=" * 80
    puts "Your Base64 Configuration:"
    puts "=" * 80
    puts
    puts config_base64
    puts
    puts "⚠️  Keep this secure - it contains your private key!"
    puts
    puts "Use in your code:"
    puts "  storage = KeeperSecretsManager::Storage::InMemoryStorage.new('#{config_base64[0..20]}...')"
    puts "  sm = KeeperSecretsManager.new(config: storage)"
  rescue => e
    puts "\n✗ Error: #{e.message}"
    exit 1
  end

else
  puts "\n✗ Invalid choice. Please run the script again."
  exit 1
end

puts "\n" + "=" * 80
puts "Setup Complete!"
puts "=" * 80
puts "Your one-time token has been consumed and cannot be reused."
puts "Use the saved configuration for all future connections."
puts "=" * 80
