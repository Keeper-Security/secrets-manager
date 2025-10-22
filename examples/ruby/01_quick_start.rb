#!/usr/bin/env ruby

# Quick Start Example - Getting started with Keeper Secrets Manager
# This example shows the simplest way to connect and retrieve secrets

require 'keeper_secrets_manager'

# Method 1: Using a one-time token (simplest)
# Get your token from: https://app.keeper-security.com/secrets-manager
begin
  token = ENV['KSM_TOKEN'] || 'US:YOUR_ONE_TIME_TOKEN'

  # Initialize SDK with token
  secrets_manager = KeeperSecretsManager.from_token(token)

  # Get all secrets
  secrets = secrets_manager.get_secrets

  puts "Found #{secrets.length} secrets:"
  secrets.each do |secret|
    puts "  - #{secret.title} (#{secret.type})"
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts 'Make sure to set KSM_TOKEN environment variable or replace with your token'
end

# Method 2: Using base64 configuration (for repeated use)
# After first connection, save your config for reuse
begin
  config_base64 = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG_STRING'

  # Initialize with saved configuration
  secrets_manager = KeeperSecretsManager.from_config(config_base64)

  # Get specific secret by UID
  secret = secrets_manager.get_secret_by_uid('RECORD_UID')
  puts "\nSecret details:"
  puts "  Title: #{secret.title}"
  puts "  Login: #{secret.fields['login']}"
rescue StandardError => e
  puts "Error: #{e.message}"
end
