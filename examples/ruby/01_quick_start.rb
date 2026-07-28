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

# Method 2: Using saved configuration file (recommended for repeated use)
# After first connection with token, config is saved to keeper_config.json
begin
  # Initialize from saved configuration file
  secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

  # Get all secrets
  secrets = secrets_manager.get_secrets
  puts "\nRetrieved #{secrets.length} secrets from saved config"

  # Get specific secret by UID
  if secrets.any?
    secret = secrets.first
    puts "\nSecret details:"
    puts "  Title: #{secret.title}"
    puts "  Login: #{secret.login}" if secret.login
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts 'Make sure keeper_config.json exists (run with token first)'
end
