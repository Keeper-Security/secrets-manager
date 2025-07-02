#!/usr/bin/env ruby

# Retrieve Secrets Example - Different ways to access your secrets

require 'keeper_secrets_manager'

# Initialize (use your preferred method)
config = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG'
secrets_manager = KeeperSecretsManager.from_config(config)

puts "=== Retrieving Secrets ==="

# 1. Get all secrets
puts "\n1. Get all secrets:"
secrets = secrets_manager.get_secrets
secrets.each do |secret|
  puts "  - #{secret.title} (UID: #{secret.uid})"
end

# 2. Get specific secret by UID
puts "\n2. Get secret by UID:"
if secrets.any?
  uid = secrets.first.uid
  secret = secrets_manager.get_secret_by_uid(uid)
  puts "  Title: #{secret.title}"
  puts "  Type: #{secret.type}"
  puts "  Fields: #{secret.fields.keys.join(', ')}"
end

# 3. Get secret by title
puts "\n3. Get secret by title:"
begin
  secret = secrets_manager.get_secret_by_title("My Login")
  puts "  Found: #{secret.title}"
rescue => e
  puts "  Not found: #{e.message}"
end

# 4. Get multiple secrets by UIDs
puts "\n4. Get multiple secrets:"
if secrets.length >= 2
  uids = secrets.first(2).map(&:uid)
  selected_secrets = secrets_manager.get_secrets(uids)
  selected_secrets.each do |secret|
    puts "  - #{secret.title}"
  end
end

# 5. Access specific fields
puts "\n5. Access secret fields:"
if secrets.any?
  secret = secrets.first
  
  # Common fields
  puts "  Login: #{secret.fields['login']}" if secret.fields['login']
  puts "  URL: #{secret.fields['url']}" if secret.fields['url']
  
  # Using dynamic field access
  puts "  Password: #{secret.password}" if secret.respond_to?(:password)
  
  # Custom fields
  secret.custom&.each do |field|
    puts "  #{field['label']}: #{field['value']}"
  end
end

# 6. Using notation to get specific values
puts "\n6. Using notation:"
if secrets.any?
  uid = secrets.first.uid
  
  # Get specific field value
  login = secrets_manager.get_notation("keeper://#{uid}/field/login")
  puts "  Login via notation: #{login}"
  
  # Get by title
  value = secrets_manager.get_notation("keeper://My Login/field/password")
  puts "  Password via notation: [hidden]"
rescue => e
  puts "  Notation error: #{e.message}"
end