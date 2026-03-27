#!/usr/bin/env ruby

# Retrieve Secrets Example - Different ways to access your secrets

require 'keeper_secrets_manager'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

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
    label = field['label'] || field['type']
    puts "  #{label}: #{field['value']}"
  end
end

# 6. Using notation to get specific values
puts "\n6. Using notation:"
begin
  if secrets.any?
    uid = secrets.first.uid

    # Get specific field value
    login = secrets_manager.get_notation("keeper://#{uid}/field/login")
    puts "  Login via notation: #{login}"

    # Get by title
    value = secrets_manager.get_notation("keeper://My Login/field/password")
    puts "  Password via notation: [hidden]"
  end
rescue => e
  puts "  Notation error: #{e.message}"
end

# 7. New DTO Fields (v17.2.0)
puts "\n7. New DTO Fields:"
puts "   Access new metadata fields on records"

begin
  query_options = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
  records_with_metadata = secrets_manager.get_secrets([], query_options)

  records_with_metadata.first(3).each do |record|
    puts "\n  #{record.title}"
    puts "    Editable: #{record.is_editable ? 'Yes' : 'No'}"
    puts "    Folder UID: #{record.inner_folder_uid}" if record.inner_folder_uid
    puts "    Has links: #{record.links && record.links.any? ? 'Yes' : 'No'}"

    if record.files && record.files.any?
      file = record.files.first
      puts "    File metadata:"
      puts "      Last modified: #{Time.at(file['lastModified'])}" if file['lastModified']
      puts "      Has thumbnail: #{file['thumbnailUrl'] ? 'Yes' : 'No'}"
    end
  end
rescue => e
  puts "  Error: #{e.message}"
end

# Tips
puts "\n=== Tips ==="
puts '- Use get_secrets() without parameters to retrieve all secrets'
puts '- Use get_secrets([uid]) to retrieve specific secrets by UID'
puts '- Use get_secret_by_title() for quick lookups by name'
puts '- Use notation for quick field access'
puts '- Dynamic field access (record.password) is convenient for standard fields'
puts '- Enable request_links: true to retrieve PAM linked credentials'
puts '- Check is_editable before attempting to modify records'