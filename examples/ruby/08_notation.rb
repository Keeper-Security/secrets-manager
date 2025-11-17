#!/usr/bin/env ruby

# Notation Example - Using Keeper Notation for quick access

require 'keeper_secrets_manager'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

puts '=== Keeper Notation Example ==='

# Keeper Notation provides a URI-style way to access secrets
# Format: keeper://<uid_or_title>/field/<field_name>
#         keeper://<uid_or_title>/file/<file_name>
#         keeper://<uid_or_title>/custom_field/<label>

puts "\n1. Basic field access:"
begin
  # Get by UID
  secrets = secrets_manager.get_secrets
  if secrets.any?
    uid = secrets.first.uid

    # Get login field
    login = secrets_manager.get_notation("keeper://#{uid}/field/login")
    puts "  Login: #{login}"

    # Get password field
    password = secrets_manager.get_notation("keeper://#{uid}/field/password")
    puts '  Password: [hidden]'
  end
rescue StandardError => e
  puts "  Error: #{e.message}"
end

puts "\n2. Access by title:"
begin
  # Use record title instead of UID
  url = secrets_manager.get_notation('keeper://My Website/field/url')
  puts "  URL: #{url}"
rescue StandardError => e
  puts "  Note: Create a record titled 'My Website' to see this work"
end

puts "\n3. Custom field access:"
begin
  # Access custom fields by label
  api_key = secrets_manager.get_notation('keeper://API Server/custom_field/API Key')
  puts "  API Key: #{api_key}"
rescue StandardError => e
  puts '  Note: Custom fields are accessed by their label'
end

puts "\n4. File access:"
begin
  # Download file by name
  file_data = secrets_manager.get_notation('keeper://My Certificates/file/server.crt')
  puts "  File downloaded: #{file_data.bytesize} bytes"
rescue StandardError => e
  puts '  Note: Files are accessed by their filename'
end

puts "\n5. Notation patterns:"
puts '  - keeper://<record>/field/<field_type>'
puts '  - keeper://<record>/custom_field/<label>'
puts '  - keeper://<record>/file/<filename>'
puts '  - keeper://<record> (returns entire record)'

puts "\n6. Advanced examples:"
# You can use notation in templates or configuration
config_template = <<~CONFIG
  database:
    host: keeper://Database Server/field/host
    port: keeper://Database Server/custom_field/Port
    username: keeper://Database Server/field/login
    password: keeper://Database Server/field/password
CONFIG

puts '  Config template example:'
puts config_template

# Process template (example)
puts "\n7. Processing notation in strings:"
text = 'Connect to keeper://Web Server/field/url with keeper://Web Server/field/login'
puts "  Template: #{text}"

# Find and replace notation patterns
result = text.gsub(%r{keeper://[^/\s]+/[^/\s]+/[^\s]+}) do |notation|
  secrets_manager.get_notation(notation) || notation
rescue StandardError
  notation
end
puts "  Processed: #{result}"

# 8. Error-safe notation access (NEW in v17.2.0)
puts "\n8. Error-safe notation with try_get_notation:"
begin
  # try_get_notation never raises exceptions - returns empty array on error
  secrets = secrets_manager.get_secrets
  uid = secrets.first&.uid

  if uid
    # Valid notation - returns value
    password = secrets_manager.try_get_notation("keeper://#{uid}/field/password")
    puts "  [OK] Valid notation returned value (#{password.class})"

    # Invalid notation - returns empty array instead of raising exception
    invalid = secrets_manager.try_get_notation('keeper://INVALID_UID/field/password')
    puts "  [OK] Invalid notation returned: #{invalid.inspect}"
    puts '       (No exception raised - safe for optional fields)'
  end
rescue StandardError => e
  puts "  [FAIL] #{e.message}"
end

# 9. Use case: Configuration with fallbacks
puts "\n9. Safe configuration access with fallbacks:"
begin
  secrets = secrets_manager.get_secrets
  uid = secrets.first&.uid

  if uid
    # Get values with fallbacks (no error handling needed)
    host = secrets_manager.try_get_notation("keeper://#{uid}/field/host[hostName]").first || 'localhost'
    port = secrets_manager.try_get_notation("keeper://#{uid}/custom_field/Port").first || '5432'
    env = secrets_manager.try_get_notation("keeper://#{uid}/custom_field/Environment").first || 'development'

    puts "  Database Host: #{host}"
    puts "  Database Port: #{port}"
    puts "  Environment: #{env}"
    puts '  [OK] Fallback values used when fields missing'
  end
rescue StandardError => e
  puts "  [FAIL] #{e.message}"
end

puts "\n=== Notation Tips ==="
puts '- Use UIDs for exact matching (no ambiguity)'
puts '- Titles are easier to read but must be unique'
puts '- Notation is great for configuration files'
puts "- get_notation() returns nil if field doesn't exist"
puts '- get_notation() throws exception if record not found'
puts '- try_get_notation() returns [] on any error (safe for optional fields)'
