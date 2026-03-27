#!/usr/bin/env ruby

# Field Types Example - Working with different field types in Keeper

require 'keeper_secrets_manager'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

puts '=== Field Types Example ==='

# Create a record with various field types
record_data = {
  type: 'login',
  title: 'Field Types Demo',
  fields: [
    # Standard fields
    { type: 'login', value: ['user@example.com'] },
    { type: 'password', value: ['SecurePassword123!'] },
    { type: 'url', value: ['https://example.com'] },

    # Complex fields
    { type: 'name', value: [{ first: 'John', middle: 'Q', last: 'Doe' }] },
    { type: 'phone', value: [{ number: '555-1234', ext: '567', type: 'Work' }] },
    { type: 'email', value: ['john.doe@example.com'] },

    # Address field
    {
      type: 'address',
      value: [{
        street1: '123 Main St',
        street2: 'Suite 100',
        city: 'New York',
        state: 'NY',
        zip: '10001',
        country: 'US'
      }]
    },

    # Host field (for servers)
    {
      type: 'host',
      value: [{
        hostName: '192.168.1.100',
        port: '22'
      }]
    },

    # Security question
    {
      type: 'securityQuestion',
      value: [{
        question: 'What is your favorite color?',
        answer: 'Blue'
      }]
    },

    # Bank account
    {
      type: 'bankAccount',
      value: [{
        accountType: 'Checking',
        routingNumber: '021000021',
        accountNumber: '1234567890'
      }]
    },

    # Payment card
    {
      type: 'paymentCard',
      value: [{
        cardNumber: '4111111111111111',
        cardExpirationDate: '12/25',
        cardSecurityCode: '123'
      }]
    },

    # Date field
    { type: 'date', value: [Time.now.to_i * 1000] }, # milliseconds

    # Multiline field
    { type: 'multiline', value: ["Line 1\nLine 2\nLine 3"] }
  ],

  # Custom fields
  custom: [
    { type: 'text', label: 'Department', value: ['Engineering'] },
    { type: 'text', label: 'Project', value: ['Secret Management'] },
    { type: 'secret', label: 'API Key', value: ['sk_test_123456789'] },
    { type: 'url', label: 'Documentation', value: ['https://docs.example.com'] }
  ]
}

# Example: Reading different field types
puts "\n1. Standard Fields:"
begin
  # If you have a record with these fields
  secret = secrets_manager.get_secrets.first

  puts "  Login: #{secret.login}" if secret.respond_to?(:login)
  puts '  Password: [hidden]' if secret.respond_to?(:password)
  puts "  URL: #{secret.url}" if secret.respond_to?(:url)
rescue StandardError => e
  puts '  (Create a record with the fields above to see this in action)'
end

# Example: Complex field access
puts "\n2. Complex Fields:"
puts "  Name field: #{record_data[:fields].find { |f| f[:type] == 'name' }[:value].first}"
puts "  Phone field: #{record_data[:fields].find { |f| f[:type] == 'phone' }[:value].first}"
puts "  Address field: #{record_data[:fields].find { |f| f[:type] == 'address' }[:value].first}"

# Example: Using field helpers (if available)
puts "\n3. Field Helpers:"
puts '  The SDK provides dynamic access to fields:'
puts '  - secret.login'
puts '  - secret.password'
puts '  - secret.url'
puts '  - secret.notes'
puts '  - secret.custom'

# Example: TOTP field (requires base32 gem)
puts "\n4. TOTP Fields:"
puts '  TOTP fields store the secret key for 2FA'
puts "  Install 'base32' gem to generate TOTP codes:"
puts "  - { type: 'oneTimeCode', value: ['JBSWY3DPEHPK3PXP'] }"

# Tips
puts "\n=== Field Type Tips ==="
puts '- Use appropriate field types for better UI experience'
puts '- Complex fields (name, address, etc.) use structured data'
puts '- Custom fields are flexible for any additional data'
puts '- File references use fileRef type'
puts '- Dates are stored as milliseconds since epoch'
