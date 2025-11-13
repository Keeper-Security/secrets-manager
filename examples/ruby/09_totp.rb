#!/usr/bin/env ruby

# TOTP Example - Generate Time-based One-Time Passwords

require 'keeper_secrets_manager'

# Initialize
config = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG'
secrets_manager = KeeperSecretsManager.from_config(config)

puts '=== TOTP (2FA) Example ==='

# NOTE: TOTP functionality requires the 'base32' gem
# Install with: gem install base32

begin
  # Check if TOTP is available
  unless defined?(KeeperSecretsManager::TOTP)
    puts "\nTOTP functionality requires the 'base32' gem."
    puts 'Install it with: gem install base32'
    puts "\nWithout TOTP, you can still:"
    puts '- Store TOTP seeds in oneTimeCode fields'
    puts '- Use external authenticator apps'
    puts '- Access the seed for manual setup'
    exit
  end

  puts "\n1. Finding records with TOTP:"
  secrets = secrets_manager.get_secrets
  totp_records = secrets.select do |s|
    s.fields.any? { |f| f['type'] == 'oneTimeCode' }
  end

  if totp_records.empty?
    puts '  No records with TOTP found.'

    # Example of creating a record with TOTP
    puts "\n2. Example: Creating a record with TOTP"
    puts '  record_data = {'
    puts "    type: 'login',"
    puts "    title: '2FA Example',"
    puts '    fields: ['
    puts "      { type: 'login', value: ['user@example.com'] },"
    puts "      { type: 'password', value: ['password123'] },"
    puts "      { type: 'oneTimeCode', value: ['JBSWY3DPEHPK3PXP'] }"
    puts '    ]'
    puts '  }'
  else
    puts "  Found #{totp_records.length} records with TOTP"

    # Generate TOTP codes
    puts "\n2. Generating TOTP codes:"
    totp_records.each do |record|
      totp_field = record.fields.find { |f| f['type'] == 'oneTimeCode' }
      next unless totp_field && totp_field['value']

      seed = totp_field['value'].first

      # Generate current code
      code = KeeperSecretsManager::TOTP.generate_code(seed)
      puts "  #{record.title}: #{code}"

      # Show time remaining
      time_remaining = 30 - (Time.now.to_i % 30)
      puts "    Valid for: #{time_remaining} seconds"
    end
  end

  puts "\n3. Using TOTP via notation:"
  if totp_records.any?
    uid = totp_records.first.uid
    begin
      totp_url = secrets_manager.get_notation("keeper://#{uid}/field/oneTimeCode")
      puts "  TOTP URL: #{totp_url}"
    rescue StandardError => e
      puts "  Error: #{e.message}"
    end
  end

  puts "\n4. TOTP URL format:"
  puts '  Standard TOTP seeds can be imported from URLs:'
  puts '  otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'

  puts "\n5. Manual TOTP setup:"
  puts '  If base32 gem is not available:'
  puts '  1. Store the seed in a oneTimeCode field'
  puts '  2. Use the seed with Google Authenticator or similar'
  puts '  3. Or install base32 gem for SDK generation'
rescue StandardError => e
  puts "Error: #{e.message}"
  puts "\nMake sure 'base32' gem is installed for TOTP support"
end

puts "\n=== TOTP Tips ==="
puts '- TOTP codes change every 30 seconds'
puts '- Store TOTP seeds in oneTimeCode fields'
puts '- Seeds are typically base32 encoded'
puts '- Compatible with Google Authenticator'
puts '- Keep TOTP seeds secure like passwords'
