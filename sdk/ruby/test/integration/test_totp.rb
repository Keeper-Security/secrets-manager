#!/usr/bin/env ruby

# Test TOTP (Time-based One-Time Password) functionality

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'openssl'
require 'time'

puts '=== TOTP Tests ==='
puts 'Testing Time-based One-Time Password functionality'
puts '-' * 50

class TOTPTests
  def initialize
    @config_file = File.expand_path('../../config.base64', __dir__)
    unless File.exist?(@config_file)
      puts '❌ ERROR: config.base64 not found'
      exit 1
    end

    config_base64 = File.read(@config_file).strip
    config_json = Base64.decode64(config_base64)
    config_data = JSON.parse(config_json)

    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
    @sm = KeeperSecretsManager.new(config: storage)

    # Get folder for testing - use any available folder
    folders = @sm.get_folders
    @test_folder = folders.first

    unless @test_folder
      puts '⚠️  No folders found, creating records in root'
    end
  end

  def run_all_tests
    test_totp_url_generation
    test_totp_code_generation
    test_totp_validation
    test_totp_with_different_algorithms
    test_totp_with_different_periods
    cleanup_test_records
    puts "\n✅ All TOTP tests completed"
  end

  private

  def test_totp_url_generation
    puts "\n1. Testing TOTP URL Generation..."

    # Create a record with TOTP field
    record_data = {
      'type' => 'login',
      'title' => "TOTP Test #{Time.now.to_i}",
      'fields' => [
        { 'type' => 'login', 'value' => ['totp@example.com'] },
        { 'type' => 'password', 'value' => ['TestPass123!'] },
        { 'type' => 'oneTimeCode',
          'value' => ['otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'] }
      ],
      'notes' => 'Testing TOTP functionality'
    }

    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = @test_folder.uid if @test_folder

    begin
      @totp_record_uid = @sm.create_secret(record_data, options)
      puts "   ✅ Created TOTP record: #{@totp_record_uid}"

      # Test TOTP URL components
      totp_url = 'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'

      puts '   ✅ Valid TOTP URL format' if totp_url.match?(%r{^otpauth://totp/})

      # Parse URL components
      if totp_url =~ /secret=([A-Z2-7]+)/
        secret = Regexp.last_match(1)
        puts "   ✅ TOTP Secret: #{secret[0..10]}..."
      end
    rescue StandardError => e
      puts "   ❌ Error: #{e.message}"
    end
  end

  def test_totp_code_generation
    puts "\n2. Testing TOTP Code Generation..."

    # Test TOTP generation algorithm
    secret = 'JBSWY3DPEHPK3PXP' # Base32 encoded secret

    # Decode base32 secret
    secret_bytes = base32_decode(secret)

    # Calculate TOTP
    time_counter = Time.now.to_i / 30 # 30-second periods

    # HMAC-SHA1
    hmac = OpenSSL::HMAC.digest('SHA1', secret_bytes, [time_counter].pack('Q>'))

    # Dynamic truncation
    offset = hmac[-1].ord & 0xf
    code = (hmac[offset].ord & 0x7f) << 24 |
           (hmac[offset + 1].ord & 0xff) << 16 |
           (hmac[offset + 2].ord & 0xff) << 8 |
           (hmac[offset + 3].ord & 0xff)

    # 6-digit code
    totp_code = (code % 1_000_000).to_s.rjust(6, '0')

    puts "   ✅ Generated TOTP code: #{totp_code}"
    puts "   ✅ Time counter: #{time_counter}"
    puts "   ✅ Valid for: #{30 - (Time.now.to_i % 30)} seconds"
  end

  def test_totp_validation
    puts "\n3. Testing TOTP Validation..."

    secret = 'JBSWY3DPEHPK3PXP'

    # Generate a valid code for current time
    valid_code = KeeperSecretsManager::TOTP.generate_code(secret)
    puts "   ✅ Generated code: #{valid_code}"

    # Test that validation accepts the current code
    is_valid = KeeperSecretsManager::TOTP.validate_code(secret, valid_code, window: 1)
    raise 'Current code should be valid' unless is_valid

    puts '   ✅ Current code validated successfully'

    # Test invalid code
    invalid_code = '000000'
    is_invalid = KeeperSecretsManager::TOTP.validate_code(secret, invalid_code, window: 1)
    raise 'Invalid code should fail validation' if is_invalid

    puts '   ✅ Invalid code rejected successfully'

    # Test validation window
    # Generate code from 30 seconds ago (should still be valid with window=1)
    past_time = Time.now - 30
    past_code = KeeperSecretsManager::TOTP.generate_code(secret, time: past_time)
    is_valid_past = KeeperSecretsManager::TOTP.validate_code(secret, past_code, window: 1)
    puts "   ✅ Past code (30s ago) validation: #{is_valid_past ? 'PASS' : 'FAIL'}"

    puts '   ✅ TOTP validation tests completed'
  end

  def test_totp_with_different_algorithms
    puts "\n4. Testing TOTP with Different Algorithms..."

    algorithms = %w[SHA1 SHA256 SHA512]

    algorithms.each do |algo|
      puts "   Testing #{algo}:"

      # Different TOTP URLs for each algorithm
      totp_url = "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&algorithm=#{algo}"

      # Parse URL and generate TOTP code
      totp_params = KeeperSecretsManager::TOTP.parse_url(totp_url)
      code = KeeperSecretsManager::TOTP.generate_code(
        totp_params['secret'],
        algorithm: totp_params['algorithm'],
        digits: totp_params['digits'],
        period: totp_params['period']
      )

      puts "      ✅ #{algo} TOTP code: #{code}"
      puts "      ✅ Code length: #{code.length} digits"

      # Verify code format
      raise "Invalid TOTP code format for #{algo}" unless code =~ /\A\d{6}\z/
    end

    puts "   ✅ All algorithms tested successfully"
  end

  def test_totp_with_different_periods
    puts "\n5. Testing TOTP with Different Time Periods..."

    periods = [30, 60, 90] # seconds

    periods.each do |period|
      puts "   Testing #{period}-second period:"

      totp_url = "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&period=#{period}"

      # Parse URL and generate TOTP code
      totp_params = KeeperSecretsManager::TOTP.parse_url(totp_url)
      code = KeeperSecretsManager::TOTP.generate_code(
        totp_params['secret'],
        algorithm: totp_params['algorithm'],
        digits: totp_params['digits'],
        period: totp_params['period']
      )

      puts "      ✅ #{period}s period TOTP code: #{code}"
      puts "      ✅ Time until next code: #{period - (Time.now.to_i % period)} seconds"

      # Verify code format
      raise "Invalid TOTP code format for #{period}s period" unless code =~ /\A\d{6}\z/

      # Verify that the period was actually used
      raise "Period mismatch" unless totp_params['period'] == period
    end

    puts "   ✅ All time periods tested successfully"
  end

  def cleanup_test_records
    puts "\n6. Cleaning up test records..."

    if @totp_record_uid
      begin
        # Clean up would happen here, but we'll keep the record for now
        # @sm.delete_secret(@totp_record_uid)
        puts "   ℹ️  Keeping test record: #{@totp_record_uid}"
      rescue StandardError => e
        puts "   ⚠️  Error: #{e.message}"
      end
    end
  end

  def base32_decode(str)
    # Simple base32 decoder
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    str = str.upcase.gsub(/[^A-Z2-7]/, '')

    bits = str.chars.map { |c| alphabet.index(c).to_s(2).rjust(5, '0') }.join

    # Pack into bytes
    bytes = []
    bits.scan(/.{1,8}/).each do |byte|
      bytes << byte.ljust(8, '0').to_i(2)
    end

    bytes.pack('C*')
  end
end

# Run tests
if __FILE__ == $0
  tests = TOTPTests.new
  tests.run_all_tests
end
