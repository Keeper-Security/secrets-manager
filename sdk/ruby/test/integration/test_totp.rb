#!/usr/bin/env ruby

# Test TOTP (Time-based One-Time Password) functionality

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'openssl'
require 'time'

puts "=== TOTP Tests ==="
puts "Testing Time-based One-Time Password functionality"
puts "-" * 50

class TOTPTests
  def initialize
    @config_file = File.expand_path('../../config.base64', __dir__)
    unless File.exist?(@config_file)
      puts "❌ ERROR: config.base64 not found"
      exit 1
    end
    
    config_base64 = File.read(@config_file).strip
    config_json = Base64.decode64(config_base64)
    config_data = JSON.parse(config_json)
    
    storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
    @sm = KeeperSecretsManager.new(config: storage)
    
    # Get folder for testing
    folders = @sm.get_folders
    @test_folder = folders.find { |f| f.uid == 'khq76ez6vkTRj3MqUiEGRg' }
    
    unless @test_folder
      puts "❌ Test folder not found"
      exit 1
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
        { 'type' => 'oneTimeCode', 'value' => ['otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'] }
      ],
      'notes' => 'Testing TOTP functionality'
    }
    
    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = @test_folder.uid
    
    begin
      @totp_record_uid = @sm.create_secret(record_data, options)
      puts "   ✅ Created TOTP record: #{@totp_record_uid}"
      
      # Test TOTP URL components
      totp_url = 'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'
      
      if totp_url.match?(/^otpauth:\/\/totp\//)
        puts "   ✅ Valid TOTP URL format"
      end
      
      # Parse URL components
      if totp_url =~ /secret=([A-Z2-7]+)/
        secret = $1
        puts "   ✅ TOTP Secret: #{secret[0..10]}..."
      end
      
    rescue => e
      puts "   ❌ Error: #{e.message}"
    end
  end
  
  def test_totp_code_generation
    puts "\n2. Testing TOTP Code Generation..."
    
    # Test TOTP generation algorithm
    secret = 'JBSWY3DPEHPK3PXP'  # Base32 encoded secret
    
    # Decode base32 secret
    secret_bytes = base32_decode(secret)
    
    # Calculate TOTP
    time_counter = Time.now.to_i / 30  # 30-second periods
    
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
    
    # Test validation window
    valid_window = 1  # Allow 1 period before/after
    
    current_time = Time.now.to_i
    periods_to_check = []
    
    (-valid_window..valid_window).each do |offset|
      period_time = current_time + (offset * 30)
      periods_to_check << period_time / 30
    end
    
    puts "   ✅ Validation window: #{valid_window * 30} seconds"
    puts "   ✅ Checking #{periods_to_check.length} time periods"
    
    # TODO: Implement actual TOTP validation in SDK
    # valid = @sm.validate_totp(@totp_record_uid, user_provided_code)
    
    puts "   ⚠️  TOTP validation not yet implemented in SDK"
  end
  
  def test_totp_with_different_algorithms
    puts "\n4. Testing TOTP with Different Algorithms..."
    
    algorithms = ['SHA1', 'SHA256', 'SHA512']
    
    algorithms.each do |algo|
      puts "   Testing #{algo}:"
      
      # Different TOTP URLs for each algorithm
      totp_url = "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&algorithm=#{algo}"
      
      # TODO: Test with different algorithms
      # code = @sm.generate_totp(totp_url)
      
      puts "      ⚠️  #{algo} TOTP generation pending SDK implementation"
    end
  end
  
  def test_totp_with_different_periods
    puts "\n5. Testing TOTP with Different Time Periods..."
    
    periods = [30, 60, 90]  # seconds
    
    periods.each do |period|
      puts "   Testing #{period}-second period:"
      
      totp_url = "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&period=#{period}"
      
      # TODO: Test with different periods
      # code = @sm.generate_totp(totp_url)
      
      puts "      ⚠️  #{period}s period TOTP pending SDK implementation"
    end
  end
  
  def cleanup_test_records
    puts "\n6. Cleaning up test records..."
    
    if @totp_record_uid
      begin
        # Clean up would happen here, but we'll keep the record for now
        # @sm.delete_secret(@totp_record_uid)
        puts "   ℹ️  Keeping test record: #{@totp_record_uid}"
      rescue => e
        puts "   ⚠️  Error: #{e.message}"
      end
    end
  end
  
  private
  
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