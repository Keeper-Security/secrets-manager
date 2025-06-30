#!/usr/bin/env ruby

# Test newly implemented features: file download and TOTP

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'

puts "=== Testing New Features ==="
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts "-" * 50

class NewFeaturesTest
  def initialize
    @sm = MockHelper.create_mock_secrets_manager
  end
  
  def run_all_tests
    test_totp_functionality
    test_file_operations
    puts "\n✅ All new feature tests completed"
  end
  
  private
  
  def test_totp_functionality
    puts "\n1. Testing TOTP Implementation..."
    
    # Test secret generation
    secret = KeeperSecretsManager::TOTP.generate_secret
    puts "   ✓ Generated TOTP secret: #{secret[0..10]}..."
    
    # Test URL parsing
    totp_url = 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'
    parsed = KeeperSecretsManager::TOTP.parse_url(totp_url)
    puts "   ✓ Parsed TOTP URL:"
    puts "     - Account: #{parsed['account']}"
    puts "     - Issuer: #{parsed['issuer']}"
    puts "     - Algorithm: #{parsed['algorithm']}"
    
    # Test code generation
    code = KeeperSecretsManager::TOTP.generate_code('JBSWY3DPEHPK3PXP')
    puts "   ✓ Generated TOTP code: #{code}"
    
    # Test code validation
    valid = KeeperSecretsManager::TOTP.validate_code('JBSWY3DPEHPK3PXP', code)
    puts "   ✓ Code validation: #{valid ? 'VALID' : 'INVALID'}"
    
    # Test different algorithms
    ['SHA1', 'SHA256', 'SHA512'].each do |algo|
      code = KeeperSecretsManager::TOTP.generate_code('JBSWY3DPEHPK3PXP', algorithm: algo)
      puts "   ✓ Generated #{algo} code: #{code}"
    end
    
    # Test URL generation
    url = KeeperSecretsManager::TOTP.generate_url(
      'user@example.com',
      secret,
      issuer: 'Keeper Test',
      algorithm: 'SHA256',
      digits: 8
    )
    puts "   ✓ Generated TOTP URL: #{url[0..50]}..."
    
  rescue => e
    puts "   ❌ TOTP test failed: #{e.message}"
    puts e.backtrace.first(3)
  end
  
  def test_file_operations
    puts "\n2. Testing File Operations..."
    
    if MockHelper.mock_mode?
      puts "   ℹ️  File operations in mock mode"
      
      # Test mock file upload
      file_info = MockHelper.mock_file_upload('test_record_uid', {
        name: 'test_document.pdf',
        content: 'Mock PDF content',
        size: 1024,
        mime_type: 'application/pdf'
      })
      puts "   ✓ Mock file upload: #{file_info['fileName']}"
      
      # Test mock file download
      download_info = MockHelper.mock_file_download(file_info['fileUid'])
      puts "   ✓ Mock file download: #{download_info['fileName']}"
    else
      puts "   ℹ️  Testing with real API (if implemented)"
      
      # Note: Real file operations would require:
      # 1. A record with file attachments
      # 2. Proper file UIDs
      # 3. Server support for file endpoints
      
      begin
        # This will likely fail until server endpoints are confirmed
        # file_data = @sm.download_file('some_file_uid')
        puts "   ⚠️  Real file operations require server support"
      rescue => e
        puts "   ℹ️  File operations not available: #{e.message}"
      end
    end
  end
end

# Run tests
if __FILE__ == $0
  test = NewFeaturesTest.new
  test.run_all_tests
end