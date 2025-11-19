#!/usr/bin/env ruby

# Comprehensive test for Keeper Notation including files, TOTP, and complex scenarios

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'
require 'tempfile'

puts '=== Comprehensive Keeper Notation Test ==='
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts '-' * 50

class NotationCompleteTest
  def initialize
    if MockHelper.mock_mode?
      @sm = MockHelper.create_mock_secrets_manager
    else
      config_file = File.expand_path('../../config.base64', __dir__)
      unless File.exist?(config_file)
        puts '❌ ERROR: config.base64 not found (set KEEPER_MOCK_MODE=true for mock testing)'
        exit 1
      end

      config_base64 = File.read(config_file).strip
      config_json = Base64.decode64(config_base64)
      config_data = JSON.parse(config_json)

      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
      @sm = KeeperSecretsManager.new(config: storage)
    end

    @parser = KeeperSecretsManager::Notation::Parser.new(@sm)
    @test_folder_uid = 'khq76ez6vkTRj3MqUiEGRg'
    @created_records = []
  end

  def run_all_tests
    test_basic_notation
    test_field_notation
    test_complex_field_notation
    test_file_notation
    test_totp_notation
    test_escape_sequences
    test_base64_notation
    test_error_cases

    cleanup_test_records
    puts "\n✅ All notation tests completed!"
  end

  private

  def test_basic_notation
    puts "\n1. Testing Basic Notation..."

    # Create test record
    record_data = {
      'type' => 'login',
      'title' => 'Notation Test Record',
      'notes' => 'Testing notation functionality',
      'fields' => [
        { 'type' => 'login', 'value' => ['test@example.com'] },
        { 'type' => 'password', 'value' => ['SecurePassword123!'] },
        { 'type' => 'url', 'value' => ['https://example.com', 'https://backup.example.com'] }
      ]
    }

    if !MockHelper.mock_mode?
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      record_uid = @sm.create_secret(record_data, options)
      @created_records << record_uid
      sleep 2
    else
      record_uid = 'gBKkeUkNMyeuLbGXXchF4Q' # Mock UID
    end

    # Test type selector
    type_value = @parser.parse("keeper://#{record_uid}/type")
    puts "   ✓ Type: #{type_value}"

    # Test title selector
    title_value = @parser.parse("keeper://#{record_uid}/title")
    puts "   ✓ Title: #{title_value}"

    # Test notes selector
    notes_value = @parser.parse("keeper://#{record_uid}/notes")
    puts "   ✓ Notes: #{notes_value[0..30]}..."

    # Test by title instead of UID
    title_result = @parser.parse('keeper://Notation Test Record/type')
    puts "   ✓ Access by title: #{title_result}"
  rescue StandardError => e
    puts "   ❌ Basic notation test failed: #{e.message}"
  end

  def test_field_notation
    puts "\n2. Testing Field Notation..."

    record_uid = MockHelper.mock_mode? ? 'gBKkeUkNMyeuLbGXXchF4Q' : @created_records.first
    return puts '   ⚠️  No test record available' unless record_uid

    # Test simple field access
    login = @parser.parse("keeper://#{record_uid}/field/login")
    puts "   ✓ Login field: #{login}"

    # Test field with index
    first_url = @parser.parse("keeper://#{record_uid}/field/url[0]")
    puts "   ✓ First URL: #{first_url}"

    # Test field returning all values
    all_urls = @parser.parse("keeper://#{record_uid}/field/url[]")
    puts "   ✓ All URLs: #{all_urls.inspect}"
  rescue StandardError => e
    puts "   ❌ Field notation test failed: #{e.message}"
  end

  def test_complex_field_notation
    puts "\n3. Testing Complex Field Notation..."

    # Create record with complex fields
    complex_data = {
      'type' => 'login',
      'title' => 'Complex Fields Test',
      'fields' => [
        { 'type' => 'name', 'value' => [{ 'first' => 'John', 'middle' => 'Q', 'last' => 'Public' }] },
        { 'type' => 'phone', 'value' => [
          { 'region' => 'US', 'number' => '555-1234', 'ext' => '567', 'type' => 'Mobile' },
          { 'region' => 'US', 'number' => '555-5678', 'ext' => '', 'type' => 'Home' }
        ] },
        { 'type' => 'address', 'value' => [{
          'street1' => '123 Main St',
          'street2' => 'Apt 4B',
          'city' => 'Anytown',
          'state' => 'CA',
          'zip' => '12345',
          'country' => 'US'
        }] }
      ],
      'custom' => [
        { 'type' => 'text', 'label' => 'Employee ID', 'value' => ['EMP123456'] },
        { 'type' => 'text', 'label' => 'Department', 'value' => %w[Engineering Research] }
      ]
    }

    if !MockHelper.mock_mode?
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      record_uid = @sm.create_secret(complex_data, options)
      @created_records << record_uid
      sleep 2
    else
      # For mock mode, update existing record
      record_uid = 'gBKkeUkNMyeuLbGXXchF4Q'
    end

    # Test complex field property access
    first_name = @parser.parse("keeper://#{record_uid}/field/name[0][first]")
    puts "   ✓ First name: #{first_name}"

    middle_name = @parser.parse("keeper://#{record_uid}/field/name[0][middle]")
    puts "   ✓ Middle name: #{middle_name}"

    # Test phone number access
    mobile_number = @parser.parse("keeper://#{record_uid}/field/phone[0][number]")
    puts "   ✓ Mobile number: #{mobile_number}"

    # Test custom field access
    employee_id = @parser.parse("keeper://#{record_uid}/custom_field/Employee ID")
    puts "   ✓ Employee ID: #{employee_id}"

    # Test custom field with index
    departments = @parser.parse("keeper://#{record_uid}/custom_field/Department[]")
    puts "   ✓ All departments: #{departments.inspect}"
  rescue StandardError => e
    puts "   ❌ Complex field test failed: #{e.message}"
  end

  def test_file_notation
    puts "\n4. Testing File Notation..."

    # Create record with file
    file_data = {
      'type' => 'file',
      'title' => 'File Notation Test',
      'fields' => []
    }

    if !MockHelper.mock_mode?
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      record_uid = @sm.create_secret(file_data, options)
      @created_records << record_uid
      sleep 2

      # Upload a test file
      test_content = "Test file for notation\nLine 2\nLine 3"
      file_uid = @sm.upload_file(record_uid, test_content, 'test_notation.txt', 'Test File')
      sleep 2

      # Get record to verify file attachment
      records = @sm.get_secrets([record_uid])
      if records.any? && records.first.files&.any?
        # Test file notation - returns file object
        file_obj = @parser.parse("keeper://#{record_uid}/file/test_notation.txt")
        puts "   ✓ File object retrieved: #{file_obj['name']}"
        puts "   ✓ File UID: #{file_obj['fileUid']}"

        # Download file using the UID from notation
        downloaded = @sm.download_file(file_obj['fileUid'])
        puts "   ✓ File downloaded: #{downloaded['name']}"
        puts "   ✓ File content matches: #{downloaded['data'] == test_content}"
      else
        puts '   ⚠️  File attachment not found on record'
      end
    else
      puts '   ℹ️  File notation in mock mode'
      # Mock mode doesn't have real files
      begin
        file_obj = @parser.parse('keeper://gBKkeUkNMyeuLbGXXchF4Q/file/test.txt')
        puts '   ❌ Should have failed - no files in mock record'
      rescue StandardError => e
        puts "   ✓ Correctly failed for missing file: #{e.message}"
      end
    end
  rescue StandardError => e
    puts "   ❌ File notation test failed: #{e.message}"
  end

  def test_totp_notation
    puts "\n5. Testing TOTP Notation..."

    # Create record with TOTP
    totp_data = {
      'type' => 'login',
      'title' => 'TOTP Notation Test',
      'fields' => [
        { 'type' => 'login', 'value' => ['totp@example.com'] },
        { 'type' => 'password', 'value' => ['TOTPPassword123!'] },
        { 'type' => 'oneTimeCode',
          'value' => ['otpauth://totp/Test:totp@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA1&digits=6&period=30'] }
      ]
    }

    if !MockHelper.mock_mode?
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      record_uid = @sm.create_secret(totp_data, options)
      @created_records << record_uid
      sleep 2
    else
      record_uid = 'TOTPTestRecord123456789' # Mock record with TOTP
    end

    # Get TOTP URL via notation
    totp_url = @parser.parse("keeper://#{record_uid}/field/oneTimeCode")
    puts "   ✓ TOTP URL retrieved: #{totp_url[0..50]}..."

    # Parse TOTP URL and generate code
    if totp_url && totp_url.start_with?('otpauth://')
      totp_params = KeeperSecretsManager::TOTP.parse_url(totp_url)
      code = KeeperSecretsManager::TOTP.generate_code(
        totp_params['secret'],
        algorithm: totp_params['algorithm'],
        digits: totp_params['digits'],
        period: totp_params['period']
      )
      puts "   ✓ TOTP code generated: #{code}"
      puts "   ✓ Algorithm: #{totp_params['algorithm']}"
      puts "   ✓ Digits: #{totp_params['digits']}"
      puts "   ✓ Period: #{totp_params['period']}s"
    end
  rescue StandardError => e
    puts "   ❌ TOTP notation test failed: #{e.message}"
  end

  def test_escape_sequences
    puts "\n6. Testing Escape Sequences..."

    # Create record with special characters
    special_data = {
      'type' => 'login',
      'title' => 'Record/With/Slashes',
      'fields' => [
        { 'type' => 'login', 'value' => ['user@example.com'] }
      ],
      'custom' => [
        { 'type' => 'text', 'label' => 'Path/With/Slashes', 'value' => ['C:\\Users\\Test'] },
        { 'type' => 'text', 'label' => 'Array[0]', 'value' => ['Special value'] }
      ]
    }

    if !MockHelper.mock_mode?
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      record_uid = @sm.create_secret(special_data, options)
      @created_records << record_uid
      sleep 2

      # Test escaped title
      escaped_title = 'Record\\/With\\/Slashes'
      type_value = @parser.parse("keeper://#{escaped_title}/type")
      puts "   ✓ Escaped title notation: #{type_value}"

      # Test escaped custom field label
      escaped_label = 'Path\\/With\\/Slashes'
      path_value = @parser.parse("keeper://#{record_uid}/custom_field/#{escaped_label}")
      puts "   ✓ Escaped field label: #{path_value}"

      # Test field with brackets in label
      bracket_value = @parser.parse("keeper://#{record_uid}/custom_field/Array\\[0\\]")
      puts "   ✓ Escaped bracket label: #{bracket_value}"
    else
      puts '   ℹ️  Escape sequence testing requires live mode'
    end
  rescue StandardError => e
    puts "   ❌ Escape sequence test failed: #{e.message}"
  end

  def test_base64_notation
    puts "\n7. Testing Base64 Notation..."

    record_uid = MockHelper.mock_mode? ? 'gBKkeUkNMyeuLbGXXchF4Q' : @created_records.first
    return puts '   ⚠️  No test record available' unless record_uid

    # Create notation and encode it
    plain_notation = "keeper://#{record_uid}/field/login"
    encoded_notation = Base64.urlsafe_encode64(plain_notation, padding: false)

    # Parse base64 notation
    result = @parser.parse(encoded_notation)
    puts "   ✓ Plain notation: #{plain_notation}"
    puts "   ✓ Encoded notation: #{encoded_notation}"
    puts "   ✓ Decoded result: #{result}"
  rescue StandardError => e
    puts "   ❌ Base64 notation test failed: #{e.message}"
  end

  def test_error_cases
    puts "\n8. Testing Error Cases..."

    # Test invalid notation
    test_cases = [
      ['', 'Empty notation'],
      ['keeper://', 'Missing record'],
      ['keeper://InvalidUID', 'Non-existent record'],
      ['keeper://InvalidUID/InvalidSelector', 'Invalid selector'],
      ['keeper://gBKkeUkNMyeuLbGXXchF4Q/field', 'Missing field parameter'],
      ['keeper://gBKkeUkNMyeuLbGXXchF4Q/field/nonexistent', 'Non-existent field'],
      ['keeper://gBKkeUkNMyeuLbGXXchF4Q/field/login[999]', 'Index out of bounds'],
      ['keeper://gBKkeUkNMyeuLbGXXchF4Q/field/login[abc]', 'Invalid index'],
      ['keeper://test\\', 'Invalid escape sequence'],
      ['keeper://test/field/test[', 'Unclosed bracket']
    ]

    test_cases.each do |notation, description|
      @parser.parse(notation)
      puts "   ❌ #{description} - should have failed"
    rescue StandardError => e
      puts "   ✓ #{description} - correctly failed"
    end
  end

  def cleanup_test_records
    puts "\n9. Cleaning up test records..."

    @created_records.each do |uid|
      @sm.delete_secret(uid)
      print '.'
    rescue StandardError => e
      print 'X'
    end
    puts "\n   ✓ Cleanup completed" if @created_records.any?
  end
end

# Run tests
if __FILE__ == $0
  test = NotationCompleteTest.new
  test.run_all_tests
end
