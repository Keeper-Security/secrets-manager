#!/usr/bin/env ruby

# Test file upload and download functionality

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'
require 'tempfile'

puts "=== File Upload/Download Test ==="
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts "-" * 50

class FileUploadDownloadTest
  def initialize
    if MockHelper.mock_mode?
      @sm = MockHelper.create_mock_secrets_manager
    else
      # Use real config for live testing
      config_file = File.expand_path('../../config.base64', __dir__)
      unless File.exist?(config_file)
        puts "❌ ERROR: config.base64 not found (set KEEPER_MOCK_MODE=true for mock testing)"
        exit 1
      end
      
      config_base64 = File.read(config_file).strip
      config_json = Base64.decode64(config_base64)
      config_data = JSON.parse(config_json)
      
      storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
      @sm = KeeperSecretsManager.new(config: storage)
    end
    
    @test_folder_uid = 'khq76ez6vkTRj3MqUiEGRg'
  end
  
  def run_test
    if MockHelper.mock_mode?
      test_mock_file_operations
    else
      test_real_file_operations
    end
  end
  
  private
  
  def test_mock_file_operations
    puts "\n=== Mock File Operations Test ==="
    
    # Create a test record
    record_data = {
      'type' => 'login',
      'title' => 'File Upload Test Record',
      'fields' => [
        { 'type' => 'login', 'value' => ['test@example.com'] },
        { 'type' => 'password', 'value' => ['TestPassword123!'] }
      ]
    }
    
    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = @test_folder_uid
    
    puts "1. Creating test record..."
    record_uid = @sm.create_secret(record_data, options)
    puts "   ✓ Created record: #{record_uid}"
    
    # Mock file upload
    puts "\n2. Testing file upload (mock)..."
    file_content = "This is a test file content\nLine 2\nLine 3"
    file_name = "test_document.txt"
    
    # In mock mode, we simulate the upload
    file_uid = MockHelper.mock_file_upload(record_uid, {
      name: file_name,
      content: file_content,
      mime_type: 'text/plain'
    })['fileUid']
    
    puts "   ✓ Uploaded file: #{file_uid}"
    
    # Mock file download
    puts "\n3. Testing file download (mock)..."
    downloaded = MockHelper.mock_file_download(file_uid)
    
    puts "   ✓ Downloaded file: #{downloaded['fileName']}"
    puts "   ✓ File size: #{downloaded['fileSize']} bytes"
    puts "   ✓ MIME type: #{downloaded['mimeType']}"
    
    # Cleanup
    puts "\n4. Cleaning up..."
    @sm.delete_secret(record_uid)
    puts "   ✓ Deleted test record"
    
    puts "\n✅ Mock file operations test completed successfully!"
  end
  
  def test_real_file_operations
    puts "\n=== Real File Operations Test ==="
    
    begin
      # Create a test record
      record_data = {
        'type' => 'login',
        'title' => "File Upload Test - #{Time.now.strftime('%Y%m%d_%H%M%S')}",
        'fields' => [
          { 'type' => 'login', 'value' => ['test@example.com'] },
          { 'type' => 'password', 'value' => ['TestPassword123!'] },
          { 'type' => 'url', 'value' => ['https://example.com'] }
        ],
        'notes' => 'Testing file upload/download functionality'
      }
      
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder_uid
      
      puts "1. Creating test record..."
      record_uid = @sm.create_secret(record_data, options)
      puts "   ✓ Created record: #{record_uid}"
      
      # Wait a moment for record to be available
      sleep 2
      
      # Test file upload
      puts "\n2. Testing file upload..."
      file_content = "Test file content generated at #{Time.now}\nThis is line 2\nThis is line 3\n"
      file_name = "test_upload_#{Time.now.to_i}.txt"
      
      file_uid = @sm.upload_file(
        record_uid,
        file_content,
        file_name,
        "Test Upload File"
      )
      
      puts "   ✓ Uploaded file: #{file_uid}"
      puts "   ✓ File name: #{file_name}"
      puts "   ✓ File size: #{file_content.bytesize} bytes"
      
      # Wait for file to be processed
      sleep 2
      
      # Test file download
      puts "\n3. Testing file download..."
      begin
        downloaded = @sm.download_file(file_uid)
        
        puts "   ✓ Downloaded file: #{downloaded['name']}"
        puts "   ✓ File size: #{downloaded['size']} bytes"
        puts "   ✓ MIME type: #{downloaded['mimeType']}"
        
        # Verify content
        if downloaded['data'] == file_content
          puts "   ✓ File content matches!"
        else
          puts "   ❌ File content mismatch!"
          puts "   Expected: #{file_content.inspect}"
          puts "   Got: #{downloaded['data'].inspect}"
        end
      rescue => e
        puts "   ❌ Download failed: #{e.message}"
        puts "   Note: File may need more time to be available on server"
      end
      
      # Test with binary file
      puts "\n4. Testing binary file upload..."
      binary_content = Random.bytes(1024)  # 1KB of random binary data
      binary_name = "test_binary_#{Time.now.to_i}.bin"
      
      binary_uid = @sm.upload_file(
        record_uid,
        binary_content,
        binary_name,
        "Test Binary File"
      )
      
      puts "   ✓ Uploaded binary file: #{binary_uid}"
      puts "   ✓ Binary file size: #{binary_content.bytesize} bytes"
      
      # Cleanup
      puts "\n5. Cleaning up..."
      begin
        @sm.delete_secret(record_uid)
        puts "   ✓ Deleted test record and files"
      rescue => e
        puts "   ⚠️  Cleanup failed: #{e.message}"
      end
      
      puts "\n✅ Real file operations test completed!"
      
    rescue => e
      puts "\n❌ Test failed: #{e.message}"
      puts e.backtrace.first(5)
      
      # Try to cleanup on error
      if defined?(record_uid) && record_uid
        begin
          @sm.delete_secret(record_uid)
          puts "   ✓ Cleaned up test record"
        rescue
          # Ignore cleanup errors
        end
      end
    end
  end
end

# Run the test
if __FILE__ == $0
  test = FileUploadDownloadTest.new
  test.run_test
end