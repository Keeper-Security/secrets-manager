#!/usr/bin/env ruby

# Test file upload and download operations

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'tempfile'
require 'fileutils'

puts '=== File Operations Tests ==='
puts 'Testing file upload, download, and management'
puts '-' * 50

class FileOperationsTests
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

    # Get folder for testing
    folders = @sm.get_folders
    @test_folder = folders.find { |f| f.uid == 'khq76ez6vkTRj3MqUiEGRg' }

    unless @test_folder
      puts '❌ Test folder not found'
      exit 1
    end
  end

  def run_all_tests
    test_file_upload
    test_file_download
    test_large_file_handling
    test_multiple_files
    test_file_metadata
    test_file_deletion
    cleanup_test_records
    puts "\n✅ All file operations tests completed"
  end

  private

  def test_file_upload
    puts "\n1. Testing File Upload..."

    # Create a test file
    test_content = "This is a test file for Keeper Secrets Manager Ruby SDK\n" * 10
    test_file = Tempfile.new(['test_upload', '.txt'])
    test_file.write(test_content)
    test_file.close

    begin
      # Create a record with file attachment
      record_data = {
        'type' => 'file',
        'title' => "File Upload Test #{Time.now.to_i}",
        'fields' => [],
        'notes' => 'Testing file upload functionality'
      }

      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder.uid

      @file_record_uid = @sm.create_secret(record_data, options)
      puts "   ✅ Created file record: #{@file_record_uid}"

      # Upload the file
      file_data = File.read(test_file.path)
      file_uid = @sm.upload_file(@file_record_uid, file_data, File.basename(test_file.path), 'Test Upload')
      puts "   ✅ Uploaded file: #{file_uid}"

      @uploaded_file_uid = file_uid
    ensure
      test_file.unlink
    end
  end

  def test_file_download
    puts "\n2. Testing File Download..."

    # Download the uploaded file
    if @uploaded_file_uid
      begin
        file_data = @sm.download_file(@uploaded_file_uid)
        puts "   ✅ Downloaded file: #{file_data['name']}"
        puts "   ✅ File size: #{file_data['size']} bytes"
        puts "   ✅ MIME type: #{file_data['mimeType']}"

        # Save to temp file to verify
        temp_file = Tempfile.new(['downloaded', File.extname(file_data['name'])])
        temp_file.write(file_data['data'])
        temp_file.close
        puts "   ✅ Saved to: #{temp_file.path}"
        temp_file.unlink
      rescue StandardError => e
        puts "   ❌ Download failed: #{e.message}"
      end
    else
      puts '   ⚠️  No file uploaded to download'
    end
  end

  def test_large_file_handling
    puts "\n3. Testing Large File Handling..."

    # Create a large test file (5MB)
    large_file = Tempfile.new(['large_test', '.bin'])

    begin
      # Write 5MB of random data
      5.times do
        large_file.write(Random.bytes(1024 * 1024))
      end
      large_file.close

      file_size_mb = File.size(large_file.path) / (1024.0 * 1024.0)
      puts "   ✅ Created test file: #{file_size_mb.round(2)} MB"

      # Test upload of large file
      if @file_record_uid
        large_data = File.read(large_file.path, mode: 'rb')
        file_uid = @sm.upload_file(@file_record_uid, large_data, 'large_test.bin', 'Large Test File')
        puts "   ✅ Uploaded large file: #{file_uid}"
      else
        puts '   ⚠️  No record available for large file upload'
      end
    ensure
      large_file.unlink
    end
  end

  def test_multiple_files
    puts "\n4. Testing Multiple Files per Record..."

    # Create multiple test files
    test_files = []

    begin
      3.times do |i|
        file = Tempfile.new(["test_#{i}", '.txt'])
        file.write("Test file #{i + 1} content")
        file.close
        test_files << file
      end

      puts "   ✅ Created #{test_files.length} test files"

      # TODO: Upload multiple files to same record
      # test_files.each do |file|
      #   @sm.upload_file(@file_record_uid, file.path)
      # end

      puts '   ⚠️  Multiple file upload test pending SDK implementation'
    ensure
      test_files.each(&:unlink)
    end
  end

  def test_file_metadata
    puts "\n5. Testing File Metadata..."

    # Test file metadata structure
    metadata = {
      name: 'test_document.pdf',
      size: 1024 * 1024, # 1MB
      mime_type: 'application/pdf',
      last_modified: Time.now.to_i
    }

    puts '   ✅ File metadata structure:'
    metadata.each do |key, value|
      puts "      - #{key}: #{value}"
    end

    # TODO: Test actual metadata retrieval
    # if @file_record_uid
    #   files = @sm.get_file_metadata(@file_record_uid)
    #   files.each do |file|
    #     puts "   File: #{file.name}"
    #     puts "   Size: #{file.size} bytes"
    #     puts "   Type: #{file.mime_type}"
    #   end
    # end

    puts '   ⚠️  File metadata API not yet implemented in SDK'
  end

  def test_file_deletion
    puts "\n6. Testing File Deletion..."

    # TODO: Test file deletion
    # if @file_record_uid
    #   files = @sm.get_files(@file_record_uid)
    #   if files.any?
    #     @sm.delete_file(files.first.uid)
    #     puts "   ✅ Deleted file: #{files.first.uid}"
    #   end
    # end

    puts '   ⚠️  File deletion API not yet implemented in SDK'
  end

  def cleanup_test_records
    puts "\n7. Cleaning up test records..."

    if @file_record_uid
      begin
        @sm.delete_secret(@file_record_uid)
        puts "   ✅ Deleted test record: #{@file_record_uid}"
      rescue StandardError => e
        puts "   ⚠️  Could not delete test record: #{e.message}"
      end
    end
  end
end

# Run tests
if __FILE__ == $0
  tests = FileOperationsTests.new
  tests.run_all_tests
end
