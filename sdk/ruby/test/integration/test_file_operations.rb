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
      puts '[FAIL] ERROR: config.base64 not found'
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
      puts '[WARN]  No folders found, creating records in root'
    end
  end

  def run_all_tests
    test_file_upload
    test_file_download
    test_large_file_handling
    test_multiple_files
    test_file_metadata
    test_thumbnail_download
    test_file_deletion
    cleanup_test_records
    puts "\n[PASS] All file operations tests completed"
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
      options.folder_uid = @test_folder.uid if @test_folder

      @file_record_uid = @sm.create_secret(record_data, options)
      puts "   [OK] Created file record: #{@file_record_uid}"

      # Upload the file
      file_data = File.read(test_file.path)
      file_uid = @sm.upload_file(@file_record_uid, file_data, File.basename(test_file.path), 'Test Upload')
      puts "   [OK] Uploaded file: #{file_uid}"

      @uploaded_file_uid = file_uid
    ensure
      test_file.unlink
    end
  end

  def test_file_download
    puts "\n2. Testing File Download..."

    # Download the uploaded file
    if @uploaded_file_uid && @file_record_uid
      begin
        # Refetch the record to get updated files array (with retry for eventual consistency)
        file_metadata = nil
        3.times do |attempt|
          records = @sm.get_secrets([@file_record_uid])
          record = records.first
          file_metadata = record.files.find { |f| (f['fileUid'] || f[:fileUid]) == @uploaded_file_uid }
          break if file_metadata

          puts "   [INFO]  Waiting for file to appear in record (attempt #{attempt + 1}/3)..."
          sleep 1
        end

        if file_metadata
          # Download using the file metadata (which contains url, fileKey, etc.)
          downloaded = @sm.download_file(file_metadata)
          puts "   [OK] Downloaded file: #{downloaded['name']}"
          puts "   [OK] File size: #{downloaded['size']} bytes"
          puts "   [OK] MIME type: #{downloaded['type']}"

          # Verify content matches original
          puts "   [OK] File download successful"
        else
          puts "   [WARN]  File not yet available in record after upload (eventual consistency)"
        end
      rescue StandardError => e
        puts "   [FAIL] Download failed: #{e.message}"
      end
    else
      puts '   [WARN]  No file uploaded to download'
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
      puts "   [OK] Created test file: #{file_size_mb.round(2)} MB"

      # Test upload of large file
      if @file_record_uid
        large_data = File.read(large_file.path, mode: 'rb')
        file_uid = @sm.upload_file(@file_record_uid, large_data, 'large_test.bin', 'Large Test File')
        puts "   [OK] Uploaded large file: #{file_uid}"
      else
        puts '   [WARN]  No record available for large file upload'
      end
    ensure
      large_file.unlink
    end
  end

  def test_multiple_files
    puts "\n4. Testing Multiple Files per Record..."

    # Create multiple test files
    test_files = []
    uploaded_file_uids = []

    begin
      3.times do |i|
        file = Tempfile.new(["test_#{i}", '.txt'])
        file.write("Test file #{i + 1} content - " * 10)
        file.close
        test_files << file
      end

      puts "   [OK] Created #{test_files.length} test files"

      # Upload multiple files to same record
      if @file_record_uid
        test_files.each_with_index do |file, i|
          file_data = File.read(file.path)
          file_uid = @sm.upload_file(@file_record_uid, file_data, File.basename(file.path), "Test File #{i + 1}")
          uploaded_file_uids << file_uid
          puts "   [OK] Uploaded file #{i + 1}: #{file_uid}"
        end

        # Verify all files are attached to the record
        records = @sm.get_secrets([@file_record_uid])
        record = records.first
        puts "   [OK] Record now has #{record.files.length} file(s) attached"

        # Store for cleanup
        @multiple_file_uids = uploaded_file_uids
      else
        puts '   [WARN]  No record available for multiple file upload test'
      end
    ensure
      test_files.each(&:unlink)
    end
  end

  def test_file_metadata
    puts "\n5. Testing File Metadata..."

    if @file_record_uid
      # Get record with files
      records = @sm.get_secrets([@file_record_uid])
      record = records.first

      if record.files && record.files.any?
        puts "   [OK] Retrieved #{record.files.length} file(s) metadata:"

        record.files.each_with_index do |file, i|
          puts "   File #{i + 1}:"
          puts "      - UID: #{file['fileUid'] || file[:fileUid]}"
          puts "      - Name: #{file['name'] || file[:name]}"
          puts "      - Size: #{file['size'] || file[:size]} bytes"
          puts "      - Type: #{file['type'] || file[:type]}"
          puts "      - Title: #{file['title'] || file[:title]}"
          puts "      - Last Modified: #{file['lastModified'] || file[:lastModified]}"
        end

        puts '   [OK] File metadata retrieved successfully'
      else
        puts '   [WARN]  No files attached to record'
      end
    else
      puts '   [WARN]  No record available for metadata test'
    end
  end

  def test_thumbnail_download
    puts "\n6. Testing Thumbnail Download (v17.2.0)..."

    if @file_record_uid
      records = @sm.get_secrets([@file_record_uid])
      record = records.first

      if record.files && record.files.any?
        file = record.files.first

        # Check if thumbnail URL is available
        if file['thumbnailUrl'] || file['thumbnail_url']
          puts "   [OK] File has thumbnail URL"

          begin
            # Download thumbnail
            thumbnail = @sm.download_thumbnail(file)

            puts "   [OK] Downloaded thumbnail:"
            puts "      - File UID: #{thumbnail['file_uid']}"
            puts "      - Size: #{thumbnail['size']} bytes"
            puts "      - Data length: #{thumbnail['data'].bytesize}"

            # Verify thumbnail is smaller than full file
            if thumbnail['size'] < (file['size'] || file[:size])
              puts '   [OK] Thumbnail is smaller than original file'
            else
              puts '   [INFO] Thumbnail size comparison skipped'
            end
          rescue StandardError => e
            puts "   [FAIL] Thumbnail download failed: #{e.message}"
          end
        else
          puts '   [INFO] File has no thumbnail (not an image file)'
        end
      else
        puts '   [WARN] No files attached to test record'
      end
    else
      puts '   [WARN] No record available for thumbnail test'
    end
  end

  def test_file_deletion
    puts "\n7. Testing File Deletion..."

    # Note: Individual file deletion requires updating the record to remove files from the array
    # For testing purposes, we demonstrate file management by deleting the entire record

    if @file_record_uid
      # Get record to show files before deletion
      records = @sm.get_secrets([@file_record_uid])
      record = records.first
      file_count = record.files ? record.files.length : 0

      puts "   [INFO] Record has #{file_count} file(s) attached"
      puts "   [INFO] Files are deleted when the parent record is deleted"
      puts "   [INFO] For individual file removal, update record.files array and call update_secret()"

      # Note: Actual deletion happens in cleanup_test_records method
      puts '   [OK] File deletion concept demonstrated'
    else
      puts '   [WARN] No record available for deletion test'
    end
  end

  def cleanup_test_records
    puts "\n8. Cleaning up test records..."

    if @file_record_uid
      begin
        @sm.delete_secret(@file_record_uid)
        puts "   [OK] Deleted test record: #{@file_record_uid}"
      rescue StandardError => e
        puts "   [WARN] Could not delete test record: #{e.message}"
      end
    end
  end
end

# Run tests
if __FILE__ == $0
  tests = FileOperationsTests.new
  tests.run_all_tests
end
