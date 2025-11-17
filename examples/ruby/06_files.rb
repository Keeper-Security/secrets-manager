#!/usr/bin/env ruby

# Files Example - Upload and download file attachments

require 'keeper_secrets_manager'
require 'tempfile'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

puts '=== File Operations Example ==='

# 1. Find records with files
puts "\n1. Finding records with files..."
secrets = secrets_manager.get_secrets
records_with_files = secrets.select { |s| s.files && s.files.any? }

if records_with_files.empty?
  puts 'No records with files found. Upload example will create one.'
else
  puts "Found #{records_with_files.length} records with files:"
  records_with_files.each do |record|
    puts "  - #{record.title}: #{record.files.length} file(s)"
  end
end

# 2. Download files
if records_with_files.any?
  puts "\n2. Downloading files..."
  record = records_with_files.first

  record.files.each do |file|
    # Download the file
    downloaded = secrets_manager.download_file(file)

    # Save to disk
    filename = downloaded['name'] || 'downloaded_file'
    File.write(filename, downloaded['data'])

    puts "[OK] Downloaded: #{filename} (#{downloaded['size']} bytes)"
    puts "  Type: #{downloaded['type']}"

    # Clean up
    File.delete(filename) if File.exist?(filename)

  rescue StandardError => e
    puts "[FAIL] Download failed: #{e.message}"
  end
end

# 2.5. Download file thumbnails (new in v17.2.0)
if records_with_files.any?
  puts "\n2.5. Downloading file thumbnails..."
  record = records_with_files.first

  record.files.each do |file|
    # Check if thumbnail is available
    if file['thumbnailUrl'] || file['thumbnail_url']
      puts "  Downloading thumbnail for: #{file['name']}"

      begin
        thumbnail = secrets_manager.download_thumbnail(file)

        # Save thumbnail to disk
        thumb_filename = "thumb_#{file['name']}"
        File.write(thumb_filename, thumbnail['data'])

        puts "  [OK] Saved: #{thumb_filename} (#{thumbnail['size']} bytes, #{thumbnail['type']})"

        # Clean up
        File.delete(thumb_filename) if File.exist?(thumb_filename)
      rescue StandardError => e
        puts "  [FAIL] Thumbnail download failed: #{e.message}"
      end
    else
      puts "  No thumbnail available for: #{file['name']}"
    end
  end
end

# 3. Upload a file (traditional method)
puts "\n3. Uploading a file (traditional method)..."
begin
  # Create a test file
  test_content = "This is a test file created at #{Time.now}\n"
  test_content += "It contains some sample data for demonstration.\n"

  # Get a record to attach the file to
  record = secrets.first
  if record
    puts "Uploading to record: #{record.title}"

    # Upload the file (traditional method with file data)
    file_uid = secrets_manager.upload_file(
      record.uid,
      test_content,
      'test_document.txt',
      'Test Document'
    )

    puts "[OK] Uploaded file with UID: #{file_uid}"
  else
    puts '[WARN] No records available for file upload test'
  end
rescue StandardError => e
  puts "[FAIL] Upload failed: #{e.message}"
  puts '  Note: File upload requires write permissions'
end

# 3.5. Upload file from path (convenience method - NEW in v17.2.0)
puts "\n3.5. Uploading file from disk path (convenience method)..."
begin
  # Create a temporary file on disk
  temp_file = Tempfile.new(['keeper_test', '.txt'])
  temp_file.write("Test file content from disk\nCreated: #{Time.now}")
  temp_file.close

  record = secrets.first
  if record
    puts "Uploading from path: #{temp_file.path}"

    # Convenience method - reads file automatically
    file_uid = secrets_manager.upload_file_from_path(
      record.uid,
      temp_file.path,
      file_title: 'Uploaded from Disk'
    )

    puts "[OK] Uploaded file with UID: #{file_uid}"
    puts "  Filename auto-detected: #{File.basename(temp_file.path)}"
  else
    puts '[WARN] No records available for file upload test'
  end

  # Clean up
  temp_file.unlink
rescue StandardError => e
  puts "[FAIL] Upload from path failed: #{e.message}"
  temp_file&.unlink
end

# 4. Working with different file types
puts "\n4. File Type Examples:"
puts '  Text files: .txt, .log, .conf'
puts '  Documents: .pdf, .doc, .docx'
puts '  Images: .jpg, .png, .gif'
puts '  Archives: .zip, .tar.gz'
puts '  Keys/Certs: .pem, .key, .crt'

# 5. File size considerations
puts "\n5. File Size Tips:"
puts '  - Maximum file size depends on your vault settings'
puts '  - Large files may take time to upload/download'
puts '  - Consider compression for large text files'
puts '  - Binary files are handled automatically'

# Example: Upload a certificate file
puts "\n6. Certificate Upload Example:"
cert_example = <<~CERT
  -----BEGIN CERTIFICATE-----
  MIIDXTCCAkWgAwIBAgIJAKLdQVPy90WJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
  ... (certificate content) ...
  -----END CERTIFICATE-----
CERT

puts '  # Upload a certificate'
puts '  file_uid = secrets_manager.upload_file('
puts '    owner_record_uid: record.uid,'
puts "    file_name: 'server.crt',"
puts '    file_data: cert_content,'
puts "    mime_type: 'application/x-x509-ca-cert'"
puts '  )'

puts "\n=== Tips ==="
puts '- Files are attached to records (you need a record first)'
puts '- File data is encrypted before upload'
puts '- Download returns decrypted file content'
puts '- MIME type helps with file handling but is optional'
