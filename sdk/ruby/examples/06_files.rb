#!/usr/bin/env ruby

# Files Example - Upload and download file attachments

require 'keeper_secrets_manager'
require 'tempfile'

# Initialize
config = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG'
secrets_manager = KeeperSecretsManager.from_config(config)

puts "=== File Operations Example ==="

# 1. Find records with files
puts "\n1. Finding records with files..."
secrets = secrets_manager.get_secrets
records_with_files = secrets.select { |s| s.files && s.files.any? }

if records_with_files.empty?
  puts "No records with files found. Upload example will create one."
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
    begin
      # Download the file
      downloaded = secrets_manager.download_file(file)
      
      # Save to disk
      filename = downloaded['name'] || 'downloaded_file'
      File.write(filename, downloaded['data'])
      
      puts "✓ Downloaded: #{filename} (#{downloaded['size']} bytes)"
      puts "  Type: #{downloaded['type']}"
      
      # Clean up
      File.delete(filename) if File.exist?(filename)
      
    rescue => e
      puts "✗ Download failed: #{e.message}"
    end
  end
end

# 3. Upload a file
puts "\n3. Uploading a file..."
begin
  # Create a test file
  test_content = "This is a test file created at #{Time.now}\n"
  test_content += "It contains some sample data for demonstration.\n"
  
  # Create or find a record to attach the file to
  record = secrets.first || begin
    # Create a new record if none exist
    uid = secrets_manager.create_secret({
      type: 'login',
      title: 'File Upload Test',
      fields: [
        { type: 'login', value: ['test@example.com'] },
        { type: 'password', value: ['test123'] }
      ]
    })
    secrets_manager.get_secret_by_uid(uid)
  end
  
  puts "Uploading to record: #{record.title}"
  
  # Upload the file
  file_uid = secrets_manager.upload_file(
    owner_record_uid: record.uid,
    file_name: 'test_document.txt',
    file_data: test_content,
    mime_type: 'text/plain'
  )
  
  puts "✓ Uploaded file with UID: #{file_uid}"
  
  # Verify by downloading
  updated_record = secrets_manager.get_secret_by_uid(record.uid)
  new_file = updated_record.files.find { |f| f['fileUid'] == file_uid }
  
  if new_file
    downloaded = secrets_manager.download_file(new_file)
    puts "✓ Verified: #{downloaded['name']}"
  end
  
rescue => e
  puts "✗ Upload failed: #{e.message}"
  puts "  Note: File upload requires write permissions"
end

# 4. Working with different file types
puts "\n4. File Type Examples:"
puts "  Text files: .txt, .log, .conf"
puts "  Documents: .pdf, .doc, .docx"
puts "  Images: .jpg, .png, .gif"
puts "  Archives: .zip, .tar.gz"
puts "  Keys/Certs: .pem, .key, .crt"

# 5. File size considerations
puts "\n5. File Size Tips:"
puts "  - Maximum file size depends on your vault settings"
puts "  - Large files may take time to upload/download"
puts "  - Consider compression for large text files"
puts "  - Binary files are handled automatically"

# Example: Upload a certificate file
puts "\n6. Certificate Upload Example:"
cert_example = <<~CERT
  -----BEGIN CERTIFICATE-----
  MIIDXTCCAkWgAwIBAgIJAKLdQVPy90WJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
  ... (certificate content) ...
  -----END CERTIFICATE-----
CERT

puts "  # Upload a certificate"
puts "  file_uid = secrets_manager.upload_file("
puts "    owner_record_uid: record.uid,"
puts "    file_name: 'server.crt',"
puts "    file_data: cert_content,"
puts "    mime_type: 'application/x-x509-ca-cert'"
puts "  )"

puts "\n=== Tips ==="
puts "- Files are attached to records (you need a record first)"
puts "- File data is encrypted before upload"
puts "- Download returns decrypted file content"
puts "- MIME type helps with file handling but is optional"