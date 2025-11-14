#!/usr/bin/env ruby

# CRUD Operations Example - Create, Read, Update, and Delete secrets

require 'keeper_secrets_manager'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

puts '=== CRUD Operations Example ==='

# 1. CREATE - Add a new secret
puts "\n1. Creating a new secret..."
begin
  # Create a login record
  new_record = {
    type: 'login',
    title: "Test Login #{Time.now.strftime('%Y%m%d_%H%M%S')}",
    fields: [
      { type: 'login', value: ['testuser@example.com'] },
      { type: 'password', value: [KeeperSecretsManager::Utils.generate_password(length: 32)] },
      { type: 'url', value: ['https://example.com'] }
    ],
    custom: [
      { type: 'text', label: 'Environment', value: ['Testing'] }
    ],
    notes: 'Created via Ruby SDK example'
  }

  # Get the first available folder for creating the record
  folders = secrets_manager.get_folders
  folder_uid = folders.first&.uid
  raise 'No folders available. Please create a folder in your vault first.' unless folder_uid

  # Create the record with CreateOptions
  options = KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: folder_uid)
  record_uid = secrets_manager.create_secret(new_record, options)

  puts "✓ Created record with UID: #{record_uid}"
  puts "  Folder: #{folder_uid}"

  # 2. READ - Retrieve the created secret
  puts "\n2. Reading the secret..."
  secret = secrets_manager.get_secret_by_uid(record_uid)
  puts "✓ Retrieved: #{secret.title}"
  puts "  Login: #{secret.login}"
  puts "  URL: #{secret.url}"
  puts "  Custom field: #{secret.custom.first['value']}" if secret.custom.any?

  # 3. UPDATE - Modify the secret
  puts "\n3. Updating the secret..."

  # Update specific fields
  secret.password = KeeperSecretsManager::Utils.generate_password(length: 40) # New password
  secret.url = 'https://updated-example.com'
  secret.notes = "Updated on #{Time.now}"

  # Add a new custom field
  secret.custom ||= []
  secret.custom << {
    'type' => 'text',
    'label' => 'Last Updated',
    'value' => [Time.now.to_s]
  }

  # Save the updates
  secrets_manager.update_secret(secret)
  puts '✓ Updated successfully'

  # Verify the update
  updated = secrets_manager.get_secret_by_uid(record_uid)
  puts "  New URL: #{updated.url}"
  puts "  Notes: #{updated.notes}"

  # 3.5. Advanced Update - Password Rotation with Transaction Type
  puts "\n3.5. Password rotation with transaction type..."
  begin
    # Get a fresh copy of the record
    secret = secrets_manager.get_secrets([record_uid]).first

    # Generate new password
    new_password = KeeperSecretsManager::Utils.generate_password(length: 32)
    secret.password = new_password

    # Update with rotation transaction type
    update_options = KeeperSecretsManager::Dto::UpdateOptions.new(
      transaction_type: 'rotation'
    )

    secrets_manager.update_secret_with_options(secret, update_options)
    puts '✓ Password rotated with transaction tracking'
    puts "  New password: #{new_password[0..5]}..." # Show first 6 chars only

  rescue StandardError => e
    puts "✗ Error: #{e.message}"
  end

  # 3.6. Advanced Update - Remove File Links
  puts "\n3.6. Removing file attachments (if any)..."
  begin
    # Refresh the record
    secret = secrets_manager.get_secrets([record_uid]).first

    if secret.files && secret.files.any?
      # Find files to remove (e.g., files starting with "old_")
      file_uids_to_remove = secret.files
        .select { |f| f['name'] =~ /^old_/ }
        .map { |f| f['fileUid'] }

      if file_uids_to_remove.any?
        update_options = KeeperSecretsManager::Dto::UpdateOptions.new(
          transaction_type: 'general',
          links_to_remove: file_uids_to_remove
        )

        secrets_manager.update_secret_with_options(secret, update_options)
        puts "✓ Removed #{file_uids_to_remove.length} file link(s)"
      else
        puts "  (No old files to remove)"
      end
    else
      puts "  (No files attached to record)"
    end

  rescue StandardError => e
    puts "✗ Error: #{e.message}"
  end

  # 4. DELETE - Remove the secret
  puts "\n4. Deleting the secret..."
  puts 'Press Enter to delete the test record...'
  gets

  secrets_manager.delete_secret(record_uid)
  puts "✓ Deleted record: #{record_uid}"

  # Verify deletion
  begin
    secrets_manager.get_secret_by_uid(record_uid)
    puts '✗ Record still exists!'
  rescue StandardError
    puts '✓ Confirmed: Record no longer exists'
  end
rescue StandardError => e
  puts "Error: #{e.message}"
  puts 'Make sure you have write permissions in your vault'
end

# Batch operations example
puts "\n=== Batch Operations ==="
puts '1. Create multiple records at once'
puts '2. Update multiple records'
puts '3. Delete multiple records'
puts '(See documentation for batch operation examples)'

# Tips
puts "\n=== Tips ==="
puts '- Always handle errors when creating/updating/deleting'
puts '- Use CreateOptions with folder_uid to specify where to create records'
puts '- Check permissions if operations fail'
puts '- Use batch operations for better performance with multiple records'
puts '- Generate secure passwords with KeeperSecretsManager::Utils.generate_password'
puts "\n# Example with specific folder:"
puts "options = KeeperSecretsManager::Dto::CreateOptions.new(folder_uid: 'YOUR_FOLDER_UID')"
puts 'record_uid = secrets_manager.create_secret(record_data, options)'
