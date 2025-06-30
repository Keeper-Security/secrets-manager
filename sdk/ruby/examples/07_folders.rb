#!/usr/bin/env ruby

# Folders Example - Organize secrets in folders

require 'keeper_secrets_manager'

# Initialize
config = ENV['KSM_CONFIG'] || 'YOUR_BASE64_CONFIG'
secrets_manager = KeeperSecretsManager.from_config(config)

puts "=== Folder Operations Example ==="

# 1. Get all folders
puts "\n1. Getting all folders..."
response = secrets_manager.get_secrets(full_response: true)
folders = response.folders

if folders.empty?
  puts "No folders found in vault"
else
  puts "Found #{folders.length} folders:"
  folders.each do |folder|
    puts "  - #{folder.name || folder.uid} (UID: #{folder.uid})"
  end
end

# 2. Get folder hierarchy
puts "\n2. Folder Hierarchy:"
if folders.any?
  # Build folder tree
  folder_tree = secrets_manager.folder_manager.build_folder_tree
  
  # Print tree structure
  secrets_manager.folder_manager.print_tree
end

# 3. Create a folder
puts "\n3. Creating a folder..."
begin
  folder_name = "Test Folder #{Time.now.strftime('%Y%m%d_%H%M%S')}"
  
  # Create at root level
  folder_uid = secrets_manager.create_folder(folder_name)
  puts "✓ Created folder: #{folder_name}"
  puts "  UID: #{folder_uid}"
  
  # Create a subfolder
  subfolder_name = "Subfolder"
  subfolder_uid = secrets_manager.create_folder(
    name: subfolder_name,
    parent_uid: folder_uid
  )
  puts "✓ Created subfolder: #{subfolder_name}"
  
rescue => e
  puts "✗ Error creating folder: #{e.message}"
end

# 4. Move records to folders
puts "\n4. Organizing records in folders..."
begin
  # Get a record to move
  record = secrets_manager.get_secrets.first
  
  if record && defined?(folder_uid)
    # Move record to folder
    record.folder_uid = folder_uid
    secrets_manager.update_secret(record)
    
    puts "✓ Moved '#{record.title}' to folder"
  end
  
rescue => e
  puts "✗ Error moving record: #{e.message}"
end

# 5. Find folders
puts "\n5. Finding folders..."
if folders.any?
  # Find by name
  folder = secrets_manager.find_folder_by_name("Test Folder")
  puts "✓ Found folder by name: #{folder.uid}" if folder
  
  # Get folder path
  if folder
    path = secrets_manager.get_folder_path(folder.uid)
    puts "✓ Folder path: #{path}"
  end
  
  # Get folder ancestors
  ancestors = secrets_manager.folder_manager.get_ancestors(folder.uid) if folder
  puts "✓ Ancestors: #{ancestors.map(&:name).join(' > ')}" if ancestors&.any?
end

# 6. List records in a folder
puts "\n6. Records in folders:"
response.records.group_by(&:folder_uid).each do |folder_uid, records|
  folder = folders.find { |f| f.uid == folder_uid }
  folder_name = folder&.name || folder_uid || 'Root'
  
  puts "\n  #{folder_name}:"
  records.each do |record|
    puts "    - #{record.title}"
  end
end

# 7. Update folder
puts "\n7. Updating folder..."
begin
  if defined?(folder_uid)
    secrets_manager.update_folder(
      folder_uid: folder_uid,
      name: "Updated Test Folder"
    )
    puts "✓ Updated folder name"
  end
rescue => e
  puts "✗ Error updating folder: #{e.message}"
end

# 8. Delete folder
puts "\n8. Cleanup - Delete test folders..."
puts "Press Enter to delete test folders (or Ctrl+C to keep them)..."
gets

begin
  if defined?(subfolder_uid)
    secrets_manager.delete_folder(subfolder_uid)
    puts "✓ Deleted subfolder"
  end
  
  if defined?(folder_uid)
    secrets_manager.delete_folder(folder_uid, force: true)
    puts "✓ Deleted folder"
  end
rescue => e
  puts "✗ Error deleting folder: #{e.message}"
end

puts "\n=== Folder Tips ==="
puts "- Folders help organize secrets logically"
puts "- Use folders for environments (Dev, Test, Prod)"
puts "- Use folders for teams or projects"
puts "- Folders can be nested for complex hierarchies"
puts "- Force delete removes folder even with records"