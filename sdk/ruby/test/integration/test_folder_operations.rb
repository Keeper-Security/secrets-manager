#!/usr/bin/env ruby

# Test folder CRUD operations

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'
require 'base64'

puts '=== Folder Operations Test ==='
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts '-' * 50

class FolderOperationsTest
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

    @created_folders = []
    @created_records = []
  end

  def run_all_tests
    test_list_folders
    test_create_folder
    test_update_folder
    test_create_subfolder
    test_create_record_in_folder
    test_delete_folder

    cleanup
    puts "\n✅ All folder tests completed!"
  end

  private

  def test_list_folders
    puts "\n1. Testing List Folders..."

    folders = @sm.get_folders
    puts "   ✓ Retrieved #{folders.length} folders"

    folders.first(3).each do |folder|
      puts "   ✓ Folder: #{folder.name} (#{folder.uid})"
    end

    # Store a folder for later tests
    @test_folder = folders.first if folders.any?
  rescue StandardError => e
    puts "   ❌ List folders failed: #{e.message}"
  end

  def test_create_folder
    puts "\n2. Testing Create Folder..."

    if MockHelper.mock_mode?
      puts '   ℹ️  Folder creation in mock mode'
      # Mock doesn't support actual folder creation
      return
    end

    folder_name = "Ruby SDK Test Folder #{Time.now.to_i}"

    begin
      folder_uid = @sm.create_folder(folder_name)
      @created_folders << folder_uid
      puts "   ✓ Created folder: #{folder_name}"
      puts "   ✓ Folder UID: #{folder_uid}"

      # Verify folder was created
      sleep 2
      folders = @sm.get_folders
      new_folder = folders.find { |f| f.uid == folder_uid }

      if new_folder
        puts "   ✓ Folder verified: #{new_folder.name}"
        @test_created_folder = new_folder
      else
        puts '   ⚠️  Could not verify folder creation'
      end
    rescue StandardError => e
      puts "   ❌ Create folder failed: #{e.message}"
      puts '   Note: Folder creation may require specific permissions'
    end
  end

  def test_update_folder
    puts "\n3. Testing Update Folder..."

    if MockHelper.mock_mode? || !@test_created_folder
      puts '   ℹ️  Folder update requires a created folder'
      return
    end

    new_name = "Updated Ruby SDK Test Folder #{Time.now.to_i}"

    begin
      @sm.update_folder(@test_created_folder.uid, new_name)
      puts "   ✓ Updated folder name to: #{new_name}"

      # Verify update
      sleep 2
      folders = @sm.get_folders
      updated_folder = folders.find { |f| f.uid == @test_created_folder.uid }

      if updated_folder && updated_folder.name == new_name
        puts '   ✓ Folder name update verified'
      else
        puts '   ⚠️  Could not verify folder update'
      end
    rescue StandardError => e
      puts "   ❌ Update folder failed: #{e.message}"
    end
  end

  def test_create_subfolder
    puts "\n4. Testing Create Subfolder..."

    if MockHelper.mock_mode? || !@test_created_folder
      puts '   ℹ️  Subfolder creation requires a parent folder'
      return
    end

    subfolder_name = "Ruby SDK Subfolder #{Time.now.to_i}"

    begin
      subfolder_uid = @sm.create_folder(subfolder_name, parent_uid: @test_created_folder.uid)
      @created_folders << subfolder_uid
      puts "   ✓ Created subfolder: #{subfolder_name}"
      puts "   ✓ Parent folder: #{@test_created_folder.name}"
      puts "   ✓ Subfolder UID: #{subfolder_uid}"
    rescue StandardError => e
      puts "   ❌ Create subfolder failed: #{e.message}"
    end
  end

  def test_create_record_in_folder
    puts "\n5. Testing Create Record in Folder..."

    target_folder = @test_created_folder || @test_folder

    unless target_folder
      puts '   ⚠️  No folder available for record creation'
      return
    end

    record_data = {
      'type' => 'login',
      'title' => "Folder Test Record #{Time.now.to_i}",
      'fields' => [
        { 'type' => 'login', 'value' => ['folder_test@example.com'] },
        { 'type' => 'password', 'value' => ['FolderPassword123!'] }
      ],
      'notes' => "Created in folder: #{target_folder.name}"
    }

    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = target_folder.uid

    begin
      record_uid = @sm.create_secret(record_data, options)
      @created_records << record_uid
      puts "   ✓ Created record in folder: #{target_folder.name}"
      puts "   ✓ Record UID: #{record_uid}"
    rescue StandardError => e
      puts "   ❌ Create record in folder failed: #{e.message}"
    end
  end

  def test_delete_folder
    puts "\n6. Testing Delete Folder..."

    if MockHelper.mock_mode? || @created_folders.empty?
      puts '   ℹ️  No folders to delete'
      return
    end

    # Delete only the folders we created
    folder_to_delete = @created_folders.last

    begin
      # First, try without force flag
      @sm.delete_folder(folder_to_delete, force: false)
      puts "   ✓ Deleted folder: #{folder_to_delete}"
      @created_folders.delete(folder_to_delete)
    rescue StandardError => e
      puts "   ⚠️  Soft delete failed: #{e.message}"

      # Try with force flag if folder has contents
      begin
        @sm.delete_folder(folder_to_delete, force: true)
        puts "   ✓ Force deleted folder: #{folder_to_delete}"
        @created_folders.delete(folder_to_delete)
      rescue StandardError => e2
        puts "   ❌ Force delete also failed: #{e2.message}"
      end
    end
  end

  def cleanup
    puts "\n7. Cleaning up..."

    # Delete created records
    @created_records.each do |uid|
      @sm.delete_secret(uid)
      print '.'
    rescue StandardError
      print 'x'
    end

    # Delete remaining created folders
    @created_folders.each do |uid|
      @sm.delete_folder(uid, force: true)
      print '.'
    rescue StandardError
      print 'x'
    end

    puts "\n   ✓ Cleanup completed" if @created_records.any? || @created_folders.any?
  end
end

# Run tests
if __FILE__ == $0
  test = FolderOperationsTest.new
  test.run_all_tests
end
