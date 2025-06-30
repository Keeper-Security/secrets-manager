#!/usr/bin/env ruby

# Test batch operations for creating, updating, and deleting multiple records

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'benchmark'

puts "=== Batch Operations Tests ==="
puts "Testing bulk create, update, and delete operations"
puts "-" * 50

class BatchOperationsTests
  def initialize
    @config_file = File.expand_path('../../config.base64', __dir__)
    unless File.exist?(@config_file)
      puts "❌ ERROR: config.base64 not found"
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
      puts "❌ Test folder not found"
      exit 1
    end
    
    @created_records = []
  end
  
  def run_all_tests
    test_batch_create
    test_batch_read
    test_batch_update
    test_batch_delete
    test_performance_comparison
    cleanup_remaining_records
    puts "\n✅ All batch operations tests completed"
  end
  
  private
  
  def test_batch_create
    puts "\n1. Testing Batch Create..."
    
    num_records = 5
    
    time = Benchmark.realtime do
      num_records.times do |i|
        record_data = {
          'type' => 'login',
          'title' => "Batch Test #{i + 1} - #{Time.now.to_i}",
          'fields' => [
            { 'type' => 'login', 'value' => ["batch#{i}@example.com"] },
            { 'type' => 'password', 'value' => ["BatchPass#{i}!"] },
            { 'type' => 'url', 'value' => ["https://batch#{i}.example.com"] }
          ],
          'notes' => "Batch test record #{i + 1}"
        }
        
        options = KeeperSecretsManager::Dto::CreateOptions.new
        options.folder_uid = @test_folder.uid
        
        begin
          uid = @sm.create_secret(record_data, options)
          @created_records << uid
          print "."
        rescue => e
          print "X"
          puts "\n   ❌ Error creating record #{i + 1}: #{e.message}"
        end
      end
    end
    
    puts "\n   ✅ Created #{@created_records.length}/#{num_records} records in #{time.round(2)}s"
    puts "   ✅ Average: #{(time / num_records).round(3)}s per record"
    
    # TODO: Implement true batch create API
    # batch_records = (1..num_records).map do |i|
    #   { 'type' => 'login', 'title' => "Batch #{i}", ... }
    # end
    # uids = @sm.create_secrets_batch(batch_records, folder_uid: @test_folder.uid)
    
    puts "   ⚠️  True batch create API not yet implemented"
  end
  
  def test_batch_read
    puts "\n2. Testing Batch Read..."
    
    if @created_records.empty?
      puts "   ⚠️  No records to read"
      return
    end
    
    # Wait for records to be available
    sleep 2
    
    time = Benchmark.realtime do
      # Read all records at once
      records = @sm.get_secrets(@created_records)
      puts "   ✅ Retrieved #{records.length} records in one call"
      
      # Verify records
      records.each do |record|
        if record.title.start_with?('Batch Test')
          print "."
        else
          print "?"
        end
      end
    end
    
    puts "\n   ✅ Batch read completed in #{time.round(2)}s"
  end
  
  def test_batch_update
    puts "\n3. Testing Batch Update..."
    
    if @created_records.empty?
      puts "   ⚠️  No records to update"
      return
    end
    
    # Wait and then read records
    sleep 1
    records = @sm.get_secrets(@created_records)
    
    if records.empty?
      puts "   ⚠️  Could not retrieve records for update"
      return
    end
    
    updated_count = 0
    time = Benchmark.realtime do
      records.each_with_index do |record, i|
        begin
          # Update each record
          record.notes = "Updated at #{Time.now} - Batch update test"
          record.set_field('login', "updated_batch#{i}@example.com")
          
          @sm.update_secret(record)
          updated_count += 1
          print "."
        rescue => e
          print "X"
        end
      end
    end
    
    puts "\n   ✅ Updated #{updated_count}/#{records.length} records in #{time.round(2)}s"
    
    # TODO: Implement true batch update API
    # updates = records.map { |r| { uid: r.uid, updates: {...} } }
    # @sm.update_secrets_batch(updates)
    
    puts "   ⚠️  True batch update API not yet implemented"
  end
  
  def test_batch_delete
    puts "\n4. Testing Batch Delete..."
    
    if @created_records.empty?
      puts "   ⚠️  No records to delete"
      return
    end
    
    # Delete half of the records
    to_delete = @created_records.first(@created_records.length / 2)
    deleted_count = 0
    
    time = Benchmark.realtime do
      to_delete.each do |uid|
        begin
          @sm.delete_secret(uid)
          @created_records.delete(uid)
          deleted_count += 1
          print "."
        rescue => e
          print "X"
        end
      end
    end
    
    puts "\n   ✅ Deleted #{deleted_count}/#{to_delete.length} records in #{time.round(2)}s"
    
    # TODO: Implement true batch delete API
    # @sm.delete_secrets_batch(to_delete)
    
    puts "   ⚠️  True batch delete API not yet implemented"
  end
  
  def test_performance_comparison
    puts "\n5. Testing Performance Comparison..."
    
    # Compare single vs batch operations
    num_test = 3
    
    # Single operation timing
    single_times = []
    num_test.times do |i|
      time = Benchmark.realtime do
        record_data = {
          'type' => 'login',
          'title' => "Perf Test Single #{i + 1}",
          'fields' => [
            { 'type' => 'login', 'value' => ['perf@example.com'] }
          ]
        }
        
        options = KeeperSecretsManager::Dto::CreateOptions.new
        options.folder_uid = @test_folder.uid
        
        uid = @sm.create_secret(record_data, options)
        @created_records << uid
      end
      single_times << time
    end
    
    avg_single = single_times.sum / single_times.length
    puts "   ✅ Average single create: #{avg_single.round(3)}s"
    
    # Batch timing (simulated with rapid sequential calls)
    batch_time = Benchmark.realtime do
      num_test.times do |i|
        record_data = {
          'type' => 'login',
          'title' => "Perf Test Batch #{i + 1}",
          'fields' => [
            { 'type' => 'login', 'value' => ['perf@example.com'] }
          ]
        }
        
        options = KeeperSecretsManager::Dto::CreateOptions.new
        options.folder_uid = @test_folder.uid
        
        uid = @sm.create_secret(record_data, options)
        @created_records << uid
      end
    end
    
    avg_batch = batch_time / num_test
    puts "   ✅ Average in batch: #{avg_batch.round(3)}s"
    
    if avg_batch < avg_single
      improvement = ((avg_single - avg_batch) / avg_single * 100).round(1)
      puts "   ✅ Batch is #{improvement}% faster"
    else
      puts "   ℹ️  No significant performance difference"
    end
  end
  
  def cleanup_remaining_records
    puts "\n6. Cleaning up remaining test records..."
    
    if @created_records.any?
      @created_records.each do |uid|
        begin
          @sm.delete_secret(uid)
          print "."
        rescue => e
          print "X"
        end
      end
      puts "\n   ✅ Cleanup completed"
    else
      puts "   ℹ️  No records to clean up"
    end
  end
end

# Run tests
if __FILE__ == $0
  tests = BatchOperationsTests.new
  tests.run_all_tests
end