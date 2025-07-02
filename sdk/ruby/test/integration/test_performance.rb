#!/usr/bin/env ruby

# Performance and benchmark tests

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'
require 'benchmark'

# Try to load memory_profiler if available
begin
  require 'memory_profiler'
  MEMORY_PROFILER_AVAILABLE = true
rescue LoadError
  MEMORY_PROFILER_AVAILABLE = false
end

puts "=== Performance Tests ==="
puts "Testing SDK performance and resource usage"
puts "-" * 50

class PerformanceTests
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
    begin
      folders = @sm.get_folders
      @test_folder = folders.find { |f| f.uid == 'khq76ez6vkTRj3MqUiEGRg' }
    rescue => e
      puts "Warning: Could not get folders: #{e.message}"
      @test_folder = nil
    end
    
    @created_records = []
  end
  
  def run_all_tests
    test_initialization_performance
    test_record_retrieval_performance
    test_encryption_performance
    test_large_payload_performance
    test_concurrent_operations
    test_memory_usage
    test_cache_performance
    cleanup_test_records
    puts "\n✅ All performance tests completed"
  end
  
  private
  
  def test_initialization_performance
    puts "\n1. Testing Initialization Performance..."
    
    times = []
    
    5.times do
      time = Benchmark.realtime do
        storage = KeeperSecretsManager::Storage::InMemoryStorage.new(@config_data)
        KeeperSecretsManager.new(config: storage)
      end
      times << time
    end
    
    avg_time = times.sum / times.length
    puts "   ✅ Average initialization: #{(avg_time * 1000).round(2)}ms"
    puts "   ✅ Min: #{(times.min * 1000).round(2)}ms, Max: #{(times.max * 1000).round(2)}ms"
  end
  
  def test_record_retrieval_performance
    puts "\n2. Testing Record Retrieval Performance..."
    
    # Test single record retrieval
    puts "   Single record retrieval:"
    times = []
    
    5.times do
      time = Benchmark.realtime do
        @sm.get_secrets
      end
      times << time
    end
    
    avg_time = times.sum / times.length
    puts "   ✅ Average time: #{(avg_time * 1000).round(2)}ms"
    
    # Test with specific UIDs (if any exist)
    all_records = @sm.get_secrets
    if all_records.any?
      uid = all_records.first.uid
      
      times = []
      5.times do
        time = Benchmark.realtime do
          @sm.get_secrets([uid])
        end
        times << time
      end
      
      avg_time = times.sum / times.length
      puts "   ✅ Specific UID retrieval: #{(avg_time * 1000).round(2)}ms"
    end
  end
  
  def test_encryption_performance
    puts "\n3. Testing Encryption Performance..."
    
    # Test various data sizes
    sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    
    sizes.each do |size|
      data = 'a' * size
      key = KeeperSecretsManager::Crypto.generate_encryption_key_bytes
      
      # Encryption
      times = []
      10.times do
        time = Benchmark.realtime do
          KeeperSecretsManager::Crypto.encrypt_aes_gcm(data, key)
        end
        times << time
      end
      
      avg_time = times.sum / times.length
      throughput = size / avg_time / 1024 / 1024  # MB/s
      
      puts "   ✅ Encrypt #{size/1024}KB: #{(avg_time * 1000).round(2)}ms (#{throughput.round(1)} MB/s)"
      
      # Decryption
      encrypted = KeeperSecretsManager::Crypto.encrypt_aes_gcm(data, key)
      
      times = []
      10.times do
        time = Benchmark.realtime do
          KeeperSecretsManager::Crypto.decrypt_aes_gcm(encrypted, key)
        end
        times << time
      end
      
      avg_time = times.sum / times.length
      throughput = size / avg_time / 1024 / 1024  # MB/s
      
      puts "   ✅ Decrypt #{size/1024}KB: #{(avg_time * 1000).round(2)}ms (#{throughput.round(1)} MB/s)"
    end
  end
  
  def test_large_payload_performance
    puts "\n4. Testing Large Payload Performance..."
    
    if @test_folder.nil?
      puts "   ⚠️  Skipping - no test folder available"
      return
    end
    
    # Create record with large data
    large_notes = 'x' * 50000  # 50KB of notes
    large_fields = (1..20).map do |i|
      { 'type' => 'text', 'label' => "Field #{i}", 'value' => ['y' * 1000] }
    end
    
    record_data = {
      'type' => 'login',
      'title' => "Large Payload Test #{Time.now.to_i}",
      'fields' => large_fields,
      'notes' => large_notes
    }
    
    options = KeeperSecretsManager::Dto::CreateOptions.new
    options.folder_uid = @test_folder.uid
    
    begin
      time = Benchmark.realtime do
        uid = @sm.create_secret(record_data, options)
        @created_records << uid
      end
      puts "   ✅ Created large record in #{(time * 1000).round(2)}ms"
    rescue => e
      puts "   ❌ Failed: #{e.message}"
    end
  end
  
  def test_concurrent_operations
    puts "\n5. Testing Concurrent Operations..."
    
    # Ruby doesn't have true parallelism with threads due to GIL,
    # but we can test concurrent I/O operations
    
    threads = []
    results = []
    mutex = Mutex.new
    
    time = Benchmark.realtime do
      5.times do |i|
        threads << Thread.new do
          begin
            records = @sm.get_secrets
            mutex.synchronize { results << records.length }
          rescue => e
            mutex.synchronize { results << "Error: #{e.message}" }
          end
        end
      end
      
      threads.each(&:join)
    end
    
    puts "   ✅ Completed #{threads.length} concurrent operations in #{(time * 1000).round(2)}ms"
    puts "   ✅ Results: #{results.inspect}"
  end
  
  def test_memory_usage
    puts "\n6. Testing Memory Usage..."
    
    if MEMORY_PROFILER_AVAILABLE
      report = MemoryProfiler.report do
        # Create and process multiple records
        10.times do
          records = @sm.get_secrets
          records.each { |r| r.title }  # Access fields
        end
      end
      
      puts "   ✅ Total allocated: #{(report.total_allocated_memsize / 1024.0).round(2)} KB"
      puts "   ✅ Total retained: #{(report.total_retained_memsize / 1024.0).round(2)} KB"
      
      # Top allocations
      puts "   Top allocations by gem:"
      report.allocated_memory_by_gem.first(3).each do |gem, size|
        puts "     - #{gem}: #{(size / 1024.0).round(2)} KB"
      end
    else
      # Simple memory estimation
      before = `ps -o rss= -p #{Process.pid}`.to_i
      
      # Perform operations
      100.times { @sm.get_secrets }
      
      after = `ps -o rss= -p #{Process.pid}`.to_i
      diff = after - before
      
      puts "   ✅ Memory increase: ~#{diff} KB"
      puts "   ℹ️  Install 'memory_profiler' gem for detailed analysis"
    end
  end
  
  def test_cache_performance
    puts "\n7. Testing Cache Performance..."
    
    # First call (cache miss)
    time_no_cache = Benchmark.realtime { @sm.get_secrets }
    
    # Subsequent calls (cache hit) - if caching is implemented
    times_cached = []
    5.times do
      time = Benchmark.realtime { @sm.get_secrets }
      times_cached << time
    end
    
    avg_cached = times_cached.sum / times_cached.length
    
    puts "   ✅ First call: #{(time_no_cache * 1000).round(2)}ms"
    puts "   ✅ Cached calls avg: #{(avg_cached * 1000).round(2)}ms"
    
    if avg_cached < time_no_cache * 0.5
      improvement = ((time_no_cache - avg_cached) / time_no_cache * 100).round(1)
      puts "   ✅ Cache improvement: #{improvement}%"
    else
      puts "   ℹ️  No significant caching detected"
    end
  end
  
  def cleanup_test_records
    puts "\n8. Cleaning up test records..."
    
    @created_records.each do |uid|
      begin
        @sm.delete_secret(uid)
        print "."
      rescue => e
        print "X"
      end
    end
    puts "\n   ✅ Cleanup completed" if @created_records.any?
  end
end

# Run tests
if __FILE__ == $0
  tests = PerformanceTests.new
  tests.run_all_tests
end