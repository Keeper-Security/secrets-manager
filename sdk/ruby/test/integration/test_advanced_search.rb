#!/usr/bin/env ruby

# Test advanced search functionality

require_relative '../../lib/keeper_secrets_manager'
require 'json'
require 'base64'

puts "=== Advanced Search Tests ==="
puts "Testing search by various criteria"
puts "-" * 50

class AdvancedSearchTests
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
    
    @test_records = []
  end
  
  def run_all_tests
    setup_test_records
    test_search_by_title
    test_search_by_field_value
    test_search_by_type
    test_search_by_notes
    test_search_with_filters
    test_fuzzy_search
    test_search_across_folders
    cleanup_test_records
    puts "\n✅ All advanced search tests completed"
  end
  
  private
  
  def setup_test_records
    puts "\n0. Setting up test records for search..."
    
    test_data = [
      {
        title: 'Production Database',
        type: 'databaseCredentials',
        fields: [
          { type: 'host', value: [{ 'hostName' => 'db.prod.example.com', 'port' => '5432' }] },
          { type: 'login', value: ['postgres'] },
          { type: 'password', value: ['ProdPass123!'] }
        ],
        notes: 'Production PostgreSQL database'
      },
      {
        title: 'Development API Key',
        type: 'login',
        fields: [
          { type: 'login', value: ['dev-api-key'] },
          { type: 'password', value: ['dev-secret-key-123'] },
          { type: 'url', value: ['https://api.dev.example.com'] }
        ],
        notes: 'Development environment API credentials'
      },
      {
        title: 'Test Server SSH',
        type: 'sshKeys',
        fields: [
          { type: 'host', value: [{ 'hostName' => 'test.example.com', 'port' => '22' }] },
          { type: 'login', value: ['testuser'] },
          { type: 'privateKey', value: ['-----BEGIN RSA PRIVATE KEY-----\ntest-key-content\n-----END RSA PRIVATE KEY-----'] }
        ],
        notes: 'SSH access to test environment'
      }
    ]
    
    test_data.each do |data|
      record_data = {
        'type' => data[:type],
        'title' => "Search Test - #{data[:title]} #{Time.now.to_i}",
        'fields' => data[:fields],
        'notes' => data[:notes]
      }
      
      options = KeeperSecretsManager::Dto::CreateOptions.new
      options.folder_uid = @test_folder.uid
      
      begin
        uid = @sm.create_secret(record_data, options)
        @test_records << uid
        puts "   ✅ Created: #{data[:title]}"
      rescue => e
        puts "   ❌ Failed to create #{data[:title]}: #{e.message}"
      end
    end
    
    # Wait for records to be indexed
    sleep 3
  end
  
  def test_search_by_title
    puts "\n1. Testing Search by Title..."
    
    # Get all records and search locally
    all_records = @sm.get_secrets
    
    # Exact match
    results = all_records.select { |r| r.title.include?('Production Database') }
    puts "   ✅ Found #{results.length} record(s) with 'Production Database' in title"
    
    # Partial match
    results = all_records.select { |r| r.title.downcase.include?('search test') }
    puts "   ✅ Found #{results.length} record(s) with 'search test' in title"
    
    # Case insensitive
    results = all_records.select { |r| r.title.downcase.include?('api key') }
    puts "   ✅ Found #{results.length} record(s) with 'api key' in title"
    
    # Using built-in method
    results = @sm.get_secrets_by_title('Search Test')
    puts "   ✅ get_secrets_by_title found #{results.length} record(s)"
  end
  
  def test_search_by_field_value
    puts "\n2. Testing Search by Field Value..."
    
    all_records = @sm.get_secrets
    
    # Search by login field
    results = all_records.select do |r|
      r.respond_to?(:login) && r.login && r.login.include?('postgres')
    end
    puts "   ✅ Found #{results.length} record(s) with 'postgres' login"
    
    # Search by host
    results = all_records.select do |r|
      if r.respond_to?(:host) && r.host
        host_data = r.host
        host_data.is_a?(Hash) && host_data['hostName']&.include?('.example.com')
      end
    end
    puts "   ✅ Found #{results.length} record(s) with '.example.com' host"
    
    # Search by URL
    results = all_records.select do |r|
      r.respond_to?(:url) && r.url && r.url.include?('api.')
    end
    puts "   ✅ Found #{results.length} record(s) with 'api.' in URL"
  end
  
  def test_search_by_type
    puts "\n3. Testing Search by Record Type..."
    
    all_records = @sm.get_secrets
    
    # Group by type
    types = all_records.group_by(&:type)
    
    types.each do |type, records|
      puts "   ✅ Type '#{type}': #{records.length} record(s)"
    end
    
    # Filter specific types
    db_records = all_records.select { |r| r.type == 'databaseCredentials' }
    puts "   ✅ Database credentials: #{db_records.length}"
    
    ssh_records = all_records.select { |r| r.type == 'sshKeys' }
    puts "   ✅ SSH keys: #{ssh_records.length}"
  end
  
  def test_search_by_notes
    puts "\n4. Testing Search by Notes..."
    
    all_records = @sm.get_secrets
    
    # Search in notes
    results = all_records.select do |r|
      r.notes && r.notes.downcase.include?('environment')
    end
    puts "   ✅ Found #{results.length} record(s) with 'environment' in notes"
    
    results = all_records.select do |r|
      r.notes && r.notes.downcase.include?('production')
    end
    puts "   ✅ Found #{results.length} record(s) with 'production' in notes"
  end
  
  def test_search_with_filters
    puts "\n5. Testing Search with Multiple Filters..."
    
    all_records = @sm.get_secrets
    
    # Complex filter: login type with specific domain
    results = all_records.select do |r|
      r.type == 'login' && 
      r.respond_to?(:url) && 
      r.url && 
      r.url.include?('.dev.')
    end
    puts "   ✅ Login records with .dev. domain: #{results.length}"
    
    # Records created in last hour
    one_hour_ago = Time.now.to_i - 3600
    results = all_records.select do |r|
      r.title =~ /\d{10}/ && r.title.match(/(\d{10})/)[1].to_i > one_hour_ago
    end
    puts "   ✅ Records created in last hour: #{results.length}"
  end
  
  def test_fuzzy_search
    puts "\n6. Testing Fuzzy Search..."
    
    all_records = @sm.get_secrets
    
    # Simulate fuzzy search with simple algorithm
    def fuzzy_match(text, query, threshold = 0.7)
      return false unless text && query
      
      text = text.downcase
      query = query.downcase
      
      # Simple character match ratio
      matches = 0
      query.chars.each do |char|
        if text.include?(char)
          matches += 1
          text = text.sub(char, '')  # Remove first occurrence
        end
      end
      
      (matches.to_f / query.length) >= threshold
    end
    
    # Test fuzzy search
    results = all_records.select { |r| fuzzy_match(r.title, 'Prodction', 0.8) }
    puts "   ✅ Fuzzy match 'Prodction' (typo): #{results.length} record(s)"
    
    results = all_records.select { |r| fuzzy_match(r.title, 'Databse', 0.7) }
    puts "   ✅ Fuzzy match 'Databse' (typo): #{results.length} record(s)"
  end
  
  def test_search_across_folders
    puts "\n7. Testing Search Across Folders..."
    
    # Get all records (searches across all accessible folders)
    all_records = @sm.get_secrets
    
    # Group by folder (would need folder info in record)
    # For now, we'll just count total accessible records
    puts "   ✅ Total accessible records: #{all_records.length}"
    
    # Get all folders
    all_folders = @sm.get_folders
    puts "   ✅ Total accessible folders: #{all_folders.length}"
    
    # TODO: Implement folder-specific search
    # results = @sm.search_in_folder(folder_uid, query)
    
    puts "   ⚠️  Folder-specific search not yet implemented"
  end
  
  def cleanup_test_records
    puts "\n8. Cleaning up test records..."
    
    @test_records.each do |uid|
      begin
        @sm.delete_secret(uid)
        print "."
      rescue => e
        print "X"
      end
    end
    puts "\n   ✅ Cleanup completed"
  end
end

# Run tests
if __FILE__ == $0
  tests = AdvancedSearchTests.new
  tests.run_all_tests
end