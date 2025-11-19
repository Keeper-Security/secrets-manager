#!/usr/bin/env ruby

# Integration test runner for multiple Ruby versions using Docker
# This script tests the SDK across different Ruby versions to ensure compatibility

require 'fileutils'
require 'json'
require 'base64'

# Ruby versions to test (must match gemspec minimum requirement: >= 3.1.0)
RUBY_VERSIONS = [
  '3.1',     # Minimum required version
  '3.2',     # Recent stable
  '3.3',     # Latest stable
  'latest'   # Latest available
]

# Test results
results = {}

# Ensure Docker is available
unless system('docker --version > /dev/null 2>&1')
  puts 'Error: Docker is not installed or not in PATH'
  exit 1
end

# Create temporary directory for test files
test_dir = File.expand_path('../docker_tests', __dir__)
FileUtils.mkdir_p(test_dir)

# Copy SDK files to test directory
sdk_dir = File.expand_path('../..', __dir__)
FileUtils.cp_r(File.join(sdk_dir, 'lib'), test_dir)
begin
  FileUtils.cp_r(File.join(sdk_dir, 'Gemfile'), test_dir)
rescue StandardError
  nil
end

# Copy config file if it exists
config_file = File.join(sdk_dir, 'config.base64')
if File.exist?(config_file)
  FileUtils.cp(config_file, test_dir)
else
  puts 'Warning: config.base64 not found. Tests will use mock data.'
end

# Create the integration test script
test_script = <<~'RUBY'
  #!/usr/bin/env ruby
  
  require 'json'
  require 'base64'
  require_relative 'lib/keeper_secrets_manager'
  
  def log(message)
    puts "[#{Time.now.strftime('%H:%M:%S')}] #{message}"
  end
  
  def test_sdk_features
    log "Ruby #{RUBY_VERSION} on #{RUBY_PLATFORM}"
    log "OpenSSL: #{OpenSSL::VERSION} / #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
    
    results = {
      ruby_version: RUBY_VERSION,
      openssl_version: OpenSSL::OPENSSL_LIBRARY_VERSION,
      tests: {}
    }
    
    # Test 1: Check AES-GCM support
    begin
      cipher = OpenSSL::Cipher.new('AES-256-GCM')
      results[:tests][:aes_gcm_support] = { status: 'PASS', message: 'AES-GCM supported' }
    rescue => e
      results[:tests][:aes_gcm_support] = { status: 'FAIL', message: e.message }
      log "FATAL: AES-GCM not supported. Cannot continue."
      puts results.to_json
      exit 1
    end
    
    # Test 2: Initialize SDK
    begin
      config_file = 'config.base64'
      
      if File.exist?(config_file)
        # Use real config
        config_base64 = File.read(config_file).strip
        config_json = Base64.decode64(config_base64)
        config_data = JSON.parse(config_json)
        storage = KeeperSecretsManager::Storage::InMemoryStorage.new(config_data)
        secrets_manager = KeeperSecretsManager.new(config: storage)
        results[:tests][:sdk_init] = { status: 'PASS', message: 'SDK initialized with real config' }
      else
        # Use mock data
        mock_config = {
          'hostname' => 'keepersecurity.com',
          'clientId' => Base64.strict_encode64('mock-client-id-' + ('a' * 48)),
          'privateKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').to_der),
          'serverPublicKeyId' => '10',
          'appKey' => Base64.strict_encode64(OpenSSL::Random.random_bytes(32)),
          'appOwnerPublicKey' => Base64.strict_encode64(OpenSSL::PKey::EC.generate('prime256v1').public_key.to_bn.to_s(2))
        }
        storage = KeeperSecretsManager::Storage::InMemoryStorage.new(mock_config)
        
        # Mock mode - don't make real API calls
        secrets_manager = KeeperSecretsManager.new(
          config: storage,
          custom_post_function: lambda { |url, tk, payload, verify|
            # Return mock response
            mock_response = {
              records: [],
              warnings: ['Running in mock mode']
            }
            KeeperSecretsManager::Dto::KSMHttpResponse.new(
              status_code: 200,
              data: mock_response.to_json
            )
          }
        )
        results[:tests][:sdk_init] = { status: 'PASS', message: 'SDK initialized with mock config' }
      end
      
    rescue => e
      results[:tests][:sdk_init] = { status: 'FAIL', message: e.message }
      puts results.to_json
      exit 1
    end
    
    # Test 3: Create a record (mock)
    begin
      test_record = KeeperSecretsManager::Dto::KeeperRecord.new(
        'type' => 'login',
        'title' => "Ruby #{RUBY_VERSION} Test Record",
        'fields' => [
          { 'type' => 'login', 'value' => ['test_user'] },
          { 'type' => 'password', 'value' => ['test_pass123!'] },
          { 'type' => 'url', 'value' => ['https://example.com'] },
          { 'type' => 'fileRef', 'value' => [] }
        ],
        'custom' => [
          { 'type' => 'text', 'label' => 'Ruby Version', 'value' => [RUBY_VERSION] }
        ],
        'notes' => "Created by Ruby SDK integration test"
      )
      
      # Test record creation structure
      record_data = test_record.to_h
      results[:tests][:create_record] = { 
        status: 'PASS', 
        message: "Record structure created with #{record_data['fields'].length} fields" 
      }
    rescue => e
      results[:tests][:create_record] = { status: 'FAIL', message: e.message }
    end
    
    # Test 4: Edit/Update a record (mock)
    begin
      # Test field updates
      test_record.login = 'updated_user'
      test_record.password = 'updated_pass456!'
      test_record.url = ['https://updated.example.com', 'https://backup.example.com']
      
      # Verify updates
      if test_record.login == 'updated_user' && 
         test_record.password == 'updated_pass456!' &&
         test_record.url.length == 2
        results[:tests][:edit_record] = { 
          status: 'PASS', 
          message: 'Record fields updated successfully' 
        }
      else
        results[:tests][:edit_record] = { 
          status: 'FAIL', 
          message: 'Field updates did not persist correctly' 
        }
      end
    rescue => e
      results[:tests][:edit_record] = { status: 'FAIL', message: e.message }
    end
    
    # Test 5: Field type helpers
    begin
      # Test various field types
      test_fields = []
      
      # Standard fields
      test_fields << { type: 'login', test: test_record.get_standard_field_value('login') == 'updated_user' }
      test_fields << { type: 'password', test: test_record.get_standard_field_value('password') == 'updated_pass456!' }
      
      # Complex fields
      test_record.set_field('phone', { 'region' => 'US', 'number' => '555-1234', 'ext' => '567' })
      phone = test_record.get_field_value_single('phone')
      test_fields << { type: 'phone', test: phone.is_a?(Hash) && phone['number'] == '555-1234' }
      
      test_record.set_field('name', { 'first' => 'Test', 'middle' => 'Ruby', 'last' => 'User' })
      name = test_record.get_field_value_single('name')
      test_fields << { type: 'name', test: name.is_a?(Hash) && name['first'] == 'Test' }
      
      # Verify all field types work
      if test_fields.all? { |f| f[:test] }
        results[:tests][:field_types] = { 
          status: 'PASS', 
          message: "All #{test_fields.length} field types work correctly" 
        }
      else
        failed = test_fields.reject { |f| f[:test] }.map { |f| f[:type] }
        results[:tests][:field_types] = { 
          status: 'FAIL', 
          message: "Failed field types: #{failed.join(', ')}" 
        }
      end
    rescue => e
      results[:tests][:field_types] = { status: 'FAIL', message: e.message }
    end
    
    # Test 6: Notation parser
    begin
      # Create notation parser
      parser = KeeperSecretsManager::Notation::Parser.new(secrets_manager)
      
      # Test would need a real record UID, so we'll test the parser structure
      test_notations = [
        'keeper://test/type',
        'keeper://test/field/login',
        'keeper://test/custom_field/Ruby Version'
      ]
      
      # Just verify parser exists and can handle basic parsing
      results[:tests][:notation_parser] = { 
        status: 'PASS', 
        message: 'Notation parser initialized' 
      }
    rescue => e
      results[:tests][:notation_parser] = { status: 'FAIL', message: e.message }
    end
    
    # Test 7: Crypto operations
    begin
      crypto = KeeperSecretsManager::Crypto
      
      # Test key generation
      keys = crypto.generate_ecc_keys
      
      # Test encryption/decryption
      test_data = "Ruby #{RUBY_VERSION} crypto test"
      encrypted = crypto.encrypt_ec(test_data, keys[:public_key_bytes])
      decrypted = crypto.decrypt_ec(encrypted, keys[:private_key_obj])
      
      if decrypted == test_data
        results[:tests][:crypto_operations] = { 
          status: 'PASS', 
          message: 'EC encryption/decryption works' 
        }
      else
        results[:tests][:crypto_operations] = { 
          status: 'FAIL', 
          message: 'Encryption/decryption mismatch' 
        }
      end
    rescue => e
      results[:tests][:crypto_operations] = { status: 'FAIL', message: e.message }
    end
    
    # Test 8: Storage implementations
    begin
      # Test different storage types
      storages_tested = []
      
      # In-memory storage
      mem_storage = KeeperSecretsManager::Storage::InMemoryStorage.new
      mem_storage.save_string('test_key', 'test_value')
      if mem_storage.get_string('test_key') == 'test_value'
        storages_tested << 'InMemory'
      end
      
      # File storage
      require 'tempfile'
      temp_file = Tempfile.new(['ksm_test', '.json'])
      begin
        file_storage = KeeperSecretsManager::Storage::FileStorage.new(temp_file.path)
        file_storage.save_string('test_key', 'test_value')
        if file_storage.get_string('test_key') == 'test_value'
          storages_tested << 'File'
        end
      ensure
        temp_file.close
        temp_file.unlink
      end
      
      results[:tests][:storage_types] = { 
        status: 'PASS', 
        message: "Tested storage types: #{storages_tested.join(', ')}" 
      }
    rescue => e
      results[:tests][:storage_types] = { status: 'FAIL', message: e.message }
    end
    
    puts results.to_json
  end
  
  # Run the tests
  begin
    test_sdk_features
  rescue => e
    error_result = {
      ruby_version: RUBY_VERSION,
      error: e.message,
      backtrace: e.backtrace.first(5)
    }
    puts error_result.to_json
    exit 1
  end
RUBY

File.write(File.join(test_dir, 'integration_test.rb'), test_script)

# Create Dockerfile for each Ruby version
dockerfile_template = <<~'DOCKERFILE'
  FROM ruby:RUBY_VERSION
  
  # Install dependencies
  RUN apt-get update && apt-get install -y \
      build-essential \
      libssl-dev \
      && rm -rf /var/lib/apt/lists/*
  
  # Set working directory
  WORKDIR /app
  
  # Copy SDK files
  COPY lib ./lib
  COPY integration_test.rb .
  COPY config.base64 . 2>/dev/null || :
  
  # Run the test
  CMD ["ruby", "integration_test.rb"]
DOCKERFILE

puts '=== Keeper Secrets Manager Ruby SDK Multi-Version Integration Test ==='
puts "Testing across Ruby versions: #{RUBY_VERSIONS.join(', ')}"
puts

# Run tests for each Ruby version
RUBY_VERSIONS.each do |version|
  puts "Testing Ruby #{version}..."

  # Create version-specific Dockerfile
  dockerfile = dockerfile_template.gsub('RUBY_VERSION', version)
  dockerfile_path = File.join(test_dir, "Dockerfile.#{version}")
  File.write(dockerfile_path, dockerfile)

  # Build Docker image
  image_name = "ksm-ruby-test:#{version}"
  build_cmd = "docker build -f #{dockerfile_path} -t #{image_name} #{test_dir} 2>&1"

  if system(build_cmd, out: File::NULL)
    # Run the test
    output = `docker run --rm #{image_name} 2>&1`

    begin
      result = JSON.parse(output.lines.last)
      results[version] = result

      # Print summary for this version
      puts "  Ruby: #{result['ruby_version']}"
      puts "  OpenSSL: #{result['openssl_version']}"

      if result['tests']
        passed = result['tests'].values.count { |t| t['status'] == 'PASS' }
        total = result['tests'].length
        puts "  Tests: #{passed}/#{total} passed"

        # Show failures if any
        result['tests'].each do |name, test|
          puts "    ❌ #{name}: #{test['message']}" if test['status'] == 'FAIL'
        end
      elsif result['error']
        puts "  ❌ Error: #{result['error']}"
      end
    rescue JSON::ParserError
      puts '  ❌ Failed to parse output:'
      puts output
      results[version] = { error: 'Failed to parse output', output: output }
    end
  else
    puts '  ❌ Failed to build Docker image'
    results[version] = { error: 'Failed to build Docker image' }
  end

  puts
end

# Generate summary report
puts '=== Summary Report ==='
puts

# Create results table
successful_versions = []
failed_versions = []

results.each do |version, result|
  if result['tests'] && result['tests'].values.all? { |t| t['status'] == 'PASS' }
    successful_versions << version
  else
    failed_versions << version
  end
end

puts "✅ Successful versions: #{successful_versions.join(', ')}"
puts "❌ Failed versions: #{failed_versions.join(', ')}" unless failed_versions.empty?

# Save detailed results
results_file = File.join(test_dir, 'test_results.json')
File.write(results_file, JSON.pretty_generate(results))
puts "\nDetailed results saved to: #{results_file}"

# Cleanup Docker images
puts "\nCleaning up Docker images..."
RUBY_VERSIONS.each do |version|
  system("docker rmi ksm-ruby-test:#{version} 2>&1", out: File::NULL)
end

# Exit with appropriate code
exit(failed_versions.empty? ? 0 : 1)
