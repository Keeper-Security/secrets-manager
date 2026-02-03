#!/usr/bin/env ruby

# Proxy Usage Example - Using Keeper Secrets Manager behind HTTP proxies
# Shows how to configure proxy support for enterprise environments

require 'keeper_secrets_manager'

puts '=== Keeper Secrets Manager - Proxy Configuration ==='
puts

# Method 1: Explicit proxy_url parameter (recommended for programmatic configuration)
puts '1. Explicit Proxy Configuration'
puts '   --------------------------'
begin
  # Configure proxy explicitly in code
  secrets_manager = KeeperSecretsManager.from_file(
    'keeper_config.json',
    proxy_url: 'http://proxy.company.com:8080'
  )

  records = secrets_manager.get_secrets
  puts "   Connected through proxy: proxy.company.com:8080"
  puts "   Retrieved #{records.length} secrets"
  puts '   [OK] Explicit proxy configuration works'
rescue StandardError => e
  puts "   [FAIL] #{e.message}"
end

puts

# Method 2: Authenticated proxy (with username and password)
puts '2. Authenticated Proxy'
puts '   ------------------'
begin
  # Proxy requiring authentication
  secrets_manager = KeeperSecretsManager.from_file(
    'keeper_config.json',
    proxy_url: 'http://username:password@proxy.company.com:8080'
  )

  records = secrets_manager.get_secrets
  puts "   Connected through authenticated proxy"
  puts "   Retrieved #{records.length} secrets"
  puts '   [OK] Authenticated proxy works'
rescue StandardError => e
  puts "   [FAIL] #{e.message}"
end

puts

# Method 3: Environment variable HTTPS_PROXY (recommended for deployment)
puts '3. Environment Variable HTTPS_PROXY'
puts '   --------------------------------'

# Simulate environment variable (in production, this would be set externally)
original_proxy = ENV['HTTPS_PROXY']
ENV['HTTPS_PROXY'] = 'http://proxy.company.com:8080'

begin
  # SDK automatically detects HTTPS_PROXY
  secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

  records = secrets_manager.get_secrets
  puts "   Auto-detected proxy from HTTPS_PROXY environment variable"
  puts "   Retrieved #{records.length} secrets"
  puts '   [OK] Environment variable proxy works'
rescue StandardError => e
  puts "   [FAIL] #{e.message}"
ensure
  # Restore original value
  if original_proxy
    ENV['HTTPS_PROXY'] = original_proxy
  else
    ENV.delete('HTTPS_PROXY')
  end
end

puts

# Method 4: File operations through proxy
puts '4. File Operations Through Proxy'
puts '   -----------------------------'
begin
  secrets_manager = KeeperSecretsManager.from_file(
    'keeper_config.json',
    proxy_url: 'http://proxy.company.com:8080'
  )

  # Get record with file attachments
  records = secrets_manager.get_secrets
  record_with_file = records.find { |r| r.files && r.files.any? }

  if record_with_file
    file = record_with_file.files.first
    downloaded = secrets_manager.download_file(file)

    puts "   Downloaded file: #{file['name']}"
    puts "   Size: #{downloaded['size']} bytes"
    puts '   [OK] File download works through proxy'
  else
    puts '   [INFO] No files available to test download'
    puts '   [OK] Proxy configuration applies to file operations'
  end
rescue StandardError => e
  puts "   [FAIL] #{e.message}"
end

puts

# Tips and Best Practices
puts '=== Proxy Configuration Tips ==='
puts
puts 'Environment Variable (Recommended for Production):'
puts '  export HTTPS_PROXY=http://proxy.company.com:8080'
puts '  ruby your_app.rb  # Proxy auto-detected'
puts
puts 'Docker/Kubernetes:'
puts '  env:'
puts '    - name: HTTPS_PROXY'
puts '      value: "http://proxy.company.com:8080"'
puts
puts 'Authenticated Proxy:'
puts '  proxy_url: "http://username:password@proxy.example.com:8080"'
puts
puts 'No Proxy Needed:'
puts '  # Just omit proxy_url parameter and unset HTTPS_PROXY'
puts '  secrets_manager = KeeperSecretsManager.from_file("config.json")'
puts

puts '=== Common Proxy URLs ==='
puts '  Unauthenticated:  http://proxy.company.com:8080'
puts '  Authenticated:    http://user:pass@proxy.company.com:8080'
puts '  HTTPS proxy:      https://proxy.company.com:443'
puts '  With IP:          http://192.168.1.100:3128'
puts

puts '=== Troubleshooting ==='
puts '  Connection Refused: Check proxy is running and accessible'
puts '  Auth Failed: Verify username/password are correct'
puts '  SSL Errors: Check proxy SSL certificate configuration'
puts '  Timeout: Verify proxy allows outbound HTTPS to keepersecurity.com'
