#!/usr/bin/env ruby

# Comprehensive Docker test suite for all integration tests
# Tests the SDK across multiple Ruby versions

require 'fileutils'
require 'json'
require 'base64'
require 'optparse'

# Ruby versions to test
RUBY_VERSIONS = {
  '2.7' => 'Minimum supported version',
  '3.0' => 'Major version update',
  '3.1' => 'Stable version',
  '3.2' => 'Recent stable',
  '3.3' => 'Latest stable',
  'latest' => 'Latest available'
}

# Test files to run
TEST_SUITES = {
  'quick_test.rb' => 'Basic CRUD operations',
  'test_error_handling.rb' => 'Error handling',
  'test_file_operations.rb' => 'File operations',
  'test_totp.rb' => 'TOTP functionality',
  'test_batch_operations.rb' => 'Batch operations',
  'test_advanced_search.rb' => 'Advanced search',
  'test_performance.rb' => 'Performance benchmarks'
}

# Parse command line options
options = {
  versions: RUBY_VERSIONS.keys,
  tests: TEST_SUITES.keys,
  verbose: false,
  keep_containers: false
}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby docker_test_suite.rb [options]"
  
  opts.on("-v", "--version VERSION", "Test specific Ruby version") do |v|
    options[:versions] = [v]
  end
  
  opts.on("-t", "--test TEST", "Run specific test file") do |t|
    options[:tests] = [t]
  end
  
  opts.on("--verbose", "Show detailed output") do
    options[:verbose] = true
  end
  
  opts.on("-k", "--keep", "Keep containers after tests") do
    options[:keep_containers] = true
  end
  
  opts.on("-h", "--help", "Show this help") do
    puts opts
    puts "\nAvailable Ruby versions:"
    RUBY_VERSIONS.each { |v, desc| puts "  #{v.ljust(10)} - #{desc}" }
    puts "\nAvailable test suites:"
    TEST_SUITES.each { |file, desc| puts "  #{file.ljust(25)} - #{desc}" }
    exit 0
  end
end.parse!

# Check Docker availability
unless system('docker --version > /dev/null 2>&1')
  puts "❌ Error: Docker is not installed or not available"
  exit 1
end

puts "=== Keeper Secrets Manager Ruby SDK - Docker Test Suite ==="
puts "Testing #{options[:tests].length} test suite(s) on #{options[:versions].length} Ruby version(s)"
puts "=" * 70

# Setup test environment
sdk_dir = File.expand_path('../..', __dir__)
docker_dir = File.join(sdk_dir, 'docker_test_env')
FileUtils.rm_rf(docker_dir) if Dir.exist?(docker_dir)
FileUtils.mkdir_p(docker_dir)

# Copy SDK files
FileUtils.cp_r(File.join(sdk_dir, 'lib'), docker_dir)
FileUtils.cp_r(File.join(sdk_dir, 'test'), docker_dir)
FileUtils.cp(File.join(sdk_dir, 'config.base64'), docker_dir) rescue nil

# Create Dockerfile template
dockerfile_template = <<~DOCKERFILE
  FROM ruby:RUBY_VERSION
  
  WORKDIR /app
  
  # Install dependencies
  RUN gem install bundler
  
  # Install runtime dependencies
  RUN gem install base32
  
  # Copy SDK files
  COPY lib/ ./lib/
  COPY test/ ./test/
  COPY config.base64* ./
  COPY run_test.rb ./
  
  # Set up environment
  ENV RUBYOPT="-I/app/lib"
  
  # Default command
  CMD ["ruby", "--version"]
DOCKERFILE

# Create test runner script
test_runner = <<~'RUBY'
#!/usr/bin/env ruby

test_file = ARGV[0]
exit 1 unless test_file

puts "Running #{test_file} on Ruby #{RUBY_VERSION}"
puts "-" * 50

begin
  require_relative test_file
  exit 0
rescue => e
  puts "ERROR: #{e.class} - #{e.message}"
  puts e.backtrace.first(5).join("\n")
  exit 1
end
RUBY

File.write(File.join(docker_dir, 'run_test.rb'), test_runner)

# Results tracking
results = {}
start_time = Time.now

# Run tests for each Ruby version
options[:versions].each do |version|
  puts "\n" + "=" * 70
  puts "Testing Ruby #{version}"
  puts "=" * 70
  
  results[version] = {}
  
  # Create version-specific Dockerfile
  dockerfile = dockerfile_template.gsub('RUBY_VERSION', version)
  dockerfile_path = File.join(docker_dir, "Dockerfile.#{version}")
  File.write(dockerfile_path, dockerfile)
  
  # Build Docker image
  image_name = "ksm-ruby-test:#{version}"
  print "Building Docker image... "
  
  build_cmd = "docker build -f #{dockerfile_path} -t #{image_name} #{docker_dir}"
  build_cmd += " > /dev/null 2>&1" unless options[:verbose]
  
  if system(build_cmd)
    puts "✅"
  else
    puts "❌"
    results[version][:build] = :failed
    next
  end
  
  # Run each test suite
  options[:tests].each do |test_file|
    print "  #{test_file.ljust(30)} ... "
    
    # Run test in container
    run_cmd = "docker run --rm #{image_name} ruby /app/run_test.rb /app/test/integration/#{test_file}"
    run_cmd += " > /dev/null 2>&1" unless options[:verbose]
    
    test_start = Time.now
    if system(run_cmd)
      test_time = Time.now - test_start
      puts "✅ (#{test_time.round(2)}s)"
      results[version][test_file] = :passed
    else
      puts "❌"
      results[version][test_file] = :failed
    end
  end
  
  # Clean up image unless keeping
  unless options[:keep_containers]
    system("docker rmi #{image_name} > /dev/null 2>&1")
  end
end

# Print summary
total_time = Time.now - start_time
puts "\n" + "=" * 70
puts "TEST SUMMARY"
puts "=" * 70

# Version summary
puts "\nBy Ruby Version:"
results.each do |version, tests|
  if tests[:build] == :failed
    puts "  Ruby #{version}: BUILD FAILED"
  else
    passed = tests.values.count(:passed)
    failed = tests.values.count(:failed)
    total = passed + failed
    status = failed == 0 ? "✅ ALL PASSED" : "❌ #{failed}/#{total} FAILED"
    puts "  Ruby #{version}: #{status}"
  end
end

# Test summary
puts "\nBy Test Suite:"
options[:tests].each do |test_file|
  results_for_test = results.map { |v, t| t[test_file] }.compact
  passed = results_for_test.count(:passed)
  failed = results_for_test.count(:failed)
  total = passed + failed
  
  if total > 0
    status = failed == 0 ? "✅ ALL PASSED" : "❌ #{failed}/#{total} FAILED"
    puts "  #{test_file.ljust(30)}: #{status}"
  end
end

puts "\nTotal time: #{total_time.round(2)}s"

# Detailed failures
failures = []
results.each do |version, tests|
  tests.each do |test, result|
    failures << "Ruby #{version} - #{test}" if result == :failed
  end
end

if failures.any?
  puts "\nFailed tests:"
  failures.each { |f| puts "  - #{f}" }
end

# Cleanup
unless options[:keep_containers]
  FileUtils.rm_rf(docker_dir)
end

# Exit code
exit failures.any? ? 1 : 0