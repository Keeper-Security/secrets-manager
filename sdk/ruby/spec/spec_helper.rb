begin
  require 'bundler/setup'
rescue StandardError
  LoadError
end
require 'keeper_secrets_manager'
begin
  require 'webmock/rspec'
rescue LoadError
  # WebMock not available, tests will run against real API
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Allow real connections in integration tests
  config.before(:each) do |example|
    if example.metadata[:integration]
      WebMock.allow_net_connect!
    else
      WebMock.disable_net_connect!
    end
  end
end

# Test helpers
module TestHelpers
  def mock_config
    KeeperSecretsManager::Storage::InMemoryStorage.new({
                                                         'hostname' => 'test.keepersecurity.com',
                                                         'clientId' => 'test-client-id',
                                                         'privateKey' => Base64.encode64('test-private-key'),
                                                         'appKey' => Base64.encode64('test-app-key'),
                                                         'serverPublicKeyId' => '10'
                                                       })
  end

  def mock_record_data
    {
      'recordUid' => 'test-record-uid',
      'revision' => 1,
      'data' => {
        'title' => 'Test Record',
        'type' => 'login',
        'fields' => [
          { 'type' => 'login', 'value' => ['testuser'] },
          { 'type' => 'password', 'value' => ['testpass'] },
          { 'type' => 'url', 'value' => ['https://example.com'] }
        ],
        'custom' => [
          { 'type' => 'text', 'label' => 'Custom Field', 'value' => ['custom value'] }
        ],
        'notes' => 'Test notes'
      }
    }
  end
end

RSpec.configure do |c|
  c.include TestHelpers
end

# Load support files
Dir[File.expand_path('support/**/*.rb', __dir__)].each { |f| require f }
