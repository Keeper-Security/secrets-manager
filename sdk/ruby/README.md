# Keeper Secrets Manager Ruby SDK

The Ruby SDK for Keeper Secrets Manager provides a flexible, dynamic interface for accessing and managing secrets stored in Keeper's zero-knowledge vault.

## Features

- **Ruby 3.1+ Compatible**: Works with Chef, Puppet, and modern Ruby applications
- **Dynamic Record Handling**: JavaScript-style flexible records with no rigid class hierarchies
- **Minimal Dependencies**: Uses only Ruby standard library (no external runtime dependencies)
- **Comprehensive Crypto**: Full encryption/decryption support using OpenSSL
- **Multiple Storage Options**: In-memory, file-based, environment variables, and caching
- **Notation Support**: Access specific fields using `keeper://` URI notation
- **Field Helpers**: Optional convenience methods for common field types

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'keeper_secrets_manager'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install keeper_secrets_manager
```

## Quick Start

### Initialize with One-Time Token

```ruby
require 'keeper_secrets_manager'

# Initialize with one-time token
token = "US:ONE_TIME_TOKEN_HERE"
secrets_manager = KeeperSecretsManager.from_token(token)

# Retrieve secrets
records = secrets_manager.get_secrets
records.each do |record|
  puts "#{record.title}: #{record.get_field_value_single('login')}"
end
```

### Initialize with Existing Configuration

```ruby
# From config file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

# From environment (reads KSM_* variables)
config = KeeperSecretsManager::Storage::EnvironmentStorage.new('KSM_')
secrets_manager = KeeperSecretsManager.new(config: config)
```

## Dynamic Record Creation

The Ruby SDK uses a flexible, JavaScript-style approach to records:

```ruby
# Create record with hash syntax
record = KeeperSecretsManager::Dto::KeeperRecord.new(
  title: 'My Server',
  type: 'login',
  fields: [
    { 'type' => 'login', 'value' => ['admin'] },
    { 'type' => 'password', 'value' => ['SecurePass123!'] },
    { 'type' => 'url', 'value' => ['https://example.com'] },
    { 
      'type' => 'host', 
      'value' => [{ 'hostName' => '192.168.1.1', 'port' => '22' }],
      'label' => 'SSH Server'
    }
  ],
  custom: [
    { 'type' => 'text', 'label' => 'Environment', 'value' => ['Production'] }
  ]
)

# Dynamic field access
puts record.login          # => "admin"
record.password = 'NewPassword123!'

# Set complex fields
record.set_field('address', {
  'street1' => '123 Main St',
  'city' => 'New York',
  'state' => 'NY',
  'zip' => '10001'
})
```

## Notation Support

Access specific field values using Keeper notation:

```ruby
# Get password from record
password = secrets_manager.get_notation("keeper://RECORD_UID/field/password")

# Get specific property from complex field
hostname = secrets_manager.get_notation("keeper://RECORD_UID/field/host[hostName]")
port = secrets_manager.get_notation("keeper://RECORD_UID/field/host[port]")

# Get custom field by label
env = secrets_manager.get_notation("keeper://RECORD_UID/custom_field/Environment")

# Access by record title
url = secrets_manager.get_notation("keeper://My Login/field/url")
```

## Field Type Helpers

Optional convenience methods for creating typed fields:

```ruby
# Using field helpers
fields = [
  KeeperSecretsManager::FieldTypes::Helpers.login('username'),
  KeeperSecretsManager::FieldTypes::Helpers.password('SecurePass123!'),
  KeeperSecretsManager::FieldTypes::Helpers.host(
    hostname: '192.168.1.100',
    port: 22
  ),
  KeeperSecretsManager::FieldTypes::Helpers.name(
    first: 'John',
    last: 'Doe',
    middle: 'Q'
  )
]

record = KeeperSecretsManager::Dto::KeeperRecord.new(
  title: 'Server with Helpers',
  type: 'login',
  fields: fields.map(&:to_h)
)
```

## Storage Options

### In-Memory Storage
```ruby
storage = KeeperSecretsManager::Storage::InMemoryStorage.new
```

### File Storage
```ruby
storage = KeeperSecretsManager::Storage::FileStorage.new('keeper_config.json')
```

### Environment Variables
```ruby
# Reads from KSM_* environment variables (read-only)
storage = KeeperSecretsManager::Storage::EnvironmentStorage.new('KSM_')
```

### Caching Storage
```ruby
# Wrap any storage with caching (600 second TTL)
# This caches configuration data, not API responses
base_storage = KeeperSecretsManager::Storage::FileStorage.new('config.json')
storage = KeeperSecretsManager::Storage::CachingStorage.new(base_storage, 600)
```

## API Response Caching (Disaster Recovery)

Enable caching to protect against network failures. When enabled, encrypted API responses are saved to a local file. If the network becomes unavailable, the SDK automatically falls back to cached data.

```ruby
# Enable caching for disaster recovery
storage = KeeperSecretsManager::Storage::FileStorage.new('config.json')
secrets_manager = KeeperSecretsManager.new(
  config: storage,
  custom_post_function: KeeperSecretsManager::CachingPostFunction
)

# First call - hits network and saves to cache
records = secrets_manager.get_secrets

# Subsequent calls - use network if available, fall back to cache if network fails
records = secrets_manager.get_secrets  # Uses cache if network is down
```

**Cache behavior**:
- Network requests are always tried first
- Successful responses are automatically saved to cache
- Cache is used only when network requests fail
- Cache stores encrypted data for security
- Default cache location: `./ksm_cache.bin`

**Configure cache location**:
```ruby
# Set via environment variable
ENV['KSM_CACHE_DIR'] = '/path/to/cache/directory'

# Or programmatically
KeeperSecretsManager::Cache.cache_file_path  # => '/path/to/cache/directory/ksm_cache.bin'
```

**Clear cache**:
```ruby
KeeperSecretsManager::Cache.clear_cache
```

## CRUD Operations

### Create Record
```ruby
record = KeeperSecretsManager::Dto::KeeperRecord.new(
  title: 'New Record',
  type: 'login',
  fields: [
    { 'type' => 'login', 'value' => ['user'] },
    { 'type' => 'password', 'value' => ['pass'] }
  ]
)

record_uid = secrets_manager.create_secret(record)
```

### Update Record
```ruby
# Get existing record
record = secrets_manager.get_secret_by_title("My Record")

# Update fields
record.set_field('password', 'NewPassword123!')
record.notes = "Updated on #{Time.now}"

# Save changes
secrets_manager.update_secret(record)
```

### Delete Records
```ruby
# Delete single record
secrets_manager.delete_secret('RECORD_UID')

# Delete multiple records
secrets_manager.delete_secret(['UID1', 'UID2', 'UID3'])
```

### Folder Operations
```ruby
# Get all folders
folders = secrets_manager.get_folders

# Create folder
folder_uid = secrets_manager.create_folder('New Folder', parent_uid: 'PARENT_UID')

# Update folder
secrets_manager.update_folder(folder_uid, 'Renamed Folder')

# Delete folder
secrets_manager.delete_folder(folder_uid, force: true)

# Folder hierarchy features
fm = secrets_manager.folder_manager

# Build folder tree structure
tree = fm.build_folder_tree

# Get folder path from root
path = secrets_manager.get_folder_path(folder_uid)  # "Parent/Child/Grandchild"

# Find folder by name
folder = secrets_manager.find_folder_by_name("Finance")
folder = secrets_manager.find_folder_by_name("Finance", parent_uid: "parent_uid")

# Get folder relationships
ancestors = fm.get_ancestors(folder_uid)    # [parent, grandparent, ...]
descendants = fm.get_descendants(folder_uid) # [children, grandchildren, ...]

# Print folder tree to console
fm.print_tree
```

## Error Handling

```ruby
begin
  records = secrets_manager.get_secrets
rescue KeeperSecretsManager::AuthenticationError => e
  puts "Authentication failed: #{e.message}"
rescue KeeperSecretsManager::NetworkError => e
  puts "Network error: #{e.message}"
rescue KeeperSecretsManager::Error => e
  puts "General error: #{e.message}"
end
```

## Configuration

The SDK can be configured through various options:

```ruby
secrets_manager = KeeperSecretsManager.new(
  config: storage,
  hostname: 'keepersecurity.eu',    # EU datacenter
  verify_ssl_certs: true,           # Verify SSL certificates
  logger: Logger.new(STDOUT),       # Custom logger
  log_level: Logger::DEBUG          # Log level
)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests.

To install this gem onto your local machine, run `bundle exec rake install`.

## Testing

```bash
# Run all tests
bundle exec rake spec

# Run unit tests only
bundle exec rake unit

# Run with coverage
bundle exec rake coverage

# Run linter
bundle exec rubocop
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Keeper-Security/secrets-manager.

## License

The gem is available as open source under the terms of the MIT License.

## Support

For support, please visit https://docs.keeper.io/secrets-manager/ or contact sm@keepersecurity.com