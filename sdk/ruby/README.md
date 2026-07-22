## Keeper Secrets Manager Ruby SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/ruby-sdk

# Change Log

## 17.2.0 - 2025-11-14
- KSM-685 - Fixed `CreateOptions.subfolder_uid` parameter API transmission
- KSM-686 - Implemented disaster recovery caching with `CachingPostFunction`
- KSM-687 - Added missing DTO fields for complete SDK parity (links, is_editable, inner_folder_uid, thumbnail_url, last_modified, expires_on)
- KSM-1013 - Added typed linked-credential accessors (`KeeperRecordLink` via `record.get_links`) and a `request_links:` option on `get_secrets`
- KSM-692 - Added HTTP proxy support for enterprise environments
- KSM-694 - Added convenience methods (`upload_file_from_path`, `try_get_notation`)
- KSM-696 - Fixed file permissions for Ruby SDK config files
- KSM-697 - Comprehensive unit test coverage improvements (+358 tests, 63.3% coverage)
- KSM-734 - Fixed notation lookup to handle duplicate UIDs from record shortcuts
- KSM-743 - Added transmission public key #18 for Gov Cloud Dev environment support
- Added `from_config()` convenience method for base64 config initialization
- Added `update_secret_with_options()` method for removing file links
- Added `download_thumbnail()` method for file thumbnails
- Added development console (`bin/console`) for interactive SDK exploration
- Fixed example files to use correct SDK APIs
- Improved mock infrastructure with proper AES-256-GCM encryption

## 17.1.0 - 2025-01-06
- **BREAKING**: Minimum Ruby version increased to 3.1.0 (from 2.6.0)
- Fixed ECC key generation to return 32-byte raw private keys
- Fixed `update_secret` to correctly encrypt and persist changes
- Fixed `download_file` SSL certificate verification
- Fixed `upload_file` to use correct endpoint
- Fixed `create_folder` encryption and parent_uid handling

For full version history, see [CHANGELOG.md](CHANGELOG.md)

# Quick Start

## Installation

```bash
gem install keeper_secrets_manager
```

## Basic Usage

```ruby
require 'keeper_secrets_manager'

# Initialize from config file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

# Get all secrets
records = secrets_manager.get_secrets

# Access secret fields
record = records.first
puts "Password: #{record.password}"
```

## Linked Credentials (PAM)

PAM records can carry linked credentials. Request them with `request_links: true`, then use the typed `KeeperRecordLink` accessors returned by `record.get_links` (the raw entries remain available on `record.links`):

```ruby
records = secrets_manager.get_secrets(request_links: true)

records.each do |record|
  record.get_links.each do |link|
    puts "-> #{link.record_uid} (path: #{link.path.inspect})"

    # Permission booleans read allowedSettings when nested (e.g. on "meta" links)
    puts "  rotation allowed: #{link.allows_rotation?}"
    puts "  admin user: #{link.admin_user?}"

    # Encrypted ai_settings / jit_settings decrypt with the owning record's key
    ai = link.get_ai_settings_data(record.record_key)
    puts "  ai settings: #{ai.inspect}" if ai
  end
end
```

Accessors never raise — decode or decryption failures return `nil`/`false`.

## Proxy Support

For enterprise environments behind HTTP proxies:

```ruby
# Method 1: Explicit proxy_url parameter
secrets_manager = KeeperSecretsManager.from_file(
  'keeper_config.json',
  proxy_url: 'http://proxy.company.com:8080'
)

# Method 2: Authenticated proxy
secrets_manager = KeeperSecretsManager.from_file(
  'keeper_config.json',
  proxy_url: 'http://username:password@proxy.company.com:8080'
)

# Method 3: HTTPS_PROXY environment variable (recommended)
# export HTTPS_PROXY=http://proxy.company.com:8080
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')
# Proxy auto-detected from environment
```

See `examples/ruby/12_proxy_usage.rb` for complete examples.

# Documentation

For complete documentation, see: https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/ruby-sdk