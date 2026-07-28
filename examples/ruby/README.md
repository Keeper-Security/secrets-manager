# Keeper Secrets Manager Ruby SDK Examples

This directory contains examples demonstrating various features of the Keeper Secrets Manager Ruby SDK.

## Prerequisites

1. **First-time setup**: Run `00_interactive_setup.rb` to create your configuration, OR manually bind a one-time token and save to `keeper_config.json`

2. **Subsequent use**: All examples (01-11) expect a saved configuration file at `keeper_config.json`

3. Install dependencies:

   **Option A: Using Bundler (Recommended)**
   ```bash
   cd examples
   bundle install
   ```
   This installs all required dependencies including the SDK and optional gems.

   **Option B: Manual Installation**
   ```bash
   gem install keeper_secrets_manager
   gem install base32  # Optional, for 09_totp.rb
   ```

## Getting Started

### Quick Start Workflow

**For first-time users:**
1. Run `00_interactive_setup.rb` to create `keeper_config.json`
2. Run `01_quick_start.rb` to verify your setup
3. Work through examples 02-09 to learn features
4. Try advanced examples 10-11 for PAM and custom caching

**For existing users with `keeper_config.json`:**
1. Jump to `01_quick_start.rb` for a basic overview
2. Explore specific features in examples 02-11

## Examples

### 00_interactive_setup.rb
Interactive first-time user onboarding with step-by-step guidance:
- Prompts for one-time token input
- Guides through storage options (file, environment variable, or display base64)
- Validates connection and displays available secrets
- Perfect starting point for new users

### 01_quick_start.rb
Basic connection and simple secret retrieval. Quick overview of core SDK functionality.

### 02_authentication.rb
Different ways to authenticate with Keeper Secrets Manager:
- Using one-time token authentication
- Using file-based configuration (recommended)
- Using base64 configuration string
- Using environment variables
- Choosing the right authentication method for your use case

### 03_retrieve_secrets.rb
Various methods to retrieve secrets:
- Get all secrets
- Get by UID (single and multiple)
- Get by title (search)
- Access specific fields
- Using Keeper Notation
- New DTO fields: `is_editable`, `inner_folder_uid`, `links`

Related: See `08_notation.rb` for advanced notation patterns.

### 04_create_update_delete.rb
CRUD operations for managing secrets:
- Create new records with `CreateOptions`
- Update existing records
- Advanced updates: Password rotation with transaction types
- Advanced updates: Remove file links with `UpdateOptions`
- Delete records
- Batch operation tips

Prerequisites: Understanding of record structure from examples 01-03.

### 05_field_types.rb
Working with different Keeper field types:
- Standard fields (login, password, URL)
- Complex fields (name, address, phone)
- Custom fields
- Special fields (payment cards, bank accounts)

### 06_files.rb
File attachment operations:
- Download files from records
- Download file thumbnails
- Upload files to records
- Handle different file types
- Manage file metadata

### 07_folders.rb
Folder management:
- List folders
- Create folders and subfolders
- Move records between folders
- Get folder hierarchy
- Delete folders

### 08_notation.rb
Using Keeper Notation for quick access:
- Access fields with URI-style notation (`keeper://`)
- Use in configuration templates
- Access custom fields and files
- Complex field property access

Related: Builds on retrieval patterns from `03_retrieve_secrets.rb`.

### 09_totp.rb
Time-based One-Time Passwords (2FA):
- Generate TOTP codes
- Store TOTP seeds
- Integration with authenticator apps

Prerequisites: Requires `base32` gem (`gem install base32`).

### 10_custom_caching.rb
 ustom HTTP handling and caching patterns using `custom_post_function`:
- Built-in disaster recovery caching
- Request logging and debugging
- Response caching with TTL
- Offline fallback with cache
- Rate limiting and throttling
- Combined patterns for production use

### 11_pam_linked_records.rb
Working with PAM (Privileged Access Manager) resources and linked credentials:
- Retrieve PAM resources with `request_links: true`
- Access linked admin and launch credentials
- Navigate PAM resource hierarchies
- New DTO fields: `links`, `is_editable`, `inner_folder_uid`
- Zero-trust access patterns

This example demonstrates PAM integration for privileged access management. Requires PAM resources in your vault.

## Running Examples

Each example can be run directly:

**Using Bundler (Recommended)**
```bash
cd examples
bundle exec ruby 00_interactive_setup.rb
bundle exec ruby 01_quick_start.rb
bundle exec ruby 03_retrieve_secrets.rb
# etc.
```

**Or run directly if gems installed globally:**
```bash
ruby 00_interactive_setup.rb
ruby 01_quick_start.rb
# etc.
```

**Note**: Most examples expect a saved configuration file at `keeper_config.json`. Run `00_interactive_setup.rb` first if you don't have one.

## Advanced Topics

### Disaster Recovery Caching
The SDK includes built-in disaster recovery caching via `CachingPostFunction`:
- **Automatic failover**: Uses cached data when network is unavailable
- **Zero configuration**: Just enable the feature
- **Encrypted cache**: Cached data remains secure
- **Production-ready**: Network-first with automatic fallback

```ruby
# Recommended for production applications
secrets_manager = KeeperSecretsManager.from_file(
  'keeper_config.json',
  custom_post_function: KeeperSecretsManager::CachingPostFunction
)
```

See Example 0 in `10_custom_caching.rb` for complete demonstration.

### Custom HTTP Handling
For advanced use cases, customize HTTP request handling via the `custom_post_function` parameter:
- **Custom caching**: Implement TTL-based caching or cache warming
- **Logging**: Track all API requests for debugging
- **Rate limiting**: Throttle requests to stay within quotas
- **Monitoring**: Integrate with observability systems
- **Proxy integration**: Corporate proxy or authentication requirements

See Examples 1-5 in `10_custom_caching.rb` for implementation patterns.

### When to Use Each Approach
- **Built-in CachingPostFunction** (Example 0): Production disaster recovery, high availability
- **Custom caching** (Examples 1-5): Advanced patterns, specific TTL requirements, custom logic

For most use cases, the built-in `CachingPostFunction` is recommended.

### Performance Optimization Tips
1. **Disaster recovery caching**: Enable `CachingPostFunction` for production apps
2. **Retrieve by UID**: Faster than searching by title
3. **Batch operations**: Group multiple updates when possible
4. **File-based storage**: Use `from_file()` to avoid re-authentication on every run
5. **Custom caching**: Implement TTL-based caching for read-heavy workloads (see example 10)

## Security Notes

- Never hardcode credentials in your code
- Use environment variables for configuration
- Keep your tokens and configurations secure
- Don't commit credentials to version control
- Use file-based storage with appropriate file permissions (0600)
- Rotate tokens regularly following security best practices
