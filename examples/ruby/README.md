# Keeper Secrets Manager Ruby SDK Examples

This directory contains examples demonstrating various features of the Keeper Secrets Manager Ruby SDK.

## Prerequisites

1. Set up your configuration using one of these methods:
   - Token: `export KSM_TOKEN='your_token_here'`
   - Base64 Config: `export KSM_CONFIG='your_base64_config_here'`

2. Install dependencies:

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

**First-time users**: Start with `00_interactive_setup.rb` which guides you through the setup process step-by-step.

**Existing users**: If you already have a configuration, jump to `01_quick_start.rb` for a basic overview.

**Recommended progression**: Work through examples 00-09 in order to build understanding progressively. Example 10 is advanced and best attempted after mastering the basics.

## Examples

### 00_interactive_setup.rb
**[Beginner]** Interactive first-time user onboarding with step-by-step guidance:
- Prompts for one-time token input
- Guides through storage options (file, environment variable, or display base64)
- Validates connection and displays available secrets
- Perfect starting point for new users

### 01_quick_start.rb
**[Beginner]** Basic connection and simple secret retrieval. Quick overview of core SDK functionality.

### 02_authentication.rb
**[Beginner]** Different ways to authenticate with Keeper Secrets Manager:
- Using token authentication
- Using base64 configuration string
- Choosing the right authentication method for your use case

### 03_retrieve_secrets.rb
**[Intermediate]** Various methods to retrieve secrets:
- Get all secrets
- Get by UID (single and multiple)
- Get by title (search)
- Access specific fields
- Using Keeper Notation

Related: See `08_notation.rb` for advanced notation patterns.

### 04_create_update_delete.rb
**[Intermediate]** CRUD operations for managing secrets:
- Create new records
- Update existing records
- Delete records
- Batch operation tips

Prerequisites: Understanding of record structure from examples 01-03.

### 05_field_types.rb
**[Intermediate]** Working with different Keeper field types:
- Standard fields (login, password, URL)
- Complex fields (name, address, phone)
- Custom fields
- Special fields (payment cards, bank accounts)

### 06_files.rb
**[Intermediate]** File attachment operations:
- Download files from records
- Upload files to records
- Handle different file types
- Manage file metadata

### 07_folders.rb
**[Intermediate]** Folder management:
- List folders
- Create folders and subfolders
- Move records between folders
- Get folder hierarchy
- Delete folders

### 08_notation.rb
**[Intermediate]** Using Keeper Notation for quick access:
- Access fields with URI-style notation (`keeper://`)
- Use in configuration templates
- Access custom fields and files
- Complex field property access

Related: Builds on retrieval patterns from `03_retrieve_secrets.rb`.

### 09_totp.rb
**[Intermediate]** Time-based One-Time Passwords (2FA):
- Generate TOTP codes
- Store TOTP seeds
- Integration with authenticator apps

Prerequisites: Requires `base32` gem (`gem install base32`).

### 10_custom_caching.rb
**[Advanced]** Custom HTTP handling and caching patterns using `custom_post_function`:
- Request logging and debugging
- Response caching with TTL
- Offline fallback with cache
- Rate limiting and throttling
- Combined patterns for production use

This example demonstrates advanced SDK customization for performance optimization and production scenarios. Best attempted after mastering examples 01-09.

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

Make sure your environment variables are set before running the examples (except `00_interactive_setup.rb`, which guides you through setup).

## Advanced Topics

### Custom HTTP Handling
The SDK allows you to customize HTTP request handling via the `custom_post_function` parameter. This enables:
- **Caching**: Store API responses to reduce network calls
- **Logging**: Track all API requests for debugging
- **Rate limiting**: Throttle requests to stay within quotas
- **Offline support**: Implement fallback behavior when network is unavailable
- **Custom authentication**: Integrate with proxy servers or corporate authentication systems

See `10_custom_caching.rb` for complete implementation examples.

### When to Use Custom Functions
Use `custom_post_function` when you need to:
- Implement response caching for performance
- Add request/response logging for debugging
- Handle rate limiting or throttling
- Provide offline fallback behavior
- Integrate with monitoring systems
- Add custom retry logic

For standard use cases, the default HTTP handler is sufficient and recommended.

### Performance Optimization Tips
1. **Cache secrets locally**: Use `CachingStorage` to reduce API calls
2. **Retrieve by UID**: Faster than searching by title
3. **Batch operations**: Group multiple updates when possible
4. **Custom caching**: Implement response caching for read-heavy workloads (see example 10)
5. **Persistent storage**: Use `FileStorage` to avoid re-authentication on every run

## Security Notes

- Never hardcode credentials in your code
- Use environment variables for configuration
- Keep your tokens and configurations secure
- Don't commit credentials to version control
- Use file-based storage with appropriate file permissions (0600)
- Rotate tokens regularly following security best practices
