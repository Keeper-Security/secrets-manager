# Keeper Secrets Manager Ruby SDK Examples

This directory contains examples demonstrating various features of the Keeper Secrets Manager Ruby SDK.

## Prerequisites

1. Set up your configuration using one of these methods:
   - Token: `export KSM_TOKEN='your_token_here'`
   - Base64 Config: `export KSM_CONFIG='your_base64_config_here'`

2. Install the SDK:
   ```bash
   gem install keeper_secrets_manager
   ```

## Examples

### 01_quick_start.rb
Basic connection and simple secret retrieval. Start here if you're new to the SDK.

### 02_authentication.rb
Different ways to authenticate with Keeper Secrets Manager:
- Using token authentication
- Using base64 configuration string

### 03_retrieve_secrets.rb
Various methods to retrieve secrets:
- Get all secrets
- Get by UID
- Get by title
- Access specific fields
- Using Keeper Notation

### 04_create_update_delete.rb
CRUD operations for managing secrets:
- Create new records
- Update existing records
- Delete records
- Batch operations tips

### 05_field_types.rb
Working with different Keeper field types:
- Standard fields (login, password, URL)
- Complex fields (name, address, phone)
- Custom fields
- Special fields (payment cards, bank accounts)

### 06_files.rb
File attachment operations:
- Download files from records
- Upload files to records
- Handle different file types

### 07_folders.rb
Folder management:
- List folders
- Create folders and subfolders
- Move records between folders
- Get folder hierarchy
- Delete folders

### 08_notation.rb
Using Keeper Notation for quick access:
- Access fields with URI-style notation
- Use in configuration templates
- Access custom fields and files

### 09_totp.rb
Time-based One-Time Passwords (2FA):
- Generate TOTP codes
- Store TOTP seeds
- Integration with authenticator apps

## Running Examples

Each example can be run directly:

```bash
ruby 01_quick_start.rb
```

Make sure your environment variables are set before running the examples.

## Security Notes

- Never hardcode credentials in your code
- Use environment variables for configuration
- Keep your tokens and configurations secure
- Don't commit credentials to version control