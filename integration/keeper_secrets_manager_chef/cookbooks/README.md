# Chef

Keeper Secrets Manager cookbook for Chef Infra automation platform

## About

Chef Infra is a powerful automation platform that transforms infrastructure into code. Whether you're operating in the cloud, on-premises, or in a hybrid environment, Chef automates how infrastructure is configured, deployed, and managed across your network, no matter its size.

The Keeper Secrets Manager cookbook allows Chef-managed nodes to integrate with Keeper Secrets Manager to make managing secrets in Chef infrastructure easier and more secure.

## Features

* Install and configure Keeper Secrets Manager Python SDK on Chef-managed nodes
* Retrieve secrets from the Keeper vault during Chef runs using Keeper Notation
* Secure authentication through encrypted data bags
* Cross-platform support (Linux, macOS, Windows)
* Support for environment variables, JSON output, and file secrets

## Prerequisites

* Keeper Secrets Manager access (See the [Quick Start Guide](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide) for more details)
  * Secrets Manager add-on enabled for your Keeper subscription
  * Membership in a Role with the Secrets Manager enforcement policy enabled
* A Keeper Secrets Manager Application with secrets shared to it
  * See the Quick Start Guide for instructions on creating an Application
* An initialized Keeper Secrets Manager Configuration
  * The cookbook accepts Base64 format configurations

## Installation

### Using Berkshelf

Add this line to your `Berksfile`:

```ruby
cookbook 'keeper_secrets_manager', git: 'https://github.com/your-org/keeper_secrets_manager.git'
```

### Using Chef Supermarket

```bash
knife cookbook site install keeper_secrets_manager
```

### Manual Installation

1. Download the cookbook
2. Place it in your cookbooks directory
3. Upload to your Chef server:

```bash
knife cookbook upload keeper_secrets_manager
```

## Setup

### Authentication

The cookbook uses **Encrypted Data Bags** for secure authentication. This method allows you to store your Keeper configuration securely on the Chef server and make it available to your nodes.

#### Configuring Encrypted Data Bags

Create an encrypted data bag to store your Keeper configuration:

```bash
# Create the data bag
knife data bag create keeper

# Create configuration item
cat > keeper_config.json << EOF
{
  "id": "keeper_config",
  "config_json": "eyJhcHBLZXkiOiJCaU..."
}
EOF

# Encrypt and upload to Chef server
knife data bag from file keeper keeper_config.json --secret-file /path/to/secret
```

The encrypted data bag will store your Keeper Secrets Manager configuration as environment variables that can be securely accessed by your Chef nodes.

### Input Configuration File

The `input.json` file is **mandatory** and defines which secrets to retrieve from your Keeper vault. This file uses Keeper Notation to specify the secrets you want to fetch.

#### Creating input.json

Create an `input.json` file with the following structure:

```json
{
  "authentication": [
    "base64"
  ],
  "secrets": [
    "jnPuLYWXt7b6Ym-_9OCvFA/field/password > APP_PASSWORD",
    "jnPuLYWXt7b6Ym-_9OCvFA/field/login > LOGIN",
    "jnPuLYWXt7b6Ym-_9OCvFA/file/dummy.crt > file:/tmp/Certificate.crt"
  ]
}
```

## 📝 Keeper Notation

The cookbook supports comprehensive Keeper notation for flexible secret mapping. For complete documentation, visit: [Keeper Notation Documentation](https://docs.keeper.io/en/keeperpam/secrets-manager/about/keeper-notation)

### Notation Format

The notation follows the pattern: `"KEEPER_NOTATION > OUTPUT_SPECIFICATION"`

- **Left side**: Keeper notation (e.g., `UID/custom_field/Label1`)
- **Right side**: Output specification (e.g., `Label2`, `env:Label2`, `file:/path/to/file`)

### Output Mapping Options

#### 1. Simple Key Mapping
```json
"UID/custom_field/Label1 > Label2"
```
**Result**: `{ "Label2": "VALUE_HERE" }` in output JSON

#### 2. Environment Variable Output
```json
"secret-uid/field/password > env:DB_PASSWORD"
```
**Result**: Sets `DB_PASSWORD` environment variable on the Chef node
**Note**: `env:Label2` will be exported as environment variable, and `Label2` will not be included in output JSON

#### 3. File Output
```json
"secret-uid/file/ssl_cert.pem > file:/opt/ssl/cert.pem"
```
**Result**: Downloads file to specified path on the Chef node
**Output JSON**: `{ "ssl_cert.pem": "/opt/ssl/cert.pem" }`
**Note**: Filename becomes the key, file path becomes the value

### Complete input.json Example

```json
{
  "authentication": [
    "base64"
  ],
  "secrets": [
    "jnPuLYWXt7b6Ym-_9OCvFA/field/password > env:DB_PASSWORD",
    "jnPuLYWXt7b6Ym-_9OCvFA/field/login > DB_USERNAME",
    "jnPuLYWXt7b6Ym-_9OCvFA/custom_field/api_key > API_KEY",
    "jnPuLYWXt7b6Ym-_9OCvFA/file/ssl_cert.pem > file:/opt/ssl/cert.pem",
    "jnPuLYWXt7b6Ym-_9OCvFA/file/ssl_key.pem > file:/opt/ssl/key.pem"
  ]
}
```

#### Finding Record UIDs

You can find the Record UID in:
- **Keeper Commander**: Use the `ls -l` command to see record UIDs
- **Keeper Web Vault**: Click on a record and look at the URL or record details
- **Keeper Desktop App**: Right-click on a record and select "Copy Record UID"

## Usage

### Basic Installation

```ruby
# Install Keeper Secrets Manager
ksm_install 'keeper_setup' do
  python_sdk true
  cli_tool false
  action :install
end
```

### Retrieving Secrets

```ruby
# Fetch secrets from Keeper vault using custom input.json path
ksm_fetch 'fetch_app_secrets' do
  input_path '/path/to/your/input.json'
  timeout 300
  action :run
end

# Or use default path (/opt/keeper_secrets_manager/input.json)
ksm_fetch 'fetch_app_secrets' do
  timeout 300
  action :run
end
```

### Complete Example

```ruby
# Install Keeper Secrets Manager
ksm_install 'keeper_setup' do
  python_sdk true
  cli_tool true
  base_dir '/opt/keeper_secrets_manager'
  action :install
end

# Create input.json file
cookbook_file '/opt/keeper_secrets_manager/input.json' do
  source 'input.json'
  mode '0600'
  action :create
end

# Retrieve secrets from Keeper vault
ksm_fetch 'fetch_app_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  timeout 300
  action :run
end

# Use environment variables set by Keeper (from env: mappings)
template '/etc/myapp/config.yml' do
  source 'config.yml.erb'
  variables({
    db_password: lazy { ENV['DB_PASSWORD'] },  # From env: mapping
    api_key: lazy { ENV['API_KEY'] }          # From env: mapping
  })
end

# Use files downloaded by Keeper (from file: mappings)
template '/etc/nginx/ssl.conf' do
  source 'ssl.conf.erb'
  variables({
    ssl_cert_path: '/opt/ssl/cert.pem',       # From file: mapping
    ssl_key_path: '/opt/ssl/key.pem'          # From file: mapping
  })
end
```

## Resources

### ksm_install

Installs Keeper Secrets Manager Python SDK and CLI tools.

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `python_sdk` | Boolean | `true` | Install Python SDK |
| `cli_tool` | Boolean | `false` | Install CLI tool |
| `user_install` | Boolean | `false` | Install for current user only |
| `base_dir` | String | Platform-specific | Base installation directory |

#### Actions

- `:install` - Install Keeper Secrets Manager (default)

### ksm_fetch

Retrieves secrets from the Keeper vault using the input.json configuration file.

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `input_path` | String | `/opt/keeper_secrets_manager/input.json` | Path to input.json configuration file |
| `timeout` | Integer | `300` | Timeout for script execution |
| `deploy_path` | String | `/opt/keeper_secrets_manager/ksm.py` | Script deployment path |

#### Actions

- `:run` - Retrieve secrets from Keeper vault (default)

**Note:** If `input_path` is not specified, the cookbook will look for `input.json` in `/opt/keeper_secrets_manager/input.json`.

## Platforms

The following platforms are supported:

- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+
- **macOS**: 10.14+
- **Windows**: Server 2016+

## Requirements

### Chef

- Chef Infra Client 16.0+
- Chef Workstation 21.0+ (for development)

### Dependencies

- Python 3.6+ (automatically installed if not present)
- pip (automatically installed)
- Internet connection for downloading Keeper SDK

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Submit a pull request

## License

All Rights Reserved

## Support

For technical questions, you can email **support@keeper.io**.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.