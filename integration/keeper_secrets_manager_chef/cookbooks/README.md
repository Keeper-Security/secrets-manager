# Chef

Keeper Secrets Manager cookbook for Chef Infra automation platform

## About

Chef Infra is a powerful automation platform that transforms infrastructure into code. Whether you're operating in the cloud, on-premises, or in a hybrid environment, Chef automates how infrastructure is configured, deployed, and managed across your network, no matter its size.

The Keeper Secrets Manager cookbook allows Chef-managed nodes to integrate with Keeper Secrets Manager to make managing secrets in Chef infrastructure easier and more secure.

## Features

* Install and configure the Keeper Secrets Manager Ruby SDK gem on Chef-managed nodes
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
cookbook 'keeper_secrets_manager', git: 'https://github.com/Keeper-Security/secrets-manager.git', rel: 'integration/keeper_secrets_manager_chef/cookbooks/keeper_secrets_manager'
```

### Using Chef Supermarket

```bash
knife supermarket install keeper_secrets_manager
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

#### 🔐 Creating the Secret Key File

Before creating encrypted data bags, you need to create a shared **secret file** that Chef will use to encrypt and decrypt sensitive data.

Run the following commands:

```bash
# MacOS/Linux: 
# Create directory for Chef secrets if it doesn't exist
sudo mkdir -p /etc/chef

# Generate a base64-encoded secret and store it securely
openssl rand -base64 512 | sudo tee /etc/chef/encrypted_data_bag_secret > /dev/null

# Windows: Generate a base64-encoded secret and store it securely
New-Item -ItemType Directory -Path C:\chef -Force
$bytes = New-Object 'System.Byte[]' 512
[System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes) | Out-File -FilePath 'C:\chef\encrypted_data_bag_secret' -Encoding ASCII -Force


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
**Result**: `node.run_state['keeper_secrets']['Label2']` is set to the value. Nothing is written to disk - read it in a later resource via `lazy { node.run_state['keeper_secrets']['Label2'] }`.

#### 2. Environment Variable Output
```json
"secret-uid/field/password > env:DB_PASSWORD"
```
**Result**: Sets the real `DB_PASSWORD` environment variable in the chef-client process, during `ksm_fetch`'s converge step.
**Note**: A later resource reads it the same way as any other environment variable - `lazy { ENV['DB_PASSWORD'] }`.

#### 3. File Output
```json
"secret-uid/file/ssl_cert.pem > file:/opt/ssl/cert.pem"
```
**Result**: Writes the file to the specified path on the Chef node, then restricts it to `chmod 0600`.
**Note**: Reference the path directly in a later resource; nothing is added to `node.run_state` for this mode.

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
  action :install
end
```

### Retrieving Secrets

```ruby
# Fetch secrets from Keeper vault using custom input.json path
ksm_fetch 'fetch_app_secrets' do
  input_path '/path/to/your/input.json'
  action :run
end

# Or use default path (/opt/keeper_secrets_manager/input.json)
ksm_fetch 'fetch_app_secrets' do
  action :run
end
```

### Complete Example

```ruby
# Install Keeper Secrets Manager
ksm_install 'keeper_setup' do
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

Installs the Keeper Secrets Manager Ruby SDK gem via `chef_gem`.

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `base_dir` | String | Platform-specific (`node['keeper_secrets_manager']['base_dir']`) | Base directory for the config file |
| `sdk_version` | String | `17.2.1` | Pinned `keeper_secrets_manager` gem version |

#### Actions

- `:install` - Install the gem and write the config file (default)
- `:remove` - Remove the gem and delete `base_dir`
- `:upgrade` - Upgrade the gem to `sdk_version`

### ksm_fetch

Retrieves secrets from the Keeper vault using the input.json configuration file, directly via the Ruby SDK.

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `input_path` | String | `base_dir/input.json` | Path to input.json configuration file |
| `base_dir` | String | Platform-specific (`node['keeper_secrets_manager']['base_dir']`) | Where the `token` auth method persists its bound config |

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

- Chef Infra Client 18.0+ (the `keeper_secrets_manager` Ruby SDK gem requires Ruby >= 3.1, which Chef 18 is the first line to ship on all supported platforms)
- Chef Workstation 21.0+ (for development)

### Dependencies

- `keeper_secrets_manager` Ruby gem (installed automatically via `chef_gem`)
- Internet connection for installing the gem

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Submit a pull request

## License

This module is licensed under the Apache License, Version 2.0. See [LICENSE](keeper_secrets_manager/LICENSE).

## Support

For technical questions, you can email **support@keeper.io**.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.