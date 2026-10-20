# Keeper Secrets Manager Cookbook

[![Cookbook Version](https://img.shields.io/badge/cookbook-v1.0.0-blue)](https://github.com/Keeper-Security/secrets-manager/tree/master/integration/keeper_secrets_manager_chef)
[![Chef](https://img.shields.io/badge/chef-%3E%3D16.0-orange)](https://www.chef.io/)
[![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-red)](LICENSE)

Install and configure Keeper Secrets Manager for secure secret retrieval in Chef-managed infrastructure.

## Maintainers

This cookbook is maintained by Keeper Security. If you'd like to contribute or report issues, please visit our [GitHub repository](https://github.com/Keeper-Security/secrets-manager/tree/master/integration/keeper_secrets_manager_chef).

## Platforms

The following platforms have been certified with integration tests:

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

## Usage

This cookbook provides custom resources for installing and configuring Keeper Secrets Manager. It is recommended to create a project-specific wrapper cookbook and add the desired custom resources to your run list.

### Basic Installation

```ruby
# Install Keeper Secrets Manager
ksm_install 'keeper_setup' do
  python_sdk true
  cli_tool true
  action :install
end

# Retrieve secrets from Keeper vault
ksm_fetch 'fetch_app_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  action :run
end
```

### Advanced Configuration

```ruby
# Custom installation directory
ksm_install 'keeper_custom' do
  python_sdk true
  cli_tool true
  base_dir '/custom/keeper/path'
  action :install
end

# Retrieve secrets with custom timeout
ksm_fetch 'database_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  timeout 600
  action :run
end

# Use retrieved secrets in templates
secrets = lazy { JSON.parse(File.read('/opt/keeper_secrets_manager/keeper_output.txt')) }

template '/etc/myapp/config.yml' do
  source 'config.yml.erb'
  variables(
    db_password: secrets['DB_PASSWORD'],
    api_key: secrets['API_KEY']
  )
  sensitive true
end
```

## Authentication

The cookbook supports multiple authentication methods with the following priority:

1. **Encrypted Data Bags** (Production)
2. **Environment Variables** (Development)
3. **Input File Configuration** (Testing)

### Encrypted Data Bags

**Create the data bag:**
```bash
knife data bag create keeper
```

**Create the configuration item (`keeper_config.json`):**
```json
{
  "id": "keeper_config",
  "config_json": "eyJhcHBLZXkiOiJCaU..."
}
```

**Encrypt and store:**
```bash
knife data bag from file keeper keeper_config.json --secret-file /path/to/secret
```

**Usage in recipes:**
```ruby
# The cookbook automatically checks for encrypted data bags
# Priority: 1. Encrypted data bags, 2. Environment variables, 3. Input file
include_recipe 'keeper_secrets_manager::install'
include_recipe 'keeper_secrets_manager::fetch'
```

### Environment Variables

```bash
export KEEPER_CONFIG='eyJhcHBLZXkiOiJCaU...'
```

### Input File Format

```json
{
  "authentication": ["base64"],
  "secrets": [
    "record-uid/field/password > DB_PASSWORD",
    "record-uid/file/cert.crt > file:/tmp/Certificate.crt"
  ]
}
```

## Resources

### `ksm_install`

Installs Keeper Secrets Manager components.

#### Actions

- `:install` (default) - Installs all components

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `python_sdk` | Boolean | `true` | Install Python SDK |
| `cli_tool` | Boolean | `true` | Install CLI tool |
| `user_install` | Boolean | `false` | Install for user only |
| `base_dir` | String | Platform-specific | Base installation directory |

#### Examples

```ruby
# Basic installation
ksm_install 'keeper_setup'

# Custom configuration
ksm_install 'keeper_custom' do
  python_sdk true
  cli_tool false
  base_dir '/opt/keeper'
  action :install
end
```

### `ksm_fetch`

Retrieves secrets from Keeper vault.

#### Actions

- `:run` (default) - Executes secret retrieval

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `input_path` | String | Required | Path to input JSON file |
| `deploy_path` | String | Auto-generated | Path to deploy Python script |
| `timeout` | Integer | `300` | Execution timeout in seconds |

#### Examples

```ruby
# Basic secret retrieval
ksm_fetch 'fetch_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
end

# With custom timeout
ksm_fetch 'long_running_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  timeout 600
  action :run
end
```

## Recipes

### `keeper_secrets_manager::default`

Empty recipe that serves as an entry point.

### `keeper_secrets_manager::install`

Installs and configures Keeper Secrets Manager using the `ksm_install` resource with default settings.

### `keeper_secrets_manager::fetch`

Demonstrates secret retrieval using the `ksm_fetch` resource.

## Attributes

This cookbook uses no node attributes. All configuration is done through resource properties.

## Testing

### Prerequisites

```bash
# Set up testing environment
export KEEPER_CONFIG='your-base64-config'
```

### Running Tests

```bash
# Run all tests
./run_all_tests.sh

# Run individual test types
./test_python.sh          # Python unit tests
chef exec rspec           # ChefSpec tests
chef exec cookstyle .     # Style checks
```

### Test Coverage

- Python Unit Tests (11 tests)
- ChefSpec Tests (Resource and recipe testing)
- Integration Tests (Docker-based end-to-end testing)
- Style Tests (Cookstyle compliance)

## External Documentation

- [Keeper Secrets Manager Documentation](https://docs.keeper.io/secrets-manager/)
- [Keeper Developer Portal](https://developer.keeper.io/)
- [Python SDK Documentation](https://github.com/Keeper-Security/secrets-manager)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the style guidelines
4. Add tests for new functionality
5. Run the test suite (`./run_all_tests.sh`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Requirements

- Chef Workstation 21.0+
- Docker (for integration tests)
- Python 3.6+ (for unit tests)

### Code Style

- Follow [Chef Style Guide](https://docs.chef.io/ruby/)
- Use Cookstyle for Ruby code formatting
- Follow PEP 8 for Python code
- Write clear, descriptive commit messages

## License

This module is licensed under the Apache License, Version 2.0.

---

**Version:** 1.0.0
**Last Updated:** 2025
