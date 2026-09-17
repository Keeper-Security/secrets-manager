# Keeper Secrets Manager Cookbook

[![Cookbook Version](https://img.shields.io/badge/cookbook-v1.0.0-blue)](https://github.com/Keeper-Security/secrets-manager/tree/master/integration/keeper_secrets_manager_chef)
[![Chef](https://img.shields.io/badge/chef-%3E%3D18.0-orange)](https://www.chef.io/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

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

- Chef Infra Client 18.0+ (the `keeper_secrets_manager` Ruby SDK gem requires Ruby >= 3.1, which Chef 18 is the first line to ship on all supported platforms)
- Chef Workstation 21.0+ (for development)

### Dependencies

- `keeper_secrets_manager` Ruby gem (installed automatically via `chef_gem`, pinned to a specific version by `ksm_install`'s `sdk_version` property)
- Internet connection for installing the gem

## Usage

This cookbook provides custom resources for installing and configuring Keeper Secrets Manager. It is recommended to create a project-specific wrapper cookbook and add the desired custom resources to your run list.

### Basic Installation

```ruby
# Install Keeper Secrets Manager
ksm_install 'keeper_setup' do
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
# Custom installation directory and gem version
ksm_install 'keeper_custom' do
  base_dir '/custom/keeper/path'
  sdk_version '17.2.1'
  action :install
end

ksm_fetch 'database_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
  action :run
end

# Secrets with no env:/file: prefix in input.json are stored in
# node.run_state, never written to disk
secrets = lazy { node.run_state['keeper_secrets'] }

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

`input.json`'s `authentication` array selects one of three methods. Where the
credential value comes from depends on which method is chosen:

| Method | Value source | Typical use |
|--------|---------------|-------------|
| `base64` | Encrypted data bag (`keeper`/`keeper_config`), falling back to the `KEEPER_CONFIG` environment variable. Never read from `input.json` itself. | Production - a persistent, reusable vault credential |
| `token` | The literal one-time token, as `input.json`'s `authentication[1]`. Binds once, then persists the result to `base_dir/config/keeper_config.json` so a spent token is never reused. | First-run bootstrap |
| `json` | A literal config file path, as `input.json`'s `authentication[1]`, unconditionally - never overridden by `KEEPER_CONFIG` | An existing config file already on the node |

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
# With authentication: ["base64"] in input.json, the data bag above is
# checked first; KEEPER_CONFIG is only a fallback if it's missing.
include_recipe 'keeper_secrets_manager::install'
include_recipe 'keeper_secrets_manager::fetch'
```

### Environment Variables

Only consulted as a fallback for the `base64` method when the encrypted data
bag above isn't available:

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

Installs the `keeper_secrets_manager` Ruby SDK gem and writes the encrypted-data-bag config file.

#### Actions

- `:install` (default) - Installs the gem and writes the config file
- `:remove` - Removes the gem and deletes `base_dir`
- `:upgrade` - Upgrades the gem to `sdk_version`

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `base_dir` | String | From the `node['keeper_secrets_manager']['base_dir']` attribute (platform-specific) | Base directory for the config file |
| `sdk_version` | String | `17.2.1` | Pinned `keeper_secrets_manager` gem version |

#### Examples

```ruby
# Basic installation
ksm_install 'keeper_setup'

# Custom configuration
ksm_install 'keeper_custom' do
  base_dir '/opt/keeper'
  sdk_version '17.2.1'
  action :install
end
```

### `ksm_fetch`

Retrieves secrets from Keeper vault directly via the Ruby SDK - no subprocess, no Python.

#### Actions

- `:run` (default) - Executes secret retrieval

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `input_path` | String | `base_dir/input.json` | Path to input JSON file |
| `base_dir` | String | From the `node['keeper_secrets_manager']['base_dir']` attribute (platform-specific) | Where the `token` method persists its bound config |

#### Examples

```ruby
# Basic secret retrieval
ksm_fetch 'fetch_secrets' do
  input_path '/opt/keeper_secrets_manager/input.json'
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

| Attribute | Default | Description |
|-----------|---------|--------------|
| `node['keeper_secrets_manager']['base_dir']` | `/opt/keeper_secrets_manager` (Linux/macOS), `C:\ProgramData\keeper_secrets_manager` (Windows) | Shared default for both `ksm_install` and `ksm_fetch`'s `base_dir` property, so a `token`-method bind in `ksm_fetch` persists to the same directory `ksm_install` writes the encrypted-data-bag config to |

## Testing

### Prerequisites

```bash
# Set up testing environment
export KEEPER_CONFIG='your-base64-config'

# Install pinned test/dev gems (chefspec, keeper_secrets_manager) from the Gemfile
chef exec bundle install
```

### Running Tests

```bash
# Run all tests
./run_all_tests.sh

# Run individual test types
chef exec bundle exec rspec       # RSpec + ChefSpec tests
chef exec cookstyle .              # Style checks
```

### Test Coverage

- RSpec (Ruby notation-parsing logic in `libraries/ksm_helpers.rb`)
- ChefSpec Tests (Resource and recipe testing)
- Integration Tests (Docker-based end-to-end testing, Test Kitchen + InSpec)
- Style Tests (Cookstyle compliance)

## External Documentation

- [Keeper Secrets Manager Documentation](https://docs.keeper.io/secrets-manager/)
- [Keeper Developer Portal](https://developer.keeper.io/)
- [Ruby SDK Documentation](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/ruby)

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

### Code Style

- Follow [Chef Style Guide](https://docs.chef.io/ruby/)
- Use Cookstyle for Ruby code formatting
- Write clear, descriptive commit messages

## License

This module is licensed under the Apache License, Version 2.0.

---

**Version:** 1.0.0
**Last Updated:** 2025
