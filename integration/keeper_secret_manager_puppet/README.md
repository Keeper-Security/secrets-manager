# Puppet Keeper Secret Manager

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Keeper Notation](#keeper-notation)
- [Usage](#usage)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Support](#support)

## Overview

This `keepersecurity-keeper_secret_manager_puppet` module facilitates secure integration between Puppet and Keeper Secret Manager, enabling the retrieval of secrets during catalog execution. It supports a range of authentication mechanisms, including token-based and encoded credential formats, while also allowing for environment-specific configurations to enhance access control. Retrieved secrets are returned in structured JSON, ensuring seamless integration and efficient consumption within Puppet manifests.

## Features

- 🔐 **Secure Secret Retrieval**: Uses deferred functions for runtime secret access
- 🌐 **Cross-Platform Support**: Linux, Windows, and macOS compatibility
- 🔑 **Multiple Authentication Methods**: Base64, JSON and Token authentication
- 🛡️ **Error Handling**: Graceful error handling with helpful messages
- 📁 **File Management**: Supports secret output to files and environment variables

## Prerequisites

### System Requirements

- **Puppet**: 7.24 or later (for `preprocess_deferred` support)
- **Python**: 3.6 or later on agent nodes
- **Keeper Secrets Manager**: Valid credentials and access

### Supported Operating Systems
- **Linux**
- **Windows**
- **macOS**
<!-- - **Linux**: CentOS/RHEL 7, 8, 9; Ubuntu 18.04, 20.04, 22.04; Debian 10, 11, 12 -->
<!-- - **Windows**: Windows Server 2019, 2022; Windows 10, 11
- **macOS**: 10.15, 11, 12, 13, 14 -->

### Critical Configuration

**Required**: Add this setting to your agent's `puppet.conf`:

```ini
[agent]
preprocess_deferred = false
```

This ensures deferred functions execute during catalog enforcement, not before.

## Keeper Notation

The module supports comprehensive Keeper notation for flexible secret mapping: [Visit Docs](https://docs.keeper.io/en/keeperpam/secrets-manager/about/keeper-notation)

### Notation Format 

The notation follows the pattern: `"KEEPER_NOTATION > OUTPUT_SPECIFICATION"`

- **Left side**: Keeper notation (e.g., `UID/custom_field/Label1`)
- **Right side**: Output specification
  - `VARIABLE_NAME` (eg: `Label2`)
  - `env:VARIABLE_NAME` (eg: `env:Label2`)
  - `file:/path/to/file-on-agent` (eg: `file:/opt/ssl/cert.pem`)

### Output Mapping Options

#### 1. Simple Key Mapping
```puppet
"UID/custom_field/Label1 > Label2"
# Output JSON: { "Label2": "VALUE_HERE" }
```

#### 2. Environment Variable Output
```puppet
"secret-uid/field/password > env:DB_PASSWORD"
# Sets DB_PASSWORD environment variable on agent node
# Note: env:DB_PASSWORD will be exported as environment variable, and DB_PASSWORD will not be included in output JSON
```

#### 3. File Output
```puppet
"secret-uid/file/ssl_cert.pem > file:/opt/ssl/cert.pem"
# Downloads file to specified path on agent node
# Output JSON: { "ssl_cert.pem": "/opt/ssl/cert.pem" }
# Note: filename becomes the key, file path becomes the value
```

## Configuration

### Step 1: Install the Module

```bash
# Install from Puppet Forge
puppet module install keepersecurity-keeper_secret_manager_puppet
```

### Step 2: Configure Hiera

Create or update your Hiera configuration file (eg : `data/common.yaml`):



```yaml
keeper::config:
  authentication:
    - "AUTH_TYPE" # base64, token, json
    - "AUTH_VALUE" # your-base64-string/your-token/your-json-path-on-master or ENV:KEEPER_CONFIG
  secrets:
    - "your-secret-uid/title"
    - "your-secret-uid/field/login > login_name"
    - "your-secret-uid/field/password > env:DB_PASSWORD"
```
**Note**: Passing secrets array under **keeper::config** can be skipped if you are passing secrets array directly as parameter in the ```'keeper_secret_manager_puppet::lookup'``` function call.

### Step 3: Set Up Environment Variable (Optional)

If you're using `ENV:KEEPER_CONFIG` for AUTH_VALUE, then set the environment variable on your Puppet master:

```bash
# For base64 authentication (recommended)
echo "KEEPER_CONFIG='your-base64-string-configuration'" >> /etc/environment

# For token authentication
echo "KEEPER_CONFIG='your-token-configuration'" >> /etc/environment

# For JSON authentication
echo "KEEPER_CONFIG='your-json-configuration-path-on-master'" >> /etc/environment
```

**Note**: You can use your own environment variable name instead of `KEEPER_CONFIG`.

## Usage


#### Include the Module

```puppet
# Include the module in your manifests
include keeper_secret_manager_puppet
```

#### Using Deferred Functions

**1. Default Lookup (No Parameters)**
```puppet
# Use deferred function to lookup secrets using Hiera configuration
$multiple_secrets = Deferred('keeper_secret_manager_puppet::lookup', [])
```

**2. Lookup with Parameters**
```puppet
# Define secrets in Array[String<Keeper Notation Format>] 
$node_secrets = [
  'UID/custom_field/Label1 > Label2',
  'UID/field/login > agent2_login',
  'UID/field/password > env:agent2_password',
  'UID/file/ssl_cert.pem > file:/opt/keeper_secret_manager/agent2_ssl_cert.pem',
]

# Use deferred function to lookup secrets, which returns parsed JSON response
$multiple_secrets = Deferred('keeper_secret_manager_puppet::lookup', [$node_secrets])
```

**3. Accessing Individual Secret Values**
```puppet
# Access individual values from JSON response
$label2_value = Deferred('dig', [$multiple_secrets, 'Label2'])
```


## Examples

### Example 1: Basic Secret Retrieval

```puppet
node 'puppetagent' {
  # Define node-specific secrets
  $secrets = [
    'UID/custom_field/Label1 > Label2',
    'UID/field/login > agent2_login',
    'UID/field/password > env:agent2_password',
    'UID/file/ssl_cert.pem > file:/opt/keeper_secret_manager/agent2_ssl_cert.pem',
  ]

  # Use deferred function to fetch secrets
  $multiple_secrets = Deferred('keeper_secret_manager_puppet::lookup', [$secrets])

  # Access individual values from parsed JSON response
  $label2_value = Deferred('dig', [$multiple_secrets, 'Label2'])

  # Include the keeper module
  contain keeper_secret_manager_puppet

  notify { 'multiple_secrets is':
    message => $multiple_secrets,
  }

  notify { 'Label2 value is':
    message => $label2_value,
  }

  # Use $agent2_password env variable value to create file on agent node
  exec { 'use_keeper_password_agent2':
    command => '/bin/echo $agent2_password > /tmp/keeper_password_agent2.txt',
    path    => ['/bin', '/usr/bin'],
    require => Notify['multiple_secrets is'],
  }
}
```

### Example 2: Database Configuration

```puppet
class profile::database {
  include keeper_secret_manager_puppet

  # Define database secrets
  $db_secrets = [
    'db-secret-uid/field/hostname > db_host',
    'db-secret-uid/field/port > db_port',
    'db-secret-uid/field/username > db_user',
    'db-secret-uid/field/password > env:DB_PASSWORD',
    'db-secret-uid/file/ssl_cert.pem > file:/opt/db/ssl/cert.pem'
  ]

  # Use deferred function to retrieve database credentials
  $db_config = Deferred('keeper_secret_manager_puppet::lookup', [$db_secrets])
  
  # Use the retrieved values
  class { 'postgresql::server':
    postgres_password => Deferred('dig', [$db_config, 'db_user']),
    listen_addresses  => '*',
  }
  
  postgresql::server::db { 'myapp':
    user     => Deferred('dig', [$db_config, 'db_user']),
    password => Deferred('dig', [$db_config, 'db_host']),
    host     => Deferred('dig', [$db_config, 'db_port']),
  }
}
```

### Example 3: API Client Configuration

```puppet
class profile::api_client {
  include keeper_secret_manager_puppet

  # Define API secrets
  $api_secrets = [
    'api-secret-uid/custom_field/API_KEY > api_key',
    'api-secret-uid/custom_field/API_SECRET > env:API_SECRET',
    'api-secret-uid/file/config.json > file:/etc/api/config.json'
  ]

  # Use deferred function to retrieve API credentials
  $api_config = Deferred('keeper_secret_manager_puppet::lookup', [$api_secrets])

  # Configure API client
  file { '/etc/api-client/config':
    ensure  => file,
    content => Deferred('sprintf', ['API_KEY=%s', Deferred('dig', [$api_config, 'api_key'])]),
    mode    => '0600',
  }
}
```

### Example 4: SSL Certificate Management

```puppet
class profile::ssl_certificates {
  include keeper_secret_manager_puppet

  # Define SSL secrets
  $ssl_secrets = [
    'ssl-secret-uid/file/certificate.pem > file:/etc/ssl/certs/myapp.crt',
    'ssl-secret-uid/file/private_key.pem > file:/etc/ssl/private/myapp.key'
  ]

  # Use deferred function to retrieve SSL certificate and key
  $ssl_config = Deferred('keeper_secret_manager_puppet::lookup', [$ssl_secrets])

  # Ensure proper permissions
  file { '/etc/ssl/certs/myapp.crt':
    ensure => file,
    mode   => '0644',
  }

  file { '/etc/ssl/private/myapp.key':
    ensure => file,
    mode   => '0600',
  }
}
```

### Example 5: Application Configuration

```puppet
class profile::myapp {
  include keeper_secret_manager_puppet

  # Define application secrets
  $app_secrets = [
    'app-secret-uid/field/username > app_user',
    'app-secret-uid/field/password > env:APP_PASSWORD',
    'app-secret-uid/custom_field/DATABASE_URL > env:DATABASE_URL',
    'app-secret-uid/file/app_config.yml > file:/etc/myapp/config.yml'
  ]

  # Use deferred function to retrieve application secrets
  $app_config = Deferred('keeper_secret_manager_puppet::lookup', [$app_secrets])

  # Deploy application with secrets
  file { '/etc/myapp/application.conf':
    ensure  => file,
    content => Deferred('epp', ['profile/myapp/application.conf.epp', {
      'username' => Deferred('dig', [$app_config, 'app_user']),
      'database_url' => Deferred('dig', [$app_config, 'DATABASE_URL'])
    }]),
    mode    => '0600',
  }
}
```


## Troubleshooting

### Debug Mode

Enable debug logging by setting the log level in your Puppet configuration:

```ini
[agent]
log_level = debug
```

### Common Issues

#### 1. "preprocess_deferred = false" Error

**Problem**: Module fails with configuration error
**Solution**: Add `preprocess_deferred = false` to the `[agent]` section of your `puppet.conf`

#### 2. "KSM script not found" Error

**Problem**: Deferred function fails on first run
**Solution**: Ensure the module is properly included and Python installation completes

#### 3. Authentication Failures

**Problem**: "Authentication failed" errors
**Solution**: Verify Keeper credentials and network connectivity



## Security Considerations

### Best Practices

1. **Environment Variables**: Use environment variables for sensitive authentication data
2. **File Permissions**: Ensure proper file permissions for configuration files
4. **Access Control**: Implement proper access controls for Puppet master nodes

### Security Features

- **Deferred Execution**: Secrets are retrieved at runtime, not during catalog compilation
- **Environment Variable Support**: Sensitive data can be stored in environment variables
- **File Output Control**: Direct file writing with proper permissions
- **Cross-Platform Security**: Consistent security across different operating systems

## Support

### Getting Help

- **Documentation**: This README and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/root/puppet-keeper-python/issues)
- **Forge**: [Puppet Forge](https://forge.puppet.com/root/keeper_secret_manager_puppet)


## License

This module is licensed under the Apache License, Version 2.0.