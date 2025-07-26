# Puppet Keeper Secret Manager

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Secrets Notation Format](#secrets-notation-format)
- [Setup](#setup)
- [Usage](#usage)
- [Complete Example](#complete-example)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

This `keepersecurity-keeper_secrets_manager_puppet` module facilitates secure integration between Puppet and Keeper Secret Manager, enabling the retrieval of secrets during catalog execution. 

It supports a range of authentication mechanisms, including token-based and encoded credential formats, while also allowing for environment-specific configurations to enhance access control. Retrieved secrets are returned in structured JSON, ensuring seamless integration and efficient consumption within Puppet manifests.

## Features

- 🔐 **Secure Secret Retrieval**: Uses deferred functions for runtime secret access
- 🌐 **Cross-Platform Support**: Linux, Windows, and macOS compatibility
- 🔑 **Multiple Authentication Methods**: Base64, JSON and Token authentication
- 🛡️ **Error Handling**: Graceful error handling with helpful messages
- 📁 **File Management**: Supports secret output to files and environment variables

## Prerequisites

- **Keeper Secrets Manager access** (See the [Quick Start Guide](https://docs.keeper.io/en/keeperpam/secrets-manager/quick-start-guide) for more details)
  - Secrets Manager add-on enabled for your Keeper subscription
  - Membership in a Role with the Secrets Manager enforcement policy enabled
- A Keeper [Secrets Manager Application](https://docs.keeper.io/en/keeperpam/secrets-manager/about/terminology#application) with secrets shared to it 
  - See the [Quick Start Guide](https://docs.keeper.io/en/keeperpam/secrets-manager/quick-start-guide#2.-create-an-application) for instructions on creating an Application
- An initialized Keeper [Secrets Manager Configuration](https://docs.keeper.io/en/keeperpam/secrets-manager/about/secrets-manager-configuration)
  - Puppet module accepts Base64, Token, JSON format configurations

- System Requirements
  - **Puppet**: 7.24 or later (for `preprocess_deferred` support)
  - **Python**: 3.6 or later on agent nodes
  - **Supported Operating Systems**: Linux , macOS , Windows

- Critical Configuration

  - **Required**: Add this setting to your agent's `puppet.conf`:

    ```ini
    [agent]
    preprocess_deferred = false
    ```

    This ensures deferred functions execute during catalog enforcement, not before.

## Secrets Notation Format

### Notation Format 

The notation follows the pattern: `"KEEPER_NOTATION > OUTPUT_SPECIFICATION"`

**Left side**: Uses [Keeper notation](https://docs.keeper.io/en/keeperpam/secrets-manager/about/keeper-notation) format

**Right side**: Output specification
  - `VARIABLE_NAME` (eg: `Label2`)
  - `env:VARIABLE_NAME` (eg: `env:Label2`)
  - `file:/path/to/file-on-agent` (eg: `file:/opt/ssl/cert.pem`)

| **Notation\Destination <br>prefix** | Default (empty) | env: | file: |
|---------------------------------| ----------------|------|-------|
`field` or `custom_field` | Notation query result <br>is placed into JSON output | Notation query result <br>is exported as environment variable on agent| Not allowed
`file` | file is downloaded and <br>placed into agent's destination |  file is downloaded and <br>placed into agent's destination | file is downloaded and <br>placed into agent's destination


### Examples:

#### 1. Default (empty)
```puppet
"UID/custom_field/Label1 > Label2"
# Output JSON: { "Label2": "VALUE_HERE" }
```

#### 2. Environment Variable Output (`env:`)
```puppet
"secret-uid/field/password > env:DB_PASSWORD"
# Sets DB_PASSWORD environment variable on agent node
# Note: env:DB_PASSWORD will be exported as environment variable, and DB_PASSWORD will not be included in output JSON
```

#### 3. File Output (`file:`)
```puppet
"secret-uid/file/ssl_cert.pem > file:/opt/ssl/cert.pem"
# Downloads file to specified path on agent node
# Output JSON: { "ssl_cert.pem": "/opt/ssl/cert.pem" }
# Note: filename becomes the key, file path on agent becomes the value
```

## Setup

### Step 1: Install the Module

```bash
# Install from Puppet Forge
puppet module install keepersecurity-keeper_secrets_manager_puppet
```

### Step 2: Configure Hiera

Create or update your Hiera configuration file (eg : `data/common.yaml`):

#### Configuration Structure

#### Basic Configuration (Required)
```yaml
keeper::config:
  authentication:
    - "AUTH_TYPE"    # base64, token, or json
    - "AUTH_VALUE"   # your credentials or ENV:KEEPER_CONFIG
```

#### Adding Secrets (Optional)

##### Note: This secrets will be used when `Default Lookup` as parameter type is used.
```yaml
keeper::config:
  authentication:
    - "AUTH_TYPE"
    - "AUTH_VALUE"
  secrets: # Optional: List of secrets to retrieve
    - "your-secret-uid/title > title"
    - "your-secret-uid/field/login > login_name"
    - "your-secret-uid/field/password > env:DB_PASSWORD"
```

**Configuration Details:**
- **`keeper::config`** (Required): Main configuration container
- **`authentication`** (Required): Array with exactly 2 elements:
  - `[0]`: Authentication type (`base64`, `token`, or `json`)
  - `[1]`: Authentication value (your credentials or `ENV:VARIABLE_NAME`)
- **`secrets`** (Optional): Array of Keeper notation strings

**Note**: Passing secrets array under **keeper::config** can be skipped if you are passing secrets array directly as parameter in the ```Deferred('keeper_secrets_manager_puppet::lookup', [SECRETS_ARRAY_HERE])``` function call.

### Step 3: Set Up Environment Variable (Optional)

If you're using `ENV:KEEPER_CONFIG` for *AUTH_VALUE*, then set the environment variable on your `Puppet master`:

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
contain keeper_secrets_manager_puppet
```

#### Using the Custom Lookup Function with Deferred

The module provides a custom function `keeper_secrets_manager_puppet::lookup` that must be used with Puppet's `Deferred()` wrapper for runtime execution. [Learn more about Deferred Functions](https://www.puppet.com/docs/puppet/7/deferred_functions)


The `Deferred('keeper_secrets_manager_puppet::lookup', [])` function accepts three parameter options:

| **Parameter Type** | **Description** | **Example** |
---------------------|-----------------|-------------|
**No Parameters** | Uses secrets from Hiera configuration |  `Deferred('keeper_secrets_manager_puppet::lookup', [])` |
**Array[String]** | Uses secrets from parameters | `Deferred('keeper_secrets_manager_puppet::lookup', [$secrets_array])` |
**String** | Uses secrets from parameters | `Deferred('keeper_secrets_manager_puppet::lookup', ['UID/field/login > login_name'])` |

**Detailed Examples:**


**Option 1: Default Lookup - No Parameters**
```puppet
# Uses secrets defined in Hiera configuration
$secrets = Deferred('keeper_secrets_manager_puppet::lookup', [])
```

**Option 2: Array of Strings**
```puppet
# Define secrets array
$secrets_array = [
  'UID/custom_field/Label1 > Label2',
  'UID/field/login > agent2_login',
  'UID/field/password > env:agent2_password',
  'UID/file/ssl_cert.pem > file:/etc/ssl/certs/agent2_ssl_cert.pem',
]

$secrets = Deferred('keeper_secrets_manager_puppet::lookup', [$secrets_array])
```

**Option 3: Single String**
```puppet
# Single secret lookup
$secrets = Deferred('keeper_secrets_manager_puppet::lookup', ['UID/field/login > agent2_login'])
```

**4. Accessing Individual Secret Values**
```puppet
# Access individual values from JSON response
$label2_value = Deferred('dig', [$secrets, 'Label2'])
```


## Complete Example

```puppet
node 'puppetagent' {
  # Include the keeper module
  contain keeper_secrets_manager_puppet

  # Define secrets to retrieve
  $secrets = [
    'UID/custom_field/Label1 > Label2',
    'UID/field/login > agent2_login',
    'UID/field/password > env:agent2_password',
    'UID/file/ssl_cert.pem > file:/etc/ssl/certs/agent2_ssl_cert.pem',
  ]

  # Fetch secrets using deferred function
  $secrets_result = Deferred('keeper_secrets_manager_puppet::lookup', [$secrets])

  # Use retrieved secrets
  notify { 'Retrieved secrets':
    message => $secrets_result,
  }

  # Use environment variable set by the module
  exec { 'create_file_with_secret':
    command => '/bin/echo $agent2_password > /tmp/secret.txt',
    path    => ['/bin', '/usr/bin'],
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

**Problem**: "Authentication failed" errors or `Error: access_denied, message=Unable to validate Keeper application access`

**Solution**: Verify Keeper authentication credentials in configuration and network connectivity

## License

This module is licensed under the Apache License, Version 2.0.
