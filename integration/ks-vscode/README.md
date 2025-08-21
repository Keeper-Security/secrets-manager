# Keeper Security VS Code Extension

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Extension Settings](#extension-settings)
- [Troubleshooting](#troubleshooting)
- [Common Issues](#common-issues)
- [License](#license)

## Overview

A comprehensive VS Code extension that integrates Keeper Security vault functionality directly into the development workflow. The extension provides secure secret management capabilities including saving, retrieving, generating, and running commands with secrets from Keeper Security vault.

The goal is to enable developers to manage secrets securely without leaving their development environment, while maintaining the highest security standards and providing seamless integration with existing Keeper Security infrastructure.

## Features

- **Secret Management**: Save, retrieve, and generate secrets directly from VS Code using Keeper Security vault
- **Secret Detection**: Automatically detect potential secrets from configuration files using pattern recognition (API keys, passwords, tokens, JWT, AWS keys, Stripe keys, and more)
- **Secure Execution**: Run commands with secrets injected from Keeper vault
- **Comprehensive Logging**: Built-in logging system with debug mode support

## Prerequisites

- **Keeper Commander CLI**: Must be installed and authenticated on your system
  - Download from [Keeper Commander Installation Guide](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup)
  - Authenticate using [Persistent login](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/logging-in#persistent-login-sessions-stay-logged-in) or [Biometric login](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/logging-in#logging-in-with-biometric-authentication)
- **Keeper Security Account**: Active subscription with vault access
- **System Requirements**:
  - **VS Code**: 1.99.0 or later

## Setup

### Install the extension

From the VS Code Marketplace: Search `Keeper Security`

### Install Keeper Commander CLI

1. Follow the [Keeper Commander Installation Guide](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup)
2. Ensure the CLI is accessible from your system PATH
3. Open terminal/command prompt and run `keeper login`
4. Enter your Keeper Security credentials
5. Verify installation with `keeper --version`

### Authenticate with Keeper Commander CLI
1. Open terminal/command prompt
2. Run `keeper login` and enter your credentials
3. Authenticate using [Persistent login](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/logging-in#persistent-login-sessions-stay-logged-in) or [Biometric login](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/logging-in#logging-in-with-biometric-authentication)

### Verify Extension Access
1. Open VS Code Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Type `Keeper Security` to see all available commands

## Usage

### Available Commands

Once authenticated, you can access the following commands through the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description | Use Case |
|---------|-------------|----------|
| **Save in Keeper Security** | Save selected text as secret in vault | Replace hardcoded secrets with vault references |
| **Get from Keeper Security** | Insert existing secrets from vault | Retrieve stored secrets without exposing values |
| **Generate Password** | Generate and store secure passwords | Create new secure credentials |
| **Run Securely** | Execute commands with injected secrets | Run applications with vault credentials |
| **Choose Folder** | Select vault folder for storing secrets in there | To store secret in specific folder |
| **Open Logs** | View extension activity logs | Debug and monitor extension operations |

### Command Details

#### Save Secrets in Keeper Vault

1. **Using Command Palette**

    **Purpose**: Save selected text as a secret in Keeper Security vault and replace it with a reference.

    **Steps**:
    1. Select text containing a secret (password, token, API key, ...etc)
    2. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
    3. Type `Keeper Security: Save in Keeper Vault` and select it
    4. Extension will authenticate with Keeper Security (if needed)
    5. Enter record / field name 
    6. Extension creates new item in Keeper vault
    7. Selected text is replaced with secret reference (`keeper://...`)

**Example**:
```javascript
// Before: Selected text
const apiKey = "sk-1234567890abcdef";

// After: Replaced with reference
const apiKey = "keeper://record-uid/field/openai";
```

2. **Automatic Secret Detection**

    **Purpose**: Automatically detect potential secrets in your code for easy identification and securing.

    **Features**:
    - Extension scans files for known secret patterns
    - Provides CodeLens for detected secrets
    - CodeLens shows `Save in Keeper Security` option
    - Click CodeLens and follow prompts to save detected secret
    - The secret reference will be automatically replaced with detected secret

    **Supported File Types**:
    - **Environment Files**: eg. `.env`, `.env.*`
    - **Configuration Files**: eg. `config.json`, `docker-compose.yml`

#### Retrieve Secrets from Keeper Vault

**Purpose**: Insert existing Keeper Security secrets into your code without exposing actual values.

**Steps**:
1. Open Command Palette
2. Type `Keeper Security: Get from Keeper Vault` and select it
3. Extension shows list of available records
4. Select specific `record` and then `field` that you want to use
5. Extension inserts secret reference at cursor position

**Reference Format**: `keeper://record-uid/field/item`

**Example**:
```javascript
// Cursor position before command
const databasePassword = |

// After selecting from vault
const databasePassword = keeper://record_id/field/password
```

#### Generate New Random Password

**Purpose**: Generate secure passwords and store them in Keeper Security vault.

**Steps**:
1. Open Command Palette
2. Type `Keeper Security: Generate Password` and select it
3. Enter `record` / `field` name
4. Password reference is inserted at cursor position

#### Run Commands Securely

**Purpose**: Run commands with secrets injected from Keeper Security vault.

**Steps**:
1. Open Command Palette
2. Type `Keeper Security: Run Securely` and select it
3. Enter command to run
4. Extension creates terminal with injected secrets and executes command

#### Choose Folder

**Purpose**: Specify the vault folder where secrets for this workspace will be stored.

**Steps**:
1. Open Command Palette
2. Type `Keeper Security: Choose Folder` and select it
3. Extension displays available vault folders
4. Select desired folder for this workspace
5. Future `Save in Keeper Security` and `Generate Password` operations will use the selected folder to store secret

#### Open Logs

**Purpose**: View extension activity logs for debugging and monitoring.

**Steps**:
1. Open Command Palette
2. Type `Keeper Security: Open Logs` and select it
3. Extension opens output panel with detailed logs


## Extension Settings 

The extension provides configuration options:

1. Open VS Code Settings (`Ctrl+,` / `Cmd+,`)
2. Search for `Keeper Security`
3. Configure the following options:

| Setting | Description | Default |
|---------|-------------|---------|
| **Debug Enabled** | Enable detailed logging for debugging | `false` |
| **Secret Detection** | Enable automatic secret detection | `true` |

**Note:** Debug mode requires reloading the extension to take effect.

## Troubleshooting

### Debug Mode

Enable debug logging to see detailed information about extension operations:

1. Open VS Code Settings (`Ctrl+,` / `Cmd+,`)
2. Search for "Keeper Security"
3. Enable "Debug" option
4. Reload the extension (`Ctrl+Shift+P` → "Developer: Reload Window")

### Common Issues

#### 1. Extension General Issues

**Problem**: Extension takes time to fetch secrets, shows loading continuously, fails to resolve keeper references, latest records not displaying from keeper vault, manual keeper commander CLI authentication changes, or other unexpected issue.

**Solutions**:
- **Reload VS Code Window** (`Ctrl+Shift+P` → "Developer: Reload Window")
- Ensure Keeper Commander CLI is authenticated
- Check internet connection and firewall settings
- Verify Keeper vault accessibility
- Clear extension cache if issues persist

#### 2. Keeper Commander CLI Not Found

**Problem**: "Keeper Commander CLI is not installed" error

**Solutions**:
- Install Keeper Commander CLI following the [installation guide](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup)
- Ensure CLI is accessible from your system PATH
- Verify installation with `keeper --version` in terminal

#### 3. Authentication Failures

**Problem**: "Keeper Commander CLI is not authenticated" errors

**Solutions**:
- Open terminal and run `keeper login`
- Enter your Keeper Security credentials
- Ensure authentication is successful before using extension
- Remember that authentication is session-based

#### 4. Commands Not Available

**Problem**: Keeper Security commands don't appear in Command Palette

**Solution**: 
- Ensure Keeper Commander CLI is installed and authenticated
- Reload VS Code window if commands still don't appear
- Check the extension is properly installed and activated

#### 5. Extension Not Loading

**Problem**: Extension fails to activate or shows errors

**Solutions**:
- Check VS Code version compatibility (requires 1.99.0 or later)
- Verify Node.js version (requires 18.0.0 or later)
- Check the Output panel for detailed error messages
- Try reinstalling the extension

#### 7. Run Securely Command Issues

**Problem**: Commands don't have access to injected secrets

**Solutions**:
- Verify your `.env` file contains valid `keeper://` references
- Ensure all referenced secrets exist in your vault
- Ensure other not required terminal deleted and Check that the latest terminal is created by the extension
- Verify the extension has permission to create terminals

#### 8. Folder Selection Issues

**Problem**: Cannot select or change vault folders

**Solutions**:
- Ensure you have access to multiple folders in your vault
- Check that Keeper Commander CLI has proper permissions
- Verify folder structure in your vault
- Try refreshing the extension

## License

This module is licensed under the MIT License.