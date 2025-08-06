# Keeper Secrets Manager VS Code Extension

A comprehensive VS Code extension that integrates with Keeper Secrets Manager to provide secure secret management, multi-configuration support, and developer-focused productivity features directly in your development environment.

## Features

### **🔐 Multi-Configuration Secret Management**
- **Multiple KSM Configurations**: Manage multiple Keeper configurations simultaneously (Production, Development, Testing)
- **TreeView Browser**: Dedicated sidebar with hierarchical view of configurations, folders, records, and fields
- **Secure Authentication**: Support for One-Time Tokens and base64 configurations with automatic conversion
- **Visual Status Indicators**: Clear authentication status and secret counts for each configuration
- **Persistent Storage**: Secure credential storage using VS Code's SecretStorage API

### **⚡ Quick Secret Access**
- **Field-Level Actions**: Right-click on any field to copy, add to favorites, or generate code examples
- **Favorites System**: Save frequently used secrets for instant access
- **Recent Secrets**: Track recently accessed secrets automatically
- **Smart Clipboard**: Auto-clear secrets from clipboard after 30 seconds for security
- **Terminal Detection**: Automatic hints when terminal processes need authentication

### **🛠️ Developer Productivity**
- **SDK Code Examples**: Generate code samples for JavaScript, Python, Go, Java, .NET, and CLI
- **Raw JSON Viewer**: Inspect complete record structures for debugging
- **Environment File Integration**: Add secrets to .env files with proper variable format
- **Secret References**: Insert keeper notation references directly into your code
- **Template Management**: Sync keeper references to actual values in .env files

### **🔒 Enterprise Security**
- **OS-Native Encryption**: Credentials stored using VS Code's SecretStorage API
- **No Plaintext Storage**: Secrets never stored locally in plaintext
- **Audit Trail**: All secret access logged through Keeper's enterprise logging
- **Configurable Visibility**: Toggle secret visibility with security warnings

## Installation

### From VS Code Marketplace
1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X` or `Cmd+Shift+X`)
3. Search for "Keeper Secrets Manager"
4. Click Install

### Development Setup
1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile the extension:
   ```bash
   npm run compile
   ```
4. Press `F5` to open a new VS Code window with the extension loaded

## Getting Started

### 1. Add Your First Configuration

1. Open the **Keeper Secrets Manager** sidebar (activity bar icon)
2. Click **"Add KSM Device"** or the **➕** button
3. Enter your authentication credentials:
   - **One-Time Token**: `US:YOUR_TOKEN_HERE` (replace `US` with your region)
   - **Base64 Config**: `eyJ...` (base64-encoded configuration)
4. Optionally provide a custom name (e.g., "Production", "Development")

### 2. Browse and Manage Secrets

The TreeView provides a hierarchical view of your secrets:

```
📁 Production (US) - 45 secrets
  📂 Web Applications
    🔐 GitHub Repository
      👤 username
      🔒 password
      🔗 url
  📂 Databases
    🔐 MySQL Production
      👤 username
      🔒 password
      🔗 host
```

**Field Actions** (Right-click on any field):
- **Copy Secret**: Copy the field value to clipboard
- **Add to Favorites**: Save for quick access
- **Generate Code Sample**: Create SDK code examples
- **Show SDK Examples**: View multi-language examples

**Record Actions** (Right-click on any record):
- **Add to .env File**: Add secret to environment files
- **Insert Secret Reference**: Add keeper notation to code
- **Show Raw JSON**: View complete record structure

### 3. Environment File Integration

#### Adding Secrets to .env Files
1. Right-click on a record in the TreeView
2. Select **"Add to .env File"**
3. Choose your .env file (or create a new one)
4. Enter environment variable name (e.g., `DATABASE_URL`)
5. Select the field to use
6. Optionally customize the template value

#### Syncing References to Actual Values
Use `Keeper: Sync Secret References in .env Files` to convert keeper notation to actual values:

```bash
# Before sync (safe to commit)
# DATABASE_URL=keeper://RECORD_UID/field/password
DATABASE_URL=placeholder

# After sync (local development only)
# DATABASE_URL=keeper://RECORD_UID/field/password
DATABASE_URL=myactualpassword123
```

### 4. Quick Secret Access

**Favorites System**:
- Add frequently used secrets to favorites via field context menu
- Access via `Keeper: Quick Secret Launcher` → "Quick Copy Favorites"
- Custom display names for easy identification

**Recent Secrets**:
- Automatically tracks recently accessed secrets
- Chronological ordering with usage timestamps
- Access via `Keeper: Quick Secret Launcher` → "Recent Secrets"

### 5. Developer Code Examples

Right-click any field and select **"Show SDK Examples"** to see code samples:

```javascript
// JavaScript/Node.js
const { getSecrets } = require('@keeper-security/secrets-manager-core');
const secrets = await getSecrets(options);
const record = secrets.records.find(r => r.recordUid === 'RECORD_UID');
const fieldValue = record.data.fields.find(f => f.type === 'password')?.value?.[0];
```

```python
# Python
from keeper_secrets_manager_core import SecretsManager
secrets_manager = SecretsManager(config=config)
value = secrets_manager.get_value('keeper://RECORD_UID/field/password')
```

## Multi-Configuration Management

### Adding Multiple Configurations
- Production: `US:PROD_TOKEN` → "Production (US)"
- Development: `EU:DEV_TOKEN` → "Development (EU)"
- Testing: `AU:TEST_TOKEN` → "Testing (AU)"

### Configuration Management
- **Set Active**: Right-click configuration → "Set as Active"
- **Refresh**: Update secrets cache
- **Remove**: Delete configuration and credentials
- **Authenticate**: Re-authenticate existing configuration

### Visual Indicators
- 🟢 **Green server icon**: Authenticated and ready
- 🔴 **Red server icon**: Authentication required
- **Secret count**: Number of secrets loaded
- **Last authenticated**: Timestamp of last successful login

## Commands

### Primary Commands
| Command | Description |
|---------|-------------|
| `Keeper: Quick Secret Launcher` | **⭐ Quick access to favorites, recent, and search** |
| `Keeper: Sync Secret References in .env Files` | Convert keeper notation to actual values |
| `Keeper: Generate .env Template` | Create environment templates |
| `Keeper: Generate SDK Code Sample` | Generate code samples for various languages |

### TreeView Commands
| Command | Description |
|---------|-------------|
| `Keeper: List Secrets` | Browse secrets in active configuration |
| `Keeper: Insert Secret Reference` | Insert keeper notation at cursor |
| `Keeper: Refresh Secrets` | Update secrets cache |
| `Keeper: Logout` | Clear stored credentials |

## Settings

Access settings via `Ctrl+,` (or `Cmd+,`) → Search "Keeper":

| Setting | Default | Description |
|---------|---------|-------------|
| `keeper.showSecretValues` | `false` | **⚠️ Display actual secret values in TreeView instead of masked text** |
| `keeper.clipboardAutoClear` | `true` | Automatically clear copied secrets from clipboard after 30 seconds |
| `keeper.terminalDetection` | `true` | Show suggestions when terminal processes need secrets |

### Security Settings

**Secret Visibility**:
- **Disabled (Recommended)**: Secret values masked as `••••••••`
- **Enabled**: Shows actual passwords and tokens in plain text
- ⚠️ **Warning**: Only enable in secure environments

**Clipboard Auto-Clear**:
- **Enabled**: Secrets automatically clear after 30 seconds
- **Disabled**: Secrets remain in clipboard until manually cleared
- Prevents accidental secret exposure

## Authentication Methods

### Method 1: One-Time Token
1. Generate in Keeper Vault → Applications → KSM Application
2. Format: `REGION:TOKEN`
   - `US:YOUR_TOKEN` for US region
   - `EU:YOUR_TOKEN` for EU region
   - `AU:YOUR_TOKEN` for AU region

### Method 2: Base64 Configuration
1. Generate via Keeper Admin Console
2. Copy the base64-encoded configuration string
3. Paste when prompted

### Automatic Token Conversion
One-Time Tokens are automatically converted to base64 configurations after first use for improved performance and reliability.

## Security Features

- **End-to-End Encryption**: All communication encrypted
- **OS-Native Storage**: Credentials stored using VS Code's SecretStorage API
- **No Plaintext Storage**: Secrets never stored locally in plaintext
- **Automatic Clipboard Clearing**: Prevents accidental secret exposure
- **Visual Security Warnings**: Clear indicators when sensitive data is visible
- **Audit Trail**: All access logged through Keeper's enterprise logging

## Troubleshooting

### Authentication Issues
1. **Invalid Token**: Verify token is correct and not expired
2. **Region Mismatch**: Ensure region prefix matches your Keeper region
3. **Network Issues**: Check firewall/proxy settings for Keeper API access

### TreeView Not Visible
1. Check if authentication completed successfully
2. Look for error messages in VS Code Output panel
3. Try refreshing the configuration

### Secret Access Issues
1. Verify record UID exists in your vault
2. Check field names match exactly
3. Ensure you have access permissions to the record

### Common Questions

**Q: Why don't I see the TreeView?**
A: Ensure you've completed authentication and the extension is activated. Look for the Keeper icon in the activity bar.

**Q: Can I use multiple regions simultaneously?**
A: Yes! Add separate configurations for each region (US, EU, AU) and switch between them as needed.

**Q: How do I share configurations with my team?**
A: Each developer should authenticate with their own credentials. Configuration names and structure can be shared, but credentials should remain individual.

## Use Cases

### Development Teams
- **Multi-Environment**: Separate configurations for dev/staging/prod
- **Secret Sharing**: Consistent secret access across team members
- **Environment Files**: Standardized .env file management

### DevOps Engineers
- **Deployment Scripts**: Generate code samples for automation
- **Configuration Management**: Template-based secret management
- **Security Compliance**: Audit trail and secure credential storage

### Individual Developers
- **Quick Access**: Instant access to frequently used secrets
- **Terminal Integration**: Seamless authentication workflows
- **Code Examples**: Learn SDK integration patterns

## Support

For issues and support:
- Check the VS Code Output panel for error messages
- Verify your Keeper Secrets Manager configuration
- Ensure you have the latest version of the extension
- Check network connectivity to Keeper servers

## Development

### Building
```bash
npm run compile
```

### Testing
```bash
npm test
```

### Packaging
```bash
vsce package
```

## License

This project is licensed under the MIT License.