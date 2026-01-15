# KSM Interpolate Command

The `ksm interpolate` command replaces Keeper notation in template files with actual secret values from your Keeper vault.

**Solves:** GitHub issue #543 - Enables use with shell built-ins like `source` and `eval` that `ksm exec` cannot execute.

## Why This Command Exists

`ksm exec` cannot execute shell built-in commands like `source` because they are not standalone executables. The `interpolate` command solves this by outputting the interpolated file to stdout, enabling:

```bash
# Load environment variables using eval (with security flag)
eval "$(ksm interpolate secrets.env --allow-unsafe-for-eval)"

# Or using process substitution
source <(ksm interpolate secrets.env --allow-unsafe-for-eval)
```

**SECURITY WARNING:** Only use `eval` or `source` if you fully trust all users with Keeper write access. See Security section below.

## Overview

The interpolate command:
- Reads template files containing Keeper notation
- Fetches secrets from your Keeper vault
- Replaces notation with actual values
- Supports defaults, transformations, and comment preservation
- Writes secure output files with proper permissions (0600)

## Notation Format

Basic notation:
```
keeper://RECORD_UID/field/FIELD_NAME
keeper://RECORD_UID/custom_field/CUSTOM_FIELD_NAME
keeper://RECORD_UID/file/FILE_NAME
```

With default values (shell-style `:-`):
```
keeper://RECORD_UID/field/FIELD_NAME:-default_value
```

With transformations:
```
keeper://RECORD_UID/field/FIELD_NAME|transform
keeper://RECORD_UID/field/FIELD_NAME:-default|transform
```

Available transforms: `base64`, `base64url`, `urlencode`, `urlencodeplus`, `upper`, `lower`, `trim`, `sha256`, `md5`

Examples:
- `keeper://MyDatabaseCreds/field/password`
- `keeper://ApiCredentials/custom_field/api_key`
- `keeper://DB/field/host:-localhost` (with default)
- `keeper://API/field/key|base64` (with transformation)
- `keeper://DB/field/password:-default_pass|sha256` (default + transform)

## Basic Usage

### Process from stdin to stdout
```bash
cat config.template | ksm interpolate > config.env
```

### Process a file
```bash
ksm interpolate config.template -o config.env
```

### Process multiple files
```bash
ksm interpolate *.template
```

### In-place editing with backup
```bash
ksm interpolate -w -b .bak config.env
```

## Command Options

| Option | Short | Description |
|--------|-------|-------------|
| `--output-file` | `-o` | Write output to file instead of stdout |
| `--in-place` | `-w` | Edit files in place |
| `--backup-suffix` | `-b` | Backup suffix when using -w (default: .bak) |
| `--dry-run` | `-n` | Show what would be replaced without making changes |
| `--verbose` | `-v` | Verbose output (shows replacements) |
| `--continue` | `-C` | Continue on errors |
| `--validate` |  | Ensure all notations were resolved |
| `--allow-unsafe-for-eval` |  | **[RISKY]** Allow secrets with shell metacharacters (required for eval/source) |

## Examples

### Environment File (.env)

Template file `config.env.template`:
```bash
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=keeper://MyDatabaseCreds/field/password

# API configuration
API_KEY=keeper://ApiCredentials/field/custom_field[ApiKey]
API_SECRET=keeper://ApiCredentials/field/custom_field[ApiSecret]
```

Process the template:
```bash
ksm interpolate config.env.template -o config.env
```

Result `config.env`:
```bash
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=MySecurePassword123

# API configuration
API_KEY=sk-1234567890abcdef
API_SECRET=secret_abcdef123456
```

### Shell Built-ins (Solves #543)

**Problem:** `ksm exec` cannot execute shell built-ins like `source`:
```bash
ksm exec -- source .env  # Error: No such file or directory: 'source'
```

**Solution:** Use `ksm interpolate` with eval or source:
```bash
# Option 1: Write to file (RECOMMENDED - most secure)
ksm interpolate secrets.env -o /tmp/secrets.env
source /tmp/secrets.env
rm /tmp/secrets.env

# Option 2: Direct eval (requires --allow-unsafe-for-eval flag)
eval "$(ksm interpolate secrets.env --allow-unsafe-for-eval)"

# Option 3: Process substitution (requires --allow-unsafe-for-eval flag)
source <(ksm interpolate secrets.env --allow-unsafe-for-eval)
```

**Security:** Options 2 and 3 require `--allow-unsafe-for-eval` flag and are only safe if you fully trust all Keeper users with write access. See Security section.

### Default Values

Use defaults for local development when production secrets are unavailable:

```bash
# Template with defaults (:-syntax like shell variables)
DB_HOST=keeper://ProdDB/field/host:-localhost
DB_PORT=keeper://ProdDB/field/port:-5432
API_URL=keeper://ProdAPI/field/url:-http://localhost:3000
```

If secrets don't exist or are inaccessible, defaults are used automatically.

### Transformations

Apply transformations without external tools:

```bash
# Base64 encoding
JWT_SECRET=keeper://Auth/field/secret|base64

# URL encoding for query params
CALLBACK_URL=keeper://Config/field/callback|urlencode

# Uppercase environment name
ENV=keeper://Config/field/environment|upper

# Password hashing
PASSWORD_HASH=keeper://Auth/field/password|sha256
```

All transforms use Python stdlib (no new dependencies).

### YAML Configuration

Template file `app.yaml.template`:
```yaml
database:
  host: localhost
  port: 5432
  username: dbadmin
  password: keeper://DatabaseCreds/field/password

api:
  endpoint: https://api.example.com
  key: keeper://ApiSecrets/custom_field/api_key
  secret: keeper://ApiSecrets/custom_field/api_secret
```

Process with dry run first:
```bash
ksm interpolate -n app.yaml.template
```

Then process for real:
```bash
ksm interpolate app.yaml.template -o app.yaml
```

### Docker Compose

Template file `docker-compose.yml.template`:
```yaml
version: '3.8'
services:
  app:
    image: myapp:latest
    environment:
      - DB_PASSWORD=keeper://AppSecrets/field/db_password
      - JWT_SECRET=keeper://AppSecrets/field/jwt_secret
      - SMTP_PASSWORD=keeper://EmailCreds/field/password
```

Process and deploy:
```bash
ksm interpolate docker-compose.yml.template -o docker-compose.yml
docker-compose up -d
```

### CI/CD Pipeline Example

In a GitHub Actions workflow:
```yaml
- name: Install KSM CLI
  run: pip install keeper-secrets-manager-cli

- name: Interpolate secrets
  env:
    KSM_CONFIG: ${{ secrets.KSM_CONFIG }}
  run: |
    # Process all template files
    ksm interpolate config/*.template

- name: Deploy application
  run: ./deploy.sh
```

## Security Features

### Shell Injection Protection

**CRITICAL:** By default, the command blocks secrets containing shell metacharacters (newlines, backticks, $, ;, |, &, >, <) to prevent command injection attacks.

```bash
# If a secret contains dangerous characters, interpolation fails:
$ ksm interpolate secrets.env

SECURITY ERROR: Secret contains shell metacharacters: '\n' (newline)
This is DANGEROUS if you plan to use 'eval' or 'source'!

OPTIONS:
  1. [RECOMMENDED] Write to file: ksm interpolate -o file.env
  2. [RISKY] Use: --allow-unsafe-for-eval (only if you trust all Keeper users)
```

**Why:** Malicious users with Keeper write access could inject commands:
```bash
# Attacker sets password to: password123\nrm -rf /
# Victim runs: eval "$(ksm interpolate secrets.env)"
# Result: Both lines execute → system compromised
```

Use `--allow-unsafe-for-eval` **only** if:
- You fully trust all users with Keeper write access
- You understand the risks of command injection
- Writing to a file is not an option

### File Permissions
- Output files are created with `0600` permissions (owner read/write only)
- Directories are created with `0700` permissions
- Atomic file operations prevent partial writes

### Git Safety
- Warns if output files are not in `.gitignore`
- Creates `.filename.ksm-secret` marker files
- Checks for common secret filename patterns

### Path Security
- Prevents path traversal attacks
- Validates all file paths
- Restricts to current directory by default

### Template Validation
- Blocks dangerous template patterns
- Prevents code injection attempts
- Validates notation format

### Example Security Warnings
```bash
$ ksm interpolate secrets.env -o production.env

⚠️  Git safety warnings:
  • File is not in .gitignore. Add 'production.env' to .gitignore
  • Filename suggests it may contain secrets

✅ Interpolation complete:
  • Replaced 5 secret references
  • Accessed 3 unique records
```

## Best Practices

### 1. Use Templates
Keep templates in version control, not the interpolated files:
```
config.env.template  ✓ Commit this
config.env          ✗ Add to .gitignore
```

### 2. Add to .gitignore
Always add interpolated files to `.gitignore`:
```gitignore
# Interpolated secrets
*.env
!*.env.template
config/*.yml
!config/*.yml.template
```

### 3. Use Descriptive Record Names
Use clear, descriptive record names in Keeper:
- ✓ `ProductionDatabaseCreds`
- ✗ `Creds1`

### 4. Validate Before Production
Use `--dry-run` to verify templates:
```bash
ksm interpolate --dry-run production.env.template
```

### 5. Secure Cleanup
Remove interpolated files after use:
```bash
ksm interpolate config.template -o config.env
./deploy.sh
rm -f config.env
```

## Performance Optimization

### Batch Processing
The command optimizes by:
- Pre-loading all required records in one API call
- Caching records during processing
- Reusing connections

### Large Files
- Supports files up to 10MB
- Streaming processing for efficiency
- Progress indicators with `-v` flag

## Troubleshooting

### Common Issues

**Notation not found:**
```
Error resolving keeper://InvalidRecord/field: Record not found
```
Solution: Verify the record UID exists in your vault

**Permission denied:**
```
Failed to write output file: Permission denied
```
Solution: Check directory permissions or use a different output location

**Template validation failed:**
```
Security violation in template: Potential code execution
```
Solution: Remove any code execution patterns from templates

### Debug Mode
Enable debug logging:
```bash
export KSM_DEBUG=1
ksm interpolate -v config.template
```

## Integration with Other Tools

### Docker Secrets
```bash
# Generate Docker secrets
ksm interpolate docker-secrets.template | docker secret create my-secret -
```

### Kubernetes ConfigMaps
```bash
# Create ConfigMap from interpolated file
ksm interpolate app-config.template -o app-config.yaml
kubectl create configmap app-config --from-file=app-config.yaml
```

### Terraform Variables
```bash
# Generate Terraform variables
ksm interpolate terraform.tfvars.template -o terraform.tfvars
terraform apply
```

## Advanced Usage

### Multiple Notations Per Line
```bash
CONNECTION_STRING=postgresql://keeper://DB/field/user:keeper://DB/field/password@localhost:5432/mydb
```

### Nested JSON Values
```json
{
  "database": {
    "credentials": "keeper://Database/field/connection_json"
  }
}
```

### File Content Interpolation
```yaml
ssl_cert: |
  keeper://Certificates/file/server.crt
```

## Security Considerations

1. **Never commit interpolated files** - They contain actual secrets
2. **Use secure channels** - Transfer interpolated files over encrypted connections
3. **Minimize exposure** - Delete interpolated files after use
4. **Audit access** - Monitor who runs interpolation commands
5. **Rotate secrets** - Regularly update secrets in Keeper

## See Also

- [KSM CLI Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/keeper-secrets-manager-cli)
- [Keeper Notation Reference](https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation)
- [Best Practices for Secret Management](https://docs.keeper.io/secrets-manager/best-practices)