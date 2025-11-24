# KSM Interpolate Command Implementation

This document describes the implementation of the `ksm interpolate` command for the Keeper Secrets Manager CLI.

## Feature Overview

The `ksm interpolate` command provides secure template file interpolation, replacing Keeper notation with actual secret values. This feature addresses the need for automated secret injection in CI/CD pipelines and configuration management.

## Implementation Details

### Architecture

The implementation consists of two main classes:

1. **`InterpolateSecurity`** - Handles all security aspects:
   - Path validation and traversal prevention
   - Git safety checks
   - Template content validation
   - Secure file operations
   - Safety marker creation

2. **`Interpolate`** - Core interpolation logic:
   - Notation pattern matching
   - Secret resolution via KSM SDK
   - File I/O operations
   - Batch optimization
   - Error handling

### Files Added/Modified

- `/keeper_secrets_manager_cli/interpolate.py` - Main implementation
- `/keeper_secrets_manager_cli/__main__.py` - Command registration
- `/tests/interpolate_test.py` - Comprehensive unit tests
- `/docs/interpolate.md` - User documentation
- `/examples/test.env` - Example environment file
- `/examples/config.yaml` - Example YAML configuration

### Security Features

1. **File Permission Protection**
   - Output files: `0600` (owner read/write only)
   - Directories: `0700` (owner only)
   - Atomic writes prevent partial files

2. **Path Traversal Prevention**
   - Blocks `../`, absolute paths, `~/`
   - Validates paths stay within working directory
   - Sanitizes null bytes

3. **Git Safety**
   - Detects git repositories
   - Checks `.gitignore` status
   - Creates `.filename.ksm-secret` markers
   - Warns about risky filenames

4. **Template Validation**
   - Blocks code execution patterns
   - Prevents injection attacks
   - Validates notation syntax

5. **Audit Support**
   - Operation logging to stderr
   - File hash calculation
   - User context capture

### Performance Optimizations

1. **Batch Record Loading**
   - Pre-loads all required records
   - Single API call for multiple secrets
   - Automatic deduplication

2. **Caching**
   - Records cached during operation
   - SDK-level caching utilized
   - Connection reuse

3. **Efficient Processing**
   - Streaming for large files
   - 10MB file size limit
   - Progress indicators

## Usage Examples

### Basic Usage
```bash
# Process template to stdout
ksm interpolate config.template

# Write to file
ksm interpolate config.template -o config.env

# In-place editing
ksm interpolate -w config.env
```

### CI/CD Integration
```bash
# GitHub Actions
ksm interpolate deployment.yaml.template -o deployment.yaml
kubectl apply -f deployment.yaml
rm -f deployment.yaml
```

### Docker Compose
```bash
# Generate docker-compose.yml
ksm interpolate docker-compose.yml.template -o docker-compose.yml
docker-compose up -d
```

## Testing

The implementation includes comprehensive unit tests covering:

- Security features (path traversal, permissions, git safety)
- Core functionality (notation parsing, replacement)
- Error handling (validation, continue mode)
- Edge cases (large files, invalid templates)

Run tests:
```bash
cd tests
python -m pytest interpolate_test.py -v
```

## Future Enhancements

Potential improvements for future versions:

1. **Format-Aware Processing**
   - JSON/YAML structure preservation
   - XML support
   - Properties file handling

2. **Advanced Features**
   - Recursive directory processing
   - Parallel file processing
   - Custom notation formats
   - Variable defaults

3. **Integration**
   - Direct Kubernetes secret creation
   - AWS Parameter Store sync
   - HashiCorp Vault compatibility

## Security Considerations

### Threat Model

1. **Path Traversal** - Mitigated by path validation
2. **Code Injection** - Mitigated by template validation
3. **Information Disclosure** - Mitigated by secure permissions
4. **Accidental Commits** - Mitigated by git safety checks

### Best Practices

1. Never commit interpolated files
2. Add output files to `.gitignore`
3. Use descriptive Keeper record names
4. Validate templates before production use
5. Clean up interpolated files after use

## Contributing

When modifying the interpolate command:

1. Maintain security features
2. Add tests for new functionality
3. Update documentation
4. Follow existing code patterns
5. Consider performance impact

## Support

For issues or questions:
- GitHub Issues: [keeper-secrets-manager-cli/issues](https://github.com/Keeper-Security/secrets-manager/issues)
- Documentation: [docs.keeper.io](https://docs.keeper.io/secrets-manager/)
- Support: sm@keepersecurity.com