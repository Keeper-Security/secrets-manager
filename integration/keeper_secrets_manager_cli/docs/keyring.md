# Keyring Storage for CLI Configuration

Starting in v1.3.0, KSM CLI stores profile configuration in the OS-native keyring by default instead of a plaintext `keeper.ini` file.

## Why This Change

Prior to v1.3.0, CLI profiles were stored in `keeper.ini` on disk. This file was created with world-readable permissions by default on Linux and macOS, meaning other users and processes on the same system could read your KSM credentials.

Keyring storage uses the OS credential manager, which enforces access control at the OS level — other users cannot read entries that don't belong to them.

## Platform Support

| Platform | Keyring Backend |
|----------|----------------|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service API (e.g. GNOME Keyring, KWallet) |

Linux also supports a `lkru` utility fallback for headless environments. See [Linux Setup](#linux-setup).

## How It Works

**New profiles** are stored in the keyring automatically — no `keeper.ini` is created.

**Existing profiles** in `keeper.ini` continue to work without any migration. The CLI detects which storage backend a profile uses and reads from the correct location.

### Using File-Based Storage

If you need an explicit `keeper.ini` file (e.g. Docker containers, CI/CD pipelines, or shared service accounts), use the `--ini-file` flag:

```bash
# Initialize a profile using file storage
ksm profile init --ini-file /path/to/keeper.ini

# Use a specific ini file for a command
ksm secret list --ini-file /path/to/keeper.ini
```

File-based profiles created with `--ini-file` are now written with `0600` permissions (owner read/write only).

## Linux Setup

Linux requires a running Secret Service-compatible keyring daemon (e.g. GNOME Keyring or KWallet). If one is not available, the CLI falls back to the `lkru` utility.

### Option 1: Python keyring library (recommended)

`keyring` is an optional dependency. Install it alongside the CLI:

```bash
pip install keeper-secrets-manager-cli[keyring]
```

If `keyring` is not installed, new profiles fall back to `keeper.ini` file storage (with `0600` permissions).

### Option 2: lkru utility fallback

If the `keyring` library is not available or no Secret Service daemon is running, the CLI will look for `lkru` in your `$PATH`, or at the path specified by the `KSM_CONFIG_KEYRING_UTILITY_PATH` environment variable:

```bash
export KSM_CONFIG_KEYRING_UTILITY_PATH=/usr/local/bin/lkru
```

### Headless / Server Environments

For headless Linux servers without a keyring daemon, use file-based storage instead:

```bash
ksm profile init --ini-file ~/.keeper/keeper.ini
```

## CI/CD and Docker

Keyring storage is not suitable for containerized or ephemeral environments. Use the `KSM_CONFIG` environment variable or `--ini-file` instead.

### Using KSM_CONFIG (recommended for CI/CD)

```bash
# Export your profile as a base64 config string
export KSM_CONFIG=$(ksm profile export --profile-name default)

# Use in your pipeline — no ini file needed
ksm secret list
```

### Using --ini-file in Docker

```dockerfile
# Copy your keeper.ini into the container
COPY keeper.ini /app/keeper.ini

# Use it at runtime
CMD ["ksm", "secret", "list", "--ini-file", "/app/keeper.ini"]
```

## Profile Name Requirements

Profile names stored in the keyring must be 1–64 characters and contain only letters, numbers, hyphens, and underscores:

```
✓ default
✓ my-profile
✓ prod_api_v2
✗ my profile   (spaces not allowed)
✗ ../escape    (path characters not allowed)
```

## Troubleshooting

### Keyring not available

```
Error: No keyring backend available. Install: pip install keyring
```

Install the `keyring` library or use `--ini-file` for file-based storage.

### Wrong keyring backend on Linux

If `keyring.get_keyring()` returns a `fail.Keyring` backend, no Secret Service daemon is running. Start GNOME Keyring, install KWallet, or use the `lkru` fallback.

### Finding entries in the OS keyring

The CLI stores entries under the application name `KSM-cli`:
- Common config: key `ksm-cli-common`
- Per-profile: key `ksm-cli-profile-{profile_name}`

On macOS you can view these in **Keychain Access**. On Windows, use **Credential Manager** → **Windows Credentials**.

### Migrating from keeper.ini to keyring

No automated migration is provided. To move an existing profile to keyring storage:

```bash
# 1. Export the existing profile
ksm profile export --profile-name default > token.txt

# 2. Re-initialize using keyring storage (omit --ini-file)
ksm profile init --token "$(cat token.txt)"

# 3. Verify the new profile works
ksm secret list

# 4. Remove the old keeper.ini if no longer needed
```

## See Also

- [KSM CLI Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface)
- [Profile Management](https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface/profile-management)
