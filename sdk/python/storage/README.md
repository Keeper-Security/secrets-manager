# Keeper Secrets Manager Storage

The Keeper Secrets Manager Storage module for working with custom key-value storages, creating and managing configuration files. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

## Secure OS Storage

The `SecureOSStorage` interface makes use of the `windows-credential-manager-utility` or the `linux-keyring-utility` to interact with the operating systems native secrets platform (i.e. Windows Credential Manager or Linux Keyring) to secure Keeper configuration files.

### Usage

To use the secure storage, create an instance of the `SecureOSStorage` class and pass the name of the application that will be using the storage. This name will be used to identify the applications configuration in the OS's storage platform.

```python
from keeper_secrets_manager_storage import SecureOSStorage

storage = SecureOSStorage(app_name='my_app')
```

By default, `SecureOSStorage` will check `PATH` for one of the above utilities. 

By setting the environment variable `KSM_CONFIG_EXE_PATH` to the path of the utility, users have the option to run the executable directly without it being in `PATH`. 

In addition, users can pass the path to the utility executable as an argument to the `SecureOSStorage` constructor.

```python
storage = SecureOSStorage(app_name='my_app', exe_path='path/to/utility')
```

Should the executable need to be run as a different user or as with elevated priviledges, the `SecureOSStorage` constructor accepts an optional `run_as` parameter. This value will be prepended to the command that is run to interact with the OS's storage platform.

```python
storage = SecureOSStorage(app_name='my_app', exe_path='path/to/utility', run_as='sudo')
```

You can retrieve the current configuration of an application by calling `read_storage()` on the storage object.

```python
config = storage.read_storage()
```

Save a configuration by calling `save_storage()` on the storage object. 

```python
storage.save_storage()
```

> Note: Saving a configuration will overwrite an existing configuration with the same application name without warning.

## Change Log

### 1.0.1

- Added new storage type storage type for AWS Secrets Manager

### 1.0.0
- Initial release
