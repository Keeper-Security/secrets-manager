

## 1. Obtain you One-Time Secret Key
Keeper Secrets Manager (KSM) authenticates your API requests using advanced encryption that used locally stored private key, device id and client id.
To register your device and generate private key you will need to generate a One-Time Secret Key via Web Vault or Keeper Commander CLI.

### Via Web Vault
TBD:

### Via Keeper Commander CLI
Login to Keeper Commander CLI and perform following:
1. Create Application
    ```bash
   $ app-share --app [NAME] --secret [UID]
    ```
   
    - `--app` - Name of the Application.
    - `--secret` - Record UID or Shared Folder UID
    
1. Create client
    ```bash
   $ app-client [NAME]
    ```

### Install
TBD

### Quick Start

```python
# Import Secrets Manager
from keeper_secrets_manager_core import SecretsManager

# Establish connection
# One time secrets generated via Web Vault or Commander CLI
secrets_manager = SecretsManager(token='MmzGdls - rDG39vgqgFD1HL70h0_L_sKQOdI0qwXU3JI')

# Retrieve all password records
all_records = secrets_manager.get_secrets()

# Get password from first record:
password = all_records[0].password

# Print password (WARNING: Never ever do this at home! Never print password like this 😉)
print("My password from Keeper: %s" % password)
```

## Samples
### File Download
TBD

### Update record
TBD

## Configuration

### Types

Listed in priority order
1. Environment variable
1. Configuration store
1. Code

### Available configurations:

- `secret_key` - 
- `server` - Keeper Backend server. Available values: 
    - Server name
        - `https://keepersecurity.com`
        - `keepersecurity.com`
    - Server Abbreviation
        - `US` - resolve to `keepersecurity.com` 
        - `EU` - resolve to `keepersecurity.eu`
        - `AU` - resolve to `keepersecurity.com.au`
        - `US_GOV` - resolve to `TBD`



## Adding more records or share folders to the Application

### Via Web Vault
TBD

### Via Commander CLI
```bash
app-share --app [NAME] --secret [UID2]
```

## Configuration storage
Storage is managed in ...
### Types of storages
- File storage - Default
- Cloud Storages
    - AWS <br/>Import TBD `pip install keepercommanderintegration-aws`
    - Azure <br/>Import TBD `pip install keepercommanderintegration-azure`
    - GCP <br/>Import TBD `pip install keepercommanderintegration-gcp`
    - GitHub Actions <br/>Import TBD `pip install keepercommanderintegration-gha`
    - Custom <br/>Implement your own `KeyValueStorage` class

## Available operations

### Retrieve secret(s)

```python
from keeper_secrets_manager_core import SecretsManager

secrets_manager = SecretsManager()
all_secrets = secrets_manager.get_secrets()
```
### Update secret

```python
secret_to_update = all_secrets[0]

secret_to_update.password = 'NewPassword123$'

secrets_manager.save(secret_to_update)
```
