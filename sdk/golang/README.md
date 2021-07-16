# secrets-management Go (golang) SDK

This SDK has been used on millions of machines across many different projects and has proven to be battle hardened and ready for production use.

## Features:

## 1. Obtain you One-Time Secret Key
Keeper Secrets Manager authenticates your API requests using advanced encryption that used locally stored private key, device id and client id.
To register your device and generate private key you will need to generate a One-Time Secret Key via Web Vault or Keeper Secrets Manager CLI.

### Via Web Vault
TBD:

### Via Keeper Secrets Manager CLI
Login to Keeper Secrets Manager CLI and perform following:
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

```golang
package main

// Import Commander
import "keepercommandersm/core"

func main() {
	// Establish connection
	// One time secrets generated via Web Vault or Commander CLI
	c := ksm.NewCommander()
	c.ClientKey = "MmzGdls-rDG39vgqgFD1HL70h0_L_sKQOdI0qwXU3JI"

	// Retrieve all password records
	allRecords, _ := c.GetSecrets([]string{})

	// Get password from first record:
	password := allRecords[0].Password()

	// Print password (WARNING: Never ever do this at home! Never print password like this 😉)
	print("My password from Keeper: ", password)
}
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

- `secret_key` - Client key
- `server` - Keeper Backend server. Available values:
    - Server name
        - `https://keepersecurity.com`
        - `keepersecurity.com`
    - Server Abbreviation
        - `US` - resolve to `keepersecurity.com`
        - `EU` - resolve to `keepersecurity.eu`
        - `AU` - resolve to `keepersecurity.com.au`
        - `US_GOV` - resolve to `govcloud.keepersecurity.us`

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
    - AWS <br/>Import TBD
    - Azure <br/>Import TBD
    - GCP <br/>Import TBD
    - GitHub Actions <br/>Import TBD
    - Custom <br/>Implement your own `KeyValueStorage` class

## Available operations

### Retrieve secret(s)

```golang
allSecrets, _ := commander.GetSecrets([]string{})
```
### Update secret

```golang
secretToUpdate = allSecrets[0]

secretToUpdate.SetPassword("NewPassword123$")

commander.Save(secretToUpdate)
```
