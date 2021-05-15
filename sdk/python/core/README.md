

## Intro
### Quick Start

```python
# Import Commander
from keepercommandersm import Commander

# Establish connection
# One time secrets generated via Web Vault or Commander CLI
Commander.secret_key = `s3cr3t-keyKU-LX_ksOKIA5VTC-4Ak2O-Um22oyDHzs`

# Retrieve all password records
all_records = Commander.get_all()

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



# Publish to PyPi

TBD