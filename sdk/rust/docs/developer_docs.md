# Rust SDK
Detailed Rust SDK docs for Keeper Secrets Manager

## Download and Installation

### Install with cargo

### Source Code

Find the Rust source code in the [GitHub repository](https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/rust)

## Using the SDK

### Initialize

##### Note : 

Using a token only to generate a new configuration (for later usage) requires at least one read operation to bind the token and fully populate the `test.json`

**Secrets Manager**

> SecretsManager::new(client\_options)?

**Example Usage**
``` rust
    use keeper_secrets_manager_core::{ClientOptions, SecretsManager,storage::FileKeyValueStorage}
    let client_options = ClientOptions::new_client_options_with_token(token, config);
    let mut secrets_manager = SecretsManager::new(client_options)?;
```

* Using token only to generate the config 
* requires at least one access operation to bind the token


| Parameter | Required | Type | Description |
| --- | --- | --- | --- |
| `token` | `Yes` | String | One-Time Access Token |
| `config` | `Yes` | KeyValueStorage | Storage Configuration |
| `client_options` | `Yes` | ClientOptions | Client Configuration |

## Retrieve Secrets
### Get Secrets

> secrets_manager.get_secrets(uids)

**Example: Get All Secrets**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };

    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get all records
    let filtered_secrets = secrets_manager.get_secrets(Vec::new())?;

    // print out all records
    for secret in filtered_secrets{
        secret.print();
    }
```
  
**Example: Get Secrets With a Filter**

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };

    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let uids = vec!["record_1_uid".to_string(), "record_2_uid".to_string()];
    // get filtered records
    let filtered_secrets = secrets_manager.get_secrets(uids)?;

    // print out filtered records
    for secret in filtered_secrets{
        secret.print();
    }
```
| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `uids` | `Vec<String>` | Yes | None | UIDs of the records to fetch |
  
**Response**

Type: `Vec<Record>`

All Keeper records, or records with the given UIDs

> default - we will get all records which the token given has access to

### Retrieve Values From a Secret

#### Retrieve a Password

This shortcut gets the password of a secret once that secret has been retrieved from Keeper Secrets Manager.

**Get Password**

> secret.get_standard_field_value('password', true)

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by record UID
    let secrets = secrets_manager.get_secrets(vec!["record_uid".to_string()])?;
    let secret = match secrets.len(){
        0 => return Err(KSMRError::CustomError("no secret with given uid is found".to_string())),
        _ => &secrets[0],
    };
    // get password from record
    let my_secret_password = secret.get_standard_field_value("password", true);
```
  

#### Retrieve Standard Fields

**Field**

> secret.get_standard_field_value(“FIELD_TYPE”.to_string(), true)

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::FileKeyValueStorage,
        custom_error::KSMRError,
        enums::StandardFieldTypeEnum
    };
    // setup secrets manager
    let token = "your_token_goes_here".to_string();
    let config = FileKeyValueStorage::new_config_storage("test.json".to_string())?;
    let client_options = ClientOptions::new_client_options_with_token(token, config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by record UID
    let secrets = secrets_manager.get_secrets(vec!["record_uid".to_string()])?;
    let secret = match secrets.len(){
        0 => return Err(KSMRError::CustomError("no secret with given uid is found".to_string())),
        _ => &secrets[0],
    };
    // use StandardFieldTypeEnum for getting accurate type for standard field without any typographic errors
    let login_field = StandardFieldTypeEnum::LOGIN.get_type().to_string();
    // get login field from the secret
    let my_secret_login = secret.get_standard_field_value(login_field, true)
```

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `field_type` | `String` | Yes | None | Field type to get |
| `single` | `boolean` | Optional | False | Return only the first value |

> Fields are found by type. For a list of field types, see the [Record Types](https://docs.keeper.io/en/secrets-manager/commander-cli/command-reference/record-commands/default-record-types#field-types) documentation.


### Retrieve Custom Fields

**Custom Field**
  
> secret.get_custom_field_value(“FIELD_TYPE”, true)

**Example Usage**

```rust  
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by record UID
    let secrets = secrets_manager.get_secrets(vec!["record_uid".to_string()])?;
    let secret = match secrets.len(){
        0 => return Err(KSMRError::CustomError("no secret with given uid is found".to_string())),
        _ => &secrets[0],
    };
    // Get a custom field, e.g. API Key
    let api_key = secret.get_custom_field_value(“API Key”, true)
```  

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `field_type` | `String` | Yes | - | Field type to get |
| `single` | `boolean` | Optional | False | Return only the first value |

Custom fields are any field that is not part of the record type definition but can be added by users. For a list of fields in each standard record type, see the [Record Types](https://docs.keeper.io/en/secrets-manager/commander-cli/command-reference/record-commands/default-record-types#standard-record-types) documentation.

**Response**

> Type: `String` or `Vec<String>`

the value or values of the field.  It will be a single value only if the `single=true` option is passed.

### Retrieve Secrets by Title

**Records by Title**

> secrets_manager.get_secret_by_title(record_title)

**Example Usage**
  
``` rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get first secret matching the record title
    let secret = secrets_manager.get_secret_by_title("My Credentials")?
        .ok_or_else(|| KSMRError::CustomError("No record found with that title".to_string()))?;
```
**Response**

> Type: `Option<Record>`
  

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `record_title` | `&str` | Yes | Title of the record to be fetched |

  
  

### Retrieve Values using Keeper Notation

**Get Notation**

> secrets_manager.get_notation(query)  

**Example Usage**

```rust  

    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get all secrets matching the notation
    let mut notation = "HDQTnxkTcPSOsHNAlbI4aQ/field/login".to_string();
    let mut result = secrets_manager.get_notation(notation)?;
```
  

See [Keeper Notation documentation](https://docs.keeper.io/en/secrets-manager/secrets-manager/about/keeper-notation) to learn about Keeper Notation format and capabilities

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `query` | `String` | Yes | - | Keeper Notation query for getting a value from a specified field |

#### Returns

The value of the queried field

Type: String or `Vec<String>`



### Retrieve a TOTP Code

Get TOTP Code of given record

> get_totp_code(&url)

**Example Usage**

```rust

    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get TOTP url value from a record
    let value = record.get_standard_field_value(StandardFieldTypeEnum::ONETIMECODE.get_type(), false)
    let url: String = utils::get_otp_url_from_value_obj(value)?;

    // get code from TOTP url
    let totp = utils::get_totp_code(&url)?;
    println!("{}", totp.get_code());
```
**Returns**

> Type: `Result<TotpCode,KSMRError>`

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `value` | `Value` | Yes | Value from the record |
| `url` | `String` | Yes | TOTP Url |
  

## Update a Secret

* Record update commands don't update local record data on success (esp. updated record revision) so any consecutive updates to an already updated record will fail due to revision mismatch. Make sure to reload all updated records after each update batch.

#### Save Changes to a Secret

**Save Secret**
  
> secrets_manager.save(Record, UpdateTransactionType)

**Example Usage**  

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secret_to_update = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;

    // update a field value
    let field_type= StandardFieldTypeEnum::LOGIN.get_type();
    secret_to_update.set_standard_field_value_mut(field_type, "sample@ks.com".into())?;

    let transaction_type: Option<UpdateTransactionType> = Some(UpdateTransactionType::None);

    secrets_manager.save(secret_to_update, transaction_type);
```
  
| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `record` | `Record` | Yes |  | Storage and query configuration |
| `transaction_type` | `UpdateTransactionType` | Yes |  | Configuration for transactional update |

Set field values using the `set_standard_field_value_mut` or the `set_custom_field_value_mut` method.

Fields are found by type.

For a list of field types, see the [Record Types](https://docs.keeper.io/en/secrets-manager/commander-cli/command-reference/record-commands/default-record-types#field-types) documentation. Some fields have multiple values in these cases, the value can be set to a list.

### Update a Standard Field Value

**Field**
  
> secret.set_standard_field_value_mut(field_type, "new_field_value".into())

##### Example Usage
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secret_to_update = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;

    // update a field value
    let field_type= StandardFieldTypeEnum::LOGIN.get_type();
    secret_to_update.set_standard_field_value_mut(field_type, "sample@ks.com".into())?;

    let transaction_type: Option<UpdateTransactionType> = Some(UpdateTransactionType::None);

    secrets_manager.save(secret_to_update, transaction_type);
```

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `field_type` | `String` | Yes |  | Field type to get |
| `transaction_type` | `UpdateTransactionType` | Yes | None | Configuration for transactional update |

Fields are found by type.

for a list of field types, see the [Record Types](https://docs.keeper.io/en/secrets-manager/commander-cli/command-reference/record-commands/default-record-types#field-types) documentation.

### Update a Custom Field Value

**Custom Field**

> secret.set_custom_field_value_mut(field_type, "new_field_value".into())

**Example Usage**

  
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secret_to_update = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;

    // update a field value
    secret_to_update.set_custom_field_value_mut("Email", "sample@ks.com".into())?;

    let transaction_type: Option<UpdateTransactionType> = Some(UpdateTransactionType::None);

    secrets_manager.save(secret_to_update, transaction_type);
```

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `field_type` | `String` | Yes |  | Field type to get |
| `transaction_type` | `UpdateTransactionType` | Yes | None | Configuration for transactional update |

  

### Generate a Random Password

Generate Password

> generate_password_with_options(password_options)
 
**Example Usage**  
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secret_to_update = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;

    # generate a random password
    let charset: String = "$_!?#".to_string();
    let length = 32;
    let digits = 2;
    let lowercase = 2;
    let uppercase = 2;
    let special_characters = 2;
    let password_options = PasswordOptions::new().length(length).digits(digits).lowercase(lowercase).uppercase(uppercase).special_characters(special_characters).special_characterset(charset);
    let password = generate_password_with_options(password_options).unwrap();

    # update a record with new password
    let field_type= StandardFieldTypeEnum::PASSWORD.get_type();
    secret.set_standard_field_value_mut(field_type, password.into())?;

    # Save changes to the secret
    let transaction_type: Option<UpdateTransactionType> = Some(UpdateTransactionType::None);
    secrets_manager.save(secret, transaction_type);
``` 
  

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `password_options` | `PasswordOptions` | Yes |  | Configuration for the password |
| `charset` | `String` | Optional |  | Set of special characters to be included in the password |
| `length` | `i32` | Optional | 64 | Length of password |
| `lowercase` | `i32` | Optional | 0 | Minimum count (positive) or exact count (negative, e.g. `-8` = exactly 8 lowercase) |
| `uppercase` | `i32` | Optional | 0 | Minimum count (positive) or exact count (negative) |
| `digits` | `i32` | Optional | 0 | Minimum count (positive) or exact count (negative) |
| `special_characters` | `i32` | Optional | 0 | Minimum count (positive) or exact count (negative) |

Positive values set a minimum — the generator may include more of that character type to reach the requested length. Negative values set an exact count — for example, `.lowercase(-8)` produces exactly 8 lowercase characters. In exact mode the total password length is the sum of the absolute values and the `length` parameter is ignored.

### Download a File

Download File

> download_file(file_name, path)

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secrets = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;
    let secret = &secrets[0];
    let path = format!("./temp/demo_{}.txt", secret.title);
    secret.download_file("uploaded_file.txt", &path)?;
```  

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `file_name` | `&str` | Yes |  | Name of the file to be downloaded |
| `path` | `&str` | Yes |  | Path to download file |

  
### Upload a File

Upload File

> upload_file(owner_record, keeper_file)

Example

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get a specific secret by UID
    let secrets = secrets_manager.get_secrets(vec!["<RECORD UID>".to_string()])?;
    let secret = secrets.into_iter().next()
        .ok_or_else(|| KSMRError::CustomError("Record not found".to_string()))?;
    // Prepare file data for upload
    let keeper_file = KeeperFileUpload::get_file_for_upload(file_path, Some(file_name), file_title, mime_type)?;

    // Upload file attached to the secret and get the file UID
    let file_uid = secrets_manager.upload_file(secret, keeper_file)?;
```  

**Upload File**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `owner_record` | `Record` | Yes | None | The record in which the file has to be uploaded |
| `keeper_file` | `KeeperFileUpload` | Yes |  | The file to be uploaded |

**Keeper File upload from File**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `file_path` | `&str` | Yes |  | Path to upload file |
| `file_name` | `Option<&str>` | Yes |  | Name of the file to be uploaded |
| `file_title` | `Option<&str>` | Yes |  | Title of the file to be uploaded |
| `mime_type` | `Option<&str>` | Yes | None | The type of data in the file. If none is provided, 'application/octet-stream' will be used |


#### Returns

> Type: `String`

The file UID of the attached file

### Create a Secret

#### Prerequisites:

*   Shared folder UID
    *   The shared folder must be accessible by the Secrets Manager Application
    *   You and the Secrets Manager application must have edit permission
    *   There must be at least one record in the shared folder
*   Created records and record fields must be formatted correctly
    *   See the [documentation](https://docs.keeper.io/en/secrets-manager/commander-cli/command-reference/record-commands/default-record-types#field-types) for expected field formats for each record type
*   TOTP fields accept only URL generated outside of the KSM SDK
*   After record creation, you can upload file attachments using [upload\_file](https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/rust-sdk#upload-a-file)
    

**Create a Record**

> secrets_manager.create_secret(folder_uid, record)

**Login Record Example**

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        dto::{dtos::RecordCreate, field_structs::RecordField}
    };
    use serde_json::{self, json, Number, Value};

    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // This is how we create a Record
    let mut created_record =  RecordCreate::new("login".to_string(), "Login Record RUST_LOG_TEST".to_string(), Some("Dummy Notes".to_string()));
    
    // This is how we create a single field 
    let password_field = RecordField::new_record_field_with_options("password".to_string(), Value::String(utils::generate_password()?), Some("Random password label".to_string()), false, true);

    // This is one of the ways to create a value object from JSON String
    let security_question_value = Value::from_str("{\"question\": \"What is the question?\", \"answer\": \"This is the answer!\"}")?;
    
    //This is one way to create all fields directly in a vector
    let fields = vec![
        RecordField::new_record_field("login".to_string(), Value::String("login@email.com".to_string()), Some("My Custom Login lbl".to_string())),

        RecordField::new_record_field("login".to_string(), Value::String("login@email.com".to_string()), Some("My Label".to_string())),

        password_field,
        
        RecordField::new_record_field("securityQuestion".to_string(),security_question_value , Some("My Label".to_string())),

        RecordField::new_record_field("multiline".to_string(),Value::String("This\nIs a multiline\nnote".to_string()) , Some("My Multiline lbl".to_string())),

        RecordField::new_record_field("secret".to_string(),Value::String("SecretText".to_string()) , Some("My Hidden Field lbl".to_string())),

        RecordField::new_record_field("pinCode".to_string(),Value::String("1234567890".to_string()) , Some("My Pin Code Field Lbl".to_string())),

        RecordField::new_record_field("addressRef".to_string(),Value::String("some_UID".to_string()) , Some("My Address Reference".to_string())),

        RecordField::new_record_field("phone".to_string(),json!({"region": "US", "number": "510-444-3333"}) , Some("My Phone Number".to_string())),

        RecordField::new_record_field("date".to_string(),Value::Number(Number::from(1641934793000i64)) , Some("My date".to_string())),

        RecordField::new_record_field("date".to_string(),Value::String("September eleventh two thousand and eleven".to_string()) , Some("Bad day in history of humanity".to_string())),

        RecordField::new_record_field("name".to_string(),json!({"first": "Lincoln", "last": "Adams"}) , Some("His Name".to_string())),
        ];

    // Here we are adding fields object to standard fields 
    created_record.fields = Some(fields);
    
    created_record.custom = Some(
        vec![
            RecordField::new_record_field("phone".to_string(),json!({"region": "US", "number": "510-222-5555", "ext": "99887", "type": "Mobile"}) , Some("My Custom Phone Lbl".to_string())),
        ]
    );
   
    // Make the API call
    let _ = secrets_manager.create_secret("Shared_folder_uid".to_string(), created_record)?;
```  

**Custom Type Example**
  
> secrets_manager.create_secret(parent_folder_uid, record_create_object)

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `record_type` | `DefaultRecordType` | Yes | None | Type of record to be created |
| `title` | `String` | Yes |  | The title of the created record |
| `note` | `String` | Yes | None | The note to be made in the created record |
| `value` | `String` | Yes |  | Value for the field |
| `label` | `String` | Yes | None | Label for the field |
| `required` | `bool` | Yes | false | Defines if the field is required |
| `privacy_screen` | `bool` | Yes | false | Defines if the field value should be hidden |

#### Returns

> Type: `String`

The record UID of the new record

### Delete a Secret

The Rust KSM SDK can delete records in the Keeper Vault.

Delete Secret
> secrets_manager.delete_secret(vec![record_uid])

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // delete a specific secret by UID
    let secret_to_delete = secrets_manager.delete_secret(vec!["<RECORD UID>".to_string()])?;
```

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `record_uid` | `String` | Yes | None | The uid of the record to be deleted |

  

### Caching

To protect against losing access to your secrets when network access is lost, the Rust SDK allows caching of secrets to the local machine in an encrypted file.

**Setup and Configure Cache**

In order to setup caching in the Rust SDK, include a caching post function when creating a `SecretsManager` object.

The Rust SDK includes a default caching function in the `KSMRCache` class, which stores cached queries to a local file, thus serving as a disaster recovery function (as long as there's network connectivity, it always prefers network over cached data and will use cache only if the web vault is inaccessible).

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage, cache::KSMRCache};
fn main(){
    let cache = KSMRCache::new_file_cache(Some("./cache.bin"))?;

    let token = "<Token>".to_string();

    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;
    
    let mut client_options = ClientOptions::new_client_options_with_token(token, file_name);
    client_options.set_cache(cache.into()); 
    
    let mut secrets_manager = SecretsManager::new(client_options)?;  
    let secrets = secrets_manager.get_secrets(Vec::new())?;
    for secret in secrets {
        info!("Secret: {}", secret);
    };
}
```

The default caching function in KSMCache class always stores last request only. 
For example, if the first request (R1) successfully retrieves UID1 and updates the cache, but a subsequent request (R2) for UID2 fails, the cache will not include UID2. As a result, any later operations involving UID2 (e.g., lookup or disconnect) will return an empty response, since it was never added to the cache.

Updating a record from cache (or creating a new record) invalidates cached record data, and consecutive updates of the same record will fail. Batch updates work as long as they modify different records. Always follow up cached record updates with a call to get\_secrets function to refresh cache (and pull updated metadata from vault like the new record revision, etc.)

## Folders

Folders have full CRUD support—create, read, update, and delete operations.

### Read Folders

Downloads full folder hierarchy.  
> get_folders()

**Response**

> Type: `Vec<KeeperFolder>`

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // get all folder
    let secrets = secrets_manager.get_folders()?;
```
**Returns**
> Type: `Vec<KeeperFolder>`

### Create a Folder

Requires `CreateOptions` and folder name to be provided. The folder UID parameter in `CreateOptions` is required—the UID of a shared folder, while sub-folder UID is optional, and if missing, a new regular folder is created directly under the parent (shared folder). There's no requirement for the sub-folder to be a direct descendant of the parent shared folder - it could be many levels deep.

> create_folder(create_options: CreateOptions, folder_name: str, folders=None)
 
| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `create_options` | `CreateOptions` | Yes | None | The parent and sub-folder UIDs |
| `folder_name` | `str` | Yes |  | The folder name |
| `folders` | `Vec<KeeperFolder>` | No | None | List of folders to use in the search for parent and sub-folder from CreateOptions |

**Example Usage**

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let parent_folder_uid: String = "<parent_folder_uid>".to_string();
    let sub_folder_uid: Option<String> = Option::Some((""));
    let create_options: CreateOptions = CreateOptions::new(parent_folder_uid, None);
    let new_folder_name: String = "Sample Folder 200".to_string();
    println!("Creating folder: {new_folder_name}");
    let created_folder_name = new_folder_name.clone();
    let result = secrets_manager.create_folder(create_options, new_folder_name, Vec::new())?;
    println!("Created folder {created_folder_name}");
```

### Update a Folder

Updates the folder metadata—currently folder name only.

> secrets_manager.update_folder(folder_uid: str, folder_name: str, folders=None)

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `folder_uid` | `str` | Yes |  | The folder uid |
| `folder_name` | `str` | Yes |  | The new folder name |
| `folders` | `Vec<KeeperFolder>` | No | None | List of folders to use in the search for parent folder |

**Example Usage**
```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::InMemoryKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let update_folder = secrets_manager.update_folder("<folder_uid>".to_string(),"dummy_updated_API_RUST".to_string(),Vec::new())?;
    println!("{}",(serde_json::to_string_pretty(&update_folder)?));
```

### Delete Folders

Removes a list of folders. Use the `force_deletion` flag to remove non-empty folders.

When using `force_deletion`, avoid sending parent with its children folder UIDs. Depending on the delete order, you may get an error—ex., if the parent force-deleted the child first. There's no guarantee that the list will always be processed in FIFO order.

Any folder UIDs missing from the vault or not shared with the KSM application will not result in an error.

> delete_folder(vec![“\<FOLDER_UID\>”.to_string()], false)

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `folder_uids` | `Vec<String>` | Yes |  | The folder UID list |
| `force_deletion` | `boolean` | No | false | Force deletion of non-empty folders |

Example Usage

```rust
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::FileKeyValueStorage,
        custom_error::KSMRError
    };
    // setup secrets manager
    let config_string = "your_base64_goes_here".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let folder_uids = vec!["folder1_uid".to_string(),"folder_2_uid".to_string()];
    secrets_manager.delete_folder(folder_uids, true)?;
``` 