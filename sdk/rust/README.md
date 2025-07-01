## Secrets Manager -  Rust
This SDK helps you retrieve and manage your secrets from keeper.

### How to get it to work locally
To get it to work locally we need to have
* Rust installed
* cargo installed
* rustc installed

## Code usage samples

* this is for get_secrets functionality

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};


    fn main()-> Result<(), KSMRError>{

        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let mut secrets_manager = SecretsManager::new(client_options)?;

        let secrets = secrets_manager.get_secrets(Vec::new())?;

        for secret in secrets {
            secret.print();
            println!("---");
        }
        Ok(())
    }
```

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::InMemoryKeyValueStorage};


    fn main()-> Result<(), KSMRError>{

        let im_base64 = "my_base_64_string".to_string();
        let config = InMemoryKeyValueStorage::new_config_storage(Some(im_base64))?;
        let client_options = ClientOptions::new_client_options(config);
        let mut secrets_manager = SecretsManager::new(client_options)?;
        let secrets_manager_response = secrets_manager.get_secrets_full_response(Vec::new())?;
        let records = secrets_manager_response.records;

        println!("{}",records.len());

        if !records.is_empty(){
            println!("Records returned from KSM:");
            for record in  records{
                println!("UID: {}", record.uid);
            }
        }

        if secrets_manager_response.warnings.is_some(){
            let warnings = secrets_manager_response.warnings.unwrap();
            println!("{}", warnings);
        }
        
        Ok(())
    }
```


```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::InMemoryKeyValueStorage};


    fn main()-> Result<(), KSMRError>{

        let im_base64 = "my_base_64_string".to_string();
        let config = InMemoryKeyValueStorage::new_config_storage(Some(im_base64))?;
        let client_options = ClientOptions::new_client_options(config);
        let mut secrets_manager = SecretsManager::new(client_options)?;
        let secrets_manager_response = secrets_manager.get_secrets_full_response(Vec::new())?;
        let records = secrets_manager_response.records;

        println!("{}",records.len());

        if !records.is_empty(){
            println!("Records returned from KSM:");
            for record in  records{
                println!("UID: {}", record.uid);
            }
        }

        if secrets_manager_response.warnings.is_some(){
            let warnings = secrets_manager_response.warnings.unwrap();
            println!("{}", warnings);
        }
        
        Ok(())
    }
```


* Using Download file feature

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};
    fn main()-> Result<(), KSMRError>{

        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let mut secrets_manager = SecretsManager::new(client_options)?;

        let records_filter = Vec::new(); // add record filters of needed based on UID
        let secrets = secrets_manager.get_secrets(records_filter)?;

        for secret in secrets {
            secret.download_file("file_name", "file_name_to_be_created_along_with_path")?; //secret.download("dummyy.txt","./dummy2.txt"); -> something like this
            println!("---");
        }
        Ok(())
    }

```

* using searching standard field in a record feature

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage,enums::StandardFieldTypeEnum};

    fn main()-> Result<(), KSMRError>{
        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let mut secrets_manager = SecretsManager::new(client_options)?;

        let records_filter = Vec::new(); // add record filters of needed based on UID
        let secrets = secrets_manager.get_secrets(records_filter)?;

        for secret in secrets {
            let standard_field = secret.get_standard_field_value(StandardFieldTypeEnum::CARDREF.get_type(),false)?;

            let standard_field_2 = secret.get_standard_field_value("Pin Code",false)?;
            println!("name : {}", standard_field);
            println!("label : {}", standard_field_2);
            println!("---");
        }
        Ok(())
    }

```

* using searching Custom field in a record feature

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

    fn main()-> Result<(), KSMRError>{
        let token = "<Token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let mut secrets_manager = SecretsManager::new(client_options)?;

        let mut records_filter = Vec::new(); // add record filters of needed based on UID
        records_filter.push("<Record UID>".to_string());
        let secrets = secrets_manager.get_secrets(records_filter)?;

        for secret in secrets {
            let standard_field = secret.get_custom_field_value("<Field1>>",false)?;

            let standard_field_2 = secret.get_custom_field_value("<Field2>",true)?;
            println!("multiple : {}", standard_field);
            println!("single : {}", standard_field_2);
            println!("---");
        }
        Ok(())
    }
```

* using generate password feature

```rust
    use keeper_secrets_manager_core::{custom_error::KSMRError, utils::{generate_password_with_options, PasswordOptions}};

    fn main()-> Result<(), KSMRError>{
        let password_options = PasswordOptions::new();
        let charset = "~".to_string();
        let password_options = password_options.length(34).digits(5).lowercase(5).uppercase(7).special_characters(5).special_characterset(charset);

        let password = generate_password_with_options(password_options)?;
        println!("Password: {}", password);
        Ok(())
    }

```

* using get folders feature 

```rust
    use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

    fn main()-> Result<(), KSMRError>{
        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let secrets_manager = SecretsManager::new(client_options)?;

        let secrets_folders = secrets_manager.get_folders()?;
        println!("FOLDERS:--------------------------------------------------------------------------------------------------------------------------------------");
        for secret in secrets_folders {
            let secret_string =  secret.to_serialized_string();
            println!("{}", secret_string);
            println!("---");
        }
        Ok(())
    }

```

* using update folder feature

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

    fn main()-> Result<(), KSMRError>{
        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        println!("Update Records ---------------------------------------------------------------------------------------------------------------------------------");
            let mut secrets_manager_4 = SecretsManager::new(client_options)?;
            let update_folder = secrets_manager_4.update_folder("<folder_uid>".to_string(),"dummy_updated_API_RUST".to_string(),Vec::new())?;
            println!("{}",(serde_json::to_string_pretty(&update_folder)?));
        Ok(())
    }
```

* using delete folder feature

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

    fn main()-> Result<(), KSMRError>{
        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        let mut secrets_manager = SecretsManager::new(client_options)?;
       println!("Delete Records ---------------------------------------------------------------------------------------------------------------------------------");
        let delete_response = secrets_manager.delete_folder(vec!["<folder_uid>".to_string()],true)?;
        println!("{}",(serde_json::to_string_pretty(&delete_response)?));


        Ok(())
    }
```

* using delete secret functionality

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

    fn main()-> Result<(), KSMRError>{
        let token = "<Your One time token>".to_string();
        let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

        let client_options = ClientOptions::new_client_options(token, file_name); 

        println!("Delete Secrets --------------------------------------------------------------");
        let mut secrets_manager_3 = SecretsManager::new(client_options)?;
        let uids  = vec!["<secret uid>".to_string()];
        let secrets_records_3 = secrets_manager_3.delete_secret(uids.clone())?;


        Ok(())
    }

```

* using update record standard and custom fields

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, enums::StandardFieldTypeEnum, storage::FileKeyValueStorage};
use std::{collections::HashMap, fs::File, io::Write};
use serde_json;

fn main()-> Result<(), KSMRError>{
    let token = "<token>".to_string();
    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;
    
    let client_options = ClientOptions::new_client_options(token, file_name); 
    
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let mut uids = Vec::new();
    uids.push("<secret uid>".to_string());
    // get_secrets
    let secrets_records = secrets_manager.get_secrets(uids.clone())?;
    
    for mut secret in secrets_records {
        
        let mut record_final_dict = HashMap::new();
        
        let standard_field = secret.get_standard_field_value(StandardFieldTypeEnum::EMAIL.get_type(),false)?;
        
        record_final_dict.insert("before_Standard_update", secret.record_dict.clone());
        
        let _standard_field_set = secret.set_standard_field_value_mut(StandardFieldTypeEnum::EMAIL.get_type(), "vfgatyth_changed_email_standard@email.com".into())?;

        record_final_dict.insert("after_Standard_update", secret.record_dict.clone());

        let custom_field = secret.get_custom_field_value(StandardFieldTypeEnum::EMAIL.get_type(),false)?;
        
        record_final_dict.insert("before_custom_update", secret.record_dict.clone());
        
        let _standard_field_set = secret.set_custom_field_value_mut(StandardFieldTypeEnum::EMAIL.get_type(), "vfgatyth_changed_email_custom@email.com".into())?;

        record_final_dict.insert("after_custom_update", secret.record_dict.clone());
        //save to file to check if updated as record object is very big
        let created_String: String  = serde_json::to_string(&record_final_dict).map_err(|err|KSMRError::SerializationError(err.to_string()))?;
        let mut file = File::create("setting_fields.json").unwrap();
        file.write_all(created_String.as_bytes()).unwrap();
    }
    Ok(())
}
```

* using getting totp code

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, enums::StandardFieldTypeEnum, storage::FileKeyValueStorage};
use std::{collections::HashMap, fs::File, io::Write};
use serde_json;

fn main()-> Result<(), KSMRError>{
    let token = "<token>".to_string();
    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;
    
    let client_options = ClientOptions::new_client_options(token, file_name); 
    
    let mut secrets_manager = SecretsManager::new(client_options)?;

    let mut uids = Vec::new();
    uids.push("<secret uid>".to_string());
    // get_secrets
    let secrets_records = secrets_manager.get_secrets(uids.clone())?;
    
    for mut secret in secrets_records {
        let value = secret.get_standard_field_value(StandardFieldTypeEnum::ONETIMECODE.get_type(),false)?;
        let url = utils::get_otp_url_from_value_obj(value)?;
        let totp_code = utils::get_totp_code(&url)?;
        println!("{}", totp_code.get_code());
    }
    Ok(())
}
```




* How to upload file

```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

fn main()-> Result<(), KSMRError>{
    let token = "<Your One time token>".to_string();
    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

    let client_options = ClientOptions::new_client_options(token, file_name); 

    println!("Delete Secrets --------------------------------------------------------------");
    let mut secrets_manager_3 = SecretsManager::new(client_options)?;
    let uids  = vec!["<secret uid>".to_string()];
    let secrets_records_3 = secrets_manager_3.get_secrets(uids.clone())?;
    for secret in secret_records3{
            let keeper_file = KeeperFileUpload::get_file_for_upload(
        "./dummy2222.txt", Some("test1_file.txt"), None,None
        )?;
        let upload_status = secrets_manager.upload_file(secret, keeper_file)?;
        println!("upload status: {}", upload_status);
    }
    Ok(())
}
```

* How to create a record

```rust
fn test_record_create_normal() -> Result<(), KSMRError>{
    use keeper_secrets_manager_core::{
        core::{ClientOptions, SecretsManager},
        storage::FileKeyValueStorage,
        dto::{dtos::RecordCreate, field_structs::RecordField}
    };
    use serde_json::{self, json, Number, Value};

    // setup secrets manager
    let token = "<token_here>".to_string();
    let config = FileKeyValueStorage::new_config_storage("test_demo.json".to_string())?;
    let client_options = ClientOptions::new_client_options(token, config);
    let mut secrets_manager = SecretsManager::new(client_options)?;

    // This is how we create a Record
    let mut created_record =  RecordCreate::new("login".to_string(), "Login Record RUST_LOG_TEST".to_string(), Some("Dummy Notes".to_string()));
    
    // This is how we create a single field 
    let password_field = RecordField::new_record_field_with_options("password", Value::String(utils::generate_password()?), Some("Random password label".to_string()), false, true);

    // This is one of the ways to create a value object from JSON String
    let security_question_value = Value::from_str("{\"question\": \"What is the question?\", \"answer\": \"This is the answer!\"}")?;
    
    //This is one way to create all fields directly in a vector
    let fields = vec![
        RecordField::new_record_field("login",  Value::String("login@email.com".to_string()), Some("My Custom Login lbl".to_string())),

        RecordField::new_record_field("login",  Value::String("login@email.com".to_string()), Some("My Label".to_string())),

        password_field,
        
        RecordField::new_record_field("securityQuestion", security_question_value , Some("My Label".to_string())),

        RecordField::new_record_field("multiline", Value::String("This\nIs a multiline\nnote".to_string()) , Some("My Multiline lbl".to_string())),

        RecordField::new_record_field("secret", Value::String("SecretText".to_string()) , Some("My Hidden Field lbl".to_string())),

        RecordField::new_record_field("pinCode", Value::String("1234567890".to_string()) , Some("My Pin Code Field Lbl".to_string())),

        RecordField::new_record_field("addressRef", Value::String("some_UID".to_string()) , Some("My Address Reference".to_string())),

        RecordField::new_record_field("phone", json!({"region": "US", "number": "510-444-3333"}) , Some("My Phone Number".to_string())),

        RecordField::new_record_field("date", Value::Number(Number::from(1641934793000i64)) , Some("My date".to_string())),

        RecordField::new_record_field("date", Value::String("September eleventh two thousand and eleven".to_string()) , Some("Bad day in history of humanity".to_string())),

        RecordField::new_record_field("name", json!({"first": "Lincoln", "last": "Adams"}) , Some("His Name".to_string())),
        ];

    // Here we are adding fields object to standard fields 
    created_record.fields = Some(fields);
    
    created_record.custom = Some(
        vec![
            RecordField::new_record_field("phone", json!({"region": "US", "number": "510-222-5555", "ext": "99887", "type": "Mobile"}) , Some("My Custom Phone Lbl".to_string())),
        ]
    );
   
    // Make the API call
    let _ = secrets_manager.create_secret("Shared Folder UID".to_string(), created_record)?;

    Ok(())
}
```

* How to create a record

```rust
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    custom_error::KSMRError,
    dto::{
        dtos::{RecordCreate},
        field_structs::{self},
    },
    enums::{DefaultRecordType},
    storage::FileKeyValueStorage,
    utils::{self},
};
use log::error;
use tracing::{info};

fn main()-> Result<(), KSMRError>{
    let token = "<Your One time token>".to_string();
    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;

    let client_options = ClientOptions::new_client_options(token, file_name); 

    println!("Create Secret\n--------------------------------------------------------------");
    let mut secrets_manager_3 = SecretsManager::new(client_options)?;
    let mut new_record = RecordCreate::new(
        DefaultRecordType::Login.get_type().to_string(),
        "sample create record".to_string(),
        None,
    );
    let login_field = field_structs::Login::new(
        "sample_email@metron.com".to_string(),
        None,
        Some(false),
        Some(false),
    );
    new_record.append_standard_fields(login_field);
    let password_field = field_structs::Password::new(
        "Dummy_Password#123".to_string(),
        None,
        Some(true),
        Some(false),
        Some(true),
        None,
    )?;
    new_record.append_standard_fields(password_field);
    let created_record: Result<String, KSMRError> =
        secrets_manager.create_secret("<folder_uid>".to_string(), new_record);
    match created_record {
        Ok(data) => {
            info!("created_record uid: {}", data);
            data
        }
        Err(err) => {
            error!("Error creating record: {}", err);
            return Err(err);
        }
    };

    Ok(())
}
```

Using Keeper Notation
```rust
use keeper_secrets_manager_core::{core::{ClientOptions, SecretsManager}, custom_error::KSMRError, storage::FileKeyValueStorage};

fn main()-> Result<(), KSMRError>{
    let token = "<Token>".to_string();

    let file_name = FileKeyValueStorage::new_config_storage("test.json".to_string())?;
    
    let client_options = ClientOptions::new_client_options(token, file_name); 
    
    let mut secrets_manager = SecretsManager::new(client_options)?;  
    
    let secrets_notation_result2 = secrets_manager.get_notation("<record_uid>/field/email[2]".to_string());
    
    match secrets_notation_result2 {
        Ok(data) => {
            info!("Secrets data from notation: {}", data);    
        },
        Err(err) => {
            error!("Error getting secret: {}", err);
            return Err(err);
        }
    };
    Ok(())
}
```


Using Caching functionality
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

Using In Memory Storage for Creating a Folder
```rust
use keeper_secrets_manager_core::{core::{SecretsManager, ClientOptions}, enums::InMemoryKeyValueStorage, custom_error::KSMRError};

fn main() -> Result<(), KSMRError> {
    let base_64_string = "<YOUR_BASE64_STRING>".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(base_64_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let secrets_manager = SecretsManager::new(client_options)?;

    //Create Folder
    let parent_folder_uid: String = "<PARENT_FOLDER_UID>".to_string();
    let sub_folder_uid: Option<String> = Option::Some("<SUB_FOLDER_UID>".to_string());
    let create_options: CreateOptions = CreateOptions::new(parent_folder_uid, sub_folder_uid);
    let new_folder_name: String = "New Folder".to_string();
    println!("Creating folder: {new_folder_name}");
    let created_folder_name = new_folder_name.clone();
    let result = secrets_manager.create_folder(create_options, new_folder_name, Vec::new())?;
    println!("{result}");

    Ok(())
}
```

Using In Memory Storage for retrieving all folders
```rust
use keeper_secrets_manager_core::{core::{SecretsManager, ClientOptions}, enums::InMemoryKeyValueStorage, custom_error::KSMRError};

fn main() -> Result<(), KSMRError> {
    let base_64_string = "<YOUR_BASE64_STRING>".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(base_64_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let secrets_manager = SecretsManager::new(client_options)?;

    //Get all Folders
    let result_folders = secrets_manager.get_folders();
    let folders: Vec<KeeperFolder> = result_folders.unwrap();
    for folder in folders{
        let folder_uid = folder.folder_uid;
        let name:String = folder.name;
        let parent_uid = folder.parent_uid;
        println!("\nfolder_uid: {folder_uid}\nfolder_name: {name}\nparent_uid: {parent_uid}");
    }

    Ok(())
}
```

Using In Memory Storage for update folder
```rust
use keeper_secrets_manager_core::{core::{SecretsManager, ClientOptions}, enums::InMemoryKeyValueStorage, custom_error::KSMRError};

fn main() -> Result<(), KSMRError> {
    let base_64_string = "<YOUR_BASE64_STRING>".to_string();
    let config = InMemoryKeyValueStorage::new_config_storage(Some(base_64_string))?;
    let client_options = ClientOptions::new_client_options(config);
    let secrets_manager = SecretsManager::new(client_options)?;

    //Update folder name
    secrets_manager.update_folder("<Folder_uid>".to_string(), "My folder".to_string(), Vec::new())?;

    Ok(())
}
```
