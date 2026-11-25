//! Folder cipher tests (KSM-1063): reading and renaming subfolders under both the
//! AES-GCM and the AES-CBC key formats, driven through the real SDK code with a
//! mocked HTTP transport.

use keeper_secrets_manager_core::config_keys::ConfigKeys;
use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
use keeper_secrets_manager_core::crypto::{unpad_data, CryptoUtils};
use keeper_secrets_manager_core::custom_error::KSMRError;
use keeper_secrets_manager_core::dto::payload::CreateOptions;
use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
use keeper_secrets_manager_core::enums::KvStoreType;
use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};
use keeper_secrets_manager_core::utils::bytes_to_base64;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const ROOT_UID: &str = "root-shared-uid";
const GCM_UID: &str = "gcm-subfolder-uid";
const CBC_UID: &str = "cbc-subfolder-uid";

type FoldersResponse = Arc<Mutex<Value>>;
type Requests = Arc<Mutex<Vec<(String, Value)>>>;

fn test_storage(app_key: &[u8]) -> KvStoreType {
    let mut kv_store = KvStoreType::InMemory(InMemoryKeyValueStorage::new(None).unwrap());
    let private_key = CryptoUtils::generate_private_key_ecc().unwrap();
    let private_key_der = CryptoUtils::generate_private_key_der().unwrap();
    let public_key = CryptoUtils::public_key_ecc(&private_key);
    kv_store
        .set(ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string())
        .unwrap();
    kv_store
        .set(ConfigKeys::KeyAppKey, bytes_to_base64(app_key))
        .unwrap();
    kv_store
        .set(ConfigKeys::KeyServerPublicKeyId, "10".to_string())
        .unwrap();
    kv_store
        .set(
            ConfigKeys::KeyHostname,
            "fake.keepersecurity.com".to_string(),
        )
        .unwrap();
    kv_store
        .set(ConfigKeys::KeyPrivateKey, bytes_to_base64(&private_key_der))
        .unwrap();
    kv_store
        .set(ConfigKeys::KeyOwnerPublicKey, bytes_to_base64(&public_key))
        .unwrap();
    kv_store
}

/// A client whose transport answers `get_folders` with the current folder listing and
/// every other call with success. Each decrypted request is recorded as (endpoint, body).
fn mock_client(app_key: &[u8], folders: FoldersResponse) -> (SecretsManager, Requests) {
    let requests: Requests = Arc::new(Mutex::new(Vec::new()));
    let sink = requests.clone();
    let mut options = ClientOptions::new_client_options(test_storage(app_key));
    options.set_custom_post_function(
        move |url: String, key: TransmissionKey, payload: EncryptedPayload| {
            let plain = CryptoUtils::decrypt_aes(&payload.encrypted_payload, &key.key)?;
            let request: Value = serde_json::from_slice(&plain).unwrap_or(Value::Null);
            let endpoint = url.rsplit('/').next().unwrap_or("").to_string();
            let body = if endpoint == "get_folders" {
                folders.lock().unwrap().to_string()
            } else {
                json!({"status": "success"}).to_string()
            };
            sink.lock().unwrap().push((endpoint, request));
            Ok::<_, KSMRError>(KsmHttpResponse {
                status_code: 200,
                data: CryptoUtils::encrypt_aes_gcm(body.as_bytes(), &key.key, None)?,
                http_response: None,
            })
        },
    );
    (
        SecretsManager::new(options).expect("SecretsManager::new"),
        requests,
    )
}

fn name_json(name: &str) -> Vec<u8> {
    json!({ "name": name }).to_string().into_bytes()
}

fn root_folder(app_key: &[u8], root_key: &[u8]) -> Value {
    let wrapped = CryptoUtils::encrypt_aes_gcm(root_key, app_key, None).unwrap();
    let data = CryptoUtils::encrypt_aes_cbc(&name_json("Root"), root_key, None).unwrap();
    json!({
        "folderUid": ROOT_UID,
        "folderKey": bytes_to_base64(&wrapped),
        "data": CryptoUtils::bytes_to_url_safe_str(&data),
    })
}

fn gcm_subfolder(root_key: &[u8], sub_key: &[u8]) -> Value {
    let wrapped = CryptoUtils::encrypt_aes_gcm(sub_key, root_key, None).unwrap();
    let data = CryptoUtils::encrypt_aes_gcm(&name_json("Gcm Sub"), sub_key, None).unwrap();
    json!({
        "folderUid": GCM_UID,
        "parent": ROOT_UID,
        "folderKey": bytes_to_base64(&wrapped),
        "data": CryptoUtils::bytes_to_url_safe_str(&data),
    })
}

fn cbc_subfolder(root_key: &[u8], sub_key: &[u8]) -> Value {
    let wrapped = CryptoUtils::encrypt_aes_cbc(sub_key, root_key, None).unwrap();
    let data = CryptoUtils::encrypt_aes_cbc(&name_json("Cbc Sub"), sub_key, None).unwrap();
    json!({
        "folderUid": CBC_UID,
        "parent": ROOT_UID,
        "folderKey": bytes_to_base64(&wrapped),
        "data": CryptoUtils::bytes_to_url_safe_str(&data),
    })
}

fn listing(folders: Vec<Value>) -> FoldersResponse {
    Arc::new(Mutex::new(json!({
        "folders": folders,
        "records": [],
        "expiresOn": 0,
        "warnings": []
    })))
}

fn rename_data(requests: &Requests, uid: &str) -> Vec<u8> {
    let log = requests.lock().unwrap();
    let (_, request) = log
        .iter()
        .rev()
        .find(|(endpoint, body)| endpoint == "update_folder" && body["folderUid"] == uid)
        .expect("no update_folder request for the folder");
    CryptoUtils::url_safe_str_to_bytes(request["data"].as_str().unwrap()).unwrap()
}

/// AC2: a 60-byte GCM subfolder key and a 64-byte CBC subfolder key in one listing.
///
/// A pass proves both names decrypt, the keys unwrap to the original 32 bytes, and
/// `use_gcm` follows the key length. A failure on the GCM folder means the `== 60`
/// dispatch is wrong; a failure on the CBC folder means the CBC fallback is wrong.
#[test]
fn get_folders_reads_gcm_and_cbc_subfolders() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let root_key = CryptoUtils::generate_encryption_key_bytes();
    let gcm_key = CryptoUtils::generate_encryption_key_bytes();
    let cbc_key = CryptoUtils::generate_encryption_key_bytes();
    let (mut sm, _) = mock_client(
        &app_key,
        listing(vec![
            root_folder(&app_key, &root_key),
            gcm_subfolder(&root_key, &gcm_key),
            cbc_subfolder(&root_key, &cbc_key),
        ]),
    );

    let folders = sm.get_folders().expect("get_folders");
    let by_uid = |uid: &str| folders.iter().find(|f| f.folder_uid == uid).unwrap();

    assert_eq!(folders.len(), 3);
    assert_eq!(by_uid(GCM_UID).name, "Gcm Sub");
    assert!(by_uid(GCM_UID).use_gcm);
    assert_eq!(by_uid(GCM_UID).folder_key, gcm_key);
    assert_eq!(by_uid(CBC_UID).name, "Cbc Sub");
    assert!(!by_uid(CBC_UID).use_gcm);
    assert_eq!(by_uid(CBC_UID).folder_key, cbc_key);
}

/// AC3: renaming a subfolder writes the cipher the folder already uses.
///
/// A pass proves the GCM folder's new name decrypts with AES-GCM and not with AES-CBC,
/// and the CBC folder's new name decrypts with AES-CBC and not with AES-GCM. A failure
/// means `prepare_update_payload` ignores `use_gcm`, which would write a name that
/// older readers cannot open (CBC folder) or downgrade a GCM folder.
#[test]
fn update_folder_keeps_the_folder_cipher() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let root_key = CryptoUtils::generate_encryption_key_bytes();
    let gcm_key = CryptoUtils::generate_encryption_key_bytes();
    let cbc_key = CryptoUtils::generate_encryption_key_bytes();
    let (mut sm, requests) = mock_client(
        &app_key,
        listing(vec![
            root_folder(&app_key, &root_key),
            gcm_subfolder(&root_key, &gcm_key),
            cbc_subfolder(&root_key, &cbc_key),
        ]),
    );
    let folders = sm.get_folders().expect("get_folders");

    sm.update_folder(GCM_UID, "Gcm Renamed".to_string(), folders.clone())
        .expect("rename gcm folder");
    sm.update_folder(CBC_UID, "Cbc Renamed".to_string(), folders)
        .expect("rename cbc folder");

    let gcm_data = rename_data(&requests, GCM_UID);
    let plain = CryptoUtils::decrypt_aes(&gcm_data, &gcm_key).expect("GCM folder must stay GCM");
    assert_eq!(
        serde_json::from_slice::<Value>(&plain).unwrap()["name"],
        "Gcm Renamed"
    );
    assert!(CryptoUtils::decrypt_aes_cbc(&gcm_data, &gcm_key).is_err());

    let cbc_data = rename_data(&requests, CBC_UID);
    let plain = unpad_data(
        &CryptoUtils::decrypt_aes_cbc(&cbc_data, &cbc_key).expect("CBC folder must stay CBC"),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&plain).unwrap()["name"],
        "Cbc Renamed"
    );
    assert!(CryptoUtils::decrypt_aes(&cbc_data, &cbc_key).is_err());
}

/// Create, read, rename under a classic shared folder, with the server replaying what
/// create_folder sent.
///
/// A pass proves a folder the SDK creates reads back as a CBC folder with its name and
/// stays CBC after a rename. A failure means create, read, and rename disagree on the
/// cipher, which is the exact gap KSM-1063 closes.
#[test]
fn create_read_rename_round_trip_stays_cbc() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let root_key = CryptoUtils::generate_encryption_key_bytes();
    let response = listing(vec![root_folder(&app_key, &root_key)]);
    let (mut sm, requests) = mock_client(&app_key, response.clone());
    let root = sm
        .get_folders()
        .expect("get_folders")
        .into_iter()
        .find(|f| f.folder_uid == ROOT_UID)
        .unwrap();

    let new_uid = sm
        .create_folder(
            CreateOptions::new(ROOT_UID.to_string(), None),
            "Created Sub".to_string(),
            vec![root],
        )
        .expect("create_folder");

    let created = {
        let log = requests.lock().unwrap();
        log.iter()
            .find(|(endpoint, _)| endpoint == "create_folder")
            .unwrap()
            .1
            .clone()
    };
    let wrapped_key =
        CryptoUtils::url_safe_str_to_bytes(created["sharedFolderKey"].as_str().unwrap()).unwrap();
    *response.lock().unwrap() = json!({
        "folders": [
            root_folder(&app_key, &root_key),
            {
                "folderUid": new_uid,
                "parent": ROOT_UID,
                "folderKey": bytes_to_base64(&wrapped_key),
                "data": created["data"],
            }
        ],
        "records": [],
        "expiresOn": 0,
        "warnings": []
    });

    let folders = sm.get_folders().expect("get_folders after create");
    let read_back = folders.iter().find(|f| f.folder_uid == new_uid).unwrap();
    assert_eq!(read_back.name, "Created Sub");
    assert!(!read_back.use_gcm);
    let folder_key = read_back.folder_key.clone();

    sm.update_folder(&new_uid, "Created Renamed".to_string(), folders)
        .expect("rename");
    let data = rename_data(&requests, &new_uid);
    let plain = unpad_data(&CryptoUtils::decrypt_aes_cbc(&data, &folder_key).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&plain).unwrap()["name"],
        "Created Renamed"
    );
}
