//! NSF marking (KSM-1055): a `get_secret` response marks which folders and records
//! belong to an NSF (Keeper Drive) folder.

use keeper_secrets_manager_core::config_keys::ConfigKeys;
use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
use keeper_secrets_manager_core::crypto::CryptoUtils;
use keeper_secrets_manager_core::custom_error::KSMRError;
use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
use keeper_secrets_manager_core::enums::KvStoreType;
use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};
use keeper_secrets_manager_core::utils::bytes_to_base64;
use serde_json::{json, Value};

fn test_storage(app_key: &[u8]) -> KvStoreType {
    let mut kv_store = KvStoreType::InMemory(InMemoryKeyValueStorage::new(None).unwrap());
    let private_key = CryptoUtils::generate_private_key_ecc().unwrap();
    let private_key_der = CryptoUtils::generate_private_key_der().unwrap();
    let public_key = CryptoUtils::public_key_ecc(&private_key);
    for (key, value) in [
        (ConfigKeys::KeyClientId, "TEST_CLIENT_ID".to_string()),
        (ConfigKeys::KeyAppKey, bytes_to_base64(app_key)),
        (ConfigKeys::KeyServerPublicKeyId, "10".to_string()),
        (
            ConfigKeys::KeyHostname,
            "fake.keepersecurity.com".to_string(),
        ),
        (ConfigKeys::KeyPrivateKey, bytes_to_base64(&private_key_der)),
        (ConfigKeys::KeyOwnerPublicKey, bytes_to_base64(&public_key)),
    ] {
        kv_store.set(key, value).unwrap();
    }
    kv_store
}

fn client_returning(app_key: &[u8], response: Value) -> SecretsManager {
    let body = response.to_string().into_bytes();
    let mut options = ClientOptions::new_client_options(test_storage(app_key));
    options.set_custom_post_function(
        move |_url: String, key: TransmissionKey, _payload: EncryptedPayload| {
            Ok::<_, KSMRError>(KsmHttpResponse {
                status_code: 200,
                data: CryptoUtils::encrypt_aes_gcm(&body, &key.key, None)?,
                http_response: None,
            })
        },
    );
    SecretsManager::new(options).expect("SecretsManager::new")
}

/// A record entry as the server sends it: the record key wrapped under `wrap_key`.
fn record_entry(uid: &str, title: &str, wrap_key: &[u8]) -> Value {
    let record_key = CryptoUtils::generate_encryption_key_bytes();
    let wrapped_key = CryptoUtils::encrypt_aes_gcm(&record_key, wrap_key, None).unwrap();
    let data = json!({"title": title, "type": "login", "fields": []})
        .to_string()
        .into_bytes();
    let data = CryptoUtils::encrypt_aes_gcm(&data, &record_key, None).unwrap();
    json!({
        "recordUid": uid,
        "recordKey": bytes_to_base64(&wrapped_key),
        "data": bytes_to_base64(&data),
    })
}

/// A folder entry. Only an NSF folder entry has `data` (its encrypted name).
fn folder_entry(uid: &str, app_key: &[u8], nsf: bool, records: Vec<Value>) -> (Value, Vec<u8>) {
    let folder_key = CryptoUtils::generate_encryption_key_bytes();
    let wrapped_key = CryptoUtils::encrypt_aes_gcm(&folder_key, app_key, None).unwrap();
    let mut entry = json!({
        "folderUid": uid,
        "folderKey": bytes_to_base64(&wrapped_key),
        "records": records,
    });
    if nsf {
        let name = json!({"name": "Drive Folder"}).to_string().into_bytes();
        let data = CryptoUtils::encrypt_aes_gcm(&name, &folder_key, None).unwrap();
        entry["data"] = json!(bytes_to_base64(&data));
    }
    (entry, folder_key)
}

/// Folders and records are marked from the shape of the response.
///
/// The response holds a classic folder with one record, an NSF folder with one record,
/// one individual record, and an individual record that the NSF folder also lists.
/// A pass proves a folder is NSF only when its entry has `data`, a record is NSF only
/// when an NSF folder entry holds it, and the same UID is NSF in both lists. A failure
/// means the SDK reports an NSF record as classic, so a caller cannot tell that it
/// must use the NSF write path.
#[test]
fn full_response_marks_nsf_folders_and_records() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let (classic, classic_key) = folder_entry("classic-folder", &app_key, false, vec![]);
    let (mut nsf, nsf_key) = folder_entry("nsf-folder", &app_key, true, vec![]);
    let classic_record = record_entry("classic-record", "Classic", &classic_key);
    let nsf_record = record_entry("nsf-record", "Drive", &nsf_key);
    let mut classic = classic;
    classic["records"] = json!([classic_record]);
    nsf["records"] = json!([nsf_record, record_entry("both-record", "Both", &nsf_key)]);

    let mut sm = client_returning(
        &app_key,
        json!({
            "folders": [classic, nsf],
            "records": [
                record_entry("loose-record", "Loose", &app_key),
                record_entry("both-record", "Both", &app_key),
            ],
            "expiresOn": 0,
            "warnings": []
        }),
    );

    let response = sm.get_secrets_full_response(vec![]).expect("full response");

    let folder = |uid: &str| response.folders.iter().find(|f| f.uid == uid).unwrap();
    assert!(!folder("classic-folder").is_drive);
    assert!(folder("nsf-folder").is_drive);
    let folder_records = |uid: &str| folder(uid).records().expect("folder records");
    assert!(folder_records("nsf-folder").iter().all(|r| r.is_drive));
    assert!(folder_records("classic-folder").iter().all(|r| !r.is_drive));

    let is_drive = |uid: &str| -> Vec<bool> {
        response
            .records
            .iter()
            .filter(|r| r.uid == uid)
            .map(|r| r.is_drive)
            .collect()
    };
    assert_eq!(is_drive("classic-record"), vec![false]);
    assert_eq!(is_drive("loose-record"), vec![false]);
    assert_eq!(is_drive("nsf-record"), vec![true]);
    assert!(!is_drive("both-record").is_empty());
    assert!(
        is_drive("both-record").iter().all(|d| *d),
        "every copy of a record that an NSF folder holds is NSF"
    );
}

/// An NSF folder entry whose `data` is `data` (standard base64), under a fresh folder key.
fn nsf_entry_with_data(uid: &str, app_key: &[u8], data: &dyn Fn(&[u8]) -> Vec<u8>) -> Value {
    let folder_key = CryptoUtils::generate_encryption_key_bytes();
    let wrapped_key = CryptoUtils::encrypt_aes_gcm(&folder_key, app_key, None).unwrap();
    json!({
        "folderUid": uid,
        "folderKey": bytes_to_base64(&wrapped_key),
        "data": bytes_to_base64(&data(&folder_key)),
        "records": [],
    })
}

fn gcm_name(name: &str, folder_key: &[u8]) -> Vec<u8> {
    let json_name = json!({ "name": name }).to_string().into_bytes();
    CryptoUtils::encrypt_aes_gcm(&json_name, folder_key, None).unwrap()
}

/// An NSF folder entry in a get_secret response carries its name in `data`, AES-GCM
/// encrypted. The server can zero-pad that ciphertext to a column size, and the SDK
/// must still read the name. A name that does not decrypt leaves the folder NSF with an
/// empty name, because dropping it would hide a folder the caller can write to.
///
/// A pass proves the plain name, the zero-padded name, and the unreadable name each give
/// an NSF folder, with the name, the same name, and an empty name. A failure on the
/// padded folder means the SDK reads only an exact-length ciphertext.
#[test]
fn nsf_folder_name_is_read_from_data() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let plain = nsf_entry_with_data("plain", &app_key, &|k| gcm_name("Plain Name", k));
    let padded = nsf_entry_with_data("padded", &app_key, &|k| {
        let mut data = gcm_name("Padded Name", k);
        data.extend_from_slice(&[0u8; 37]);
        data
    });
    let unreadable = nsf_entry_with_data("unreadable", &app_key, &|_| vec![7u8; 48]);
    let mut sm = client_returning(
        &app_key,
        json!({
            "folders": [plain, padded, unreadable],
            "records": [],
            "expiresOn": 0,
            "warnings": []
        }),
    );

    let response = sm.get_secrets_full_response(vec![]).expect("full response");

    let folder = |uid: &str| response.folders.iter().find(|f| f.uid == uid).unwrap();
    assert_eq!(response.folders.len(), 3);
    assert!(response.folders.iter().all(|f| f.is_drive));
    assert_eq!(folder("plain").name(), "Plain Name");
    assert_eq!(folder("padded").name(), "Padded Name");
    assert_eq!(folder("unreadable").name(), "");
}
