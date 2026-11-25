//! NSF marking (KSM-1055): a `get_secret` response marks which folders and records
//! belong to an NSF (Keeper Drive) folder.

use keeper_secrets_manager_core::config_keys::ConfigKeys;
use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
use keeper_secrets_manager_core::crypto::CryptoUtils;
use keeper_secrets_manager_core::custom_error::KSMRError;
use keeper_secrets_manager_core::dto::dtos::KeeperFolder;
use keeper_secrets_manager_core::dto::payload::{CreateOptions, FolderOptions};
use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
use keeper_secrets_manager_core::enums::KvStoreType;
use keeper_secrets_manager_core::storage::{InMemoryKeyValueStorage, KeyValueStorage};
use keeper_secrets_manager_core::utils::bytes_to_base64;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

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

type Requests = Arc<Mutex<Vec<(String, Value)>>>;

/// A client that answers `get_folders` and `get_secret` with different bodies and
/// records each decrypted request as (endpoint, body).
fn routing_client(
    app_key: &[u8],
    folders_body: Value,
    secret_body: Value,
) -> (SecretsManager, Requests) {
    routing_client_with_delete(app_key, folders_body, secret_body, Value::Null)
}

fn routing_client_with_delete(
    app_key: &[u8],
    folders_body: Value,
    secret_body: Value,
    delete_body: Value,
) -> (SecretsManager, Requests) {
    let requests: Requests = Arc::new(Mutex::new(Vec::new()));
    let sink = requests.clone();
    let mut options = ClientOptions::new_client_options(test_storage(app_key));
    options.set_custom_post_function(
        move |url: String, key: TransmissionKey, payload: EncryptedPayload| {
            let plain = CryptoUtils::decrypt_aes(&payload.encrypted_payload, &key.key)?;
            let endpoint = url.rsplit('/').next().unwrap_or("").to_string();
            let body = match endpoint.as_str() {
                "get_folders" => folders_body.to_string(),
                "delete_folder" => delete_body.to_string(),
                _ => secret_body.to_string(),
            };
            sink.lock().unwrap().push((
                endpoint,
                serde_json::from_slice(&plain).unwrap_or(Value::Null),
            ));
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

/// A top-level classic folder as `get_folders` lists it.
fn classic_root(uid: &str, app_key: &[u8]) -> Value {
    let folder_key = CryptoUtils::generate_encryption_key_bytes();
    let wrapped_key = CryptoUtils::encrypt_aes_gcm(&folder_key, app_key, None).unwrap();
    let name = json!({"name": "Classic"}).to_string().into_bytes();
    let data = CryptoUtils::encrypt_aes_cbc(&name, &folder_key, None).unwrap();
    json!({
        "folderUid": uid,
        "folderKey": bytes_to_base64(&wrapped_key),
        "data": CryptoUtils::bytes_to_url_safe_str(&data),
    })
}

fn listing(folders: Vec<Value>) -> Value {
    json!({"folders": folders, "records": [], "expiresOn": 0, "warnings": []})
}

fn count(requests: &Requests, endpoint: &str) -> usize {
    requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(e, _)| e == endpoint)
        .count()
}

/// `include_nsf` adds the NSF folders of the application to the `get_folders` result.
///
/// Off, the call sends no `get_secret` and returns only the classic folder. On, it sends
/// one `get_secret` request with no filter and adds the NSF folder as a top-level
/// AES-GCM folder with its key, its name, and `is_drive` set. A pass proves a caller can
/// find an NSF folder and its key without reading every record. A failure means an NSF
/// folder is invisible to `get_folders_with_options`, so a write to it finds no key.
#[test]
fn include_nsf_adds_nsf_folders_with_one_unfiltered_request() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let (nsf_entry, nsf_key) = folder_entry("nsf-folder", &app_key, true, vec![]);
    // get_secret also lists each classic shared folder, which must not be added again.
    let (classic_entry, _) = folder_entry("classic-folder", &app_key, false, vec![]);
    let (mut sm, requests) = routing_client(
        &app_key,
        listing(vec![classic_root("classic-folder", &app_key)]),
        listing(vec![classic_entry, nsf_entry]),
    );

    let default = sm.get_folders().expect("get_folders");
    assert_eq!(default.len(), 1);
    assert!(!default[0].is_drive);
    assert_eq!(count(&requests, "get_secret"), 0);

    let folders = sm
        .get_folders_with_options(FolderOptions::default().include_nsf(true))
        .expect("include_nsf");

    assert_eq!(folders.len(), 2);
    let nsf = folders
        .iter()
        .find(|f| f.folder_uid == "nsf-folder")
        .unwrap();
    assert!(nsf.is_drive);
    assert!(nsf.use_gcm);
    assert_eq!(nsf.parent_uid, "");
    assert_eq!(nsf.name, "Drive Folder");
    assert_eq!(nsf.folder_key, nsf_key);
    let classic = folders
        .iter()
        .find(|f| f.folder_uid == "classic-folder")
        .unwrap();
    assert!(!classic.is_drive);

    assert_eq!(count(&requests, "get_secret"), 1);
    let log = requests.lock().unwrap();
    let (_, request) = log.iter().find(|(e, _)| e == "get_secret").unwrap();
    assert!(request["requestedRecords"].is_null());
    assert!(request["requestedFolders"].is_null());
}

/// A folder that both `get_folders` and the NSF listing return appears once, as the NSF
/// copy, because only that copy has `is_drive`.
///
/// A pass proves the merge keeps one entry per UID, keeps the other folders in place, and
/// appends the NSF copy. A failure means a duplicate UID, or an NSF folder reported as
/// classic, so a caller can pick the wrong write path.
#[test]
fn include_nsf_replaces_a_folder_that_both_calls_list() {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let (nsf_entry, _) = folder_entry("shared-uid", &app_key, true, vec![]);
    let (mut sm, _) = routing_client(
        &app_key,
        listing(vec![
            classic_root("shared-uid", &app_key),
            classic_root("other-uid", &app_key),
        ]),
        listing(vec![nsf_entry]),
    );

    let folders = sm
        .get_folders_with_options(FolderOptions::default().include_nsf(true))
        .expect("include_nsf");

    let uids: Vec<&str> = folders.iter().map(|f| f.folder_uid.as_str()).collect();
    assert_eq!(uids, vec!["other-uid", "shared-uid"]);
    assert!(!folders[0].is_drive);
    assert!(folders[1].is_drive);
    assert_eq!(folders[1].name, "Drive Folder");
}

const CREATE_REFUSED: &str =
    "Unable to create folder - the SDK cannot create a folder in an NSF (Keeper Drive) folder.";
const UPDATE_REFUSED: &str =
    "Unable to update folder - the SDK cannot update an NSF (Keeper Drive) folder.";

fn keeper_folder(uid: &str, parent: &str, is_drive: bool) -> KeeperFolder {
    KeeperFolder {
        folder_key: CryptoUtils::generate_encryption_key_bytes(),
        folder_uid: uid.to_string(),
        parent_uid: parent.to_string(),
        name: "Folder".to_string(),
        use_gcm: is_drive,
        is_drive,
    }
}

fn write_client() -> (SecretsManager, Requests) {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    routing_client(&app_key, listing(vec![]), listing(vec![]))
}

fn assert_refused(result: Result<String, KSMRError>, expected: &str) {
    match result {
        Err(KSMRError::RecordDataError(message)) => assert_eq!(message, expected),
        other => panic!("expected the NSF refusal, got {:?}", other),
    }
}

/// `create_folder` refuses an NSF folder before it sends anything.
///
/// A folder that a client creates in an NSF folder is not shared to the application, so
/// the SDK refuses it. The check reads the folder list, so it covers an NSF shared folder
/// and an NSF target subfolder under a classic shared folder. A classic create still sends
/// its request. A pass proves the exact error and zero requests for both NSF shapes. A
/// failure means a create request reaches the server for an NSF folder.
#[test]
fn create_folder_refuses_an_nsf_folder_and_sends_nothing() {
    let (mut sm, requests) = write_client();

    let nsf_shared = vec![keeper_folder("nsf", "", true)];
    assert_refused(
        sm.create_folder(
            CreateOptions::new("nsf".to_string(), None),
            "New".to_string(),
            nsf_shared,
        ),
        CREATE_REFUSED,
    );

    let nsf_target = vec![
        keeper_folder("classic", "", false),
        keeper_folder("nsf-sub", "classic", true),
    ];
    assert_refused(
        sm.create_folder(
            CreateOptions::new("classic".to_string(), Some("nsf-sub".to_string())),
            "New".to_string(),
            nsf_target,
        ),
        CREATE_REFUSED,
    );
    assert!(
        requests.lock().unwrap().is_empty(),
        "no request may be sent"
    );

    sm.create_folder(
        CreateOptions::new("classic".to_string(), None),
        "New".to_string(),
        vec![
            keeper_folder("other-nsf", "", true),
            keeper_folder("classic", "", false),
        ],
    )
    .expect("a classic create still works next to an unrelated NSF folder");
    assert_eq!(count(&requests, "create_folder"), 1);
}

/// `update_folder` refuses an NSF folder before it sends anything.
///
/// A rename request carries only the folder name, so it would erase other folder data. A
/// UID that the list holds both as an NSF folder and as a classic entry is still refused.
/// A pass proves the exact error and zero requests for each case, and that a classic
/// subfolder rename still sends. A failure means a rename request reaches an NSF folder.
#[test]
fn update_folder_refuses_an_nsf_folder_and_sends_nothing() {
    let (mut sm, requests) = write_client();

    assert_refused(
        sm.update_folder(
            "nsf",
            "Renamed".to_string(),
            vec![keeper_folder("nsf", "", true)],
        ),
        UPDATE_REFUSED,
    );
    assert_refused(
        sm.update_folder(
            "both",
            "Renamed".to_string(),
            vec![
                keeper_folder("both", "classic", false),
                keeper_folder("both", "", true),
            ],
        ),
        UPDATE_REFUSED,
    );
    assert!(
        requests.lock().unwrap().is_empty(),
        "no request may be sent"
    );

    sm.update_folder(
        "sub",
        "Renamed".to_string(),
        vec![
            keeper_folder("other-nsf", "", true),
            keeper_folder("sub", "classic", false),
        ],
    )
    .expect("a classic rename still works next to an unrelated NSF folder");
    assert_eq!(count(&requests, "update_folder"), 1);
}

fn delete_item(uid: &str, code: &str) -> Value {
    json!({"folderUid": uid, "responseCode": code, "errorMessage": ""})
}

/// A `get_folders` response with a shared folder (no parent) and a subfolder of it.
/// The entries hold no keys: the delete check reads only the folder UID and the parent.
fn parent_listing() -> Value {
    listing(vec![
        json!({"folderUid": "shared-uid"}),
        json!({"folderUid": "sub-uid", "parent": "shared-uid"}),
        // Two entries with different parents are ambiguous, so the SDK treats the UID as having none.
        json!({"folderUid": "dup-uid", "parent": "shared-uid"}),
        json!({"folderUid": "dup-uid", "parent": "other-uid"}),
    ])
}

fn delete_client(delete_items: Vec<Value>) -> (SecretsManager, Requests) {
    let app_key = CryptoUtils::generate_encryption_key_bytes();
    routing_client_with_delete(
        &app_key,
        parent_listing(),
        listing(vec![]),
        json!({ "folders": delete_items }),
    )
}

fn endpoints(requests: &Requests) -> Vec<String> {
    requests
        .lock()
        .unwrap()
        .iter()
        .map(|(endpoint, _)| endpoint.clone())
        .collect()
}

fn delete_requests(requests: &Requests) -> Vec<Value> {
    requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(endpoint, _)| endpoint == "delete_folder")
        .map(|(_, body)| body.clone())
        .collect()
}

fn text(item: &std::collections::HashMap<String, Value>, key: &str) -> String {
    item[key].as_str().unwrap().to_string()
}

/// `delete_folder` sends nothing for an NSF folder or a shared folder.
///
/// An NSF folder is not in the `get_folders` response, so it has no parent and no entry.
/// A KSM delete would move it and its subtree to the trash for every member, with no
/// restore. A shared folder is listed with no parent. A pass proves the SDK reads
/// `get_folders` first, sends no `delete_folder`, and returns `doesnt_exist` for the NSF
/// UID and `access_denied` for the shared UID, each with the UID in the message. A failure
/// means a delete request for one of them reaches the server.
#[test]
fn delete_folder_sends_nothing_for_nsf_and_shared_folders() {
    let (mut sm, requests) = delete_client(vec![]);

    let results = sm
        .delete_folder(
            vec![
                "nsf-uid".to_string(),
                "shared-uid".to_string(),
                "dup-uid".to_string(),
            ],
            false,
        )
        .expect("delete_folder");

    assert_eq!(endpoints(&requests), vec!["get_folders"]);
    assert_eq!(results.len(), 3);
    assert_eq!(text(&results[2], "folderUid"), "dup-uid");
    assert_eq!(text(&results[2], "responseCode"), "access_denied");
    assert_eq!(text(&results[0], "folderUid"), "nsf-uid");
    assert_eq!(text(&results[0], "responseCode"), "doesnt_exist");
    assert!(text(&results[0], "errorMessage").contains("[nsf-uid]"));
    assert_eq!(text(&results[1], "folderUid"), "shared-uid");
    assert_eq!(text(&results[1], "responseCode"), "access_denied");
    assert!(text(&results[1], "errorMessage").contains("[shared-uid]"));
}

/// `delete_folder` still deletes a subfolder of a shared folder, and sends only that UID.
///
/// A pass proves a subfolder passes the check with the force flag intact, and in a mixed
/// call the request holds only the subfolder while the refused UIDs get local items. A
/// failure means the check blocks a delete that must work (AC6), or lets a refused UID
/// through in a mixed call.
#[test]
fn delete_folder_sends_only_subfolders() {
    let (mut sm, requests) = delete_client(vec![delete_item("sub-uid", "ok")]);

    let results = sm
        .delete_folder(vec!["sub-uid".to_string()], true)
        .expect("delete subfolder");
    assert_eq!(endpoints(&requests), vec!["get_folders", "delete_folder"]);
    let sent = &delete_requests(&requests)[0];
    assert_eq!(sent["folderUids"], json!(["sub-uid"]));
    assert_eq!(sent["forceDeletion"], json!(true));
    assert_eq!(results.len(), 1);
    assert_eq!(text(&results[0], "responseCode"), "ok");

    let results = sm
        .delete_folder(
            vec![
                "sub-uid".to_string(),
                "nsf-uid".to_string(),
                "shared-uid".to_string(),
            ],
            false,
        )
        .expect("mixed delete");
    let sent = &delete_requests(&requests)[1];
    assert_eq!(sent["folderUids"], json!(["sub-uid"]));
    let mut codes: Vec<(String, String)> = results
        .iter()
        .map(|r| (text(r, "folderUid"), text(r, "responseCode")))
        .collect();
    codes.sort();
    assert_eq!(
        codes,
        vec![
            ("nsf-uid".to_string(), "doesnt_exist".to_string()),
            ("shared-uid".to_string(), "access_denied".to_string()),
            ("sub-uid".to_string(), "ok".to_string()),
        ]
    );
}

/// An empty UID list goes straight to the server, and a failed `get_folders` deletes nothing.
///
/// A pass proves an empty call sends no `get_folders`, and that an error from `get_folders`
/// comes back to the caller with no `delete_folder` request. A failure on the second part
/// means the SDK deletes without knowing which UIDs are safe.
#[test]
fn delete_folder_handles_empty_input_and_a_failed_get_folders() {
    let (mut sm, requests) = delete_client(vec![]);
    sm.delete_folder(vec![], false).expect("empty delete");
    assert_eq!(endpoints(&requests), vec!["delete_folder"]);

    let app_key = CryptoUtils::generate_encryption_key_bytes();
    let requests: Requests = Arc::new(Mutex::new(Vec::new()));
    let sink = requests.clone();
    let mut options = ClientOptions::new_client_options(test_storage(&app_key));
    options.set_custom_post_function(
        move |url: String, _key: TransmissionKey, _payload: EncryptedPayload| {
            sink.lock()
                .unwrap()
                .push((url.rsplit('/').next().unwrap().to_string(), Value::Null));
            Err::<KsmHttpResponse, _>(KSMRError::HTTPError("get_folders failed".to_string()))
        },
    );
    let mut sm = SecretsManager::new(options).expect("SecretsManager::new");

    let result = sm.delete_folder(vec!["sub-uid".to_string()], false);

    assert!(result.is_err());
    assert_eq!(endpoints(&requests), vec!["get_folders"]);
}
