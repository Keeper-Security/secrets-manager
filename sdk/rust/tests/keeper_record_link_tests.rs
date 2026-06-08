// Tests for KSM-997: typed KeeperRecordLink accessor layer (Java parity).
//
// These mirror the Java SDK's KeeperRecordLink semantics (SecretsManager.kt). Each test
// states what it proves; a failure localizes to the specific accessor.

use keeper_secrets_manager_core::crypto::CryptoUtils;
use keeper_secrets_manager_core::dto::dtos::{KeeperRecordLink, Record};
use keeper_secrets_manager_core::utils::bytes_to_base64;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Build a link whose `data` is base64 of the given plain JSON value.
fn link_with_plain_json(path: Option<&str>, data: Value) -> KeeperRecordLink {
    let json_str = data.to_string();
    KeeperRecordLink {
        record_uid: "RU_test".to_string(),
        data: Some(bytes_to_base64(json_str.as_bytes())),
        path: path.map(str::to_string),
    }
}

// (1) Boolean accessors read from the decoded plain JSON; absent keys default to false.
#[test]
fn link_boolean_accessors_read_plain_json() {
    let link = link_with_plain_json(
        None,
        json!({ "is_admin": true, "rotation": true, "connections": false }),
    );
    assert!(link.is_admin_user(), "is_admin true should read true");
    assert!(link.allows_rotation(), "rotation true should read true");
    assert!(
        !link.allows_connections(),
        "connections false should read false"
    );
    // Absent key must default to false (matches Java getBooleanValue).
    assert!(
        !link.allows_port_forwards(),
        "absent key must default to false"
    );
    assert!(
        !link.is_launch_credential(),
        "absent key must default to false"
    );
}

// (2) Integer version + decoded-data + readable-JSON heuristic.
#[test]
fn link_version_and_decoded_data() {
    let link = link_with_plain_json(None, json!({ "version": 3, "is_admin": false }));
    assert_eq!(link.get_link_data_version(), Some(3));
    let decoded = link.get_decoded_data().expect("decodes");
    assert!(decoded.starts_with('{'), "decoded data is the raw JSON");
    assert!(link.has_readable_data(), "JSON payload is readable");

    // Non-JSON (but valid base64) decoded content is not "readable".
    let raw = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(b"not json at all")),
        path: None,
    };
    assert!(
        !raw.has_readable_data(),
        "plain text without {{/[ is not readable JSON"
    );
    assert_eq!(
        raw.get_link_data_version(),
        None,
        "no version in non-JSON data"
    );
}

// (3) might_be_encrypted is gated to the known encrypted paths only.
#[test]
fn link_might_be_encrypted_by_path() {
    let ai = link_with_plain_json(Some("ai_settings"), json!({}));
    let jit = link_with_plain_json(Some("jit_settings"), json!({}));
    let other = link_with_plain_json(Some("something_else"), json!({}));
    let none = link_with_plain_json(None, json!({}));
    assert!(ai.might_be_encrypted());
    assert!(jit.might_be_encrypted());
    assert!(
        !other.might_be_encrypted(),
        "unknown path must not be assumed encrypted"
    );
    assert!(!none.might_be_encrypted());
}

// (4) AES-256-GCM decrypt round-trip with the record key; wrong/absent key -> None.
#[test]
fn link_get_decrypted_data_roundtrip() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let plaintext = r#"{"enabled":true,"ttl":3600}"#;
    let ciphertext =
        CryptoUtils::encrypt_aes_gcm(plaintext.as_bytes(), &key, None).expect("encrypts");
    let link = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(&ciphertext)),
        path: Some("jit_settings".into()),
    };

    assert_eq!(
        link.get_decrypted_data(Some(&key)).as_deref(),
        Some(plaintext),
        "correct key decrypts to original plaintext"
    );
    assert_eq!(link.get_decrypted_data(None), None, "no key -> None");

    let wrong_key = CryptoUtils::generate_encryption_key_bytes();
    assert_eq!(
        link.get_decrypted_data(Some(&wrong_key)),
        None,
        "wrong key fails to decrypt -> None (not a panic)"
    );
}

// (5) get_link_data auto-detects plain JSON vs encrypted.
#[test]
fn link_get_link_data_plain_and_encrypted() {
    // Plain JSON parses without a key.
    let plain = link_with_plain_json(Some("ai_settings"), json!({ "aiEnabled": true }));
    let map = plain
        .get_link_data(None)
        .expect("plain JSON parses without key");
    assert_eq!(map.get("aiEnabled"), Some(&Value::Bool(true)));

    // Encrypted data parses only when the key is supplied.
    let key = CryptoUtils::generate_encryption_key_bytes();
    let ciphertext =
        CryptoUtils::encrypt_aes_gcm(br#"{"enabled":true}"#, &key, None).expect("encrypts");
    let enc = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(&ciphertext)),
        path: Some("jit_settings".into()),
    };
    assert!(
        enc.get_link_data(None).is_none(),
        "encrypted + no key -> None"
    );
    let map = enc
        .get_link_data(Some(&key))
        .expect("encrypted + key parses");
    assert_eq!(map.get("enabled"), Some(&Value::Bool(true)));
}

// (6) Settings accessors are gated to the matching path.
#[test]
fn link_settings_path_filters() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let ai = link_with_plain_json(Some("ai_settings"), json!({ "aiEnabled": true }));
    let jit = link_with_plain_json(Some("jit_settings"), json!({ "enabled": true }));

    assert!(
        ai.get_ai_settings_data(&key).is_some(),
        "ai path returns ai settings"
    );
    assert!(
        ai.get_jit_settings_data(&key).is_none(),
        "ai path is not jit"
    );
    assert!(
        jit.get_jit_settings_data(&key).is_some(),
        "jit path returns jit settings"
    );
    assert!(
        jit.get_ai_settings_data(&key).is_none(),
        "jit path is not ai"
    );

    // Generic accessor matches any path.
    assert!(
        ai.get_settings_for_path("ai_settings", None).is_some(),
        "generic accessor matches the path"
    );
    assert!(
        ai.get_settings_for_path("other", None).is_none(),
        "generic accessor returns None for non-matching path"
    );
}

// (7) Record::get_links() builds typed links from the raw `links` field, which is unchanged.
#[test]
fn record_get_links_builds_typed_links() {
    let mut link_map: HashMap<String, Value> = HashMap::new();
    link_map.insert("recordUid".into(), Value::String("LINKED_UID".into()));
    link_map.insert(
        "data".into(),
        Value::String(bytes_to_base64(br#"{"is_admin":true}"#)),
    );
    link_map.insert("path".into(), Value::String("ai_settings".into()));

    let mut record = Record {
        links: vec![link_map],
        ..Default::default()
    };

    // Raw field still populated (back-compat).
    assert_eq!(record.links.len(), 1, "raw links field is unchanged");

    let links = record.get_links();
    assert_eq!(links.len(), 1, "one typed link produced");
    assert_eq!(links[0].record_uid, "LINKED_UID");
    assert_eq!(links[0].path.as_deref(), Some("ai_settings"));
    assert!(links[0].is_admin_user(), "typed link decodes its data");

    // A malformed link entry (no recordUid) is skipped, not fatal.
    let bad: HashMap<String, Value> = HashMap::new();
    record.links.push(bad);
    assert_eq!(
        record.get_links().len(),
        1,
        "entry without recordUid is skipped"
    );
}

// (8) Java-parity: string-encoded values are NOT coerced. Java's parseJsonData returns the
// raw string for `isString` primitives (SecretsManager.kt:228), so `getBooleanValue`'s
// `as? Boolean` yields false and `getIntValue`'s `as? Int` yields null for `"true"`/`"3"`.
// Rust's `Value::as_bool`/`as_i64` behave identically. This pins that parity.
#[test]
fn link_string_encoded_values_are_not_coerced() {
    let link = link_with_plain_json(
        None,
        json!({ "is_admin": "true", "rotation": "false", "version": "3" }),
    );
    assert!(
        !link.is_admin_user(),
        "string \"true\" is not coerced to bool (matches Java)"
    );
    assert!(
        !link.allows_rotation(),
        "string \"false\" stays falsey (matches Java)"
    );
    assert_eq!(
        link.get_link_data_version(),
        None,
        "string \"3\" is not coerced to int (matches Java)"
    );

    // Real JSON bool/number ARE read.
    let typed = link_with_plain_json(None, json!({ "is_admin": true, "version": 3 }));
    assert!(typed.is_admin_user());
    assert_eq!(typed.get_link_data_version(), Some(3));
}

// (9) has_encrypted_data: true for non-JSON, non-printable bytes; false for printable text.
#[test]
fn link_has_encrypted_data_detection() {
    // Real AES-GCM ciphertext: non-JSON, non-printable -> looks encrypted.
    let key = CryptoUtils::generate_encryption_key_bytes();
    let ciphertext = CryptoUtils::encrypt_aes_gcm(b"some secret bytes", &key, None).expect("enc");
    let enc = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(&ciphertext)),
        path: None,
    };
    assert!(
        enc.has_encrypted_data(),
        "ciphertext should be detected as encrypted"
    );

    // Printable, non-JSON text -> not encrypted.
    let text = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(b"just plain readable text, not json")),
        path: None,
    };
    assert!(
        !text.has_encrypted_data(),
        "printable text is not flagged encrypted"
    );

    // JSON -> not encrypted.
    let jsonl = link_with_plain_json(None, json!({ "a": 1 }));
    assert!(!jsonl.has_encrypted_data(), "JSON is not flagged encrypted");
}

// (10) get_settings_for_path with an encrypted payload + key (generic accessor, decrypt path).
#[test]
fn link_get_settings_for_path_encrypted() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let ciphertext =
        CryptoUtils::encrypt_aes_gcm(br#"{"customSetting":42}"#, &key, None).expect("enc");
    let link = KeeperRecordLink {
        record_uid: "RU".into(),
        data: Some(bytes_to_base64(&ciphertext)),
        path: Some("custom_settings".into()),
    };
    let map = link
        .get_settings_for_path("custom_settings", Some(&key))
        .expect("matching path + key decrypts");
    assert_eq!(map.get("customSetting"), Some(&Value::Number(42.into())));
    assert!(
        link.get_settings_for_path("other", Some(&key)).is_none(),
        "non-matching path -> None"
    );
}
