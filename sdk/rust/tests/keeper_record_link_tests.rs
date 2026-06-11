// Tests for the typed KeeperRecordLink accessor layer.
//
// KSM-997 introduced the layer (Java parity); KSM-1009 aligned it with the Python SDK
// reference implementation (KSM-992): permission booleans read the nested
// `allowedSettings` object used by current `meta` links (top-level wins), new accessors
// for the live-verified payload fields, and lossless `raw` retention. Each test states
// what it proves; a failure localizes to the specific accessor.

use keeper_secrets_manager_core::crypto::CryptoUtils;
use keeper_secrets_manager_core::dto::dtos::{KeeperRecordLink, Record};
use keeper_secrets_manager_core::utils::bytes_to_base64;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Build a link whose `data` is base64 of the given plain JSON value.
fn link_with_plain_json(path: Option<&str>, data: Value) -> KeeperRecordLink {
    let json_str = data.to_string();
    KeeperRecordLink::new(
        "RU_test",
        Some(bytes_to_base64(json_str.as_bytes())),
        path.map(str::to_string),
    )
}

/// Build a link whose `data` is base64 of the payload encrypted with AES-256-GCM.
fn link_with_encrypted_json(path: Option<&str>, data: Value, key: &[u8]) -> KeeperRecordLink {
    let ciphertext =
        CryptoUtils::encrypt_aes_gcm(data.to_string().as_bytes(), key, None).expect("encrypts");
    KeeperRecordLink::new(
        "RU_test",
        Some(bytes_to_base64(&ciphertext)),
        path.map(str::to_string),
    )
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
    // Absent keys must default to false (matches the Python reference).
    assert!(
        !link.allows_port_forwards(),
        "absent key must default to false"
    );
    assert!(
        !link.is_launch_credential(),
        "absent key must default to false"
    );
    assert!(!link.is_iam_user(), "absent key must default to false");
    assert!(!link.belongs_to(), "absent key must default to false");
    assert!(
        !link.no_update_services(),
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
    let raw = KeeperRecordLink::new("RU", Some(bytes_to_base64(b"not json at all")), None);
    assert!(
        !raw.has_readable_data(),
        "plain text without {{/[ is not readable JSON"
    );
    assert_eq!(
        raw.get_link_data_version(),
        None,
        "no version in non-JSON data"
    );

    // Invalid base64 decodes to None, never panics.
    let bad = KeeperRecordLink::new("RU", Some("!!! not base64 !!!".to_string()), None);
    assert_eq!(bad.get_decoded_data(), None);
    assert_eq!(bad.get_link_data(None), None);
}

// (3) might_be_encrypted is gated to the known encrypted paths only.
#[test]
fn link_might_be_encrypted_by_path() {
    let ai = link_with_plain_json(Some("ai_settings"), json!({}));
    let jit = link_with_plain_json(Some("jit_settings"), json!({}));
    let meta = link_with_plain_json(Some("meta"), json!({}));
    let other = link_with_plain_json(Some("something_else"), json!({}));
    let none = link_with_plain_json(None, json!({}));
    assert!(ai.might_be_encrypted());
    assert!(jit.might_be_encrypted());
    assert!(
        !meta.might_be_encrypted(),
        "meta links carry plain JSON, never assumed encrypted"
    );
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
    let link = KeeperRecordLink::new(
        "RU",
        Some(bytes_to_base64(&ciphertext)),
        Some("jit_settings".into()),
    );

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
    let enc = link_with_encrypted_json(Some("jit_settings"), json!({ "enabled": true }), &key);
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
        links: vec![link_map.clone()],
        ..Default::default()
    };

    // Raw field still populated (back-compat).
    assert_eq!(record.links.len(), 1, "raw links field is unchanged");

    let links = record.get_links();
    assert_eq!(links.len(), 1, "one typed link produced");
    assert_eq!(links[0].record_uid, "LINKED_UID");
    assert_eq!(links[0].path.as_deref(), Some("ai_settings"));
    assert!(links[0].is_admin_user(), "typed link decodes its data");
    assert_eq!(
        links[0].raw, link_map,
        "typed link keeps the original entry in raw"
    );

    // A malformed link entry (no recordUid) is skipped, not fatal.
    let bad: HashMap<String, Value> = HashMap::new();
    record.links.push(bad);
    assert_eq!(
        record.get_links().len(),
        1,
        "entry without recordUid is skipped"
    );
}

// (8) Python-reference parity: string-encoded values are NOT coerced. `Value::as_bool`/
// `as_i64` return None for `"true"`/`"3"`, and a JSON bool is not an integer version.
#[test]
fn link_string_encoded_values_are_not_coerced() {
    let link = link_with_plain_json(
        None,
        json!({ "is_admin": "true", "rotation": "false", "version": "3" }),
    );
    assert!(
        !link.is_admin_user(),
        "string \"true\" is not coerced to bool"
    );
    assert!(!link.allows_rotation(), "string \"false\" stays falsey");
    assert_eq!(
        link.get_link_data_version(),
        None,
        "string \"3\" is not coerced to int"
    );

    // Real JSON bool/number ARE read.
    let typed = link_with_plain_json(None, json!({ "is_admin": true, "version": 3 }));
    assert!(typed.is_admin_user());
    assert_eq!(typed.get_link_data_version(), Some(3));

    // A JSON bool must not count as an integer version.
    let bool_version = link_with_plain_json(None, json!({ "version": true }));
    assert_eq!(
        bool_version.get_link_data_version(),
        None,
        "boolean version is not an integer version"
    );
}

// (9) has_encrypted_data: true for non-JSON, non-printable bytes; false for printable text.
#[test]
fn link_has_encrypted_data_detection() {
    // Real AES-GCM ciphertext: non-JSON, non-printable -> looks encrypted.
    let key = CryptoUtils::generate_encryption_key_bytes();
    let ciphertext = CryptoUtils::encrypt_aes_gcm(b"some secret bytes", &key, None).expect("enc");
    let enc = KeeperRecordLink::new("RU", Some(bytes_to_base64(&ciphertext)), None);
    assert!(
        enc.has_encrypted_data(),
        "ciphertext should be detected as encrypted"
    );

    // Printable, non-JSON text -> not encrypted.
    let text = KeeperRecordLink::new(
        "RU",
        Some(bytes_to_base64(b"just plain readable text, not json")),
        None,
    );
    assert!(
        !text.has_encrypted_data(),
        "printable text is not flagged encrypted"
    );

    // JSON -> not encrypted.
    let jsonl = link_with_plain_json(None, json!({ "a": 1 }));
    assert!(!jsonl.has_encrypted_data(), "JSON is not flagged encrypted");

    // No data -> not encrypted.
    let no_data = KeeperRecordLink::new("RU", None, None);
    assert!(
        !no_data.has_encrypted_data(),
        "no data is not flagged encrypted"
    );
}

// (10) get_settings_for_path with an encrypted payload + key (generic accessor, decrypt path).
#[test]
fn link_get_settings_for_path_encrypted() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let link = link_with_encrypted_json(
        Some("custom_settings"),
        json!({ "customSetting": 42 }),
        &key,
    );
    let map = link
        .get_settings_for_path("custom_settings", Some(&key))
        .expect("matching path + key decrypts");
    assert_eq!(map.get("customSetting"), Some(&Value::Number(42.into())));
    assert!(
        link.get_settings_for_path("other", Some(&key)).is_none(),
        "non-matching path -> None"
    );
}

// (11) meta self-links (live shape): permission booleans fall back to the nested
// allowedSettings object, and the meta dict accessors expose the full payload.
#[test]
fn link_meta_live_shape() {
    let link = link_with_plain_json(
        Some("meta"),
        json!({
            "allowedSettings": {
                "rotation": true,
                "connections": true,
                "portForwards": true,
                "sessionRecording": true,
                "typescriptRecording": false,
                "aiEnabled": true,
                "aiSessionTerminate": true,
                "remoteBrowserIsolation": true
            },
            "rotateOnTermination": false,
            "version": 1,
            "no_update_services": true
        }),
    );

    // Permission booleans read from allowedSettings when absent at the top level.
    assert!(link.allows_rotation(), "rotation via allowedSettings");
    assert!(link.allows_connections(), "connections via allowedSettings");
    assert!(
        link.allows_port_forwards(),
        "portForwards via allowedSettings"
    );
    assert!(
        link.allows_session_recording(),
        "sessionRecording via allowedSettings"
    );
    assert!(
        !link.allows_typescript_recording(),
        "false in allowedSettings reads false"
    );
    assert!(
        link.allows_remote_browser_isolation(),
        "remoteBrowserIsolation via allowedSettings"
    );
    assert!(link.ai_enabled(), "aiEnabled via allowedSettings");
    assert!(
        link.ai_session_terminate(),
        "aiSessionTerminate via allowedSettings"
    );

    // Top-level fields.
    assert!(!link.rotates_on_termination());
    assert_eq!(link.get_link_data_version(), Some(1));
    assert!(link.no_update_services());

    // Dict accessors.
    let allowed = link.get_allowed_settings();
    assert_eq!(allowed.get("rotation"), Some(&Value::Bool(true)));
    let meta = link.get_meta_data(None).expect("meta parses without a key");
    assert_eq!(meta.get("version"), Some(&Value::Number(1.into())));
    assert!(
        link_with_plain_json(None, json!({}))
            .get_meta_data(None)
            .is_none(),
        "get_meta_data is gated to path meta"
    );
}

// (12) Credential links (live rich shape): user flags and the nested rotation_settings.
#[test]
fn link_credential_live_shape() {
    let link = link_with_plain_json(
        None,
        json!({
            "is_admin": true,
            "is_iam_user": false,
            "belongs_to": true,
            "is_launch_credential": true,
            "rotation_settings": {
                "schedule": "",
                "pwd_complexity": "ZmFrZS1jb21wbGV4aXR5",
                "disabled": false,
                "noop": false,
                "saas_record_uid_list": []
            }
        }),
    );

    assert!(link.is_admin_user());
    assert!(!link.is_iam_user());
    assert!(link.belongs_to());
    assert!(link.is_launch_credential());

    let rotation_settings = link.get_rotation_settings().expect("settings present");
    assert_eq!(
        rotation_settings.get("schedule"),
        Some(&Value::String(String::new()))
    );
    assert_eq!(rotation_settings.get("disabled"), Some(&Value::Bool(false)));
    assert_eq!(
        rotation_settings.get("saas_record_uid_list"),
        Some(&Value::Array(vec![]))
    );

    assert!(
        link_with_plain_json(None, json!({ "is_admin": true }))
            .get_rotation_settings()
            .is_none(),
        "absent rotation_settings -> None"
    );
}

// (13) Pure reference links (data null) answer all accessors with false/None.
#[test]
fn link_data_less_reference() {
    let mut link_map: HashMap<String, Value> = HashMap::new();
    link_map.insert("recordUid".into(), Value::String("RU_ref".into()));
    link_map.insert("data".into(), Value::Null);
    link_map.insert("path".into(), Value::Null);

    let record = Record {
        links: vec![link_map],
        ..Default::default()
    };
    let links = record.get_links();
    assert_eq!(links.len(), 1, "data-less reference is still a valid link");

    let link = &links[0];
    assert_eq!(link.record_uid, "RU_ref");
    assert!(!link.is_admin_user());
    assert!(!link.allows_rotation());
    assert_eq!(link.get_link_data_version(), None);
    assert_eq!(link.get_decoded_data(), None);
    let key = CryptoUtils::generate_encryption_key_bytes();
    assert_eq!(link.get_decrypted_data(Some(&key)), None);
    assert_eq!(link.get_link_data(None), None);
    assert!(link.get_allowed_settings().is_empty());
    assert!(link.get_rotation_settings().is_none());
    assert!(!link.has_readable_data());
    assert!(!link.has_encrypted_data());
}

// (14) ai_settings links (live shape) decrypt to the current riskLevels payload; the
// string version is not an integer version.
#[test]
fn link_ai_settings_live_shape() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let payload = json!({
        "version": "v1.0.0",
        "riskLevels": {
            "critical": { "tags": { "allow": [], "deny": [] }, "aiSessionTerminate": true },
            "high": { "tags": { "allow": [], "deny": [] }, "aiSessionTerminate": true },
            "medium": { "tags": { "allow": [], "deny": [] }, "aiSessionTerminate": true },
            "low": { "tags": { "allow": [] }, "aiSessionTerminate": false }
        }
    });
    let link = link_with_encrypted_json(Some("ai_settings"), payload.clone(), &key);

    let data = link.get_ai_settings_data(&key).expect("decrypts");
    assert_eq!(
        Value::Object(data),
        payload,
        "nested riskLevels structure is preserved"
    );
    assert_eq!(
        link.get_link_data_version(),
        None,
        "string version is not an integer version (and data is encrypted anyway)"
    );
}

// (15) jit_settings links (live shape) decrypt to the current elevation payload.
#[test]
fn link_jit_settings_live_shape() {
    let key = CryptoUtils::generate_encryption_key_bytes();
    let payload = json!({
        "createEphemeral": true,
        "elevate": true,
        "elevationMethod": "group",
        "elevationString": "arn:aws",
        "baseDistinguishedName": ""
    });
    let link = link_with_encrypted_json(Some("jit_settings"), payload.clone(), &key);

    let data = link.get_jit_settings_data(&key).expect("decrypts");
    assert_eq!(Value::Object(data), payload);
}

// (16) Losslessness: unknown link-level keys survive in raw, and unknown payload fields
// pass through get_link_data.
#[test]
fn link_losslessness() {
    let payload = json!({ "is_admin": true, "futureField": { "nested": [1, 2, 3] } });
    let mut link_map: HashMap<String, Value> = HashMap::new();
    link_map.insert("recordUid".into(), Value::String("RU".into()));
    link_map.insert(
        "data".into(),
        Value::String(bytes_to_base64(payload.to_string().as_bytes())),
    );
    link_map.insert("path".into(), Value::Null);
    link_map.insert("futureLinkKey".into(), Value::String("kept".into()));

    let record = Record {
        links: vec![link_map.clone()],
        ..Default::default()
    };
    let links = record.get_links();
    assert_eq!(links.len(), 1);

    let link = &links[0];
    assert_eq!(link.raw, link_map, "raw keeps the original entry untouched");
    assert_eq!(
        link.raw.get("futureLinkKey"),
        Some(&Value::String("kept".into()))
    );

    let data = link.get_link_data(None).expect("parses");
    assert_eq!(
        data.get("futureField"),
        Some(&json!({ "nested": [1, 2, 3] })),
        "unknown payload fields pass through get_link_data"
    );
}

// (17) A top-level boolean takes precedence over the allowedSettings fallback.
#[test]
fn link_top_level_wins_over_allowed_settings() {
    let link = link_with_plain_json(
        None,
        json!({
            "rotation": false,
            "allowedSettings": { "rotation": true }
        }),
    );
    assert!(!link.allows_rotation(), "top-level value wins");

    let only_nested =
        link_with_plain_json(None, json!({ "allowedSettings": { "rotation": true } }));
    assert!(
        only_nested.allows_rotation(),
        "fallback applies when top level is absent"
    );
}
